package security

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/sirupsen/logrus"
)

// ─────────────────────────────────────────────────────────────────
// JWT (RS256) implementation
// ─────────────────────────────────────────────────────────────────

// JWTClaims are the standard claims included in every Falcn JWT.
type JWTClaims struct {
	jwt.RegisteredClaims
	UserID string `json:"uid"`
	OrgID  string `json:"oid"`
	Role   string `json:"role"`
	Scopes []string `json:"scopes,omitempty"`
}

// JWTService signs and verifies RS256 JWTs.
type JWTService struct {
	privateKey     *rsa.PrivateKey
	publicKey      *rsa.PublicKey
	accessTTL      time.Duration
	refreshTTL     time.Duration
	issuer         string
}

// NewJWTService creates a JWTService.
// If privateKeyPEM is empty a new 2048-bit key is generated (useful for tests).
func NewJWTService(privateKeyPEM, issuer string, accessTTL, refreshTTL time.Duration) (*JWTService, error) {
	var privKey *rsa.PrivateKey
	if privateKeyPEM == "" {
		generated, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("jwt: generate key: %w", err)
		}
		privKey = generated
	} else {
		block, _ := pem.Decode([]byte(privateKeyPEM))
		if block == nil {
			return nil, fmt.Errorf("jwt: invalid PEM block")
		}
		var err error
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("jwt: parse key: %w", err)
		}
	}
	return &JWTService{
		privateKey: privKey,
		publicKey:  &privKey.PublicKey,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		issuer:     issuer,
	}, nil
}

// IssueAccessToken signs a short-lived access JWT.
func (s *JWTService) IssueAccessToken(userID, orgID, role string, scopes []string) (string, error) {
	now := time.Now()
	claims := JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTTL)),
		},
		UserID: userID,
		OrgID:  orgID,
		Role:   role,
		Scopes: scopes,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return tok.SignedString(s.privateKey)
}

// IssueRefreshToken signs a long-lived refresh JWT.
func (s *JWTService) IssueRefreshToken(userID string) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    s.issuer,
		Subject:   userID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(s.refreshTTL)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return tok.SignedString(s.privateKey)
}

// Verify validates a JWT and returns its claims.
func (s *JWTService) Verify(tokenStr string) (*JWTClaims, error) {
	tok, err := jwt.ParseWithClaims(tokenStr, &JWTClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("jwt: verify: %w", err)
	}
	claims, ok := tok.Claims.(*JWTClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("jwt: invalid claims")
	}
	return claims, nil
}

// PublicKeyPEM returns the PEM-encoded RSA public key (for JWKS endpoint).
func (s *JWTService) PublicKeyPEM() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(s.publicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// ─────────────────────────────────────────────────────────────────
// OAuth2 device flow (GitHub + Google)
// ─────────────────────────────────────────────────────────────────

// OAuthProvider configuration.
type OAuthProvider struct {
	Name         string
	ClientID     string
	ClientSecret string
	DeviceURL    string // device authorization endpoint
	TokenURL     string // token endpoint
	UserInfoURL  string // user info endpoint
	Scopes       []string
}

var (
	GitHubOAuth = func(clientID, clientSecret string) OAuthProvider {
		return OAuthProvider{
			Name:         "github",
			ClientID:     clientID,
			ClientSecret: clientSecret,
			DeviceURL:    "https://github.com/login/device/code",
			TokenURL:     "https://github.com/login/oauth/access_token",
			UserInfoURL:  "https://api.github.com/user",
			Scopes:       []string{"read:user", "user:email"},
		}
	}
	GoogleOAuth = func(clientID, clientSecret string) OAuthProvider {
		return OAuthProvider{
			Name:         "google",
			ClientID:     clientID,
			ClientSecret: clientSecret,
			DeviceURL:    "https://oauth2.googleapis.com/device/code",
			TokenURL:     "https://oauth2.googleapis.com/token",
			UserInfoURL:  "https://www.googleapis.com/oauth2/v3/userinfo",
			Scopes:       []string{"openid", "email", "profile"},
		}
	}
)

// DeviceAuthResponse is returned by the device authorization endpoint.
type DeviceAuthResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// OAuthUserInfo is the normalized profile returned by any provider.
type OAuthUserInfo struct {
	ProviderID string
	Email      string
	Name       string
	AvatarURL  string
}

// OAuthService manages OAuth2 device-flow authentication.
type OAuthService struct {
	client    *http.Client
	providers map[string]OAuthProvider
}

// NewOAuthService creates an OAuthService with the given providers.
func NewOAuthService(providers ...OAuthProvider) *OAuthService {
	s := &OAuthService{
		client:    &http.Client{Timeout: 15 * time.Second},
		providers: make(map[string]OAuthProvider, len(providers)),
	}
	for _, p := range providers {
		s.providers[p.Name] = p
	}
	return s
}

// StartDeviceFlow initiates the device authorization flow for a given provider.
func (s *OAuthService) StartDeviceFlow(ctx context.Context, providerName string) (*DeviceAuthResponse, error) {
	p, ok := s.providers[providerName]
	if !ok {
		return nil, fmt.Errorf("oauth: unknown provider %q", providerName)
	}

	form := url.Values{
		"client_id": {p.ClientID},
		"scope":     {strings.Join(p.Scopes, " ")},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.DeviceURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth: device request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: device flow: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var dar DeviceAuthResponse
	if err := json.Unmarshal(body, &dar); err != nil {
		return nil, fmt.Errorf("oauth: parse device response: %w", err)
	}
	return &dar, nil
}

// PollForToken polls the token endpoint until the user completes the device flow.
func (s *OAuthService) PollForToken(ctx context.Context, providerName, deviceCode string, interval int) (string, error) {
	p := s.providers[providerName]
	tick := time.Duration(interval) * time.Second
	if tick < 5*time.Second {
		tick = 5 * time.Second
	}

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(tick):
		}

		form := url.Values{
			"client_id":   {p.ClientID},
			"device_code": {deviceCode},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL,
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")

		resp, err := s.client.Do(req)
		if err != nil {
			logrus.Warnf("oauth poll error: %v", err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var result map[string]interface{}
		_ = json.Unmarshal(body, &result)

		if token, ok := result["access_token"].(string); ok && token != "" {
			return token, nil
		}
		if errCode, ok := result["error"].(string); ok {
			switch errCode {
			case "authorization_pending", "slow_down":
				continue
			default:
				return "", fmt.Errorf("oauth: token error: %s", errCode)
			}
		}
	}
}

// GetUserInfo fetches the normalized user profile using the access token.
func (s *OAuthService) GetUserInfo(ctx context.Context, providerName, accessToken string) (*OAuthUserInfo, error) {
	p, ok := s.providers[providerName]
	if !ok {
		return nil, fmt.Errorf("oauth: unknown provider %q", providerName)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.UserInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: userinfo: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var raw map[string]interface{}
	_ = json.Unmarshal(body, &raw)

	info := &OAuthUserInfo{ProviderID: providerName}
	// Normalize across GitHub and Google response shapes
	for _, key := range []string{"email", "email_address"} {
		if v, ok := raw[key].(string); ok && v != "" {
			info.Email = v
			break
		}
	}
	for _, key := range []string{"name", "login"} {
		if v, ok := raw[key].(string); ok && v != "" {
			info.Name = v
			break
		}
	}
	for _, key := range []string{"avatar_url", "picture"} {
		if v, ok := raw[key].(string); ok && v != "" {
			info.AvatarURL = v
			break
		}
	}
	return info, nil
}

// ─────────────────────────────────────────────────────────────────
// LDAP authentication (enterprise)
// ─────────────────────────────────────────────────────────────────

// LDAPConfig holds connection and search configuration for an LDAP server.
type LDAPConfig struct {
	URL        string // ldap://host:389 or ldaps://host:636
	BindDN     string // service account DN for search
	BindPass   string
	BaseDN     string // search base DN
	UserFilter string // e.g. "(uid=%s)"
	GroupDN    string // optional group DN for membership check
}

// LDAPService authenticates users against an LDAP directory.
type LDAPService struct {
	cfg  LDAPConfig
	mu   sync.Mutex
	conn *ldap.Conn
}

// NewLDAPService creates a new LDAPService.
func NewLDAPService(cfg LDAPConfig) *LDAPService {
	return &LDAPService{cfg: cfg}
}

// Authenticate verifies username + password via LDAP bind.
// Returns (email, displayName, nil) on success.
func (s *LDAPService) Authenticate(username, password string) (email, displayName string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn, dialErr := ldap.DialURL(s.cfg.URL)
	if dialErr != nil {
		return "", "", fmt.Errorf("ldap: dial %s: %w", s.cfg.URL, dialErr)
	}
	defer conn.Close()

	// Service account bind for search
	if s.cfg.BindDN != "" {
		if err := conn.Bind(s.cfg.BindDN, s.cfg.BindPass); err != nil {
			return "", "", fmt.Errorf("ldap: service bind: %w", err)
		}
	}

	// Search for the user's DN
	filter := fmt.Sprintf(s.cfg.UserFilter, ldap.EscapeFilter(username))
	searchReq := ldap.NewSearchRequest(
		s.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 10, false,
		filter,
		[]string{"dn", "mail", "displayName", "cn"},
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return "", "", fmt.Errorf("ldap: search: %w", err)
	}
	if len(result.Entries) != 1 {
		return "", "", fmt.Errorf("ldap: user %q not found or ambiguous", username)
	}

	userDN := result.Entries[0].DN
	email = result.Entries[0].GetAttributeValue("mail")
	if email == "" {
		email = result.Entries[0].GetAttributeValue("cn")
	}
	displayName = result.Entries[0].GetAttributeValue("displayName")
	if displayName == "" {
		displayName = result.Entries[0].GetAttributeValue("cn")
	}

	// Authenticate the user with their own credentials
	if err := conn.Bind(userDN, password); err != nil {
		return "", "", fmt.Errorf("ldap: authentication failed: %w", err)
	}

	return email, displayName, nil
}

// ─────────────────────────────────────────────────────────────────
// Token hashing utilities
// ─────────────────────────────────────────────────────────────────

// HashToken returns the SHA-256 hex hash of a raw token.
// Only the hash is stored in the DB; the raw token is shown to the user once.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}

// GenerateSecureToken returns a cryptographically random base64url-encoded token.
func GenerateSecureToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ─────────────────────────────────────────────────────────────────
// HTTP middleware
// ─────────────────────────────────────────────────────────────────

type contextKey string

const (
	ContextKeyUserID contextKey = "user_id"
	ContextKeyOrgID  contextKey = "org_id"
	ContextKeyRole   contextKey = "role"
)

// JWTMiddleware validates Bearer tokens and injects claims into the request context.
func JWTMiddleware(jwtSvc *JWTService, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"error":"missing or invalid Authorization header"}`, http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := jwtSvc.Verify(tokenStr)
		if err != nil {
			logrus.Debugf("JWT verify failed: %v", err)
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ContextKeyUserID, claims.UserID)
		ctx = context.WithValue(ctx, ContextKeyOrgID, claims.OrgID)
		ctx = context.WithValue(ctx, ContextKeyRole, claims.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// APIKeyMiddleware validates API keys against a lookup function.
// lookupKey receives the SHA-256 hash of the key and returns (userID, orgID, role, ok).
func APIKeyMiddleware(lookupKey func(hash string) (userID, orgID, role string, ok bool), next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			http.Error(w, `{"error":"missing X-API-Key header"}`, http.StatusUnauthorized)
			return
		}
		hash := HashToken(key)
		userID, orgID, role, ok := lookupKey(hash)
		if !ok {
			http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ContextKeyUserID, userID)
		ctx = context.WithValue(ctx, ContextKeyOrgID, orgID)
		ctx = context.WithValue(ctx, ContextKeyRole, role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireEnvJWTKey loads the JWT private key from the FALCN_JWT_PRIVATE_KEY_FILE env var.
// Falls back to auto-generating a key (logs a warning — not suitable for production).
func RequireEnvJWTKey() (*JWTService, error) {
	keyFile := os.Getenv("FALCN_JWT_PRIVATE_KEY_FILE")
	pemBytes := ""
	if keyFile != "" {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("auth: read JWT key file %s: %w", keyFile, err)
		}
		pemBytes = string(b)
	} else {
		logrus.Warn("FALCN_JWT_PRIVATE_KEY_FILE not set — generating ephemeral JWT key (not suitable for production)")
	}
	issuer := os.Getenv("FALCN_JWT_ISSUER")
	if issuer == "" {
		issuer = "falcn"
	}
	return NewJWTService(pemBytes, issuer, 15*time.Minute, 7*24*time.Hour)
}
