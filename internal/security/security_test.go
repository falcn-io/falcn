package security

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────────────────────────
// Role definitions and AtLeast
// ──────────────────────────────────────────────

func TestRole_AtLeast(t *testing.T) {
	tests := []struct {
		role    Role
		minimum Role
		want    bool
	}{
		{RoleOwner, RoleOwner, true},
		{RoleOwner, RoleAdmin, true},
		{RoleOwner, RoleAnalyst, true},
		{RoleOwner, RoleViewer, true},
		{RoleAdmin, RoleAdmin, true},
		{RoleAdmin, RoleAnalyst, true},
		{RoleAdmin, RoleViewer, true},
		{RoleAdmin, RoleOwner, false},
		{RoleAnalyst, RoleAnalyst, true},
		{RoleAnalyst, RoleViewer, true},
		{RoleAnalyst, RoleAdmin, false},
		{RoleAnalyst, RoleOwner, false},
		{RoleViewer, RoleViewer, true},
		{RoleViewer, RoleAnalyst, false},
		{RoleViewer, RoleAdmin, false},
		{RoleViewer, RoleOwner, false},
	}

	for _, tc := range tests {
		t.Run(string(tc.role)+">="+string(tc.minimum), func(t *testing.T) {
			assert.Equal(t, tc.want, tc.role.AtLeast(tc.minimum))
		})
	}
}

func TestRole_String(t *testing.T) {
	assert.Equal(t, "viewer", RoleViewer.String())
	assert.Equal(t, "analyst", RoleAnalyst.String())
	assert.Equal(t, "admin", RoleAdmin.String())
	assert.Equal(t, "owner", RoleOwner.String())
}

func TestParseRole(t *testing.T) {
	tests := []struct {
		input string
		want  Role
	}{
		{"viewer", RoleViewer},
		{"analyst", RoleAnalyst},
		{"admin", RoleAdmin},
		{"owner", RoleOwner},
		{"unknown_role", RoleViewer}, // defaults to viewer
		{"", RoleViewer},
		{"ADMIN", RoleViewer}, // case-sensitive, falls back to viewer
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.want, ParseRole(tc.input))
		})
	}
}

// ──────────────────────────────────────────────
// Permission checks
// ──────────────────────────────────────────────

func TestHasPermission_ViewerPermissions(t *testing.T) {
	// Viewer should have read-only permissions
	assert.True(t, HasPermission(RoleViewer, PermScanRead))
	assert.True(t, HasPermission(RoleViewer, PermVulnRead))
	assert.True(t, HasPermission(RoleViewer, PermPolicyRead))

	// Viewer should NOT have write permissions
	assert.False(t, HasPermission(RoleViewer, PermScanCreate))
	assert.False(t, HasPermission(RoleViewer, PermScanDelete))
	assert.False(t, HasPermission(RoleViewer, PermUserWrite))
	assert.False(t, HasPermission(RoleViewer, PermOrgDelete))
}

func TestHasPermission_AnalystPermissions(t *testing.T) {
	assert.True(t, HasPermission(RoleAnalyst, PermScanRead))
	assert.True(t, HasPermission(RoleAnalyst, PermScanCreate))
	assert.True(t, HasPermission(RoleAnalyst, PermIntegRead))

	// Analyst should NOT have admin/owner permissions
	assert.False(t, HasPermission(RoleAnalyst, PermScanDelete))
	assert.False(t, HasPermission(RoleAnalyst, PermUserWrite))
	assert.False(t, HasPermission(RoleAnalyst, PermBillingRead))
}

func TestHasPermission_AdminPermissions(t *testing.T) {
	assert.True(t, HasPermission(RoleAdmin, PermScanDelete))
	assert.True(t, HasPermission(RoleAdmin, PermPolicyWrite))
	assert.True(t, HasPermission(RoleAdmin, PermUserWrite))
	assert.True(t, HasPermission(RoleAdmin, PermAuditRead))
	assert.True(t, HasPermission(RoleAdmin, PermBillingRead))

	// Admin should NOT have owner-only permissions
	assert.False(t, HasPermission(RoleAdmin, PermUserDelete))
	assert.False(t, HasPermission(RoleAdmin, PermBillingWrite))
	assert.False(t, HasPermission(RoleAdmin, PermOrgDelete))
}

func TestHasPermission_OwnerPermissions(t *testing.T) {
	ownerPerms := []Permission{
		PermScanRead, PermScanCreate, PermScanDelete,
		PermVulnRead, PermPolicyRead, PermPolicyWrite,
		PermUserRead, PermUserWrite, PermUserDelete,
		PermIntegRead, PermIntegWrite, PermAuditRead,
		PermBillingRead, PermBillingWrite, PermOrgDelete,
	}
	for _, perm := range ownerPerms {
		t.Run(string(perm), func(t *testing.T) {
			assert.True(t, HasPermission(RoleOwner, perm))
		})
	}
}

func TestHasPermission_UnknownRole_ReturnsFalse(t *testing.T) {
	assert.False(t, HasPermission(Role("nonexistent"), PermScanRead))
}

// ──────────────────────────────────────────────
// Context helpers
// ──────────────────────────────────────────────

func TestRoleFromContext_WithValue(t *testing.T) {
	ctx := context.WithValue(context.Background(), ContextKeyRole, "admin")
	assert.Equal(t, RoleAdmin, RoleFromContext(ctx))
}

func TestRoleFromContext_Empty_DefaultsToViewer(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, RoleViewer, RoleFromContext(ctx))
}

func TestUserIDFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), ContextKeyUserID, "user-123")
	assert.Equal(t, "user-123", UserIDFromContext(ctx))
}

func TestUserIDFromContext_Missing(t *testing.T) {
	assert.Empty(t, UserIDFromContext(context.Background()))
}

func TestOrgIDFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), ContextKeyOrgID, "org-456")
	assert.Equal(t, "org-456", OrgIDFromContext(ctx))
}

// ──────────────────────────────────────────────
// RequireRole middleware
// ──────────────────────────────────────────────

func TestRequireRole_Allowed(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := RequireRole(RoleAnalyst, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Inject admin role (which is >= analyst)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyRole, "admin"))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireRole_Forbidden(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := RequireRole(RoleAdmin, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Inject viewer role (which is < admin)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyRole, "viewer"))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "forbidden")
}

func TestRequireRole_NoRoleInContext_DefaultsToViewer_ThenForbidden(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Require at least analyst, but no role is in context
	wrapped := RequireRole(RoleAnalyst, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No role in context → defaults to viewer → forbidden
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ──────────────────────────────────────────────
// RequirePermission middleware
// ──────────────────────────────────────────────

func TestRequirePermission_Allowed(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := RequirePermission(PermScanCreate, handler)

	req := httptest.NewRequest(http.MethodPost, "/scan", nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyRole, "analyst"))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequirePermission_Forbidden(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := RequirePermission(PermOrgDelete, handler)

	req := httptest.NewRequest(http.MethodDelete, "/org", nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyRole, "admin"))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "org:delete")
}

// ──────────────────────────────────────────────
// JWT Service
// ──────────────────────────────────────────────

func TestNewJWTService_GeneratesEphemeralKey(t *testing.T) {
	svc, err := NewJWTService("", "falcn-test", 15*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)
	require.NotNil(t, svc)
}

func TestNewJWTService_InvalidPEM_ReturnsError(t *testing.T) {
	_, err := NewJWTService("this is not a valid PEM", "falcn-test", time.Minute, time.Hour)
	require.Error(t, err)
}

func TestJWTService_IssueAndVerifyAccessToken(t *testing.T) {
	svc, err := NewJWTService("", "falcn-test", 15*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	token, err := svc.IssueAccessToken("user-1", "org-1", "admin", []string{"scan:read"})
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, err := svc.Verify(token)
	require.NoError(t, err)
	assert.Equal(t, "user-1", claims.UserID)
	assert.Equal(t, "org-1", claims.OrgID)
	assert.Equal(t, "admin", claims.Role)
	assert.Equal(t, "falcn-test", claims.Issuer)
}

func TestJWTService_IssueAndVerifyRefreshToken(t *testing.T) {
	svc, err := NewJWTService("", "falcn-test", 15*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	token, err := svc.IssueRefreshToken("user-2")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Refresh token uses RegisteredClaims, parse it as JWTClaims will still work
	_, err = svc.Verify(token)
	// UserID will be empty in refresh token (not set in claims)
	require.NoError(t, err)
}

func TestJWTService_Verify_InvalidToken_ReturnsError(t *testing.T) {
	svc, err := NewJWTService("", "falcn-test", 15*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	_, err = svc.Verify("not.a.valid.jwt")
	require.Error(t, err)
}

func TestJWTService_Verify_TamperedToken_ReturnsError(t *testing.T) {
	svc, err := NewJWTService("", "falcn-test", 15*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	token, err := svc.IssueAccessToken("user-1", "org-1", "admin", nil)
	require.NoError(t, err)

	// Tamper with the token by appending garbage
	tampered := token + "garbage"
	_, err = svc.Verify(tampered)
	require.Error(t, err)
}

func TestJWTService_PublicKeyPEM(t *testing.T) {
	svc, err := NewJWTService("", "falcn-test", 15*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	pem, err := svc.PublicKeyPEM()
	require.NoError(t, err)
	assert.Contains(t, pem, "PUBLIC KEY")
}

// ──────────────────────────────────────────────
// JWT Middleware
// ──────────────────────────────────────────────

func TestJWTMiddleware_ValidToken_PassesThrough(t *testing.T) {
	svc, _ := NewJWTService("", "falcn", time.Hour, 7*24*time.Hour)
	token, _ := svc.IssueAccessToken("u1", "o1", "analyst", nil)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		assert.Equal(t, "u1", UserIDFromContext(r.Context()))
		assert.Equal(t, "o1", OrgIDFromContext(r.Context()))
		assert.Equal(t, RoleAnalyst, RoleFromContext(r.Context()))
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	JWTMiddleware(svc, next).ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestJWTMiddleware_MissingHeader_Returns401(t *testing.T) {
	svc, _ := NewJWTService("", "falcn", time.Hour, 7*24*time.Hour)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	JWTMiddleware(svc, next).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestJWTMiddleware_InvalidToken_Returns401(t *testing.T) {
	svc, _ := NewJWTService("", "falcn", time.Hour, 7*24*time.Hour)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	rec := httptest.NewRecorder()

	JWTMiddleware(svc, next).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ──────────────────────────────────────────────
// API Key Middleware
// ──────────────────────────────────────────────

func TestAPIKeyMiddleware_ValidKey_PassesThrough(t *testing.T) {
	rawKey := "my-super-secret-api-key-for-testing"
	hash := HashToken(rawKey)

	lookup := func(h string) (string, string, string, bool) {
		if h == hash {
			return "user-api", "org-api", "analyst", true
		}
		return "", "", "", false
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		assert.Equal(t, "user-api", UserIDFromContext(r.Context()))
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", rawKey)
	rec := httptest.NewRecorder()

	APIKeyMiddleware(lookup, next).ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAPIKeyMiddleware_MissingKey_Returns401(t *testing.T) {
	lookup := func(h string) (string, string, string, bool) { return "", "", "", false }
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	APIKeyMiddleware(lookup, next).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAPIKeyMiddleware_InvalidKey_Returns401(t *testing.T) {
	lookup := func(h string) (string, string, string, bool) { return "", "", "", false }
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "invalid-key")
	rec := httptest.NewRecorder()

	APIKeyMiddleware(lookup, next).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ──────────────────────────────────────────────
// Token utilities
// ──────────────────────────────────────────────

func TestHashToken_Deterministic(t *testing.T) {
	h1 := HashToken("my-raw-token")
	h2 := HashToken("my-raw-token")
	assert.Equal(t, h1, h2)
}

func TestHashToken_DifferentInputsDifferentHashes(t *testing.T) {
	h1 := HashToken("token-a")
	h2 := HashToken("token-b")
	assert.NotEqual(t, h1, h2)
}

func TestHashToken_IsHex(t *testing.T) {
	h := HashToken("test-token")
	// SHA-256 produces 64 hex chars
	assert.Len(t, h, 64)
}

func TestGenerateSecureToken_LengthAndUniqueness(t *testing.T) {
	t1, err := GenerateSecureToken(32)
	require.NoError(t, err)
	assert.NotEmpty(t, t1)

	t2, err := GenerateSecureToken(32)
	require.NoError(t, err)
	// Extremely unlikely to be equal
	assert.NotEqual(t, t1, t2)
}

// ──────────────────────────────────────────────
// SecureConfigValidator
// ──────────────────────────────────────────────

func TestSecureConfigValidator_ValidateJWTSecret(t *testing.T) {
	v := NewSecureConfigValidator()

	tests := []struct {
		name    string
		secret  string
		wantErr bool
	}{
		{"empty", "", true},
		{"too short (< 32)", "tooshort", true},
		{"contains 'secret'", "this-contains-the-word-secret-and-more", true},
		{"contains 'password'", "this-is-a-password-and-some-extra-padding", true},
		{"valid strong secret", "X8k2#mPqR9!wZn5vYe3LdHjFc7GtBsA4", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := v.ValidateJWTSecret(tc.secret)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSecureConfigValidator_ValidateAdminPassword(t *testing.T) {
	v := NewSecureConfigValidator()

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"empty", "", true},
		{"too short", "Ab1!xyz", true},
		{"no uppercase", "abc123!@#defghijk", true},
		{"no lowercase", "ABC123!@#DEFGHIJK", true},
		{"no digit", "AbcDef!@#ghijklmn", true},
		{"no special char", "AbcDef123ghijklmn", true},
		{"contains 'password'", "MyPassword123!!", true},
		{"valid strong password", "Str0ng!Pass#2024", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := v.ValidateAdminPassword(tc.password)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSecureConfigValidator_ValidateAPIKeys(t *testing.T) {
	v := NewSecureConfigValidator()

	// Empty slice should succeed (API keys are optional)
	assert.NoError(t, v.ValidateAPIKeys([]string{}))

	// Key too short
	assert.Error(t, v.ValidateAPIKeys([]string{"tooshort"}))

	// Key contains weak patterns
	assert.Error(t, v.ValidateAPIKeys([]string{"this-is-a-test-key-that-is-long-enough"}))
	assert.Error(t, v.ValidateAPIKeys([]string{"this-is-a-demo-key-that-is-long-enough"}))
	assert.Error(t, v.ValidateAPIKeys([]string{"this-is-an-example-key-that-is-long-enough"}))

	// Valid key
	assert.NoError(t, v.ValidateAPIKeys([]string{"a9b2c4d1e5f8g7h3i6j0k-valid-long-api-key"}))
}

func TestSecureConfigValidator_ValidateEncryptionKey(t *testing.T) {
	v := NewSecureConfigValidator()

	// Empty key
	assert.Error(t, v.ValidateEncryptionKey(""))

	// Too short (less than 32 chars)
	assert.Error(t, v.ValidateEncryptionKey("tooshort"))

	// Wrong length (more than 32 chars) — must be exactly 32
	assert.Error(t, v.ValidateEncryptionKey("this-key-is-longer-than-32-characters-so-it-fails"))

	// Exactly 32 chars
	assert.NoError(t, v.ValidateEncryptionKey("12345678901234567890123456789012"))
}

func TestSecureConfigValidator_GenerateSecureSecret(t *testing.T) {
	v := NewSecureConfigValidator()

	secret, err := v.GenerateSecureSecret(32)
	require.NoError(t, err)
	assert.NotEmpty(t, secret)
	// hex encoded: 32 bytes = 64 hex chars
	assert.Len(t, secret, 64)

	// Should enforce minimum of 32
	short, err := v.GenerateSecureSecret(10)
	require.NoError(t, err)
	assert.NotEmpty(t, short)
}

func TestSecureConfigValidator_GetSecurityRecommendations(t *testing.T) {
	v := NewSecureConfigValidator()
	recs := v.GetSecurityRecommendations()
	assert.NotEmpty(t, recs)
	assert.Greater(t, len(recs), 5)
}

// ──────────────────────────────────────────────
// SecurityConfig (security_config.go)
// ──────────────────────────────────────────────

func TestSecurityConfig_Validate_Valid(t *testing.T) {
	cfg := &SecurityConfig{
		JWT: JWTSecurityConfig{
			SecretKey: "a-strong-jwt-secret-that-is-at-least-32-chars!!",
		},
		Authentication: AuthSecurityConfig{
			MinPasswordLength: 10,
			MaxLoginAttempts:  5,
		},
		RateLimit: RateLimitSecurityConfig{
			GlobalRequestsPerSec: 100,
			GlobalBurstSize:      200,
		},
		Encryption: EncryptionConfig{
			EncryptSensitiveData: false,
		},
	}
	assert.NoError(t, cfg.Validate())
}

func TestSecurityConfig_Validate_MissingJWTSecret(t *testing.T) {
	cfg := &SecurityConfig{
		JWT: JWTSecurityConfig{SecretKey: ""},
	}
	assert.Error(t, cfg.Validate())
}

func TestSecurityConfig_Validate_JWTSecretTooShort(t *testing.T) {
	cfg := &SecurityConfig{
		JWT: JWTSecurityConfig{SecretKey: "tooshort"},
	}
	assert.Error(t, cfg.Validate())
}

func TestSecurityConfig_Validate_MinPasswordLengthTooLow(t *testing.T) {
	cfg := &SecurityConfig{
		JWT: JWTSecurityConfig{SecretKey: "a-strong-jwt-secret-that-is-at-least-32-chars!!"},
		Authentication: AuthSecurityConfig{
			MinPasswordLength: 6, // < 8
			MaxLoginAttempts:  5,
		},
		RateLimit: RateLimitSecurityConfig{
			GlobalRequestsPerSec: 100,
			GlobalBurstSize:      200,
		},
	}
	assert.Error(t, cfg.Validate())
}

func TestSecurityConfig_Validate_MaxLoginAttemptsZero(t *testing.T) {
	cfg := &SecurityConfig{
		JWT: JWTSecurityConfig{SecretKey: "a-strong-jwt-secret-that-is-at-least-32-chars!!"},
		Authentication: AuthSecurityConfig{
			MinPasswordLength: 8,
			MaxLoginAttempts:  0, // < 1
		},
		RateLimit: RateLimitSecurityConfig{
			GlobalRequestsPerSec: 100,
			GlobalBurstSize:      200,
		},
	}
	assert.Error(t, cfg.Validate())
}

func TestGenerateSecureJWTSecret(t *testing.T) {
	secret, err := GenerateSecureJWTSecret()
	require.NoError(t, err)
	assert.NotEmpty(t, secret)
	// 64 bytes → 128 hex chars
	assert.Len(t, secret, 128)
}

func TestGenerateSecureEncryptionKey_SecurityConfig(t *testing.T) {
	key, err := GenerateSecureEncryptionKey()
	require.NoError(t, err)
	assert.NotEmpty(t, key)
	// 32 bytes → 64 hex chars
	assert.Len(t, key, 64)
}

func TestSecurityConfig_HashAndVerifyPassword(t *testing.T) {
	cfg := &SecurityConfig{
		Authentication: AuthSecurityConfig{
			SaltLength: 16,
		},
	}

	hashed, err := cfg.HashPassword("my-secure-password")
	require.NoError(t, err)
	assert.NotEmpty(t, hashed)

	assert.True(t, cfg.VerifyPassword("my-secure-password", hashed))
	assert.False(t, cfg.VerifyPassword("wrong-password", hashed))
}

func TestSecurityConfig_VerifyPassword_MalformedHash(t *testing.T) {
	cfg := &SecurityConfig{Authentication: AuthSecurityConfig{SaltLength: 16}}

	assert.False(t, cfg.VerifyPassword("password", "no-colon-here"))
	assert.False(t, cfg.VerifyPassword("password", "notvalidhex:alsoinvalid"))
}

// ──────────────────────────────────────────────
// AttackDetector
// ──────────────────────────────────────────────

func TestAttackDetector_DetectInString_SQLInjection(t *testing.T) {
	ad := NewAttackDetector()

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{"union select", "' UNION SELECT * FROM users", true},
		{"drop table", "DROP TABLE users", true},
		{"clean input", "hello world", false},
		{"normal package name", "lodash", false},
		{"xss script tag", "<script>alert(1)</script>", true},
		{"path traversal", "../etc/passwd", true},
		{"clean url", "/api/v1/scan", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detected, attackType := ad.DetectInString(tc.input)
			assert.Equal(t, tc.wantHit, detected)
			if tc.wantHit {
				assert.NotEmpty(t, attackType)
			}
		})
	}
}

func TestBehaviorAnalyzer_AnalyzeBehavior(t *testing.T) {
	ba := NewBehaviorAnalyzer()

	// First request, not suspicious
	score := ba.AnalyzeBehavior("client-1", false)
	assert.Equal(t, 0.0, score)

	// Suspicious requests should raise the score
	ba.AnalyzeBehavior("client-1", true)
	ba.AnalyzeBehavior("client-1", true)
	ba.AnalyzeBehavior("client-1", false)
	score = ba.AnalyzeBehavior("client-1", false)
	assert.Greater(t, score, 0.0)
	assert.LessOrEqual(t, score, 1.0)
}

func TestSequenceDetector_DetectSequence(t *testing.T) {
	sd := NewSequenceDetector()

	// Not suspicious with a single pattern
	assert.False(t, sd.DetectSequence("client-a", "sql_injection"))
	assert.False(t, sd.DetectSequence("client-a", "sql_injection"))

	// Suspicious after 3+ distinct attack types
	sd.DetectSequence("client-b", "sql_injection")
	sd.DetectSequence("client-b", "xss")
	result := sd.DetectSequence("client-b", "path_traversal")
	// After 3 distinct types, should be suspicious
	assert.True(t, result)
}

// ──────────────────────────────────────────────
// PerformanceOptimizer
// ──────────────────────────────────────────────

func TestPerformanceOptimizer_Creation(t *testing.T) {
	opt := NewPerformanceOptimizer(nil) // nil uses defaults
	require.NotNil(t, opt)
}

func TestPerformanceOptimizer_OptimizePolicyEvaluation_CacheMiss(t *testing.T) {
	opt := NewPerformanceOptimizer(nil)

	callCount := 0
	result, perfResult, err := opt.OptimizePolicyEvaluation(
		context.Background(),
		"policy-key-1",
		func() (interface{}, error) {
			callCount++
			return "evaluated", nil
		},
	)

	require.NoError(t, err)
	assert.Equal(t, "evaluated", result)
	assert.False(t, perfResult.CacheHit)
	assert.Equal(t, 1, callCount)
}

func TestPerformanceOptimizer_OptimizePolicyEvaluation_CacheHit(t *testing.T) {
	opt := NewPerformanceOptimizer(nil)

	callCount := 0
	eval := func() (interface{}, error) {
		callCount++
		return "value", nil
	}

	// First call — miss
	opt.OptimizePolicyEvaluation(context.Background(), "key-cache-test", eval)
	// Second call — should be a hit
	result, perfResult, err := opt.OptimizePolicyEvaluation(context.Background(), "key-cache-test", eval)

	require.NoError(t, err)
	assert.Equal(t, "value", result)
	assert.True(t, perfResult.CacheHit)
	assert.Equal(t, 1, callCount) // evaluation func only called once
}

func TestPerformanceOptimizer_OptimizeValidation(t *testing.T) {
	opt := NewPerformanceOptimizer(nil)

	valid, perfResult, err := opt.OptimizeValidation(
		context.Background(),
		"val-key",
		func() (bool, error) { return true, nil },
	)

	require.NoError(t, err)
	assert.True(t, valid)
	assert.False(t, perfResult.CacheHit)
}

func TestPerformanceOptimizer_ClearCaches(t *testing.T) {
	opt := NewPerformanceOptimizer(nil)
	// Populate cache
	opt.OptimizePolicyEvaluation(context.Background(), "key1", func() (interface{}, error) { return 1, nil })
	opt.OptimizeValidation(context.Background(), "val1", func() (bool, error) { return true, nil })

	metrics := opt.GetMetrics()
	assert.Greater(t, metrics["policy_cache_items"], 0)

	opt.ClearCaches()

	metrics = opt.GetMetrics()
	assert.Equal(t, 0, metrics["policy_cache_items"])
}

func TestPerformanceOptimizer_GetConnection_ReleaseConnection(t *testing.T) {
	opt := NewPerformanceOptimizer(nil)
	conn := opt.GetConnection()
	require.NotNil(t, conn)
	assert.True(t, conn.InUse)

	opt.ReleaseConnection(conn)
	assert.False(t, conn.InUse)
}

func TestPerformanceOptimizer_Shutdown(t *testing.T) {
	opt := NewPerformanceOptimizer(nil)
	err := opt.Shutdown(context.Background())
	assert.NoError(t, err)
}

// ──────────────────────────────────────────────
// PolicyEngine
// ──────────────────────────────────────────────

func TestNewPolicyEngine_HasDefaultPolicies(t *testing.T) {
	pe := NewPolicyEngine(nil)
	require.NotNil(t, pe)

	policies := pe.GetPolicies()
	assert.Contains(t, policies, "sql_injection_protection")
	assert.Contains(t, policies, "xss_protection")
	assert.Contains(t, policies, "rate_limiting")
}

func TestPolicyEngine_AddAndGetPolicy(t *testing.T) {
	pe := NewPolicyEngine(nil)

	policy := &SecurityPolicy{
		ID:      "test-policy",
		Name:    "Test Policy",
		Type:    PolicyTypeInput,
		Enabled: true,
	}
	err := pe.AddPolicy(policy)
	require.NoError(t, err)

	retrieved, ok := pe.GetPolicy("test-policy")
	require.True(t, ok)
	assert.Equal(t, "Test Policy", retrieved.Name)
}

func TestPolicyEngine_AddPolicy_EmptyID_ReturnsError(t *testing.T) {
	pe := NewPolicyEngine(nil)
	err := pe.AddPolicy(&SecurityPolicy{ID: "", Name: "No ID"})
	require.Error(t, err)
}

func TestPolicyEngine_RemovePolicy(t *testing.T) {
	pe := NewPolicyEngine(nil)
	pe.AddPolicy(&SecurityPolicy{ID: "to-remove", Name: "Remove Me"})

	err := pe.RemovePolicy("to-remove")
	require.NoError(t, err)

	_, ok := pe.GetPolicy("to-remove")
	assert.False(t, ok)
}

func TestPolicyEngine_RemovePolicy_NotFound_ReturnsError(t *testing.T) {
	pe := NewPolicyEngine(nil)
	err := pe.RemovePolicy("nonexistent-policy")
	require.Error(t, err)
}

func TestPolicyEngine_EvaluatePolicy_SQLInjection(t *testing.T) {
	pe := NewPolicyEngine(nil)

	ctx := &PolicyContext{
		UserID:    "user-1",
		IPAddress: "1.2.3.4",
		Endpoint:  "/api/scan",
		Method:    "POST",
		Body:      "' UNION SELECT * FROM users --",
		Timestamp: time.Now(),
		Headers:   map[string]string{},
		Metadata:  map[string]interface{}{},
	}

	result, err := pe.EvaluatePolicy("sql_injection_protection", ctx)
	require.NoError(t, err)
	// SQL injection should be blocked
	assert.False(t, result.Allowed)
	assert.Equal(t, ActionBlock, result.Action)
}

func TestPolicyEngine_EvaluatePolicy_CleanInput_Allowed(t *testing.T) {
	pe := NewPolicyEngine(nil)

	ctx := &PolicyContext{
		UserID:    "user-2",
		IPAddress: "1.2.3.4",
		Endpoint:  "/api/scan",
		Method:    "POST",
		Body:      `{"package": "lodash", "version": "4.17.21"}`,
		Timestamp: time.Now(),
		Headers:   map[string]string{},
		Metadata:  map[string]interface{}{},
	}

	result, err := pe.EvaluatePolicy("sql_injection_protection", ctx)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestPolicyEngine_EvaluatePolicy_DisabledPolicy_Allows(t *testing.T) {
	pe := NewPolicyEngine(nil)
	pe.AddPolicy(&SecurityPolicy{
		ID:      "disabled-policy",
		Name:    "Disabled",
		Enabled: false,
		Rules: []PolicyRule{{
			ID:       "r1",
			Field:    "body",
			Operator: OperatorContains,
			Value:    "anything",
		}},
		Actions: []PolicyAction{{Type: ActionBlock}},
	})

	ctx := &PolicyContext{
		Body:      "anything",
		Timestamp: time.Now(),
		Headers:   map[string]string{},
		Metadata:  map[string]interface{}{},
	}

	result, err := pe.EvaluatePolicy("disabled-policy", ctx)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, "Policy disabled", result.Message)
}

func TestPolicyEngine_EvaluatePolicy_NotFound_ReturnsError(t *testing.T) {
	pe := NewPolicyEngine(nil)
	_, err := pe.EvaluatePolicy("nonexistent", &PolicyContext{
		Timestamp: time.Now(),
		Headers:   map[string]string{},
		Metadata:  map[string]interface{}{},
	})
	require.Error(t, err)
}

func TestPolicyEngine_EvaluateAllPolicies(t *testing.T) {
	pe := NewPolicyEngine(nil)

	ctx := &PolicyContext{
		UserID:    "user-3",
		IPAddress: "10.0.0.1",
		Endpoint:  "/api/scan",
		Method:    "GET",
		Body:      "clean body",
		Timestamp: time.Now(),
		Headers:   map[string]string{},
		Parameters: map[string]interface{}{},
		Metadata:  map[string]interface{}{},
	}

	results, err := pe.EvaluateAllPolicies(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, results)
}

// ──────────────────────────────────────────────
// FIPS
// ──────────────────────────────────────────────

func TestFIPSEnabled_IsBool(t *testing.T) {
	// In non-fips builds FIPSEnabled should be false
	assert.False(t, FIPSEnabled)
}

func TestFIPSHashNotAllowed_NoopInNonFIPS(t *testing.T) {
	// In non-FIPS build this should be a no-op, not panic
	assert.NotPanics(t, func() {
		FIPSHashNotAllowed("MD5")
	})
}

func TestFIPSAssertApprovedHash_NoopInNonFIPS(t *testing.T) {
	assert.NotPanics(t, func() {
		FIPSAssertApprovedHash("SHA-256")
		FIPSAssertApprovedHash("MD5") // Also no-op in non-FIPS
	})
}

func TestFIPSInfo_NonFIPS(t *testing.T) {
	info := FIPSInfo()
	require.NotNil(t, info)
	assert.Equal(t, false, info["fips_enabled"])
}

// ──────────────────────────────────────────────
// InputValidator
// ──────────────────────────────────────────────

func TestInputValidator_SanitizeString(t *testing.T) {
	iv := NewInputValidator()

	tests := []struct {
		name  string
		input string
		check func(t *testing.T, result string)
	}{
		{
			"removes null bytes",
			"hello\x00world",
			func(t *testing.T, result string) { assert.NotContains(t, result, "\x00") },
		},
		{
			"trims whitespace",
			"  hello  ",
			func(t *testing.T, result string) { assert.Equal(t, "hello", result) },
		},
		{
			"preserves newlines and tabs",
			"line1\nline2\ttabbed",
			func(t *testing.T, result string) {
				assert.Contains(t, result, "\n")
				assert.Contains(t, result, "\t")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := iv.SanitizeString(tc.input)
			tc.check(t, result)
		})
	}
}

func TestInputValidator_SanitizeHTML(t *testing.T) {
	iv := NewInputValidator()

	result := iv.SanitizeHTML(`<script>alert('xss')</script><p>Hello</p>`)
	assert.NotContains(t, result, "<script")
	assert.Contains(t, result, "Hello")
}

func TestInputValidator_ValidatePackageName(t *testing.T) {
	iv := NewInputValidator()

	tests := []struct {
		name    string
		pkg     string
		wantOK  bool
	}{
		{"valid simple", "lodash", true},
		{"valid with dash", "my-package", true},
		{"valid with dot", "some.package", true},
		{"empty", "", false},
		{"too long", string(make([]byte, 215)), false},
		{"contains space", "my package", false},
		{"path traversal", "../evil", false},
		{"xss", "<script>alert(1)</script>", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := iv.ValidatePackageName(tc.pkg)
			assert.Equal(t, tc.wantOK, result.Valid)
		})
	}
}

func TestInputValidator_ValidateURL(t *testing.T) {
	iv := NewInputValidator()

	tests := []struct {
		name   string
		url    string
		wantOK bool
	}{
		{"valid https", "https://example.com/path", true},
		{"valid http", "http://localhost:8080", true},
		{"valid git", "git://github.com/owner/repo.git", true},
		{"invalid scheme ftp", "ftp://files.example.com", false},
		{"javascript scheme", "javascript:alert(1)", false},
		{"data URI", "data:text/html,<h1>xss</h1>", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, result := iv.ValidateURL(tc.url)
			assert.Equal(t, tc.wantOK, result.Valid)
		})
	}
}

func TestInputValidator_ValidateAPIKey(t *testing.T) {
	iv := NewInputValidator()

	tests := []struct {
		name   string
		key    string
		wantOK bool
	}{
		{"valid key", "abcdef1234567890", true},
		{"too short", "short", false},
		{"contains space", "invalid key here!", false},
		{"valid with dash", "abc-def-123-xyz-qrs", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := iv.ValidateAPIKey(tc.key)
			assert.Equal(t, tc.wantOK, result.Valid)
		})
	}
}

func TestInputValidator_ValidateJSON(t *testing.T) {
	iv := NewInputValidator()

	validJSON := []byte(`{"package":"lodash","version":"4.17.21"}`)
	result := iv.ValidateJSON(validJSON)
	assert.True(t, result.Valid)

	invalidJSON := []byte(`{not valid json`)
	result = iv.ValidateJSON(invalidJSON)
	assert.False(t, result.Valid)
}

func TestInputValidator_ValidateJSON_TooLarge(t *testing.T) {
	iv := NewInputValidator()
	// Create JSON larger than 10MB
	huge := make([]byte, 11*1024*1024)
	result := iv.ValidateJSON(huge)
	assert.False(t, result.Valid)
}

// ──────────────────────────────────────────────
// OAuthService
// ──────────────────────────────────────────────

func TestNewOAuthService_NoProviders(t *testing.T) {
	svc := NewOAuthService()
	require.NotNil(t, svc)
}

func TestOAuthService_StartDeviceFlow_UnknownProvider_ReturnsError(t *testing.T) {
	svc := NewOAuthService()
	_, err := svc.StartDeviceFlow(context.Background(), "nonexistent-provider")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestGitHubOAuth_Constructor(t *testing.T) {
	p := GitHubOAuth("my-client-id", "my-client-secret")
	assert.Equal(t, "github", p.Name)
	assert.Equal(t, "my-client-id", p.ClientID)
	assert.NotEmpty(t, p.DeviceURL)
	assert.NotEmpty(t, p.TokenURL)
}

func TestGoogleOAuth_Constructor(t *testing.T) {
	p := GoogleOAuth("google-client-id", "google-client-secret")
	assert.Equal(t, "google", p.Name)
	assert.Equal(t, "google-client-id", p.ClientID)
	assert.NotEmpty(t, p.DeviceURL)
}
