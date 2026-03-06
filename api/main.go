// Package main implements the Falcn API server for supply chain security scanning.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	apimetrics "github.com/falcn-io/falcn/internal/api/metrics"
	apilm "github.com/falcn-io/falcn/internal/api/middleware"
	whloader "github.com/falcn-io/falcn/internal/api/webhook"
	appcfg "github.com/falcn-io/falcn/internal/config"
	containerpkg "github.com/falcn-io/falcn/internal/container"
	"github.com/falcn-io/falcn/internal/database"
	"github.com/falcn-io/falcn/internal/detector"
	internalevent "github.com/falcn-io/falcn/internal/events"
	"github.com/falcn-io/falcn/internal/integrations/hub"
	llmpkg "github.com/falcn-io/falcn/internal/llm"
	"github.com/falcn-io/falcn/internal/security"
	pkgevents "github.com/falcn-io/falcn/pkg/events"
	pkglogger "github.com/falcn-io/falcn/pkg/logger"
	pkgmetrics "github.com/falcn-io/falcn/pkg/metrics"
	pkgtypes "github.com/falcn-io/falcn/pkg/types"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	redis "github.com/redis/go-redis/v9"
	"github.com/rs/cors"
	"golang.org/x/time/rate"
)

// API server constants — replace all magic numbers throughout the file.
const (
	maxRequestBodyBytes = 10 * 1024 * 1024  // 10 MB — maximum accepted request body size
	maxScanHistory      = 500               // maximum in-memory scan records kept
	maxBatchSize        = 100               // maximum packages per batch request
	defaultRateLimit    = 10               // requests allowed per minute per IP
	shutdownTimeout     = 30 * time.Second  // graceful HTTP server shutdown window
	webhookTimeout      = 10 * time.Second  // per-webhook delivery timeout
	serverReadTimeout   = 30 * time.Second  // HTTP server read timeout
	serverWriteTimeout  = 60 * time.Second  // HTTP server write timeout
	serverIdleTimeout   = 120 * time.Second // HTTP server idle keep-alive timeout
	riskScoreThreshold  = 0.8              // minimum score to classify as high risk
)

type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
}

type ReadyResponse struct {
	Ready     bool      `json:"ready"`
	Timestamp time.Time `json:"timestamp"`
}

type AnalyzeRequest struct {
	PackageName string `json:"package_name"`
	Registry    string `json:"registry,omitempty"`
}

type AnalysisResult struct {
	PackageName string    `json:"package_name"`
	Registry    string    `json:"registry"`
	Threats     []Threat  `json:"threats"`
	Warnings    []Warning `json:"warnings"`
	RiskLevel   int       `json:"risk_level"`
	RiskScore   float64   `json:"risk_score"`
	AnalyzedAt  time.Time `json:"analyzed_at"`
}

// ThreatExplanation is the AI-generated analysis for a specific threat.
// Field names mirror types.ThreatExplanation and the frontend ThreatExplanation interface.
type ThreatExplanation struct {
	What        string    `json:"what"`
	Why         string    `json:"why"`
	Impact      string    `json:"impact"`
	Remediation string    `json:"remediation"`
	Confidence  float64   `json:"confidence"`
	GeneratedBy string    `json:"generated_by,omitempty"`
	GeneratedAt time.Time `json:"generated_at"`
	CacheHit    bool      `json:"cache_hit,omitempty"`
}

// Threat is the API-layer threat record returned by /v1/analyze.
// It deliberately matches the frontend Threat TypeScript interface.
type Threat struct {
	ID          string             `json:"id"`
	Type        string             `json:"type"`
	Severity    string             `json:"severity"`
	Title       string             `json:"title,omitempty"`
	Description string             `json:"description"`
	Package     string             `json:"package"`
	Registry    string             `json:"registry"`
	Confidence  float64            `json:"confidence"`
	SimilarTo   string             `json:"similar_to,omitempty"`
	CVEID       string             `json:"cve_id,omitempty"`
	CVSSScore   float64            `json:"cvss_score,omitempty"`
	DetectedAt  time.Time          `json:"detected_at"`
	Explanation *ThreatExplanation `json:"explanation,omitempty"`
}

type Warning struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type BatchAnalyzeRequest struct {
	Packages []AnalyzeRequest `json:"packages"`
}

type BatchAnalysisResult struct {
	Results    []AnalysisResult `json:"results"`
	Summary    BatchSummary     `json:"summary"`
	AnalyzedAt time.Time        `json:"analyzed_at"`
}

type BatchSummary struct {
	Total      int `json:"total"`
	HighRisk   int `json:"high_risk"`
	MediumRisk int `json:"medium_risk"`
	LowRisk    int `json:"low_risk"`
	NoThreats  int `json:"no_threats"`
}

// Rate limiter for API endpoints
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
	}
}

func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[ip]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		// Double-check pattern
		if limiter, exists = rl.limiters[ip]; !exists {
			// Allow defaultRateLimit requests per minute per IP.
			limiter = rate.NewLimiter(rate.Every(time.Minute/defaultRateLimit), defaultRateLimit)
			rl.limiters[ip] = limiter
		}
		rl.mu.Unlock()
	}

	return limiter
}

func (rl *RateLimiter) Allow(ip string) bool {
	return rl.getLimiter(ip).Allow()
}

// StartEviction runs a background goroutine that removes idle limiter entries
// to prevent unbounded growth of the clients map.
func (rl *RateLimiter) StartEviction(ctx context.Context, interval time.Duration) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("PANIC in rate limiter eviction goroutine: %v", r)
			}
		}()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rl.mu.Lock()
				for ip, limiter := range rl.limiters {
					// Evict limiters that have accumulated close to their full token
					// budget — they haven't been used recently.
					if limiter.Tokens() >= 9.5 {
						delete(rl.limiters, ip)
					}
				}
				rl.mu.Unlock()
			}
		}
	}()
}

// SSEEvent is a single server-sent event published to connected clients.
type SSEEvent struct {
	// Event is the SSE "event:" field (e.g. "threat", "ping", "done").
	Event string `json:"event"`
	// Data is the JSON payload.
	Data interface{} `json:"data"`
}

// SSEBroker manages SSE client subscriptions and broadcasts events.
// It is safe for concurrent use.
type SSEBroker struct {
	mu      sync.RWMutex
	clients map[chan SSEEvent]struct{}
}

func newSSEBroker() *SSEBroker {
	return &SSEBroker{clients: make(map[chan SSEEvent]struct{})}
}

// subscribe registers a new client channel and returns it.
func (b *SSEBroker) subscribe() chan SSEEvent {
	ch := make(chan SSEEvent, 64)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

// unsubscribe removes the client channel.
func (b *SSEBroker) unsubscribe(ch chan SSEEvent) {
	b.mu.Lock()
	delete(b.clients, ch)
	b.mu.Unlock()
}

// publish sends an event to all connected clients (non-blocking; slow clients are skipped).
func (b *SSEBroker) publish(evt SSEEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.clients {
		select {
		case ch <- evt:
		default: // client too slow — skip rather than block
		}
	}
}

// Global instances
var (
	rateLimiter *RateLimiter
	sseBroker   = newSSEBroker()
	// jwtSvc is initialized at startup. It may be nil if initialization fails,
	// in which case only API-key auth is available.
	jwtSvc *security.JWTService

	// LLM explainer — lazily initialized on first scan.
	llmProvider  llmpkg.Provider // nil when no API key is configured
	llmInitOnce  sync.Once

	// explainSem is a semaphore that limits the number of concurrent goroutines
	// generating LLM explanations. Prevents goroutine explosion under load.
	// At most 8 explanations are generated concurrently.
	explainSem = make(chan struct{}, 8)
)

// getLLMProvider returns the configured LLM provider (thread-safe, lazy init).
// Auto-detects provider from environment:
//   FALCN_LLM_PROVIDER=anthropic|openai|ollama  (explicit)
//   ANTHROPIC_API_KEY present → anthropic claude-haiku-4-5
//   OPENAI_API_KEY present    → openai gpt-4o-mini
//   FALCN_LLM_PROVIDER=ollama → local Ollama instance
func getLLMProvider() llmpkg.Provider {
	llmInitOnce.Do(func() {
		providerName := strings.ToLower(os.Getenv("FALCN_LLM_PROVIDER"))
		tryAnthropic := func() {
			if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
				p, err := llmpkg.NewProvider(appcfg.LLMConfig{
					Enabled: true, Provider: "anthropic",
					APIKey:  key, Model: "claude-haiku-4-5",
				})
				if err == nil && p != nil {
					llmProvider = llmpkg.NewSafeProvider(p)
				}
			}
		}
		tryOpenAI := func() {
			if key := os.Getenv("OPENAI_API_KEY"); key != "" {
				p, err := llmpkg.NewProvider(appcfg.LLMConfig{
					Enabled: true, Provider: "openai",
					APIKey:  key, Model: "gpt-4o-mini",
				})
				if err == nil && p != nil {
					llmProvider = llmpkg.NewSafeProvider(p)
				}
			}
		}
		switch providerName {
		case "anthropic":
			tryAnthropic()
		case "openai":
			tryOpenAI()
		case "ollama":
			endpoint := os.Getenv("OLLAMA_ENDPOINT")
			if endpoint == "" {
				endpoint = "http://localhost:11434"
			}
			model := os.Getenv("OLLAMA_MODEL")
			if model == "" {
				model = "llama3"
			}
			p, err := llmpkg.NewProvider(appcfg.LLMConfig{
				Enabled: true, Provider: "ollama",
				Endpoint: endpoint, Model: model,
			})
			if err == nil && p != nil {
				llmProvider = llmpkg.NewSafeProvider(p)
			}
		default:
			// Auto-detect: Anthropic → OpenAI
			tryAnthropic()
			if llmProvider == nil {
				tryOpenAI()
			}
		}
		if llmProvider != nil {
			log.Printf("🤖 LLM explainer: provider '%s' active", llmProvider.ID())
		} else {
			log.Println("🤖 LLM explainer: no API key configured — set ANTHROPIC_API_KEY or OPENAI_API_KEY to enable AI explanations")
		}
	})
	return llmProvider
}

// tokenRequest is the body accepted by POST /v1/auth/token.
type tokenRequest struct {
	APIKey string `json:"api_key"`
}

// tokenResponse is the body returned by POST /v1/auth/token.
type tokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"` // seconds
	TokenType string `json:"token_type"` // "Bearer"
}

// issueTokenHandler exchanges a valid API key for a signed JWT.
// This endpoint is intentionally exempt from authMiddleware.
func issueTokenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if jwtSvc == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "JWT service not available"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1024*64) // 64 KB cap for auth body
	var req tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}
	if req.APIKey == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "api_key is required"})
		return
	}

	if !validateAPIKey(req.APIKey) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid API key"})
		return
	}

	// Use the SHA-256 hex of the API key as the stable userID so it is never
	// stored in plaintext inside the JWT.
	sum := sha256.Sum256([]byte(req.APIKey))
	userID := fmt.Sprintf("%x", sum[:8]) // first 8 bytes → 16 hex chars

	const ttlSecs = 24 * 60 * 60 // 24 hours
	tok, err := jwtSvc.IssueAccessToken(userID, "default", string(security.RoleAnalyst), nil)
	if err != nil {
		log.Printf("issueTokenHandler: IssueAccessToken error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to issue token"})
		return
	}

	json.NewEncoder(w).Encode(tokenResponse{
		Token:     tok,
		ExpiresIn: ttlSecs,
		TokenType: "Bearer",
	})
}

// ── /metrics access control ───────────────────────────────────────────────────
// The Prometheus /metrics endpoint should never be publicly reachable.
// By default only loopback and RFC-1918 private addresses are allowed.
// Override with METRICS_ALLOWED_CIDRS (comma-separated CIDR list).

var metricsAllowedNets = func() []*net.IPNet {
	cidrList := os.Getenv("METRICS_ALLOWED_CIDRS")
	if cidrList == "" {
		// Default: loopback + RFC-1918 private ranges.
		cidrList = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
	}
	var nets []*net.IPNet
	for _, s := range strings.Split(cidrList, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(s)
		if err == nil {
			nets = append(nets, ipNet)
		}
	}
	return nets
}()

func isMetricsAllowed(r *http.Request) bool {
	ipStr := getClientIP(r)
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range metricsAllowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func metricsAllowed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isMetricsAllowed(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authDevMode reports whether the server is running without any credential
// config (no API_KEYS env var, no real JWT key file, API_AUTH_ENABLED not
// forced on). In this state every request is allowed through and a banner is
// logged at startup. Set API_KEYS or FALCN_JWT_PRIVATE_KEY_FILE to lock down.
func authDevMode() bool {
	enabled := os.Getenv("API_AUTH_ENABLED")
	if strings.EqualFold(enabled, "true") || enabled == "1" {
		return false // operator explicitly requires auth
	}
	if strings.EqualFold(enabled, "false") || enabled == "0" {
		return true // operator explicitly disables auth
	}
	// Auto dev-mode: neither API keys nor a persistent JWT key file configured.
	// The JWT service generates an ephemeral key (non-nil jwtSvc) even in dev,
	// so we must check the env var rather than the service pointer.
	noAPIKeys  := os.Getenv("API_KEYS") == ""
	noJWTKey   := os.Getenv("FALCN_JWT_PRIVATE_KEY_FILE") == "" &&
	              os.Getenv("FALCN_JWT_PRIVATE_KEY") == ""
	return noAPIKeys && noJWTKey
}

// API key authentication middleware.
// Accepts two credential forms under Authorization: Bearer <value>:
//  1. A valid RS256 JWT signed by jwtSvc (checked first when jwtSvc is non-nil).
//  2. A raw API key present in the API_KEYS env var (existing behaviour).
//
// When neither is configured (dev mode), every request is allowed through.
// Set API_KEYS=<comma-separated> in the environment to enable auth.
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/ready" {
			next(w, r)
			return
		}

		// Dev mode: no credentials configured → allow all requests.
		if authDevMode() {
			next(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			// Also accept API key via X-API-Key header (simpler for curl/scripts).
			if key := r.Header.Get("X-API-Key"); key != "" && validateAPIKey(key) {
				next(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Missing Authorization header"})
			return
		}
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Authorization format"})
			return
		}
		token := parts[1]

		// First try: validate as JWT when the service is available.
		if jwtSvc != nil {
			if claims, err := jwtSvc.Verify(token); err == nil {
				// Inject claims into request context so downstream handlers can
				// read user identity without re-parsing the token.
				ctx := context.WithValue(r.Context(), security.ContextKeyUserID, claims.UserID)
				ctx = context.WithValue(ctx, security.ContextKeyOrgID, claims.OrgID)
				ctx = context.WithValue(ctx, security.ContextKeyRole, claims.Role)
				next(w, r.WithContext(ctx))
				return
			}
		}

		// Second try: validate as a raw API key (existing behaviour).
		if validateAPIKey(token) {
			next(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
	}
}

func validateAPIKey(token string) bool {
	keys := os.Getenv("API_KEYS")
	if keys == "" {
		return false
	}
	for _, k := range strings.Split(keys, ",") {
		key := strings.TrimSpace(k)
		if subtle.ConstantTimeCompare([]byte(key), []byte(token)) == 1 {
			return true
		}
	}
	return false
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
	}
	json.NewEncoder(w).Encode(response)
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Redis readiness: prefer internal config; fall back to env DSN
	cfgMgr := appcfg.NewManager()
	if err := cfgMgr.Load("."); err != nil {
		log.Printf("config load warning in readyHandler: %v", err)
	}
	cfg := cfgMgr.Get()
	var redisDSN string
	var redisConfigured bool
	if cfg != nil && cfg.Redis.Enabled {
		if cfg.Redis.Password != "" {
			redisDSN = fmt.Sprintf("redis://:%s@%s:%d/%d", cfg.Redis.Password, cfg.Redis.Host, cfg.Redis.Port, cfg.Redis.Database)
		} else {
			redisDSN = fmt.Sprintf("redis://%s:%d/%d", cfg.Redis.Host, cfg.Redis.Port, cfg.Redis.Database)
		}
		redisConfigured = true
	} else {
		redisDSN = os.Getenv("RATE_LIMIT_REDIS_URL")
		redisConfigured = redisDSN != ""
	}
	redisOK := false
	if redisConfigured {
		if opt, err := redis.ParseURL(redisDSN); err == nil {
			c := redis.NewClient(opt)
			if c.Ping(r.Context()).Err() == nil {
				redisOK = true
			}
		}
		apimetrics.SetRedisConnected(redisOK)
	}

	// Webhook providers readiness via config/env loader
	providerStatus := whloader.LoadProviderConfigStatus()
	webhooks := make(map[string]map[string]bool)
	for p, configured := range providerStatus {
		apimetrics.SetWebhookProviderEnabled(p, configured)
		apimetrics.SetWebhookProviderSignatureConfigured(p, configured)
		webhooks[p] = map[string]bool{"configured": configured}
	}

	ready := true
	if redisConfigured && !redisOK {
		ready = false
	}

	resp := map[string]interface{}{
		"ready":     ready,
		"timestamp": time.Now(),
		"redis": map[string]interface{}{
			"configured": redisConfigured,
			"connected":  redisOK,
		},
		"webhooks": webhooks,
	}

	json.NewEncoder(w).Encode(resp)
}


// Rate limiting middleware
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		if !rateLimiter.Allow(ip) {
			apimetrics.RecordRateLimitHit(r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":       "Rate limit exceeded",
				"message":     "Too many requests. Please try again later.",
				"retry_after": "60 seconds",
			})
			return
		}
		next(w, r)
	}
}

func getClientIP(r *http.Request) string {
	// X-Forwarded-For may contain a comma-separated list of IPs added by each proxy.
	// Only the FIRST entry is the original client — subsequent entries are untrusted proxies.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := strings.SplitN(xff, ",", 2)[0]
		return strings.TrimSpace(first)
	}
	// X-Real-IP is set by nginx and contains a single IP.
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	// Fall back to RemoteAddr (host:port format)
	return r.RemoteAddr
}

func analyzeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	start := time.Now()

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var req AnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			http.Error(w, "Request body too large (max 10MB)", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.PackageName == "" {
		http.Error(w, "Package name is required", http.StatusBadRequest)
		return
	}
	if req.Registry == "" {
		req.Registry = "npm" // Default to npm
	}

	if err := validatePackageInput(req.PackageName, req.Registry); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Perform threat analysis using the real detector engine
	threats, warnings := performThreatAnalysis(req.PackageName, req.Registry)

	// Calculate risk level and score
	riskLevel, riskScore := calculateRiskLevel(threats)

	// Create response
	result := AnalysisResult{
		PackageName: req.PackageName,
		Registry:    req.Registry,
		Threats:     threats,
		Warnings:    warnings,
		RiskLevel:   riskLevel,
		RiskScore:   riskScore,
		AnalyzedAt:  time.Now(),
	}

	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}

	// Record scan in history store
	status := "clean"
	if len(threats) > 0 {
		status = "threats_found"
	}
	scanID := fmt.Sprintf("%s@%s", req.PackageName, req.Registry)
	recordScan(
		scanID,
		req.PackageName,
		status,
		len(threats),
		len(warnings),
		time.Since(start).Milliseconds(),
	)

	// Persist individual threat records to SQLite when available.
	if scanDB != nil {
		for _, t := range threats {
			_ = scanDB.InsertThreat(database.ScanThreatRecord{
				ScanID:      scanID,
				ThreatType:  t.Type,
				Severity:    t.Severity,
				PackageName: req.PackageName,
				Description: t.Description,
				Score:       t.Confidence,
				CreatedAt:   time.Now().UTC(),
			})
		}
	}

	if result.RiskLevel >= 3 {
		if webhookURL := os.Getenv("SLACK_WEBHOOK_URL"); webhookURL != "" {
			payload := map[string]interface{}{"text": fmt.Sprintf("High risk detected: %s (%s) risk=%d", result.PackageName, result.Registry, result.RiskLevel)}
			b, _ := json.Marshal(payload)
			if err := withRetry(3, func() error {
				webhookClient := &http.Client{Timeout: webhookTimeout}
				resp, err := webhookClient.Post(webhookURL, "application/json", bytes.NewBuffer(b))
				if err != nil {
					return err
				}
				resp.Body.Close()
				return nil
			}); err != nil {
				log.Printf("Slack webhook delivery failed after retries: %v", err)
			}
		}
		host := os.Getenv("SMTP_HOST")
		user := os.Getenv("SMTP_USER")
		pass := os.Getenv("SMTP_PASS")
		to := os.Getenv("EMAIL_TO")
		from := os.Getenv("EMAIL_FROM")
		if host != "" && user != "" && pass != "" && to != "" && from != "" {
			msg := []byte("Subject: Falcn Alert\r\n\r\n" + fmt.Sprintf("High risk detected: %s (%s) risk=%d", result.PackageName, result.Registry, result.RiskLevel))
			if err := withRetry(3, func() error {
				return smtp.SendMail(host+":587", smtp.PlainAuth("", user, pass, host), from, []string{to}, msg)
			}); err != nil {
				log.Printf("SMTP alert delivery failed after retries: %v", err)
			}
		}
	}
}

// withRetry executes fn up to attempts times with exponential backoff (1s, 2s, 4s).
// Each failed attempt is logged. Returns nil on first success.
func withRetry(attempts int, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		log.Printf("withRetry: attempt %d/%d failed: %v", i+1, attempts, err)
		time.Sleep(time.Duration(1<<uint(i)) * time.Second)
	}
	return err
}

func batchAnalyzeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var req BatchAnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			http.Error(w, "Request body too large (max 10MB)", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if len(req.Packages) == 0 {
		http.Error(w, "At least one package is required", http.StatusBadRequest)
		return
	}

	if len(req.Packages) > maxBatchSize {
		http.Error(w, fmt.Sprintf("Maximum %d packages allowed per batch", maxBatchSize), http.StatusBadRequest)
		return
	}

	// Analyze each package
	var results []AnalysisResult
	summary := BatchSummary{}

	for _, pkg := range req.Packages {
		// Set default registry if not provided
		if pkg.Registry == "" {
			pkg.Registry = "npm"
		}

		if err := validatePackageInput(pkg.PackageName, pkg.Registry); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Perform threat analysis
		threats, warnings := performThreatAnalysis(pkg.PackageName, pkg.Registry)

		// Calculate risk level and score
		riskLevel, riskScore := calculateRiskLevel(threats)

		// Create result
		result := AnalysisResult{
			PackageName: pkg.PackageName,
			Registry:    pkg.Registry,
			Threats:     threats,
			Warnings:    warnings,
			RiskLevel:   riskLevel,
			RiskScore:   riskScore,
			AnalyzedAt:  time.Now(),
		}

		results = append(results, result)

		// Update summary
		summary.Total++
		switch riskLevel {
		case 3:
			summary.HighRisk++
		case 2:
			summary.MediumRisk++
		case 1:
			summary.LowRisk++
		default:
			summary.NoThreats++
		}
	}

	// Create batch response
	batchResult := BatchAnalysisResult{
		Results:    results,
		Summary:    summary,
		AnalyzedAt: time.Now(),
	}

	if err := json.NewEncoder(w).Encode(batchResult); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// detectorEngine is initialized lazily on first request.
var (
	detectorEngine     *detector.Engine
	detectorEngineOnce sync.Once
)

// ── Integration hub (optional, activated when cfg.Integrations.Enabled is true)
var (
	apiEventBus     *internalevent.EventBus
	apiIntHub       *hub.IntegrationHub
	apiIntHubOnce   sync.Once
)

// serverCtx is the server-level context cancelled on graceful shutdown.
// Goroutines that outlive individual HTTP requests (e.g. LLM explanation
// generators) should derive their context from this so they stop cleanly.
// Overwritten in main() before any request-handling goroutine is spawned.
var serverCtx = context.Background()

// getIntegrationHub lazily creates the event bus + integration hub pair.
// Returns nil if integrations are not configured.
func getIntegrationHub() *hub.IntegrationHub {
	apiIntHubOnce.Do(func() {
		cfgMgr := appcfg.NewManager()
		_ = cfgMgr.Load(".")
		cfg := cfgMgr.Get()
		if cfg.Integrations == nil || !cfg.Integrations.Enabled {
			return
		}
		lg := pkglogger.New()
		apiEventBus = internalevent.NewEventBus(*lg, 512)
		apiIntHub = hub.NewIntegrationHub(apiEventBus, cfg.Integrations, *lg)
		ctx := context.Background()
		if err := apiIntHub.Initialize(ctx); err != nil {
			log.Printf("integration hub init error: %v", err)
			apiIntHub = nil
			return
		}
		apiEventBus.Start(ctx)
	})
	return apiIntHub
}

// publishThreatEvent publishes a security event for a detected threat to the
// integration hub (Jira, Teams, email, etc.) if one is configured. Non-blocking.
func publishThreatEvent(ctx context.Context, packageName, registry, version string, t pkgtypes.Threat) {
	if getIntegrationHub() == nil || apiEventBus == nil {
		return
	}
	sev := pkgevents.SeverityLow
	switch t.Severity {
	case pkgtypes.SeverityCritical:
		sev = pkgevents.SeverityCritical
	case pkgtypes.SeverityHigh:
		sev = pkgevents.SeverityHigh
	case pkgtypes.SeverityMedium:
		sev = pkgevents.SeverityMedium
	}
	event := &pkgevents.SecurityEvent{
		ID:        "api_event_" + uuid.New().String(),
		Timestamp: time.Now(),
		Type:      pkgevents.EventTypeThreatDetected,
		Severity:  sev,
		Package: pkgevents.PackageInfo{
			Name:     packageName,
			Version:  version,
			Registry: registry,
		},
		Threat: pkgevents.ThreatInfo{
			Type:        string(t.Type),
			Description: t.Description,
			RiskScore:   t.Confidence,
			Confidence:  t.Confidence,
			Mitigations: []string{t.Recommendation},
		},
		Metadata: pkgevents.EventMetadata{
			DetectionMethod: t.DetectionMethod,
			Tags:            []string{"api", "automated"},
		},
	}
	_ = apiEventBus.Publish(ctx, event)
}

func getDetectorEngine() *detector.Engine {
	detectorEngineOnce.Do(func() {
		cfgMgr := appcfg.NewManager()
		if err := cfgMgr.Load("."); err != nil {
			log.Printf("config load warning in getDetectorEngine: %v", err)
		}
		detectorEngine = detector.New(cfgMgr.Get())
	})
	return detectorEngine
}

// performThreatAnalysis uses the real detector engine to analyse a package.
// Discovered threats are published to the global SSE broker so streaming
// clients receive them in real-time. After the detector finishes, async
// goroutines generate or fetch cached LLM explanations per threat.
func performThreatAnalysis(packageName, registry string) ([]Threat, []Warning) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Publish "scan started" event to SSE clients
	sseBroker.publish(SSEEvent{
		Event: "scan_started",
		Data: map[string]interface{}{
			"package":   packageName,
			"registry":  registry,
			"timestamp": time.Now(),
		},
	})

	result, err := getDetectorEngine().CheckPackage(ctx, packageName, registry)
	if err != nil {
		log.Printf("detector error for %s/%s: %v", registry, packageName, err)
		sseBroker.publish(SSEEvent{
			Event: "scan_error",
			Data: map[string]interface{}{
				"package":  packageName,
				"registry": registry,
				"error":    err.Error(),
			},
		})
		return nil, nil
	}

	threats := make([]Threat, 0, len(result.Threats))
	for _, t := range result.Threats {
		// Check DB cache for an existing explanation to inline it.
		var inlineExpl *ThreatExplanation
		if scanDB != nil {
			cacheKey := fmt.Sprintf("explain:%s:%s:%s", packageName, normalizeVersion(t.Version), string(t.Type))
			if cached, cerr := scanDB.GetExplanation(cacheKey); cerr == nil && cached != nil {
				inlineExpl = &ThreatExplanation{
					What:        cached.What,
					Why:         cached.Why,
					Impact:      cached.Impact,
					Remediation: cached.Remediation,
					Confidence:  cached.Confidence,
					GeneratedBy: cached.ProviderID,
					CacheHit:    true,
				}
			}
		}

		apiThreat := Threat{
			ID:          t.ID,
			Type:        string(t.Type),
			Severity:    t.Severity.String(),
			Title:       threatTypeTitle(string(t.Type)),
			Description: t.Description,
			Package:     packageName,
			Registry:    registry,
			Confidence:  t.Confidence,
			SimilarTo:   t.SimilarTo,
			CVEID:       t.CVE,
			DetectedAt:  t.DetectedAt,
			Explanation: inlineExpl,
		}
		threats = append(threats, apiThreat)

		// Publish the threat immediately (with explanation if cached).
		sseBroker.publish(SSEEvent{Event: "threat", Data: apiThreat})

		// Also publish to integration hub (Jira, Teams, email) if configured.
		publishThreatEvent(ctx, packageName, registry, t.Version, t)

		// If no inline explanation, fire an async goroutine to generate one.
		if inlineExpl == nil {
			tCopy := t
			go generateAndPublishExplanation(tCopy, packageName, registry)
		}
	}

	warnings := make([]Warning, 0, len(result.Warnings))
	for _, w := range result.Warnings {
		warnings = append(warnings, Warning{
			Type:        w.Type,
			Description: w.Message,
		})
	}

	// "done" marks the end of threat discovery; explanation events may follow.
	sseBroker.publish(SSEEvent{
		Event: "done",
		Data: map[string]interface{}{
			"package":       packageName,
			"registry":      registry,
			"threat_count":  len(threats),
			"warning_count": len(warnings),
			"timestamp":     time.Now(),
		},
	})

	return threats, warnings
}

// threatTypeTitle returns a human-readable title for a threat type string.
func threatTypeTitle(t string) string {
	switch t {
	case "typosquatting":
		return "Typosquatting"
	case "malicious_package", "malicious_code":
		return "Malicious Package"
	case "dependency_confusion":
		return "Dependency Confusion"
	case "embedded_secret", "secret_leak":
		return "Secret Leak"
	case "obfuscated_code":
		return "Obfuscated Code"
	case "install_script":
		return "Suspicious Install Script"
	case "vulnerable":
		return "Known Vulnerability"
	case "homoglyph":
		return "Homoglyph Attack"
	case "cicd_injection":
		return "CI/CD Injection"
	default:
		return t
	}
}

// generateAndPublishExplanation calls the LLM to explain a threat, caches the
// result in SQLite (7-day TTL), then publishes an "explanation" SSE event so
// all connected clients receive the AI analysis in real time.
// Runs in a goroutine — all errors are logged and swallowed gracefully.
// normalizeVersion returns a canonical version string for use in cache keys.
// The detector engine fills Version as "unknown" when not specified; we treat
// that as empty so cache keys are consistent across all call sites.
func normalizeVersion(v string) string {
	if v == "unknown" || v == "latest" {
		return ""
	}
	return v
}

func generateAndPublishExplanation(t pkgtypes.Threat, packageName, registry string) {
	// Acquire semaphore slot — block until a slot is free, bounded to 8 concurrent.
	explainSem <- struct{}{}
	defer func() {
		<-explainSem // release slot
		// Recover from any panic inside this goroutine so it never silently
		// kills the process and is always logged for debugging.
		if rec := recover(); rec != nil {
			log.Printf("PANIC in generateAndPublishExplanation [%s/%s %s]: %v", registry, packageName, t.Type, rec)
		}
	}()

	provider := getLLMProvider()
	if provider == nil {
		return // LLM not configured — skip silently
	}

	cacheKey := fmt.Sprintf("explain:%s:%s:%s", packageName, normalizeVersion(t.Version), string(t.Type))

	// Check DB cache first; serve immediately if found.
	if scanDB != nil {
		if cached, err := scanDB.GetExplanation(cacheKey); err == nil && cached != nil {
			sseBroker.publish(SSEEvent{
				Event: "explanation",
				Data: map[string]interface{}{
					"threat_id": t.ID,
					"package":   packageName,
					"registry":  registry,
					"type":      string(t.Type),
					"explanation": ThreatExplanation{
						What:        cached.What,
						Why:         cached.Why,
						Impact:      cached.Impact,
						Remediation: cached.Remediation,
						Confidence:  cached.Confidence,
						GeneratedBy: cached.ProviderID,
						CacheHit:    true,
					},
				},
			})
			return
		}
	}

	// No cache hit — call the LLM.
	// Derive from serverCtx so this goroutine is cancelled on graceful shutdown.
	ctx, cancel := context.WithTimeout(serverCtx, 30*time.Second)
	defer cancel()

	prompt := llmpkg.BuildExplanationPrompt(llmpkg.ExplanationRequest{Threat: t})
	response, err := provider.GenerateExplanation(ctx, prompt)
	if err != nil {
		log.Printf("LLM explanation error for %s/%s [%s]: %v", registry, packageName, t.Type, err)
		return
	}

	expl := llmpkg.ParseStructuredExplanation(response, provider.ID(), t.Confidence)
	expl.GeneratedAt = time.Now()

	// Persist to cache (7-day TTL).
	if scanDB != nil {
		_ = scanDB.SaveExplanation(database.ExplanationRow{
			CacheKey:    cacheKey,
			PackageName: packageName,
			Version:     normalizeVersion(t.Version),
			ThreatType:  string(t.Type),
			What:        expl.What,
			Why:         expl.Why,
			Impact:      expl.Impact,
			Remediation: expl.Remediation,
			Confidence:  expl.Confidence,
			ProviderID:  expl.GeneratedBy,
			ExpiresAt:   time.Now().Add(7 * 24 * time.Hour),
		})
	}

	// Broadcast to all SSE subscribers.
	sseBroker.publish(SSEEvent{
		Event: "explanation",
		Data: map[string]interface{}{
			"threat_id": t.ID,
			"package":   packageName,
			"registry":  registry,
			"type":      string(t.Type),
			"explanation": ThreatExplanation{
				What:        expl.What,
				Why:         expl.Why,
				Impact:      expl.Impact,
				Remediation: expl.Remediation,
				Confidence:  expl.Confidence,
				GeneratedBy: expl.GeneratedBy,
				GeneratedAt: expl.GeneratedAt,
				CacheHit:    false,
			},
		},
	})
}

func calculateRiskLevel(threats []Threat) (int, float64) {
	if len(threats) == 0 {
		return 0, 0.0
	}

	maxScore := 0.0
	for _, threat := range threats {
		if threat.Confidence > maxScore {
			maxScore = threat.Confidence
		}
	}

	if maxScore >= riskScoreThreshold {
		return 3, maxScore // High risk
	} else if maxScore >= 0.5 {
		return 2, maxScore // Medium risk
	} else if maxScore > 0 {
		return 1, maxScore // Low risk
	}
	return 0, 0.0 // No threats
}

// Input validation helpers
func validatePackageInput(name, registry string) error {
	if len(name) > 214 {
		return fmt.Errorf("Package name too long")
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, ";&|`") {
		return fmt.Errorf("Invalid characters in package name")
	}
	switch registry {
	case "npm":
		if !npmValid(name) {
			return fmt.Errorf("Invalid npm package name")
		}
	case "pypi":
		if !pypiValid(name) {
			return fmt.Errorf("Invalid PyPI package name")
		}
	case "go":
		if !goValid(name) {
			return fmt.Errorf("Invalid Go package name")
		}
	case "maven":
		if !mavenValid(name) {
			return fmt.Errorf("Invalid Maven package name")
		}
	}
	return nil
}

func npmValid(name string) bool {
	// npm spec: must be lowercase, no spaces/tabs/newlines.
	if name != strings.ToLower(name) {
		return false
	}
	return !strings.ContainsAny(name, " \t\n")
}

func pypiValid(name string) bool {
	if len(name) == 0 {
		return false
	}
	return isAlphaNum(name[0]) && isAlphaNum(name[len(name)-1])
}

func goValid(name string) bool {
	if strings.ContainsAny(name, " \t\n") {
		return false
	}
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") {
		return false
	}
	if !strings.Contains(name, "/") {
		return false
	}
	return true
}

func mavenValid(name string) bool {
	if strings.ContainsAny(name, " \t\n") {
		return false
	}
	parts := strings.Split(name, ":")
	if len(parts) != 2 {
		return false
	}
	if parts[0] == "" || parts[1] == "" {
		return false
	}
	return true
}

func isAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func main() {
	// Open persistent scan store (SQLite).
	// Falls back to the in-memory scanStore if the database cannot be opened.
	dbPath := os.Getenv("FALCN_DB_PATH")
	if dbPath == "" {
		dbPath = "falcn.db"
	}
	if store, err := database.NewScanStore(dbPath); err != nil {
		log.Printf("WARNING: Could not open scan database %s: %v — using in-memory fallback", dbPath, err)
	} else {
		scanDB = store
		defer scanDB.Close()
	}

	// Initialize ring buffer for in-memory scan history.
	memStore = newRingBuffer(maxScanHistory)

	// Initialize rate limiter and start background eviction
	rateLimiter = NewRateLimiter()
	apiCtx, apiCancel := context.WithCancel(context.Background())
	defer apiCancel()
	serverCtx = apiCtx // expose to package-level goroutines (e.g. LLM explanation workers)
	rateLimiter.StartEviction(apiCtx, 5*time.Minute)

	// Initialize JWT service. On failure, JWT auth is unavailable but API-key
	// auth continues to function.
	var jwtInitErr error
	jwtSvc, jwtInitErr = security.RequireEnvJWTKey()
	if jwtInitErr != nil {
		log.Printf("WARNING: JWT service initialization failed (%v) — JWT auth disabled, API key auth still active", jwtInitErr)
	}

	// Emit a clear dev-mode banner so the operator knows auth is open.
	if authDevMode() {
		log.Println("⚠️  DEV MODE: no API_KEYS or JWT secret configured — all /v1 endpoints are open.")
		log.Println("   Set API_KEYS=<key> (or API_AUTH_ENABLED=true) to lock down the API.")
	}

	// Load config once at startup so we can emit the production checklist.
	startupCfgMgr := appcfg.NewManager()
	if err := startupCfgMgr.Load("."); err != nil {
		log.Printf("WARNING: startup config load: %v", err)
	}
	startupCfg := startupCfgMgr.Get()

	// Emit production checklist warnings.
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = os.Getenv("FALCN_APP_ENVIRONMENT")
	}
	if env == "production" && startupCfg != nil {
		for _, w := range startupCfg.ProductionChecklist() {
			log.Printf("PRODUCTION CHECKLIST: %s", w)
		}
	}

	// Create router
	r := mux.NewRouter()

	// Prometheus and JSON metrics endpoints.
	// /metrics is restricted to internal/monitoring networks via metricsAllowed().
	// Set METRICS_ALLOWED_CIDRS=10.0.0.0/8,172.16.0.0/12 to widen the allowlist.
	r.Use(apimetrics.PrometheusMiddleware())
	r.Handle("/metrics", metricsAllowed(promhttp.Handler())).Methods("GET")
	r.HandleFunc("/metrics.json", func(w http.ResponseWriter, r *http.Request) {
		if !isMetricsAllowed(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		m := pkgmetrics.GetInstance()
		json.NewEncoder(w).Encode(m.GetMetrics())
	}).Methods("GET")

	// Health check endpoints
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/ready", readyHandler).Methods("GET")

	// Auth endpoint — exempt from authMiddleware (it IS the auth endpoint).
	// POST /v1/auth/token exchanges a valid API key for a signed JWT.
	r.HandleFunc("/v1/auth/token", issueTokenHandler).Methods("POST")

	// OpenAPI and docs endpoints
	r.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		f, err := os.Open("docs/openapi.json")
		if err != nil {
			http.Error(w, "OpenAPI spec not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		if _, err := io.Copy(w, f); err != nil {
			log.Printf("io.Copy error serving openapi.json: %v", err)
		}
	}).Methods("GET")
	r.HandleFunc("/docs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		f, err := os.Open("docs/swagger.html")
		if err != nil {
			http.Error(w, "Docs page not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		if _, err := io.Copy(w, f); err != nil {
			log.Printf("io.Copy error serving docs: %v", err)
		}
	}).Methods("GET")

	// ── RBAC-aware route helpers ──────────────────────────────────────────────
	// requireRole wraps a handler with auth + RBAC role enforcement.
	// In dev mode (no credentials configured) role checks are skipped so that
	// local development is frictionless.
	requireRole := func(role security.Role, h http.HandlerFunc) http.Handler {
		return authMiddleware(func(w http.ResponseWriter, req *http.Request) {
			if !authDevMode() {
				security.RequireRole(role, http.HandlerFunc(h)).ServeHTTP(w, req)
			} else {
				h(w, req)
			}
		})
	}

	// ── API endpoints with auth, RBAC, and rate limiting ─────────────────────
	// Scan-triggering endpoints require RoleAnalyst (read-only viewers cannot
	// trigger scans that consume compute and network resources).
	analystAnalyze := func(h http.HandlerFunc) http.Handler {
		inner := requireRole(security.RoleAnalyst, h)
		return rateLimitMiddleware(inner.ServeHTTP)
	}

	if dsn := os.Getenv("RATE_LIMIT_REDIS_URL"); dsn != "" {
		if rl, err := apilm.NewRedisLimiter(dsn, apilm.RatePolicy{Limit: 10, Window: time.Minute}); err == nil {
			wrap := apilm.RateLimitMiddleware(rl, func(r *http.Request) string { return getClientIP(r) })
			r.Handle("/v1/analyze", wrap(requireRole(security.RoleAnalyst, analyzeHandler))).Methods("POST")
			r.Handle("/v1/analyze/batch", wrap(requireRole(security.RoleAnalyst, batchAnalyzeHandler))).Methods("POST")
		} else {
			r.Handle("/v1/analyze", analystAnalyze(analyzeHandler)).Methods("POST")
			r.Handle("/v1/analyze/batch", analystAnalyze(batchAnalyzeHandler)).Methods("POST")
		}
	} else {
		r.Handle("/v1/analyze", analystAnalyze(analyzeHandler)).Methods("POST")
		r.Handle("/v1/analyze/batch", analystAnalyze(batchAnalyzeHandler)).Methods("POST")
	}
	// /v1/status is intentionally public — used by load balancers and uptime monitors.
	r.HandleFunc("/v1/status", statusHandler).Methods("GET")
	// Read-only data endpoints: RoleViewer and above.
	r.Handle("/v1/stats", requireRole(security.RoleViewer, statsHandler)).Methods("GET")
	r.Handle("/v1/vulnerabilities", requireRole(security.RoleViewer, vulnerabilitiesHandler)).Methods("GET")

	// Dashboard endpoints — RoleViewer and above.
	r.Handle("/v1/dashboard/metrics", requireRole(security.RoleViewer, dashboardMetricsHandler)).Methods("GET")
	r.Handle("/v1/dashboard/performance", requireRole(security.RoleViewer, dashboardPerformanceHandler)).Methods("GET")

	// Scan history — RoleViewer and above.
	r.Handle("/v1/scans", requireRole(security.RoleViewer, scansHandler)).Methods("GET")

	// Threat list — RoleViewer and above.
	r.Handle("/v1/threats", requireRole(security.RoleViewer, threatsListHandler)).Methods("GET")

	// Container image and Dockerfile scanning — RoleAnalyst (triggers network I/O).
	r.Handle("/v1/analyze/image", analystAnalyze(analyzeImageHandler)).Methods("POST")

	// Report generation — RoleAnalyst (produces exportable artefacts).
	r.Handle("/v1/reports/generate", requireRole(security.RoleAnalyst, reportGenerateHandler)).Methods("POST")

	// Configure CORS
	// CORS: configurable via FALCN_CORS_ORIGINS env var (comma-separated).
	// In production the env var is required; omitting it in a non-dev/test environment
	// is a misconfiguration and will cause the server to exit immediately.
	var allowedOrigins []string
	if originsEnv := os.Getenv("FALCN_CORS_ORIGINS"); originsEnv != "" {
		for _, o := range strings.Split(originsEnv, ",") {
			allowedOrigins = append(allowedOrigins, strings.TrimSpace(o))
		}
	} else {
		corsAppEnv := os.Getenv("APP_ENV")
		if corsAppEnv == "" {
			corsAppEnv = os.Getenv("FALCN_APP_ENVIRONMENT")
		}
		if corsAppEnv == "production" {
			log.Fatalf("FALCN_CORS_ORIGINS must be set in production")
		}
		allowedOrigins = []string{
			"http://localhost:3000",
			"http://localhost:4173", // Vite dev/preview server
			"http://localhost:5173",
			"http://localhost:8080",
		}
	}
	c := cors.New(cors.Options{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{
			"Content-Type",
			"Authorization",
			"X-API-Key",
			"Accept",
			"X-Requested-With",
		},
		AllowCredentials: true,
	})

	// SSE stream — real-time threat and explanation events.
	//
	// Protocol:
	//   event: connected    → handshake (data: {status, timestamp})
	//   event: scan_started → scan began (data: {package, registry, timestamp})
	//   event: threat       → threat discovered (data: Threat JSON)
	//   event: explanation  → AI explanation ready (data: {threat_id, package, type, explanation})
	//   event: done         → scan complete — connection stays open for explanation events
	//   event: ping         → keepalive heartbeat every 15s
	//
	// Auth: open in dev mode; requires X-API-Key or Bearer JWT in production.
	//
	// Usage:
	//   const es = new EventSource('/v1/stream');
	//   es.addEventListener('threat',      e => handleThreat(JSON.parse(e.data)));
	//   es.addEventListener('explanation', e => handleExplanation(JSON.parse(e.data)));
	r.HandleFunc("/v1/stream", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		// PrometheusMiddleware wraps w in statusRecorder which now delegates Flush()
		// to the underlying net/http ResponseWriter, so this assertion always succeeds.
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported by server", http.StatusInternalServerError)
			return
		}

		// Disable the server write deadline for SSE — this is a long-lived connection.
		// statusRecorder.Unwrap() lets ResponseController reach the real net/http writer.
		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(time.Time{})

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no") // disable nginx proxy buffering

		// Flush headers immediately so the client knows the stream is open.
		flusher.Flush()

		ch := sseBroker.subscribe()
		defer sseBroker.unsubscribe(ch)

		heartbeat := time.NewTicker(15 * time.Second)
		defer heartbeat.Stop()

		writeSSE := func(event string, payload interface{}) {
			data, jsonErr := json.Marshal(payload)
			if jsonErr != nil {
				return
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
			flusher.Flush()
		}

		// Send initial connected event.
		writeSSE("connected", map[string]interface{}{
			"status":    "connected",
			"timestamp": time.Now(),
		})

		for {
			select {
			case <-r.Context().Done():
				// Client disconnected — clean up.
				return
			case evt, ok := <-ch:
				if !ok {
					return
				}
				writeSSE(evt.Event, evt.Data)
				// NOTE: do NOT return on "done" — LLM explanation events follow.
			case <-heartbeat.C:
				writeSSE("ping", map[string]interface{}{
					"timestamp": time.Now(),
					"clients":   func() int { sseBroker.mu.RLock(); n := len(sseBroker.clients); sseBroker.mu.RUnlock(); return n }(),
				})
			}
		}
	})).Methods("GET")

	// Wrap router with CORS
	handler := c.Handler(r)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	tlsCert := os.Getenv("FALCN_TLS_CERT")
	tlsKey := os.Getenv("FALCN_TLS_KEY")

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  serverReadTimeout,
		WriteTimeout: serverWriteTimeout,
		IdleTimeout:  serverIdleTimeout,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("PANIC in signal handler goroutine: %v — forcing shutdown", r)
				apiCancel()
			}
		}()
		<-sigCh
		log.Println("Shutdown signal received, draining connections (30s timeout)...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
		apiCancel()
	}()

	if tlsCert != "" && tlsKey != "" {
		log.Printf("Falcn API server starting on port %s (TLS)", port)
		if err := srv.ListenAndServeTLS(tlsCert, tlsKey); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	} else {
		log.Printf("Falcn API server starting on port %s (plaintext; set FALCN_TLS_CERT/FALCN_TLS_KEY to enable TLS)", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	status := map[string]interface{}{
		"service":   "Falcn API",
		"version":   "1.0.0",
		"status":    "operational",
		"timestamp": time.Now(),
		"features": map[string]bool{
			"typosquatting_detection": true,
			"malware_scanning":        true,
			"reputation_analysis":     true,
			"homoglyph_detection":     true,
			"dependency_confusion":    true,
			"batch_analysis":          true,
			"rate_limiting":           true,
		},
		"limits": map[string]interface{}{
			"requests_per_minute": defaultRateLimit,
			"batch_size_limit":    maxBatchSize,
		},
	}
	if err := json.NewEncoder(w).Encode(status); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	totalScans, totalThreats, totalWarnings := 0, 0, 0

	if scanDB != nil {
		if ts, tt, tw, err := scanDB.ThreatSummary(); err == nil {
			totalScans, totalThreats, totalWarnings = ts, tt, tw
		} else {
			log.Printf("statsHandler: SQLite read error, falling back to in-memory: %v", err)
			for _, s := range memStore.all() {
				totalScans++
				totalThreats += s.Threats
				totalWarnings += s.Warnings
			}
		}
	} else {
		for _, s := range memStore.all() {
			totalScans++
			totalThreats += s.Threats
			totalWarnings += s.Warnings
		}
	}

	stats := map[string]interface{}{
		"total_requests":     totalScans,
		"packages_analyzed":  totalScans,
		"threats_detected":   totalThreats,
		"warnings_detected":  totalWarnings,
		"popular_ecosystems": []string{"npm", "pypi", "go", "maven", "nuget", "rubygems", "crates.io", "packagist"},
	}
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// ─────────────────────────────────────────────────────────────────
// In-memory scan & vulnerability store (replaces future DB layer)
// ─────────────────────────────────────────────────────────────────

type scanRecord struct {
	ID         string          `json:"id"`
	Target     string          `json:"target"`
	Status     string          `json:"status"`
	Threats    int             `json:"threat_count"`
	Warnings   int             `json:"warning_count"`
	Duration   string          `json:"duration_ms"`
	DurationMs int64           `json:"duration_ms_raw"`
	CreatedAt  time.Time       `json:"created_at"`
	Summary    json.RawMessage `json:"summary,omitempty"`
}

// ringBuffer is a fixed-capacity bounded FIFO for scanRecord entries.
// It avoids the O(n) prepend cost of a plain slice and caps memory usage.
type ringBuffer struct {
	mu   sync.Mutex
	buf  []scanRecord
	head int
	size int
	cap  int
}

func newRingBuffer(capacity int) *ringBuffer {
	return &ringBuffer{buf: make([]scanRecord, capacity), cap: capacity}
}

func (r *ringBuffer) push(rec scanRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.head%r.cap] = rec
	r.head++
	if r.size < r.cap {
		r.size++
	}
}

func (r *ringBuffer) list(limit, offset int) []scanRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	// return most-recent first
	out := make([]scanRecord, 0, r.size)
	for i := r.size - 1; i >= 0; i-- {
		idx := (r.head - 1 - i + r.cap*2) % r.cap
		out = append(out, r.buf[idx])
	}
	if offset >= len(out) {
		return nil
	}
	out = out[offset:]
	if limit > 0 && limit < len(out) {
		out = out[:limit]
	}
	return out
}

func (r *ringBuffer) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size
}

func (r *ringBuffer) all() []scanRecord {
	return r.list(0, 0)
}

// scanDB is the persistent SQLite scan store; may be nil if the database
// could not be opened (in which case the in-memory scanStore is used as a
// fallback).
var scanDB *database.ScanStore

var (
	// memStore is the in-memory ring buffer fallback (used when SQLite is unavailable).
	memStore    *ringBuffer
	// scanStoreMu and scanStore are kept as legacy aliases so that
	// in-memory-fallback paths outside recordScan can still compile.
	// They are not used for writes; writes go through memStore.push().
	scanStoreMu sync.RWMutex
	scanStore   []scanRecord // unused write path — reads redirect to memStore
)

func recordScan(id, target, status string, threats, warnings int, durationMs int64) {
	now := time.Now().UTC()

	// Persist to SQLite when available.
	if scanDB != nil {
		// Derive a human-readable package name from the id field (format "pkg@registry").
		pkg := id
		registry := ""
		if idx := len(id) - len(target) - 1; idx > 0 && idx < len(id) {
			registry = id[idx+1:]
			pkg = target
		}
		_ = scanDB.Insert(database.ScanRecord{
			ID:         id,
			Package:    pkg,
			Name:       target,
			Registry:   registry,
			Status:     status,
			Threats:    threats,
			Warnings:   warnings,
			DurationMs: durationMs,
			CreatedAt:  now,
		})
	}

	// Also keep the in-memory ring buffer (used as fallback and for fast reads).
	rec := scanRecord{
		ID:         id,
		Target:     target,
		Status:     status,
		Threats:    threats,
		Warnings:   warnings,
		Duration:   fmt.Sprintf("%dms", durationMs),
		DurationMs: durationMs,
		CreatedAt:  now,
	}
	memStore.push(rec)
}

// GET /v1/scans — paginated scan history
func scansHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		fmt.Sscanf(v, "%d", &offset)
	}
	if limit > 200 {
		limit = 200
	}

	// Prefer SQLite when available for persistent history across restarts.
	if scanDB != nil {
		records, total, err := scanDB.List(limit, offset)
		if err == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"scans":  records,
				"total":  total,
				"limit":  limit,
				"offset": offset,
			})
			return
		}
		log.Printf("scansHandler: SQLite read error, falling back to in-memory: %v", err)
	}

	total := memStore.len()
	page := memStore.list(limit, offset)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"scans":  page,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GET /v1/vulnerabilities — aggregated vulnerability summary across all scans
func vulnerabilitiesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	totalScans, totalThreats := 0, 0
	dataNote := "Aggregated from SQLite scan history."

	if scanDB != nil {
		if ts, tt, _, err := scanDB.ThreatSummary(); err == nil {
			totalScans, totalThreats = ts, tt
		} else {
			log.Printf("vulnerabilitiesHandler: SQLite read error, falling back to in-memory: %v", err)
			dataNote = "Aggregated from in-memory scan history. Connect a database for persistence."
			for _, s := range memStore.all() {
				totalScans++
				totalThreats += s.Threats
			}
		}
	} else {
		dataNote = "Aggregated from in-memory scan history. Connect a database for persistence."
		for _, s := range memStore.all() {
			totalScans++
			totalThreats += s.Threats
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_scans":   totalScans,
		"total_threats": totalThreats,
		"ecosystems":    []string{"npm", "pypi", "go", "maven", "nuget", "rubygems", "crates.io", "packagist"},
		"last_updated":  time.Now().UTC(),
		"data_note":     dataNote,
	})
}

// GET /v1/dashboard/metrics — comprehensive metrics for the security dashboard.
// The JSON shape matches the frontend DashboardMetrics TypeScript interface exactly.
func dashboardMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	totalScans, totalThreats := 0, 0
	scansLast24h, threatsLast24h := 0, 0
	var criticalThreats, highThreats, mediumThreats, lowThreats int
	var avgRiskScore float64

	// Use typed slices so JSON always encodes [] rather than null.
	topEcosystems := []database.EcosystemStat{}
	threatTrend := []database.TrendPoint{}
	recentThreats := []database.RecentThreat{}

	if scanDB != nil {
		// Base counts
		if ts, tt, _, err := scanDB.ThreatSummary(); err == nil {
			totalScans, totalThreats = ts, tt
		} else {
			log.Printf("dashboardMetricsHandler: ThreatSummary: %v", err)
		}
		if s24, t24, err := scanDB.RecentActivity(); err == nil {
			scansLast24h, threatsLast24h = s24, t24
		} else {
			log.Printf("dashboardMetricsHandler: RecentActivity: %v", err)
		}

		// Severity breakdown
		if sev, err := scanDB.SeverityStats(); err == nil {
			criticalThreats = sev.Critical
			highThreats = sev.High
			mediumThreats = sev.Medium
			lowThreats = sev.Low
		} else {
			log.Printf("dashboardMetricsHandler: SeverityStats: %v", err)
		}

		// Average risk score (avg confidence across all recorded threats)
		if avg, err := scanDB.AvgRiskScore(); err == nil {
			avgRiskScore = avg
		} else {
			log.Printf("dashboardMetricsHandler: AvgRiskScore: %v", err)
		}

		// Ecosystem distribution
		if eco, err := scanDB.EcosystemStats(); err == nil && len(eco) > 0 {
			topEcosystems = eco
		} else if err != nil {
			log.Printf("dashboardMetricsHandler: EcosystemStats: %v", err)
		}

		// 14-day threat trend
		if trend, err := scanDB.ThreatTrend(14); err == nil && len(trend) > 0 {
			threatTrend = trend
		} else if err != nil {
			log.Printf("dashboardMetricsHandler: ThreatTrend: %v", err)
		}

		// Most-recent 10 threats for the live feed
		if threats, err := scanDB.RecentThreats(10); err == nil && len(threats) > 0 {
			recentThreats = threats
		} else if err != nil {
			log.Printf("dashboardMetricsHandler: RecentThreats: %v", err)
		}
	} else {
		// No SQLite — fall back to in-memory ring buffer for basic counts.
		cutoff := time.Now().Add(-24 * time.Hour)
		for _, s := range memStore.all() {
			totalScans++
			totalThreats += s.Threats
			if s.CreatedAt.After(cutoff) {
				scansLast24h++
				threatsLast24h += s.Threats
			}
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_scans":      totalScans,
		"total_packages":   totalScans, // one DB row per package analysed
		"total_threats":    totalThreats,
		"critical_threats": criticalThreats,
		"high_threats":     highThreats,
		"medium_threats":   mediumThreats,
		"low_threats":      lowThreats,
		"avg_risk_score":   avgRiskScore,
		"scans_today":      scansLast24h,
		"threats_today":    threatsLast24h,
		"top_ecosystems":   topEcosystems,
		"threat_trend":     threatTrend,
		"recent_threats":   recentThreats,
	})
}

// GET /v1/threats — paginated list of all recorded threats across all scans.
func threatsListHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		fmt.Sscanf(v, "%d", &offset)
	}
	if limit > 200 {
		limit = 200
	}

	if scanDB == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"threats": []database.RecentThreat{},
			"total":   0,
			"limit":   limit,
			"offset":  offset,
		})
		return
	}

	threats, total, err := scanDB.ThreatList(limit, offset)
	if err != nil {
		log.Printf("threatsListHandler: ThreatList: %v", err)
		http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
		return
	}
	if threats == nil {
		threats = []database.RecentThreat{}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"threats": threats,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// ── Report generation ────────────────────────────────────────────────────────

// POST /v1/reports/generate — streams a security report as a file download.
// ── Container image analysis ──────────────────────────────────────────────────

// analyzeImageHandler scans a container image for vulnerabilities and
// misconfigurations.
//
// POST /v1/analyze/image
// Request body:
//
//	{
//	  "image":        "nginx:1.27",        // required
//	  "light":        false,               // optional; skip layer downloads
//	  "username":     "...",               // optional registry credentials
//	  "password":     "...",
//	  "token":        "...",
//	  "max_layer_mb": 100                  // optional; skip layers above this size
//	}
//
// Response: ImageScanResult JSON.
func analyzeImageHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Image      string `json:"image"`
		Light      bool   `json:"light"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		Token      string `json:"token"`
		MaxLayerMB int64  `json:"max_layer_mb"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRequestBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Image == "" {
		http.Error(w, `"image" field is required`, http.StatusBadRequest)
		return
	}

	opts := containerpkg.ScanOptions{
		Light:          req.Light,
		Username:       req.Username,
		Password:       req.Password,
		Token:          req.Token,
		MaxLayerSizeMB: req.MaxLayerMB,
	}

	sc := containerpkg.New()
	result, err := sc.ScanImage(r.Context(), req.Image, opts)
	if err != nil {
		http.Error(w, "scan failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// ─────────────────────────────────────────────────────────────────────────────

// Request body: { "type": "technical|executive|compliance", "format": "sarif|cyclonedx|spdx|json" }
// Response: file attachment with appropriate Content-Type and Content-Disposition.
func reportGenerateHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type   string `json:"type"`
		Format string `json:"format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Format == "" {
		req.Format = "json"
	}
	if req.Type == "" {
		req.Type = "technical"
	}

	// Fetch up to 500 threats from the DB for the report.
	threats := []database.RecentThreat{}
	if scanDB != nil {
		if tt, _, err := scanDB.ThreatList(500, 0); err == nil && len(tt) > 0 {
			threats = tt
		}
	}

	now := time.Now().UTC()
	reportID := fmt.Sprintf("falcn-%s-%d", req.Type, now.UnixNano())

	var (
		body        []byte
		contentType string
		filename    string
		err         error
	)

	switch req.Format {
	case "sarif":
		body, err = buildSARIF(threats, now)
		contentType = "application/sarif+json"
		filename = fmt.Sprintf("falcn-%s-%s.sarif", req.Type, now.Format("2006-01-02"))

	case "cyclonedx":
		body, err = buildCycloneDX(threats, now, reportID)
		contentType = "application/vnd.cyclonedx+json"
		filename = fmt.Sprintf("falcn-%s-%s.cdx.json", req.Type, now.Format("2006-01-02"))

	case "spdx":
		body, err = buildSPDX(threats, now, reportID)
		contentType = "application/spdx+json"
		filename = fmt.Sprintf("falcn-%s-%s.spdx.json", req.Type, now.Format("2006-01-02"))

	default: // "json", "pdf", "executive", "technical", "compliance"
		body, err = buildJSONReport(threats, now, req.Type, reportID)
		contentType = "application/json"
		filename = fmt.Sprintf("falcn-%s-%s.json", req.Type, now.Format("2006-01-02"))
	}

	if err != nil {
		log.Printf("reportGenerateHandler: build %s error: %v", req.Format, err)
		http.Error(w, `{"error":"report generation failed"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// buildJSONReport produces a structured JSON security report.
func buildJSONReport(threats []database.RecentThreat, now time.Time, reportType, reportID string) ([]byte, error) {
	sevCount := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	typeCount := map[string]int{}
	for _, t := range threats {
		sevCount[t.Severity]++
		typeCount[t.ThreatType]++
	}
	totalThreats := len(threats)
	var avgConf float64
	for _, t := range threats {
		avgConf += t.Confidence
	}
	if totalThreats > 0 {
		avgConf /= float64(totalThreats)
	}

	report := map[string]interface{}{
		"report_id":        reportID,
		"report_type":      reportType,
		"generated_at":     now.Format(time.RFC3339),
		"generated_by":     "Falcn Supply Chain Security Scanner v3.0.0",
		"schema_version":   "3.0",
		"summary": map[string]interface{}{
			"total_threats":    totalThreats,
			"critical":         sevCount["critical"],
			"high":             sevCount["high"],
			"medium":           sevCount["medium"],
			"low":              sevCount["low"],
			"avg_confidence":   math.Round(avgConf*1000) / 1000,
			"threat_breakdown": typeCount,
		},
		"threats": threats,
	}
	return json.MarshalIndent(report, "", "  ")
}

// buildSARIF produces a SARIF 2.1.0 report from threat records.
func buildSARIF(threats []database.RecentThreat, now time.Time) ([]byte, error) {
	type sarifMsg  struct{ Text string `json:"text"` }
	type sarifRule struct {
		ID               string   `json:"id"`
		Name             string   `json:"name"`
		ShortDescription sarifMsg `json:"shortDescription"`
	}
	type sarifLoc struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID     string     `json:"ruleId"`
		Level      string     `json:"level"`
		Message    sarifMsg   `json:"message"`
		Locations  []sarifLoc `json:"locations"`
		Properties map[string]interface{} `json:"properties,omitempty"`
	}

	rules := []sarifRule{
		{ID: "TYPOSQUATTING",       Name: "Typosquatting",          ShortDescription: sarifMsg{"Package name closely resembles a popular library"}},
		{ID: "MALICIOUS_CODE",      Name: "MaliciousCode",          ShortDescription: sarifMsg{"Obfuscated or malicious code detected"}},
		{ID: "DEPENDENCY_CONFUSION",Name: "DependencyConfusion",    ShortDescription: sarifMsg{"Package name matches an internal namespace"}},
		{ID: "SECRET_LEAK",         Name: "SecretLeak",             ShortDescription: sarifMsg{"Hardcoded credentials or secrets detected"}},
		{ID: "CVE",                 Name: "KnownVulnerability",     ShortDescription: sarifMsg{"Known CVE in package version"}},
		{ID: "BEHAVIORAL",         Name: "SuspiciousBehavior",     ShortDescription: sarifMsg{"Suspicious runtime or install-time behavior"}},
	}

	levelMap := map[string]string{
		"critical": "error", "high": "error",
		"medium":   "warning", "low": "note",
	}
	results := make([]sarifResult, 0, len(threats))
	for _, t := range threats {
		loc := sarifLoc{}
		reg := strings.ToLower(t.Registry)
		loc.PhysicalLocation.ArtifactLocation.URI = fmt.Sprintf("pkg:%s/%s", reg, t.Package)

		ruleID := strings.ToUpper(strings.ReplaceAll(t.ThreatType, "-", "_"))
		level, ok := levelMap[strings.ToLower(t.Severity)]
		if !ok {
			level = "note"
		}
		results = append(results, sarifResult{
			RuleID:    ruleID,
			Level:     level,
			Message:   sarifMsg{t.Description},
			Locations: []sarifLoc{loc},
			Properties: map[string]interface{}{
				"severity":   t.Severity,
				"confidence": t.Confidence,
				"registry":   t.Registry,
			},
		})
	}

	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]interface{}{{
			"tool": map[string]interface{}{
				"driver": map[string]interface{}{
					"name":           "Falcn",
					"version":        "3.0.0",
					"informationUri": "https://falcn.io",
					"rules":          rules,
				},
			},
			"results":    results,
			"invocations": []map[string]interface{}{{
				"executionSuccessful": true,
				"endTimeUtc":         now.Format(time.RFC3339),
			}},
		}},
	}
	return json.MarshalIndent(sarif, "", "  ")
}

// buildCycloneDX produces a CycloneDX 1.5 BOM from threat records.
func buildCycloneDX(threats []database.RecentThreat, now time.Time, reportID string) ([]byte, error) {
	type cdxTool       struct{ Vendor, Name, Version string }
	type cdxMeta       struct {
		Timestamp string    `json:"timestamp"`
		Tools     []cdxTool `json:"tools"`
	}
	type cdxComp struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		PURL    string `json:"purl,omitempty"`
		BomRef  string `json:"bom-ref"`
	}
	type cdxRating struct {
		Source   map[string]string `json:"source"`
		Severity string            `json:"severity"`
		Score    float64           `json:"score,omitempty"`
	}
	type cdxAffects struct {
		Ref string `json:"ref"`
	}
	type cdxVuln struct {
		ID          string       `json:"id"`
		Source      map[string]string `json:"source,omitempty"`
		Description string       `json:"description"`
		Ratings     []cdxRating  `json:"ratings"`
		Affects     []cdxAffects `json:"affects"`
	}

	seen := map[string]bool{}
	components := []cdxComp{}
	vulns := []cdxVuln{}

	for i, t := range threats {
		key := strings.ToLower(t.Registry + "/" + t.Package)
		ref := fmt.Sprintf("pkg-%d", i)
		if !seen[key] {
			seen[key] = true
			reg := strings.ToLower(t.Registry)
			purl := fmt.Sprintf("pkg:%s/%s", reg, t.Package)
			components = append(components, cdxComp{
				Type: "library", Name: t.Package, PURL: purl, BomRef: ref,
			})
		}
		vulns = append(vulns, cdxVuln{
			ID:          fmt.Sprintf("FALCN-%d", i+1),
			Source:      map[string]string{"name": "Falcn", "url": "https://falcn.io"},
			Description: t.Description,
			Ratings: []cdxRating{{
				Source:   map[string]string{"name": "Falcn"},
				Severity: t.Severity,
				Score:    math.Round(t.Confidence*10*10) / 10,
			}},
			Affects: []cdxAffects{{Ref: ref}},
		})
	}

	bom := map[string]interface{}{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.5",
		"serialNumber": "urn:uuid:" + reportID,
		"version":      1,
		"metadata": cdxMeta{
			Timestamp: now.Format(time.RFC3339),
			Tools:     []cdxTool{{Vendor: "Falcn", Name: "falcn", Version: "3.0.0"}},
		},
		"components":      components,
		"vulnerabilities": vulns,
	}
	return json.MarshalIndent(bom, "", "  ")
}

// buildSPDX produces an SPDX 2.3 BOM from threat records.
func buildSPDX(threats []database.RecentThreat, now time.Time, reportID string) ([]byte, error) {
	type spdxPkg struct {
		SPDXID           string `json:"SPDXID"`
		Name             string `json:"name"`
		Version          string `json:"versionInfo,omitempty"`
		DownloadLocation string `json:"downloadLocation"`
		FilesAnalyzed    bool   `json:"filesAnalyzed"`
		LicenseConcluded string `json:"licenseConcluded"`
		Comment          string `json:"comment,omitempty"`
	}
	type spdxRel struct {
		SpdxElementID      string `json:"spdxElementId"`
		RelationshipType   string `json:"relationshipType"`
		RelatedSpdxElement string `json:"relatedSpdxElement"`
	}

	packages := []spdxPkg{}
	rels := []spdxRel{}
	seen := map[string]bool{}

	for i, t := range threats {
		key := strings.ToLower(t.Registry + "/" + t.Package)
		if seen[key] {
			continue
		}
		seen[key] = true
		id := fmt.Sprintf("SPDXRef-pkg-%d", i)
		reg := strings.ToLower(t.Registry)
		downloadURL := fmt.Sprintf("https://%s.org/package/%s", reg, t.Package)
		comment := fmt.Sprintf("THREAT: %s — %s (confidence: %.0f%%)", t.ThreatType, t.Description, t.Confidence*100)
		packages = append(packages, spdxPkg{
			SPDXID: id, Name: t.Package,
			DownloadLocation: downloadURL,
			FilesAnalyzed:    false,
			LicenseConcluded: "NOASSERTION",
			Comment:          comment,
		})
		rels = append(rels, spdxRel{
			SpdxElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSpdxElement: id,
		})
	}

	doc := map[string]interface{}{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              "Falcn Security Scan - " + now.Format("2006-01-02"),
		"documentNamespace": "https://falcn.io/sbom/" + reportID,
		"creationInfo": map[string]interface{}{
			"created":  now.Format(time.RFC3339),
			"creators": []string{"Tool: falcn-3.0.0"},
		},
		"packages":      packages,
		"relationships": rels,
	}
	return json.MarshalIndent(doc, "", "  ")
}

// percentile returns the p-th percentile value from a sorted int64 slice.
func percentile(sorted []int64, p int) int64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(float64(p)/100.0*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	return sorted[idx]
}

// GET /v1/dashboard/performance — latency percentiles computed from scan history.
func dashboardPerformanceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var count int
	var avgMs int64
	var p50, p95, p99 int64

	if scanDB != nil {
		if ts, _, _, err := scanDB.ThreatSummary(); err == nil {
			count = ts
		} else {
			log.Printf("dashboardPerformanceHandler: ThreatSummary error: %v", err)
		}
		if avg, err := scanDB.AvgDurationMs(); err == nil {
			avgMs = avg
		} else {
			log.Printf("dashboardPerformanceHandler: AvgDurationMs error: %v", err)
		}
	}

	// Compute percentiles from in-memory ring buffer regardless of whether
	// SQLite is available, so the response always includes p50/p95/p99.
	recs := memStore.all()
	durs := make([]int64, 0, len(recs))
	for _, rec := range recs {
		durs = append(durs, rec.DurationMs)
	}
	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
	p50 = percentile(durs, 50)
	p95 = percentile(durs, 95)
	p99 = percentile(durs, 99)

	if scanDB == nil && len(durs) > 0 {
		count = len(durs)
		var totalMs int64
		for _, d := range durs {
			totalMs += d
		}
		avgMs = totalMs / int64(count)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_count":      count,
		"avg_duration_ms": avgMs,
		"p50_duration_ms": p50,
		"p95_duration_ms": p95,
		"p99_duration_ms": p99,
		"timestamp":       time.Now().UTC(),
	})
}
