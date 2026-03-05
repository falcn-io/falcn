// Package main implements the Falcn demo API server and endpoints.
package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	apimetrics "github.com/falcn-io/falcn/internal/api/metrics"
	apilm "github.com/falcn-io/falcn/internal/api/middleware"
	whloader "github.com/falcn-io/falcn/internal/api/webhook"
	appcfg "github.com/falcn-io/falcn/internal/config"
	"github.com/falcn-io/falcn/internal/detector"
	pkgmetrics "github.com/falcn-io/falcn/pkg/metrics"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	redis "github.com/redis/go-redis/v9"
	"github.com/rs/cors"
	"golang.org/x/time/rate"
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

type TestResponse struct {
	Message   string    `json:"message"`
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

type Threat struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
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
			// Allow 10 requests per minute for demo
			limiter = rate.NewLimiter(rate.Every(6*time.Second), 10)
			rl.limiters[ip] = limiter
		}
		rl.mu.Unlock()
	}

	return limiter
}

func (rl *RateLimiter) Allow(ip string) bool {
	return rl.getLimiter(ip).Allow()
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
)

// API key authentication middleware
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/ready" || r.URL.Path == "/test" {
			next(w, r)
			return
		}

		enabled := os.Getenv("API_AUTH_ENABLED")
		if strings.EqualFold(enabled, "false") || enabled == "0" {
			next(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Missing Authorization header"})
			return
		}
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Authorization format"})
			return
		}
		token := parts[1]
		if !validateAPIKey(token) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid API key"})
			return
		}
		next(w, r)
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
	w.Header().Set("X-Demo-Mode", "true")
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
	}
	json.NewEncoder(w).Encode(response)
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Demo-Mode", "true")

	// Redis readiness: prefer internal config; fall back to env DSN
	cfgMgr := appcfg.NewManager()
	_ = cfgMgr.Load(".")
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

func testHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Demo-Mode", "true")
	response := TestResponse{
		Message:   "test endpoint working",
		Timestamp: time.Now(),
	}
	json.NewEncoder(w).Encode(response)
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
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	return r.RemoteAddr
}

func analyzeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req AnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	// Perform simplified threat analysis for demo
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

	if result.RiskLevel >= 3 {
		if url := os.Getenv("SLACK_WEBHOOK_URL"); url != "" {
			payload := map[string]interface{}{"text": fmt.Sprintf("High risk detected: %s (%s) risk=%d", result.PackageName, result.Registry, result.RiskLevel)}
			b, _ := json.Marshal(payload)
			_, _ = http.Post(url, "application/json", bytes.NewBuffer(b))
		}
		host := os.Getenv("SMTP_HOST")
		user := os.Getenv("SMTP_USER")
		pass := os.Getenv("SMTP_PASS")
		to := os.Getenv("EMAIL_TO")
		from := os.Getenv("EMAIL_FROM")
		if host != "" && user != "" && pass != "" && to != "" && from != "" {
			msg := []byte("Subject: Falcn Alert\r\n\r\n" + fmt.Sprintf("High risk detected: %s (%s) risk=%d", result.PackageName, result.Registry, result.RiskLevel))
			_ = smtp.SendMail(host+":587", smtp.PlainAuth("", user, pass, host), from, []string{to}, msg)
		}
	}
}

func batchAnalyzeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req BatchAnalyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if len(req.Packages) == 0 {
		http.Error(w, "At least one package is required", http.StatusBadRequest)
		return
	}

	// Limit batch size for demo
	if len(req.Packages) > 10 {
		http.Error(w, "Maximum 10 packages allowed per batch", http.StatusBadRequest)
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

func getDetectorEngine() *detector.Engine {
	detectorEngineOnce.Do(func() {
		cfgMgr := appcfg.NewManager()
		_ = cfgMgr.Load(".")
		detectorEngine = detector.New(cfgMgr.Get())
	})
	return detectorEngine
}

// performThreatAnalysis uses the real detector engine to analyse a package.
// Discovered threats are published to the global SSE broker so streaming
// clients receive them in real-time as they are found.
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
		apiThreat := Threat{
			Type:        string(t.Type),
			Severity:    t.Severity.String(),
			Description: t.Description,
			Confidence:  t.Confidence,
		}
		threats = append(threats, apiThreat)

		// Publish each threat individually as it is discovered
		sseBroker.publish(SSEEvent{
			Event: "threat",
			Data: map[string]interface{}{
				"package":     packageName,
				"registry":    registry,
				"type":        apiThreat.Type,
				"severity":    apiThreat.Severity,
				"description": apiThreat.Description,
				"confidence":  apiThreat.Confidence,
				"timestamp":   time.Now(),
			},
		})
	}

	warnings := make([]Warning, 0, len(result.Warnings))
	for _, w := range result.Warnings {
		warnings = append(warnings, Warning{
			Type:        w.Type,
			Description: w.Message,
		})
	}

	// Publish "done" event with summary
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

	if maxScore >= 0.8 {
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
	n := strings.ToLower(name)
	return !strings.ContainsAny(n, " \t\n")
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
	// Initialize rate limiter
	rateLimiter = NewRateLimiter()

	// Create router
	r := mux.NewRouter()

	// Prometheus and JSON metrics endpoints
	r.Use(apimetrics.PrometheusMiddleware())
	r.Handle("/metrics", promhttp.Handler()).Methods("GET")
	r.HandleFunc("/metrics.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		m := pkgmetrics.GetInstance()
		json.NewEncoder(w).Encode(m.GetMetrics())
	}).Methods("GET")

	// Health check endpoints
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/ready", readyHandler).Methods("GET")
	r.HandleFunc("/test", testHandler).Methods("GET")

	// OpenAPI and docs endpoints
	r.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		f, err := os.Open("docs/openapi.json")
		if err != nil {
			http.Error(w, "OpenAPI spec not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		io.Copy(w, f)
	}).Methods("GET")
	r.HandleFunc("/docs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		f, err := os.Open("docs/swagger.html")
		if err != nil {
			http.Error(w, "Docs page not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		io.Copy(w, f)
	}).Methods("GET")

	// API endpoints with auth and rate limiting
	if dsn := os.Getenv("RATE_LIMIT_REDIS_URL"); dsn != "" {
		if rl, err := apilm.NewRedisLimiter(dsn, apilm.RatePolicy{Limit: 10, Window: time.Minute}); err == nil {
			wrap := apilm.RateLimitMiddleware(rl, func(r *http.Request) string { return getClientIP(r) })
			r.Handle("/v1/analyze", wrap(authMiddleware(http.HandlerFunc(analyzeHandler)))).Methods("POST")
			r.Handle("/v1/analyze/batch", wrap(authMiddleware(http.HandlerFunc(batchAnalyzeHandler)))).Methods("POST")
		} else {
			r.Handle("/v1/analyze", rateLimitMiddleware(authMiddleware(http.HandlerFunc(analyzeHandler)))).Methods("POST")
			r.Handle("/v1/analyze/batch", rateLimitMiddleware(authMiddleware(http.HandlerFunc(batchAnalyzeHandler)))).Methods("POST")
		}
	} else {
		r.Handle("/v1/analyze", rateLimitMiddleware(authMiddleware(http.HandlerFunc(analyzeHandler)))).Methods("POST")
		r.Handle("/v1/analyze/batch", rateLimitMiddleware(authMiddleware(http.HandlerFunc(batchAnalyzeHandler)))).Methods("POST")
	}
	r.HandleFunc("/v1/status", statusHandler).Methods("GET")
	r.HandleFunc("/v1/stats", statsHandler).Methods("GET")
	r.HandleFunc("/v1/vulnerabilities", vulnerabilitiesHandler).Methods("GET")

	// Dashboard endpoints
	r.HandleFunc("/v1/dashboard/metrics", dashboardMetricsHandler).Methods("GET")
	r.HandleFunc("/v1/dashboard/performance", dashboardPerformanceHandler).Methods("GET")

	// Scan history
	r.HandleFunc("/v1/scans", scansHandler).Methods("GET")

	// Configure CORS
	// CORS: configurable via FALCN_CORS_ORIGINS env var (comma-separated), defaults to localhost dev origins
	allowedOrigins := []string{"http://localhost:3000", "http://localhost:8080"}
	if originsEnv := os.Getenv("FALCN_CORS_ORIGINS"); originsEnv != "" {
		allowedOrigins = strings.Split(originsEnv, ",")
		for i, o := range allowedOrigins {
			allowedOrigins[i] = strings.TrimSpace(o)
		}
	}
	c := cors.New(cors.Options{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	})

	// SSE stream — real-time threat events as they are discovered.
	//
	// Protocol:
	//   event: threat   → a threat was detected (data: ThreatEvent JSON)
	//   event: ping     → keepalive heartbeat (every 15s)
	//   event: done     → scan completed (data: DoneEvent JSON)
	//
	// Auth: requires X-API-Key header (same as other /v1 endpoints).
	//
	// Usage:
	//   const es = new EventSource('/v1/stream', { headers: { 'X-API-Key': '...' }});
	//   es.addEventListener('threat', e => console.log(JSON.parse(e.data)));
	r.HandleFunc("/v1/stream", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported by server", http.StatusInternalServerError)
			return
		}

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

		// Send initial connected event
		writeSSE("connected", map[string]interface{}{
			"status":    "connected",
			"timestamp": time.Now(),
		})

		for {
			select {
			case <-r.Context().Done():
				// Client disconnected
				return
			case evt, ok := <-ch:
				if !ok {
					return
				}
				writeSSE(evt.Event, evt.Data)
				if evt.Event == "done" {
					return
				}
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

	log.Printf("Falcn API server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Demo-Mode", "true")
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
			"requests_per_minute": 10,
			"batch_size_limit":    10,
		},
	}
	if err := json.NewEncoder(w).Encode(status); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Demo-Mode", "true")
	stats := map[string]interface{}{
		"total_requests":     "N/A (demo mode)",
		"packages_analyzed":  "N/A (demo mode)",
		"threats_detected":   "N/A (demo mode)",
		"uptime":             "N/A (demo mode)",
		"rate_limit_hits":    "N/A (demo mode)",
		"popular_ecosystems": []string{"npm", "pypi", "maven", "nuget"},
		"demo_mode":          true,
		"message":            "This is a demo API. Statistics are not tracked in demo mode.",
	}
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// ─────────────────────────────────────────────────────────────────
// In-memory scan & vulnerability store (replaces future DB layer)
// ─────────────────────────────────────────────────────────────────

type scanRecord struct {
	ID        string          `json:"id"`
	Target    string          `json:"target"`
	Status    string          `json:"status"`
	Threats   int             `json:"threat_count"`
	Warnings  int             `json:"warning_count"`
	Duration  string          `json:"duration_ms"`
	CreatedAt time.Time       `json:"created_at"`
	Summary   json.RawMessage `json:"summary,omitempty"`
}

var (
	scanStoreMu sync.RWMutex
	scanStore   []scanRecord   // newest first
	maxScans    = 500
)

func recordScan(id, target, status string, threats, warnings int, durationMs int64) {
	scanStoreMu.Lock()
	defer scanStoreMu.Unlock()
	rec := scanRecord{
		ID:        id,
		Target:    target,
		Status:    status,
		Threats:   threats,
		Warnings:  warnings,
		Duration:  fmt.Sprintf("%dms", durationMs),
		CreatedAt: time.Now().UTC(),
	}
	scanStore = append([]scanRecord{rec}, scanStore...)
	if len(scanStore) > maxScans {
		scanStore = scanStore[:maxScans]
	}
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

	scanStoreMu.RLock()
	total := len(scanStore)
	var page []scanRecord
	if offset < total {
		end := offset + limit
		if end > total {
			end = total
		}
		page = scanStore[offset:end]
	}
	scanStoreMu.RUnlock()

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

	scanStoreMu.RLock()
	totalScans := len(scanStore)
	totalThreats := 0
	for _, s := range scanStore {
		totalThreats += s.Threats
	}
	scanStoreMu.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_scans":       totalScans,
		"total_threats":     totalThreats,
		"ecosystems":        []string{"npm", "pypi", "go", "maven", "nuget", "rubygems", "crates.io", "packagist"},
		"last_updated":      time.Now().UTC(),
		"data_note":         "Aggregated from in-memory scan history. Connect a database for persistence.",
	})
}

// GET /v1/dashboard/metrics — threat trends, scan counts, top risky packages
func dashboardMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scanStoreMu.RLock()
	totalScans := len(scanStore)
	totalThreats, totalWarnings := 0, 0
	// Last 24h
	cutoff := time.Now().Add(-24 * time.Hour)
	scansLast24h, threatsLast24h := 0, 0
	for _, s := range scanStore {
		totalThreats += s.Threats
		totalWarnings += s.Warnings
		if s.CreatedAt.After(cutoff) {
			scansLast24h++
			threatsLast24h += s.Threats
		}
	}
	scanStoreMu.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_scans":        totalScans,
		"total_threats":      totalThreats,
		"total_warnings":     totalWarnings,
		"scans_last_24h":     scansLast24h,
		"threats_last_24h":   threatsLast24h,
		"avg_threats_per_scan": func() float64 {
			if totalScans == 0 {
				return 0
			}
			return float64(totalThreats) / float64(totalScans)
		}(),
		"timestamp": time.Now().UTC(),
	})
}

// GET /v1/dashboard/performance — latency percentiles from Prometheus
func dashboardPerformanceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scanStoreMu.RLock()
	count := len(scanStore)
	var totalMs int64
	for _, s := range scanStore {
		var ms int64
		fmt.Sscanf(s.Duration, "%dms", &ms)
		totalMs += ms
	}
	scanStoreMu.RUnlock()

	avgMs := int64(0)
	if count > 0 {
		avgMs = totalMs / int64(count)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_count":       count,
		"avg_duration_ms":  avgMs,
		"timestamp":        time.Now().UTC(),
		"note":             "Wire Prometheus metrics for p50/p95/p99 percentiles in production.",
	})
}
