package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// initTestGlobals ensures package-level globals used by handlers are
// initialised. Safe to call from multiple tests and goroutines.
var initTestGlobalsOnce sync.Once

func initTestGlobals() {
	initTestGlobalsOnce.Do(func() {
		// Disable authentication so handler tests don't need API keys.
		// Each test may override this via t.Setenv as needed.
		// This must be set before the handlers execute.
		rateLimiter = NewRateLimiter()
		memStore = newRingBuffer(maxScanHistory)
	})
}

// ─── healthHandler ────────────────────────────────────────────────────────────

func TestHealthHandler_Returns200(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	healthHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}
	var resp HealthResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if resp.Status != "healthy" {
		t.Fatalf("expected status 'healthy', got %q", resp.Status)
	}
}

func TestHealthHandler_ContentTypeJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	healthHandler(rr, req)

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("expected Content-Type to contain application/json, got %q", ct)
	}
}

func TestHealthHandler_HasTimestamp(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	healthHandler(rr, req)

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := resp["timestamp"]; !ok {
		t.Fatal("health response must include 'timestamp' field")
	}
}

// ─── analyzeHandler ───────────────────────────────────────────────────────────

func TestAnalyzeHandler_MissingBody(t *testing.T) {
	initTestGlobals()
	t.Setenv("API_AUTH_ENABLED", "false")

	req := httptest.NewRequest(http.MethodPost, "/v1/analyze", nil)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	analyzeHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for nil body, got %d\nbody: %s",
			rr.Code, rr.Body.String())
	}
}

func TestAnalyzeHandler_InvalidJSON(t *testing.T) {
	initTestGlobals()
	t.Setenv("API_AUTH_ENABLED", "false")

	req := httptest.NewRequest(http.MethodPost, "/v1/analyze",
		strings.NewReader("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	analyzeHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d\nbody: %s",
			rr.Code, rr.Body.String())
	}
}

func TestAnalyzeHandler_MissingPackageName(t *testing.T) {
	initTestGlobals()
	t.Setenv("API_AUTH_ENABLED", "false")

	body := `{"registry":"npm"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/analyze",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	analyzeHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when package_name is missing, got %d", rr.Code)
	}
}

func TestAnalyzeHandler_ValidRequest(t *testing.T) {
	initTestGlobals()
	t.Setenv("API_AUTH_ENABLED", "false")

	body := `{"package_name":"lodash","registry":"npm"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/analyze",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	analyzeHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d\nbody: %s", rr.Code, rr.Body.String())
	}

	var result AnalysisResult
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("response is not valid JSON AnalysisResult: %v", err)
	}
	if result.PackageName != "lodash" {
		t.Fatalf("expected package_name 'lodash', got %q", result.PackageName)
	}
	// risk_score must be in [0, 1]
	if result.RiskScore < 0 || result.RiskScore > 1 {
		t.Fatalf("risk_score %f out of range [0,1]", result.RiskScore)
	}
}

func TestAnalyzeHandler_DefaultsRegistryToNPM(t *testing.T) {
	initTestGlobals()
	t.Setenv("API_AUTH_ENABLED", "false")

	body := `{"package_name":"express"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/analyze",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	analyzeHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d\nbody: %s", rr.Code, rr.Body.String())
	}

	var result AnalysisResult
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if result.Registry != "npm" {
		t.Fatalf("expected registry to default to 'npm', got %q", result.Registry)
	}
}

// ─── batchAnalyzeHandler ──────────────────────────────────────────────────────

func TestBatchAnalyzeHandler_EmptyPackages(t *testing.T) {
	initTestGlobals()
	t.Setenv("API_AUTH_ENABLED", "false")

	body := `{"packages":[]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/analyze/batch",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	batchAnalyzeHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty packages array, got %d\nbody: %s",
			rr.Code, rr.Body.String())
	}
}

func TestBatchAnalyzeHandler_TooManyPackages(t *testing.T) {
	initTestGlobals()
	t.Setenv("API_AUTH_ENABLED", "false")

	// Build a payload with maxBatchSize+1 (101) packages.
	pkgs := make([]map[string]string, maxBatchSize+1)
	for i := range pkgs {
		pkgs[i] = map[string]string{
			"package_name": fmt.Sprintf("pkg-%d", i),
			"registry":     "npm",
		}
	}
	payload := map[string]interface{}{"packages": pkgs}
	b, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/v1/analyze/batch",
		strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	batchAnalyzeHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when batch exceeds %d packages, got %d",
			maxBatchSize, rr.Code)
	}
}

func TestBatchAnalyzeHandler_ValidBatch(t *testing.T) {
	initTestGlobals()
	t.Setenv("API_AUTH_ENABLED", "false")

	body := `{"packages":[
		{"package_name":"lodash","registry":"npm"},
		{"package_name":"express","registry":"npm"},
		{"package_name":"requests","registry":"pypi"}
	]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/analyze/batch",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	batchAnalyzeHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d\nbody: %s", rr.Code, rr.Body.String())
	}

	var result BatchAnalysisResult
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("response is not valid BatchAnalysisResult JSON: %v", err)
	}
	if len(result.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(result.Results))
	}
	if result.Summary.Total != 3 {
		t.Fatalf("expected summary.total == 3, got %d", result.Summary.Total)
	}
}

func TestBatchAnalyzeHandler_InvalidJSON(t *testing.T) {
	initTestGlobals()
	t.Setenv("API_AUTH_ENABLED", "false")

	req := httptest.NewRequest(http.MethodPost, "/v1/analyze/batch",
		strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	batchAnalyzeHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", rr.Code)
	}
}

// ─── statusHandler ────────────────────────────────────────────────────────────

func TestStatusHandler_Returns200(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	rr := httptest.NewRecorder()

	statusHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := resp["status"]; !ok {
		t.Fatal("status response must include 'status' field")
	}
}

// ─── statsHandler ─────────────────────────────────────────────────────────────

func TestStatsHandler_Returns200(t *testing.T) {
	initTestGlobals()

	req := httptest.NewRequest(http.MethodGet, "/v1/stats", nil)
	rr := httptest.NewRecorder()

	statsHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

// ─── RateLimiter ──────────────────────────────────────────────────────────────

func TestRateLimiter_NewRateLimiter_NotNil(t *testing.T) {
	rl := NewRateLimiter()
	if rl == nil {
		t.Fatal("NewRateLimiter must return non-nil")
	}
}

func TestRateLimiter_Allow_FirstRequest(t *testing.T) {
	rl := NewRateLimiter()
	if !rl.Allow("192.0.2.1") {
		t.Fatal("first request from a new IP must be allowed")
	}
}

func TestRateLimiter_SameIP_Throttled(t *testing.T) {
	rl := NewRateLimiter()
	ip := "198.51.100.5"

	// defaultRateLimit = 10 per minute. Drain the burst bucket entirely.
	allowed := 0
	denied := 0
	for i := 0; i < 25; i++ {
		if rl.Allow(ip) {
			allowed++
		} else {
			denied++
		}
	}
	if denied == 0 {
		t.Fatalf("expected at least one denied request after %d calls (allowed=%d, denied=%d)",
			25, allowed, denied)
	}
}

func TestRateLimiter_DifferentIPs_NotThrottled(t *testing.T) {
	rl := NewRateLimiter()

	// Each unique IP gets its own token bucket; a single request per IP
	// must always succeed.
	for i := 0; i < 50; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		if !rl.Allow(ip) {
			t.Fatalf("first request from unique IP %s should be allowed", ip)
		}
	}
}

func TestRateLimiter_StartEviction_DoesNotPanic(t *testing.T) {
	// Verify the eviction goroutine starts and stops cleanly without panicking.
	rl := NewRateLimiter()
	_ = rl.Allow("1.2.3.4") // populate the map so there is something to evict

	ctx, cancel := context.WithCancel(context.Background())
	rl.StartEviction(ctx, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond) // let the goroutine run at least once
	cancel()                          // signal the goroutine to stop
	time.Sleep(20 * time.Millisecond) // let it exit gracefully
}

// ─── SSEBroker ────────────────────────────────────────────────────────────────

func TestSSEBroker_SubscribeAndUnsubscribe(t *testing.T) {
	broker := newSSEBroker()

	ch := broker.subscribe()
	if ch == nil {
		t.Fatal("subscribe must return non-nil channel")
	}

	// Unsubscribing must not panic.
	broker.unsubscribe(ch)
}

func TestSSEBroker_Publish_DeliveredToSubscriber(t *testing.T) {
	broker := newSSEBroker()

	ch := broker.subscribe()
	defer broker.unsubscribe(ch)

	evt := SSEEvent{Event: "test", Data: "hello"}
	broker.publish(evt)

	select {
	case received := <-ch:
		if received.Event != "test" {
			t.Fatalf("expected event 'test', got %q", received.Event)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for published event")
	}
}

func TestSSEBroker_Publish_MultipleSubscribers(t *testing.T) {
	broker := newSSEBroker()

	channels := make([]chan SSEEvent, 3)
	for i := range channels {
		channels[i] = broker.subscribe()
	}
	defer func() {
		for _, ch := range channels {
			broker.unsubscribe(ch)
		}
	}()

	broker.publish(SSEEvent{Event: "broadcast", Data: nil})

	for i, ch := range channels {
		select {
		case evt := <-ch:
			if evt.Event != "broadcast" {
				t.Fatalf("subscriber %d received wrong event: %q", i, evt.Event)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("timeout waiting for event on subscriber %d", i)
		}
	}
}

// ─── calculateRiskLevel ───────────────────────────────────────────────────────

func TestCalculateRiskLevel_NoThreats(t *testing.T) {
	level, score := calculateRiskLevel(nil)
	if level != 0 || score != 0.0 {
		t.Fatalf("expected (0, 0.0), got (%d, %f)", level, score)
	}
}

func TestCalculateRiskLevel_HighRisk(t *testing.T) {
	threats := []Threat{{Confidence: 0.95}}
	level, score := calculateRiskLevel(threats)
	if level != 3 {
		t.Fatalf("expected level 3 (high risk) for confidence 0.95, got %d", level)
	}
	if score < 0 || score > 1 {
		t.Fatalf("risk score out of range: %f", score)
	}
}

func TestCalculateRiskLevel_MediumRisk(t *testing.T) {
	threats := []Threat{{Confidence: 0.65}}
	level, _ := calculateRiskLevel(threats)
	if level != 2 {
		t.Fatalf("expected level 2 (medium risk) for confidence 0.65, got %d", level)
	}
}

func TestCalculateRiskLevel_LowRisk(t *testing.T) {
	threats := []Threat{{Confidence: 0.3}}
	level, _ := calculateRiskLevel(threats)
	if level != 1 {
		t.Fatalf("expected level 1 (low risk) for confidence 0.3, got %d", level)
	}
}

// ─── getClientIP ──────────────────────────────────────────────────────────────

func TestGetClientIP_ForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")

	ip := getClientIP(req)
	if ip != "1.2.3.4" {
		t.Fatalf("expected first IP '1.2.3.4', got %q", ip)
	}
}

func TestGetClientIP_RealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "9.9.9.9")

	ip := getClientIP(req)
	if ip != "9.9.9.9" {
		t.Fatalf("expected '9.9.9.9', got %q", ip)
	}
}

func TestGetClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:54321"

	ip := getClientIP(req)
	if ip != "192.168.1.1:54321" {
		t.Fatalf("expected RemoteAddr fallback '192.168.1.1:54321', got %q", ip)
	}
}

// ─── authMiddleware ───────────────────────────────────────────────────────────

func TestAuthMiddleware_BypassedForHealth(t *testing.T) {
	// Even with auth enabled and no key, /health must pass through.
	t.Setenv("API_AUTH_ENABLED", "true")
	t.Setenv("API_KEYS", "secret-key")

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	authMiddleware(inner)(rr, req)

	if !called {
		t.Fatal("/health must bypass auth middleware")
	}
}

func TestAuthMiddleware_RejectsNoToken(t *testing.T) {
	t.Setenv("API_AUTH_ENABLED", "true")
	t.Setenv("API_KEYS", "mykey")

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/analyze", nil)
	rr := httptest.NewRecorder()
	authMiddleware(inner)(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", rr.Code)
	}
}

func TestAuthMiddleware_AcceptsValidToken(t *testing.T) {
	t.Setenv("API_AUTH_ENABLED", "true")
	t.Setenv("API_KEYS", "good-token")

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/analyze", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rr := httptest.NewRecorder()
	authMiddleware(inner)(rr, req)

	if !called {
		t.Fatal("valid token must allow through auth middleware")
	}
}

// ─── rateLimitMiddleware ──────────────────────────────────────────────────────

func TestRateLimitMiddleware_PassesThrough(t *testing.T) {
	initTestGlobals()

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/stats", nil)
	req.RemoteAddr = "203.0.113.77:9999"
	rr := httptest.NewRecorder()

	rateLimitMiddleware(inner)(rr, req)

	if !called {
		t.Fatal("first request must pass through rate-limit middleware")
	}
}

