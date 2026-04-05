package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/falcn-io/falcn/internal/detector"
	"github.com/falcn-io/falcn/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock checker ---

// mockChecker implements PackageChecker for testing.
type mockChecker struct {
	mu      sync.Mutex
	results map[string]*detector.CheckPackageResult
	err     error
	calls   []string // records package names that were checked
}

func newMockChecker() *mockChecker {
	return &mockChecker{
		results: make(map[string]*detector.CheckPackageResult),
	}
}

func (m *mockChecker) setResult(name string, result *detector.CheckPackageResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results[name] = result
}

func (m *mockChecker) CheckPackage(_ context.Context, name, registry string) (*detector.CheckPackageResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, name)
	if m.err != nil {
		return nil, m.err
	}
	if r, ok := m.results[name]; ok {
		return r, nil
	}
	return &detector.CheckPackageResult{Name: name}, nil
}

// --- Helper to create a proxy with a mock upstream ---

func newTestProxy(t *testing.T, checker *mockChecker, cfgOverrides func(*ProxyConfig)) (*RegistryProxy, *httptest.Server) {
	t.Helper()

	// Upstream mock for npm and pypi.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"test-etag"`)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name":    "upstream-response",
			"path":    r.URL.Path,
			"version": "1.0.0",
		})
	}))
	t.Cleanup(upstream.Close)

	cfg := &ProxyConfig{
		ListenAddr:      ":0",
		NPMUpstream:     upstream.URL,
		PyPIUpstream:    upstream.URL,
		MavenUpstream:   upstream.URL,
		GoProxyUpstream: upstream.URL,
		CargoUpstream:   upstream.URL,
		BlockSeverity:   "high",
		WarnSeverity:    "medium",
		MaxAuditLog:     100,
		CacheTTL:        1 * time.Second,
	}
	if cfgOverrides != nil {
		cfgOverrides(cfg)
	}

	p := NewRegistryProxy(cfg, checker)
	return p, upstream
}

// --- Tests ---

func TestProxyConfig_Defaults(t *testing.T) {
	cfg := DefaultProxyConfig()
	assert.Equal(t, ":8888", cfg.ListenAddr)
	assert.Equal(t, "https://registry.npmjs.org", cfg.NPMUpstream)
	assert.Equal(t, "https://pypi.org", cfg.PyPIUpstream)
	assert.Equal(t, "high", cfg.BlockSeverity)
	assert.Equal(t, "medium", cfg.WarnSeverity)
	assert.Equal(t, 10000, cfg.MaxAuditLog)
	assert.Equal(t, 5*time.Minute, cfg.CacheTTL)
}

func TestNPMProxy_AllowCleanPackage(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/npm/lodash", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get("X-Falcn-Warning"))
	assert.Equal(t, "true", rec.Header().Get("X-Falcn-Proxy"))
}

func TestNPMProxy_BlockMalicious(t *testing.T) {
	mc := newMockChecker()
	mc.setResult("evil-package", &detector.CheckPackageResult{
		Name: "evil-package",
		Threats: []types.Threat{
			{
				Type:        types.ThreatTypeTyposquatting,
				Severity:    types.SeverityHigh,
				Description: "Typosquatting attack on popular package",
			},
		},
	})
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/npm/evil-package", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)

	var body map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&body)
	require.NoError(t, err)
	assert.Equal(t, "package_blocked", body["error"])
	assert.Contains(t, body["message"], "evil-package")
	threats, ok := body["threats"].([]interface{})
	require.True(t, ok)
	assert.Len(t, threats, 1)
}

func TestNPMProxy_WarnMedium(t *testing.T) {
	mc := newMockChecker()
	mc.setResult("sketchy-pkg", &detector.CheckPackageResult{
		Name: "sketchy-pkg",
		Threats: []types.Threat{
			{
				Type:        types.ThreatTypeSuspicious,
				Severity:    types.SeverityMedium,
				Description: "Suspicious patterns detected",
			},
		},
	})
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/npm/sketchy-pkg", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	warning := rec.Header().Get("X-Falcn-Warning")
	assert.NotEmpty(t, warning)
	assert.Contains(t, warning, "sketchy-pkg")
}

func TestNPMProxy_ScopedPackage(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/npm/@babel/core", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify the checker was called with the scoped name.
	mc.mu.Lock()
	defer mc.mu.Unlock()
	require.Len(t, mc.calls, 1)
	assert.Equal(t, "@babel/core", mc.calls[0])
}

func TestNPMProxy_VersionedRequest(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/npm/express/4.18.2", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestPyPIProxy_AllowClean(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/pypi/simple/requests/", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get("X-Falcn-Warning"))
}

func TestPyPIProxy_BlockMalicious(t *testing.T) {
	mc := newMockChecker()
	// PyPI names are normalized: "Evil_Package" -> "evil-package"
	mc.setResult("evil-package", &detector.CheckPackageResult{
		Name: "evil-package",
		Threats: []types.Threat{
			{
				Type:        types.ThreatTypeMalicious,
				Severity:    types.SeverityCritical,
				Description: "Known malicious package",
			},
		},
	})
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/pypi/simple/Evil_Package/", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestPyPIProxy_NameNormalization(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"requests", "requests"},
		{"Requests", "requests"},
		{"my_package", "my-package"},
		{"My.Package", "my-package"},
		{"some--pkg", "some-pkg"},
		{"UPPER_CASE.name", "upper-case-name"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizePyPIName(tt.input))
		})
	}
}

func TestAllowList_BypassesScan(t *testing.T) {
	mc := newMockChecker()
	// Set a threat that would block, but the package is allow-listed.
	mc.setResult("trusted-pkg", &detector.CheckPackageResult{
		Name: "trusted-pkg",
		Threats: []types.Threat{
			{
				Type:     types.ThreatTypeTyposquatting,
				Severity: types.SeverityHigh,
			},
		},
	})

	p, _ := newTestProxy(t, mc, func(cfg *ProxyConfig) {
		cfg.AllowList = []string{"trusted-pkg"}
	})

	req := httptest.NewRequest("GET", "/npm/trusted-pkg", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// The detector should NOT have been called since allow-list short-circuits.
	mc.mu.Lock()
	defer mc.mu.Unlock()
	assert.Empty(t, mc.calls)
}

func TestBlockList_AlwaysBlocks(t *testing.T) {
	mc := newMockChecker()
	// No threats set — the package is clean, but block-listed.
	p, _ := newTestProxy(t, mc, func(cfg *ProxyConfig) {
		cfg.BlockList = []string{"banned-pkg"}
	})

	req := httptest.NewRequest("GET", "/npm/banned-pkg", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)

	var body map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&body)
	assert.Equal(t, "package_blocked", body["error"])

	// The detector should NOT have been called.
	mc.mu.Lock()
	defer mc.mu.Unlock()
	assert.Empty(t, mc.calls)
}

func TestAuditLog_RecordsDecisions(t *testing.T) {
	mc := newMockChecker()
	mc.setResult("bad-pkg", &detector.CheckPackageResult{
		Name: "bad-pkg",
		Threats: []types.Threat{
			{
				Type:     types.ThreatTypeMalicious,
				Severity: types.SeverityCritical,
			},
		},
	})
	p, _ := newTestProxy(t, mc, nil)

	// Make a few requests.
	for _, pkg := range []string{"lodash", "bad-pkg", "express"} {
		req := httptest.NewRequest("GET", "/npm/"+pkg, nil)
		rec := httptest.NewRecorder()
		p.Router().ServeHTTP(rec, req)
	}

	// Fetch audit log via admin API.
	req := httptest.NewRequest("GET", "/api/v1/audit-log", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var entries []AuditEntry
	err := json.NewDecoder(rec.Body).Decode(&entries)
	require.NoError(t, err)
	assert.Len(t, entries, 3)

	// Verify decisions.
	decisions := map[string]Decision{}
	for _, e := range entries {
		decisions[e.Package] = e.Decision
	}
	assert.Equal(t, DecisionAllow, decisions["lodash"])
	assert.Equal(t, DecisionBlock, decisions["bad-pkg"])
	assert.Equal(t, DecisionAllow, decisions["express"])
}

func TestProxyStats_Increments(t *testing.T) {
	mc := newMockChecker()
	mc.setResult("bad", &detector.CheckPackageResult{
		Name: "bad",
		Threats: []types.Threat{
			{Type: types.ThreatTypeMalicious, Severity: types.SeverityCritical},
		},
	})
	mc.setResult("meh", &detector.CheckPackageResult{
		Name: "meh",
		Threats: []types.Threat{
			{Type: types.ThreatTypeSuspicious, Severity: types.SeverityMedium},
		},
	})

	p, _ := newTestProxy(t, mc, nil)

	// Clean package.
	p.Router().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/npm/clean", nil))
	// Blocked package.
	p.Router().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/npm/bad", nil))
	// Warned package.
	p.Router().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/npm/meh", nil))

	// Fetch stats.
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	var stats ProxyStats
	err := json.NewDecoder(rec.Body).Decode(&stats)
	require.NoError(t, err)

	assert.Equal(t, int64(3), stats.PackagesScanned)
	assert.Equal(t, int64(1), stats.Blocked)
	assert.Equal(t, int64(1), stats.Warned)
	assert.Equal(t, int64(1), stats.Allowed)
	assert.Equal(t, int64(3), stats.TotalRequests) // 3 proxy requests (admin API not counted)
}

func TestConcurrentRequests(t *testing.T) {
	mc := newMockChecker()
	mc.setResult("risky", &detector.CheckPackageResult{
		Name: "risky",
		Threats: []types.Threat{
			{Type: types.ThreatTypeTyposquatting, Severity: types.SeverityHigh},
		},
	})

	p, _ := newTestProxy(t, mc, nil)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			var pkg string
			if i%3 == 0 {
				pkg = "risky"
			} else {
				pkg = fmt.Sprintf("pkg-%d", i)
			}
			req := httptest.NewRequest("GET", "/npm/"+pkg, nil)
			rec := httptest.NewRecorder()
			p.Router().ServeHTTP(rec, req)
			// Every request should complete without panicking.
			if pkg == "risky" {
				assert.Equal(t, http.StatusForbidden, rec.Code)
			} else {
				assert.Equal(t, http.StatusOK, rec.Code)
			}
		}(i)
	}

	wg.Wait()

	// Verify stats are consistent.
	assert.Equal(t, int64(n), p.totalRequests.Load())
}

func TestAdminAPI_GetPolicies(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, func(cfg *ProxyConfig) {
		cfg.AllowList = []string{"safe-a", "safe-b"}
		cfg.BlockList = []string{"bad-c"}
	})

	req := httptest.NewRequest("GET", "/api/v1/policies", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var policies ProxyPolicies
	err := json.NewDecoder(rec.Body).Decode(&policies)
	require.NoError(t, err)
	assert.Equal(t, "high", policies.BlockSeverity)
	assert.Equal(t, "medium", policies.WarnSeverity)
	assert.Equal(t, []string{"safe-a", "safe-b"}, policies.AllowList)
	assert.Equal(t, []string{"bad-c"}, policies.BlockList)
}

func TestAdminAPI_UpdatePolicies(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	// Update policies.
	update := ProxyPolicies{
		BlockSeverity: "critical",
		WarnSeverity:  "high",
		AllowList:     []string{"new-allow"},
		BlockList:     []string{"new-block"},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest("PUT", "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ProxyPolicies
	json.NewDecoder(rec.Body).Decode(&resp)
	assert.Equal(t, "critical", resp.BlockSeverity)
	assert.Equal(t, "high", resp.WarnSeverity)
	assert.Equal(t, []string{"new-allow"}, resp.AllowList)
	assert.Equal(t, []string{"new-block"}, resp.BlockList)

	// Verify the new block list is enforced: "new-block" should be blocked.
	req2 := httptest.NewRequest("GET", "/npm/new-block", nil)
	rec2 := httptest.NewRecorder()
	p.Router().ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusForbidden, rec2.Code)

	// And that a previously-would-be-blocked high-severity package is now only warned
	// (because we changed block threshold to "critical").
	mc.setResult("high-threat", &detector.CheckPackageResult{
		Name: "high-threat",
		Threats: []types.Threat{
			{Type: types.ThreatTypeTyposquatting, Severity: types.SeverityHigh},
		},
	})
	req3 := httptest.NewRequest("GET", "/npm/high-threat", nil)
	rec3 := httptest.NewRecorder()
	p.Router().ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusOK, rec3.Code)
	assert.NotEmpty(t, rec3.Header().Get("X-Falcn-Warning"))
}

func TestScanCache_ReusesResult(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, func(cfg *ProxyConfig) {
		cfg.CacheTTL = 5 * time.Second
	})

	// First request: cache miss.
	req := httptest.NewRequest("GET", "/npm/cached-pkg", nil)
	p.Router().ServeHTTP(httptest.NewRecorder(), req)

	// Second request: should be a cache hit.
	req2 := httptest.NewRequest("GET", "/npm/cached-pkg", nil)
	p.Router().ServeHTTP(httptest.NewRecorder(), req2)

	// Checker should have been called only once.
	mc.mu.Lock()
	callCount := 0
	for _, c := range mc.calls {
		if c == "cached-pkg" {
			callCount++
		}
	}
	mc.mu.Unlock()
	assert.Equal(t, 1, callCount)

	assert.Equal(t, int64(1), p.cacheHits.Load())
	assert.Equal(t, int64(1), p.cacheMisses.Load())
}

func TestHealthz(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	assert.Equal(t, "ok", body["status"])
}

func TestSeverityLevel(t *testing.T) {
	assert.Equal(t, 4, severityLevel("critical"))
	assert.Equal(t, 3, severityLevel("high"))
	assert.Equal(t, 2, severityLevel("medium"))
	assert.Equal(t, 1, severityLevel("low"))
	assert.Equal(t, 0, severityLevel("unknown"))
	assert.Equal(t, 4, severityLevel("CRITICAL")) // case-insensitive
}

func TestNPMTarball_ProxiedTransparently(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	// Pre-populate cache so tarball download does not trigger a new scan.
	p.cache.Store("npm:lodash", &scanCacheEntry{
		decision: DecisionAllow,
		threats:  nil,
		expiry:   time.Now().Add(5 * time.Minute),
	})

	req := httptest.NewRequest("GET", "/npm/lodash/-/lodash-4.17.21.tgz", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	// When cache is populated, tarball downloads should not trigger a scan.
	mc.mu.Lock()
	defer mc.mu.Unlock()
	assert.Empty(t, mc.calls)
}

func TestPyPIDownload_ProxiedTransparently(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	// Pre-populate cache so download does not trigger a new scan.
	p.cache.Store("pypi:requests", &scanCacheEntry{
		decision: DecisionAllow,
		threats:  nil,
		expiry:   time.Now().Add(5 * time.Minute),
	})

	req := httptest.NewRequest("GET", "/pypi/packages/source/r/requests/requests-2.31.0.tar.gz", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mc.mu.Lock()
	defer mc.mu.Unlock()
	assert.Empty(t, mc.calls)
}

func TestAuditLog_MaxSizeEnforced(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, func(cfg *ProxyConfig) {
		cfg.MaxAuditLog = 20
	})

	// Make 30 requests to exceed the max.
	for i := 0; i < 30; i++ {
		req := httptest.NewRequest("GET", fmt.Sprintf("/npm/pkg-%d", i), nil)
		p.Router().ServeHTTP(httptest.NewRecorder(), req)
	}

	p.auditMu.RLock()
	logLen := len(p.auditLog)
	p.auditMu.RUnlock()

	assert.LessOrEqual(t, logLen, 20)
}

// --- New security tests ---

func TestAdminAPI_RequiresAuth(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, func(cfg *ProxyConfig) {
		cfg.AdminToken = "secret-token-123"
	})

	// No token => 401
	req := httptest.NewRequest("GET", "/api/v1/policies", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "Bearer")

	// Wrong token => 403
	req2 := httptest.NewRequest("GET", "/api/v1/policies", nil)
	req2.Header.Set("Authorization", "Bearer wrong-token")
	rec2 := httptest.NewRecorder()
	p.Router().ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusForbidden, rec2.Code)

	// Correct token => 200
	req3 := httptest.NewRequest("GET", "/api/v1/policies", nil)
	req3.Header.Set("Authorization", "Bearer secret-token-123")
	rec3 := httptest.NewRecorder()
	p.Router().ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusOK, rec3.Code)
}

func TestAdminAPI_UpdatePolicies_InvalidSeverity(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	// Invalid block_severity
	update := ProxyPolicies{BlockSeverity: "invalid"}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest("PUT", "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid block_severity")

	// Invalid warn_severity
	update2 := ProxyPolicies{WarnSeverity: "bogus"}
	body2, _ := json.Marshal(update2)
	req2 := httptest.NewRequest("PUT", "/api/v1/policies", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	p.Router().ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusBadRequest, rec2.Code)
	assert.Contains(t, rec2.Body.String(), "invalid warn_severity")

	// Valid severities should still work
	update3 := ProxyPolicies{BlockSeverity: "critical", WarnSeverity: "low"}
	body3, _ := json.Marshal(update3)
	req3 := httptest.NewRequest("PUT", "/api/v1/policies", bytes.NewReader(body3))
	req3.Header.Set("Content-Type", "application/json")
	rec3 := httptest.NewRecorder()
	p.Router().ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusOK, rec3.Code)
}

func TestFailClosed_OnDetectorError(t *testing.T) {
	mc := newMockChecker()
	mc.err = fmt.Errorf("database connection timeout")
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/npm/some-package", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	// Fail-closed: should block, not allow
	assert.Equal(t, http.StatusForbidden, rec.Code)

	var body map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&body)
	require.NoError(t, err)
	assert.Equal(t, "package_blocked", body["error"])

	// Verify audit log records a block with scan_error threat type.
	p.auditMu.RLock()
	defer p.auditMu.RUnlock()
	require.Len(t, p.auditLog, 1)
	assert.Equal(t, DecisionBlock, p.auditLog[0].Decision)
	require.Len(t, p.auditLog[0].Threats, 1)
	assert.Equal(t, "scan_error", p.auditLog[0].Threats[0].Type)
}

func TestPackageNameValidation(t *testing.T) {
	tests := []struct {
		name     string
		registry string
		valid    bool
	}{
		// Valid names
		{"lodash", "npm", true},
		{"@babel/core", "npm", true},
		{"my-package", "npm", true},
		{"requests", "pypi", true},
		{"my-pkg", "pypi", true},
		{"Flask", "pypi", true},

		// Invalid: empty
		{"", "npm", false},
		{"", "pypi", false},

		// Invalid: path traversal
		{"../etc/passwd", "npm", false},
		{"foo/../bar", "npm", false},

		// Invalid: control characters
		{"pkg\x00name", "npm", false},
		{"pkg\nname", "npm", false},

		// Invalid: too long
		{string(make([]byte, 215)), "npm", false},

		// Invalid: npm patterns
		{".hidden", "npm", false},
		{"-leading-dash", "npm", false},

		// Invalid: pypi with control chars
		{"pkg\x00name", "pypi", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.registry, tt.name), func(t *testing.T) {
			assert.Equal(t, tt.valid, validatePackageName(tt.name, tt.registry))
		})
	}
}

func TestPackageNameValidation_BlocksInHandler(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	// Path traversal attempt via npm
	req := httptest.NewRequest("GET", "/npm/..%2F..%2Fetc%2Fpasswd", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)
	// The mux may decode this differently, but validatePackageName catches it
	// if it reaches the handler. Any non-200 is acceptable.
	// Verify checker was never called with traversal attempt.
	mc.mu.Lock()
	for _, c := range mc.calls {
		assert.NotContains(t, c, "..")
	}
	mc.mu.Unlock()
}

func TestNPMTarball_ScanIfNotCached(t *testing.T) {
	mc := newMockChecker()
	mc.setResult("evil-lib", &detector.CheckPackageResult{
		Name: "evil-lib",
		Threats: []types.Threat{
			{
				Type:     types.ThreatTypeMalicious,
				Severity: types.SeverityCritical,
			},
		},
	})
	p, _ := newTestProxy(t, mc, nil)

	// Request tarball directly without prior metadata fetch.
	req := httptest.NewRequest("GET", "/npm/evil-lib/-/evil-lib-1.0.0.tgz", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	// Should block because scan is triggered and finds threats.
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// Verify the checker was called.
	mc.mu.Lock()
	defer mc.mu.Unlock()
	assert.Contains(t, mc.calls, "evil-lib")
}

func TestNPMTarball_AllowIfClean(t *testing.T) {
	mc := newMockChecker()
	// Default result is clean (no threats).
	p, _ := newTestProxy(t, mc, nil)

	// Tarball without prior metadata request — should scan and allow.
	req := httptest.NewRequest("GET", "/npm/clean-pkg/-/clean-pkg-1.0.0.tgz", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	mc.mu.Lock()
	defer mc.mu.Unlock()
	assert.Contains(t, mc.calls, "clean-pkg")
}

func TestMetricsEndpoint(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	// Make a request to trigger some metrics.
	req := httptest.NewRequest("GET", "/npm/lodash", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	// Now check metrics endpoint.
	req = httptest.NewRequest("GET", "/metrics", nil)
	rec = httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "falcn_proxy_requests_total")
	assert.Contains(t, body, "falcn_proxy_packages_scanned_total")
	assert.Contains(t, body, "falcn_proxy_scan_duration_seconds")
}

func TestConnectionPooling(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	// Verify the shared HTTP client is initialized.
	require.NotNil(t, p.httpClient)
	require.NotNil(t, p.httpClient.Transport)

	transport, ok := p.httpClient.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Equal(t, 100, transport.MaxIdleConns)
	assert.Equal(t, 20, transport.MaxIdleConnsPerHost)
	assert.Equal(t, 90*time.Second, transport.IdleConnTimeout)

	// Make multiple requests and verify they all succeed (reusing the same client).
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", fmt.Sprintf("/npm/pool-test-%d", i), nil)
		rec := httptest.NewRecorder()
		p.Router().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestPersistentAuditLog(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.jsonl")

	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, func(cfg *ProxyConfig) {
		cfg.AuditLogFile = logFile
	})

	// Make a request
	req := httptest.NewRequest("GET", "/npm/lodash", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify file was written
	data, err := os.ReadFile(logFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "lodash")
	assert.Contains(t, string(data), "allow")

	// Verify it's valid JSON
	var entry AuditEntry
	err = json.Unmarshal(bytes.TrimSpace(data), &entry)
	require.NoError(t, err)
	assert.Equal(t, "lodash", entry.Package)
}

func TestAuditLogRotation(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.jsonl")

	logger, err := NewAuditLogger(logFile)
	require.NoError(t, err)
	defer logger.Close()

	// Write an entry
	logger.Write(AuditEntry{Package: "test-pkg", Decision: DecisionAllow, Timestamp: time.Now()})
	assert.Equal(t, int64(1), logger.Entries())

	// Rotate
	err = logger.Rotate()
	require.NoError(t, err)
	assert.Equal(t, int64(0), logger.Entries())

	// Verify rotated file exists
	matches, _ := filepath.Glob(filepath.Join(tmpDir, "audit.jsonl.*"))
	assert.Len(t, matches, 1)

	// Write another entry after rotation
	logger.Write(AuditEntry{Package: "another-pkg", Decision: DecisionBlock, Timestamp: time.Now()})

	// New file should have the new entry
	data, _ := os.ReadFile(logFile)
	assert.Contains(t, string(data), "another-pkg")
}

// --- Maven proxy tests ---

func TestMavenProxy_AllowClean(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/maven/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)
	// Should attempt upstream (not blocked)
	assert.NotEqual(t, http.StatusForbidden, rec.Code)
}

func TestMavenProxy_BlockMalicious(t *testing.T) {
	mc := newMockChecker()
	mc.setResult("com.evil.malware:malware", &detector.CheckPackageResult{
		Name: "com.evil.malware:malware",
		Threats: []types.Threat{
			{Type: types.ThreatTypeTyposquatting, Severity: types.SeverityCritical},
		},
	})
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/maven/com/evil/malware/malware/1.0/malware-1.0.jar", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestMavenProxy_Metadata(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/maven/com/google/guava/guava/maven-metadata.xml", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusForbidden, rec.Code)
}

// --- Go proxy tests ---

func TestGoProxy_AllowClean(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/go/github.com/gorilla/mux/@v/list", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusForbidden, rec.Code)
}

func TestGoProxy_BlockMalicious(t *testing.T) {
	mc := newMockChecker()
	mc.setResult("github.com/evil/malware", &detector.CheckPackageResult{
		Name: "github.com/evil/malware",
		Threats: []types.Threat{
			{Type: types.ThreatTypeTyposquatting, Severity: types.SeverityCritical},
		},
	})
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/go/github.com/evil/malware/@v/v1.0.0.info", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestGoProxy_DecodeModulePath(t *testing.T) {
	assert.Equal(t, "github.com/Azure/sdk", decodeModulePath("github.com/!azure/sdk"))
	assert.Equal(t, "github.com/GoogleCloudPlatform/xyz", decodeModulePath("github.com/!google!cloud!platform/xyz"))
	assert.Equal(t, "simple/path", decodeModulePath("simple/path"))
}

func TestGoProxy_LatestEndpoint(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/go/github.com/gorilla/mux/@latest", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusForbidden, rec.Code)
}

// --- Cargo proxy tests ---

func TestCargoProxy_AllowClean(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/cargo/api/v1/crates/serde", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusForbidden, rec.Code)
}

func TestCargoProxy_BlockMalicious(t *testing.T) {
	mc := newMockChecker()
	mc.setResult("evil-crate", &detector.CheckPackageResult{
		Name: "evil-crate",
		Threats: []types.Threat{
			{Type: types.ThreatTypeTyposquatting, Severity: types.SeverityCritical},
		},
	})
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/cargo/api/v1/crates/evil-crate", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCargoProxy_DownloadGated(t *testing.T) {
	mc := newMockChecker()
	mc.setResult("evil-crate", &detector.CheckPackageResult{
		Name: "evil-crate",
		Threats: []types.Threat{
			{Type: types.ThreatTypeMalicious, Severity: types.SeverityCritical},
		},
	})
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/cargo/api/v1/crates/evil-crate/1.0.0/download", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCargoProxy_VersionedMetadata(t *testing.T) {
	mc := newMockChecker()
	p, _ := newTestProxy(t, mc, nil)

	req := httptest.NewRequest("GET", "/cargo/api/v1/crates/serde/1.0.197", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusForbidden, rec.Code)
}
