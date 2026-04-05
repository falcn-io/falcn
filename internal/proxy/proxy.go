// Package proxy provides an enterprise registry firewall/proxy that intercepts
// package manager requests, runs falcn security analysis, and blocks malicious
// packages before they reach developer machines.
//
// Usage:
//
//	proxy := NewRegistryProxy(config, detectorEngine)
//	proxy.Start(":8888")
//
// npm: npm config set registry http://localhost:8888/npm/
// pip: pip install --index-url http://localhost:8888/pypi/simple/ <package>
package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/falcn-io/falcn/internal/detector"
	"github.com/falcn-io/falcn/pkg/types"
)

// Decision represents the proxy's verdict on a package request.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionWarn  Decision = "warn"
	DecisionBlock Decision = "block"
)

// ProxyConfig holds all configuration for the registry proxy.
type ProxyConfig struct {
	ListenAddr    string        `json:"listen_addr"`
	NPMUpstream   string        `json:"npm_upstream"`
	PyPIUpstream    string        `json:"pypi_upstream"`
	MavenUpstream   string        `json:"maven_upstream"`
	GoProxyUpstream string        `json:"go_proxy_upstream"`
	CargoUpstream   string        `json:"cargo_upstream"`
	BlockSeverity   string        `json:"block_severity"`
	WarnSeverity    string        `json:"warn_severity"`
	MaxAuditLog   int           `json:"max_audit_log"`
	TLSCert       string        `json:"tls_cert"`
	TLSKey        string        `json:"tls_key"`
	AllowList     []string      `json:"allow_list"`
	BlockList     []string      `json:"block_list"`
	CacheTTL      time.Duration `json:"cache_ttl"`
	AdminToken    string        `json:"admin_token"`
	AuditLogFile  string        `json:"audit_log_file"`
}

// DefaultProxyConfig returns a ProxyConfig with sensible defaults.
func DefaultProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		ListenAddr:    ":8888",
		NPMUpstream:   "https://registry.npmjs.org",
		PyPIUpstream:  "https://pypi.org",
		MavenUpstream:   "https://repo1.maven.org/maven2",
		GoProxyUpstream: "https://proxy.golang.org",
		CargoUpstream:   "https://crates.io",
		BlockSeverity:   "high",
		WarnSeverity:  "medium",
		MaxAuditLog:   10000,
		CacheTTL:      5 * time.Minute,
	}
}

// ThreatSummary is a compact representation of a detected threat for audit logs
// and API responses.
type ThreatSummary struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// AuditEntry records a single proxy decision for the audit log.
type AuditEntry struct {
	Timestamp  time.Time       `json:"timestamp"`
	Package    string          `json:"package"`
	Registry   string          `json:"registry"`
	Version    string          `json:"version"`
	Decision   Decision        `json:"decision"`
	Threats    []ThreatSummary `json:"threats,omitempty"`
	ScanTimeMs int64           `json:"scan_time_ms"`
	ClientIP   string          `json:"client_ip"`
}

// ProxyStats exposes runtime metrics for the admin API.
type ProxyStats struct {
	StartedAt       time.Time `json:"started_at"`
	TotalRequests   int64     `json:"total_requests"`
	PackagesScanned int64     `json:"packages_scanned"`
	Blocked         int64     `json:"blocked"`
	Warned          int64     `json:"warned"`
	Allowed         int64     `json:"allowed"`
	AvgScanTimeMs   float64   `json:"avg_scan_time_ms"`
	CacheHits       int64     `json:"cache_hits"`
	CacheMisses     int64     `json:"cache_misses"`
}

// scanCacheEntry stores a cached scan result with an expiry time.
type scanCacheEntry struct {
	decision Decision
	threats  []ThreatSummary
	expiry   time.Time
}

// ProxyPolicies holds the mutable allow/block lists and severity thresholds
// that can be updated at runtime via the admin API.
type ProxyPolicies struct {
	BlockSeverity string   `json:"block_severity"`
	WarnSeverity  string   `json:"warn_severity"`
	AllowList     []string `json:"allow_list"`
	BlockList     []string `json:"block_list"`
}

// PackageChecker is the interface the proxy uses to scan packages. This
// abstraction makes testing straightforward: tests supply a mock, while
// production code provides a real *detector.Engine.
type PackageChecker interface {
	CheckPackage(ctx context.Context, name, registry string) (*detector.CheckPackageResult, error)
}

// RegistryProxy is the main proxy server struct.
type RegistryProxy struct {
	config   *ProxyConfig
	checker  PackageChecker
	router   *mux.Router
	policies ProxyPolicies
	policyMu sync.RWMutex

	auditLog    []AuditEntry
	auditMu     sync.RWMutex
	auditLogger *AuditLogger

	// Atomic counters for stats.
	totalRequests   atomic.Int64
	packagesScanned atomic.Int64
	blocked         atomic.Int64
	warned          atomic.Int64
	allowed         atomic.Int64
	cacheHits       atomic.Int64
	cacheMisses     atomic.Int64
	totalScanTimeNs atomic.Int64
	startedAt       time.Time

	// Cache scan results keyed by "registry:package".
	cache    sync.Map
	cacheTTL time.Duration

	// Shared HTTP client for upstream requests (connection pooling).
	httpClient *http.Client
}

// NewRegistryProxy creates and configures a new RegistryProxy.
func NewRegistryProxy(cfg *ProxyConfig, checker PackageChecker) *RegistryProxy {
	if cfg == nil {
		cfg = DefaultProxyConfig()
	}
	if cfg.MaxAuditLog <= 0 {
		cfg.MaxAuditLog = 10000
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.NPMUpstream == "" {
		cfg.NPMUpstream = "https://registry.npmjs.org"
	}
	if cfg.PyPIUpstream == "" {
		cfg.PyPIUpstream = "https://pypi.org"
	}
	if cfg.MavenUpstream == "" {
		cfg.MavenUpstream = "https://repo1.maven.org/maven2"
	}
	if cfg.MavenUpstream == "" {
		cfg.MavenUpstream = "https://repo1.maven.org/maven2"
	}
	if cfg.GoProxyUpstream == "" {
		cfg.GoProxyUpstream = "https://proxy.golang.org"
	}
	if cfg.CargoUpstream == "" {
		cfg.CargoUpstream = "https://crates.io"
	}
	if cfg.BlockSeverity == "" {
		cfg.BlockSeverity = "high"
	}
	if cfg.WarnSeverity == "" {
		cfg.WarnSeverity = "medium"
	}

	p := &RegistryProxy{
		config:  cfg,
		checker: checker,
		policies: ProxyPolicies{
			BlockSeverity: cfg.BlockSeverity,
			WarnSeverity:  cfg.WarnSeverity,
			AllowList:     cfg.AllowList,
			BlockList:     cfg.BlockList,
		},
		auditLog:  make([]AuditEntry, 0, cfg.MaxAuditLog),
		startedAt: time.Now(),
		cacheTTL:  cfg.CacheTTL,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}

	var auditLogger *AuditLogger
	if cfg.AuditLogFile != "" {
		var err error
		auditLogger, err = NewAuditLogger(cfg.AuditLogFile)
		if err != nil {
			logrus.WithError(err).Warn("failed to initialize persistent audit log, using in-memory only")
			auditLogger = &AuditLogger{}
		}
	} else {
		auditLogger = &AuditLogger{}
	}
	p.auditLogger = auditLogger

	p.router = p.buildRouter()
	return p
}

// Router returns the underlying HTTP handler (useful for testing with httptest).
func (p *RegistryProxy) Router() http.Handler {
	return p.router
}

// Start begins listening for HTTP requests. It blocks until the server stops.
func (p *RegistryProxy) Start(addr string) error {
	if addr == "" {
		addr = p.config.ListenAddr
	}
	logrus.Infof("Falcn registry proxy listening on %s", addr)
	logrus.Infof("  npm  -> %s", p.config.NPMUpstream)
	logrus.Infof("  pypi  -> %s", p.config.PyPIUpstream)
	logrus.Infof("  maven -> %s", p.config.MavenUpstream)
	logrus.Infof("  go    -> %s", p.config.GoProxyUpstream)
	logrus.Infof("  cargo -> %s", p.config.CargoUpstream)

	srv := &http.Server{
		Addr:         addr,
		Handler:      p.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if p.config.TLSCert != "" && p.config.TLSKey != "" {
		return srv.ListenAndServeTLS(p.config.TLSCert, p.config.TLSKey)
	}
	return srv.ListenAndServe()
}

// buildRouter sets up all routes.
func (p *RegistryProxy) buildRouter() *mux.Router {
	r := mux.NewRouter()

	// Health check
	r.HandleFunc("/healthz", p.handleHealthz).Methods("GET")

	// Prometheus metrics (unauthenticated — Prometheus scraper needs access)
	r.Handle("/metrics", MetricsHandler()).Methods("GET")

	// Admin API
	admin := r.PathPrefix("/api/v1").Subrouter()
	admin.HandleFunc("/policies", p.adminAuth(p.handleGetPolicies)).Methods("GET")
	admin.HandleFunc("/policies", p.adminAuth(p.handleUpdatePolicies)).Methods("PUT")
	admin.HandleFunc("/audit-log", p.adminAuth(p.handleGetAuditLog)).Methods("GET")
	admin.HandleFunc("/stats", p.adminAuth(p.handleGetStats)).Methods("GET")

	// npm proxy
	npmRouter := r.PathPrefix("/npm").Subrouter()
	p.registerNPMRoutes(npmRouter)

	// PyPI proxy
	pypiRouter := r.PathPrefix("/pypi").Subrouter()
	p.registerPyPIRoutes(pypiRouter)

	// Maven proxy
	mavenRouter := r.PathPrefix("/maven").Subrouter()
	p.registerMavenRoutes(mavenRouter)

	// Go module proxy (GOPROXY compatible)
	goRouter := r.PathPrefix("/go").Subrouter()
	p.registerGoRoutes(goRouter)

	// Cargo/crates.io proxy
	cargoRouter := r.PathPrefix("/cargo").Subrouter()
	p.registerCargoRoutes(cargoRouter)

	return r
}

// --- Admin auth middleware ---

func (p *RegistryProxy) adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p.config.AdminToken == "" {
			// No token configured = allow (dev mode)
			next(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="falcn-proxy-admin"`)
			http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		// Constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(token), []byte(p.config.AdminToken)) != 1 {
			http.Error(w, `{"error":"invalid token"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// --- Admin API handlers ---

func (p *RegistryProxy) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (p *RegistryProxy) handleGetPolicies(w http.ResponseWriter, r *http.Request) {
	p.policyMu.RLock()
	policies := p.policies
	p.policyMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies)
}

func (p *RegistryProxy) handleUpdatePolicies(w http.ResponseWriter, r *http.Request) {
	var update ProxyPolicies
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	validSeverities := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	if update.BlockSeverity != "" && !validSeverities[strings.ToLower(update.BlockSeverity)] {
		http.Error(w, `{"error":"invalid block_severity; must be critical, high, medium, or low"}`, http.StatusBadRequest)
		return
	}
	if update.WarnSeverity != "" && !validSeverities[strings.ToLower(update.WarnSeverity)] {
		http.Error(w, `{"error":"invalid warn_severity; must be critical, high, medium, or low"}`, http.StatusBadRequest)
		return
	}

	p.policyMu.Lock()
	if update.BlockSeverity != "" {
		p.policies.BlockSeverity = update.BlockSeverity
	}
	if update.WarnSeverity != "" {
		p.policies.WarnSeverity = update.WarnSeverity
	}
	if update.AllowList != nil {
		p.policies.AllowList = update.AllowList
	}
	if update.BlockList != nil {
		p.policies.BlockList = update.BlockList
	}
	policies := p.policies
	p.policyMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies)
}

func (p *RegistryProxy) handleGetAuditLog(w http.ResponseWriter, r *http.Request) {
	p.auditMu.RLock()
	entries := make([]AuditEntry, len(p.auditLog))
	copy(entries, p.auditLog)
	p.auditMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func (p *RegistryProxy) handleGetStats(w http.ResponseWriter, r *http.Request) {
	scanned := p.packagesScanned.Load()
	var avgMs float64
	if scanned > 0 {
		avgMs = float64(p.totalScanTimeNs.Load()) / float64(scanned) / 1e6
	}

	stats := ProxyStats{
		StartedAt:       p.startedAt,
		TotalRequests:   p.totalRequests.Load(),
		PackagesScanned: scanned,
		Blocked:         p.blocked.Load(),
		Warned:          p.warned.Load(),
		Allowed:         p.allowed.Load(),
		AvgScanTimeMs:   avgMs,
		CacheHits:       p.cacheHits.Load(),
		CacheMisses:     p.cacheMisses.Load(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// --- Scan and decision logic ---

// scanPackage runs the detector on the given package and returns a decision
// together with any threat summaries. Results are cached.
func (p *RegistryProxy) scanPackage(ctx context.Context, registry, pkgName, version, clientIP string) (Decision, []ThreatSummary, int64) {
	cacheKey := fmt.Sprintf("%s:%s", registry, pkgName)

	// Check cache.
	if entry, ok := p.cache.Load(cacheKey); ok {
		ce := entry.(*scanCacheEntry)
		if time.Now().Before(ce.expiry) {
			p.cacheHits.Add(1)
			proxyCacheHits.Inc()
			return ce.decision, ce.threats, 0
		}
		p.cache.Delete(cacheKey)
	}
	p.cacheMisses.Add(1)
	proxyCacheMisses.Inc()

	// Check allow/block lists.
	p.policyMu.RLock()
	policies := p.policies
	p.policyMu.RUnlock()

	for _, allowed := range policies.AllowList {
		if strings.EqualFold(pkgName, allowed) {
			p.recordAudit(pkgName, registry, version, DecisionAllow, nil, 0, clientIP)
			p.allowed.Add(1)
			p.packagesScanned.Add(1)
			proxyPackagesScanned.Inc()
			proxyRequestsTotal.WithLabelValues(registry, string(DecisionAllow)).Inc()
			return DecisionAllow, nil, 0
		}
	}
	for _, blocked := range policies.BlockList {
		if strings.EqualFold(pkgName, blocked) {
			threats := []ThreatSummary{{
				Type:        "blocklist",
				Severity:    "critical",
				Description: fmt.Sprintf("Package %q is on the block list", pkgName),
			}}
			p.recordAudit(pkgName, registry, version, DecisionBlock, threats, 0, clientIP)
			p.blocked.Add(1)
			p.packagesScanned.Add(1)
			proxyPackagesScanned.Inc()
			proxyPackagesBlocked.Inc()
			proxyThreatsByType.WithLabelValues("blocklist", "critical").Inc()
			proxyRequestsTotal.WithLabelValues(registry, string(DecisionBlock)).Inc()
			return DecisionBlock, threats, 0
		}
	}

	// Run the detector.
	start := time.Now()
	result, err := p.checker.CheckPackage(ctx, pkgName, registry)
	elapsed := time.Since(start)
	scanTimeMs := elapsed.Milliseconds()
	p.totalScanTimeNs.Add(elapsed.Nanoseconds())
	p.packagesScanned.Add(1)
	proxyScanDuration.Observe(elapsed.Seconds())
	proxyPackagesScanned.Inc()

	if err != nil {
		logrus.WithError(err).WithField("package", pkgName).Error("detector scan failed, blocking package for safety")
		threats := []ThreatSummary{{
			Type:        "scan_error",
			Severity:    "critical",
			Description: fmt.Sprintf("Security scan failed for %q: %v", pkgName, err),
		}}
		p.recordAudit(pkgName, registry, version, DecisionBlock, threats, scanTimeMs, clientIP)
		p.blocked.Add(1)
		proxyPackagesBlocked.Inc()
		proxyThreatsByType.WithLabelValues("scan_error", "critical").Inc()
		proxyRequestsTotal.WithLabelValues(registry, string(DecisionBlock)).Inc()
		return DecisionBlock, threats, scanTimeMs
	}

	// Convert threats.
	threats := threatsToSummaries(result.Threats)
	decision := p.evaluateThreats(result.Threats, policies)

	// Cache result.
	p.cache.Store(cacheKey, &scanCacheEntry{
		decision: decision,
		threats:  threats,
		expiry:   time.Now().Add(p.cacheTTL),
	})

	// Record per-threat Prometheus counters.
	for _, t := range threats {
		proxyThreatsByType.WithLabelValues(t.Type, t.Severity).Inc()
	}

	// Record.
	p.recordAudit(pkgName, registry, version, decision, threats, scanTimeMs, clientIP)
	switch decision {
	case DecisionBlock:
		p.blocked.Add(1)
		proxyPackagesBlocked.Inc()
	case DecisionWarn:
		p.warned.Add(1)
		proxyPackagesWarned.Inc()
	default:
		p.allowed.Add(1)
	}

	proxyRequestsTotal.WithLabelValues(registry, string(decision)).Inc()
	return decision, threats, scanTimeMs
}

// evaluateThreats determines the proxy decision based on the highest severity
// found in the threat list.
func (p *RegistryProxy) evaluateThreats(threats []types.Threat, policies ProxyPolicies) Decision {
	if len(threats) == 0 {
		return DecisionAllow
	}

	blockLevel := severityLevel(policies.BlockSeverity)
	warnLevel := severityLevel(policies.WarnSeverity)

	highestLevel := -1
	for _, t := range threats {
		lvl := severityLevel(t.Severity.String())
		if lvl > highestLevel {
			highestLevel = lvl
		}
	}

	if highestLevel >= blockLevel {
		return DecisionBlock
	}
	if highestLevel >= warnLevel {
		return DecisionWarn
	}
	return DecisionAllow
}

// severityLevel maps a severity string to a numeric level for comparison.
func severityLevel(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// threatsToSummaries converts full Threat structs to compact ThreatSummary values.
func threatsToSummaries(threats []types.Threat) []ThreatSummary {
	summaries := make([]ThreatSummary, 0, len(threats))
	for _, t := range threats {
		summaries = append(summaries, ThreatSummary{
			Type:        string(t.Type),
			Severity:    t.Severity.String(),
			Description: t.Description,
		})
	}
	return summaries
}

// recordAudit appends an entry to the audit log, evicting the oldest entry
// when the configured maximum is exceeded.
func (p *RegistryProxy) recordAudit(pkg, registry, version string, decision Decision, threats []ThreatSummary, scanTimeMs int64, clientIP string) {
	entry := AuditEntry{
		Timestamp:  time.Now(),
		Package:    pkg,
		Registry:   registry,
		Version:    version,
		Decision:   decision,
		Threats:    threats,
		ScanTimeMs: scanTimeMs,
		ClientIP:   clientIP,
	}

	p.auditLogger.Write(entry)

	p.auditMu.Lock()
	defer p.auditMu.Unlock()
	p.auditLog = append(p.auditLog, entry)
	if len(p.auditLog) > p.config.MaxAuditLog {
		// Drop the oldest 10% to avoid constant trimming.
		trim := p.config.MaxAuditLog / 10
		if trim < 1 {
			trim = 1
		}
		p.auditLog = p.auditLog[trim:]
	}
}

// writeBlockResponse writes a 403 JSON response with threat details.
func writeBlockResponse(w http.ResponseWriter, pkgName string, threats []ThreatSummary) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   "package_blocked",
		"message": fmt.Sprintf("Package %q was blocked by Falcn registry firewall", pkgName),
		"threats": threats,
	})
}

// validatePackageName rejects package names that could be used for path traversal
// or URL injection attacks.
var validNPMPackageName = regexp.MustCompile(`^(@[a-zA-Z0-9][\w.-]*/)?[a-zA-Z0-9][\w.-]*$`)
var validPyPIPackageName = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$`)
var validMavenName = regexp.MustCompile(`^[a-zA-Z0-9][\w.-]*$`)
var validCargoName = regexp.MustCompile(`^[a-zA-Z][\w-]*$`)

func validatePackageName(name, registry string) bool {
	if name == "" || len(name) > 214 {
		return false
	}
	// Reject path traversal
	if strings.Contains(name, "..") || strings.Contains(name, "//") {
		return false
	}
	// Reject null bytes and control characters
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	switch registry {
	case "npm":
		return validNPMPackageName.MatchString(name)
	case "pypi":
		return validPyPIPackageName.MatchString(name)
	case "maven":
		// Maven artifacts: alphanumeric, dots, hyphens, underscores
		return validMavenName.MatchString(name)
	case "cargo":
		return validCargoName.MatchString(name)
	case "go":
		// Go module paths are URLs — allow dots, slashes, hyphens
		return len(name) > 0 && !strings.Contains(name, "..") && !strings.Contains(name, "//")
	default:
		return true
	}
}

// clientIP extracts the client IP from the request, respecting X-Forwarded-For.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	return r.RemoteAddr
}
