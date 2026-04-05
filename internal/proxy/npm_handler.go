package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// registerNPMRoutes installs the npm registry proxy routes on the given router.
// npm clients hit:
//   - GET /{package}           — package metadata (JSON)
//   - GET /{@scope}/{name}     — scoped package metadata
//   - GET /{package}/-/{file}  — tarball download
//   - GET /{@scope}/{name}/-/{file} — scoped tarball download
func (p *RegistryProxy) registerNPMRoutes(r *mux.Router) {
	// Scoped package tarball: /npm/@scope/name/-/tarball.tgz
	r.HandleFunc("/{scope:@[^/]+}/{name}/-/{tarball}", p.handleNPMTarball).Methods("GET")
	// Unscoped tarball: /npm/name/-/tarball.tgz
	r.HandleFunc("/{name}/-/{tarball}", p.handleNPMTarball).Methods("GET")
	// Scoped package metadata: /npm/@scope/name or /npm/@scope/name/version
	r.HandleFunc("/{scope:@[^/]+}/{name}/{version}", p.handleNPMMetadata).Methods("GET")
	r.HandleFunc("/{scope:@[^/]+}/{name}", p.handleNPMMetadata).Methods("GET")
	// Unscoped package metadata: /npm/name or /npm/name/version
	r.HandleFunc("/{name}/{version}", p.handleNPMMetadata).Methods("GET")
	r.HandleFunc("/{name}", p.handleNPMMetadata).Methods("GET")
}

// handleNPMMetadata intercepts npm metadata requests, scans the package,
// and either proxies the response or blocks with a 403.
func (p *RegistryProxy) handleNPMMetadata(w http.ResponseWriter, r *http.Request) {
	p.totalRequests.Add(1)
	vars := mux.Vars(r)
	pkgName := npmPackageName(vars)
	version := vars["version"]

	if !validatePackageName(pkgName, "npm") {
		http.Error(w, `{"error":"invalid package name"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	decision, threats, _ := p.scanPackage(ctx, "npm", pkgName, version, clientIP(r))

	switch decision {
	case DecisionBlock:
		writeBlockResponse(w, pkgName, threats)
		return
	case DecisionWarn:
		w.Header().Set("X-Falcn-Warning", formatWarningHeader(pkgName, threats))
	}

	// Proxy the request to the upstream registry.
	p.proxyNPM(w, r, pkgName, version)
}

// handleNPMTarball proxies tarball downloads transparently. The package was
// already scanned when its metadata was fetched.
func (p *RegistryProxy) handleNPMTarball(w http.ResponseWriter, r *http.Request) {
	p.totalRequests.Add(1)
	vars := mux.Vars(r)
	tarball := vars["tarball"]
	pkgName := npmPackageName(vars)

	// Verify this package was scanned (via metadata request).
	// If not in cache, scan it now before allowing download.
	cacheKey := fmt.Sprintf("npm:%s", pkgName)
	if _, ok := p.cache.Load(cacheKey); !ok {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		decision, threats, _ := p.scanPackage(ctx, "npm", pkgName, "", clientIP(r))
		if decision == DecisionBlock {
			writeBlockResponse(w, pkgName, threats)
			return
		}
	}

	upstreamURL := fmt.Sprintf("%s/%s/-/%s", p.config.NPMUpstream, pkgName, tarball)
	p.reverseProxy(w, r, upstreamURL)
}

// proxyNPM forwards an npm metadata request to the upstream registry and
// copies the response back to the client, preserving headers.
func (p *RegistryProxy) proxyNPM(w http.ResponseWriter, r *http.Request, pkgName, version string) {
	upstreamURL := fmt.Sprintf("%s/%s", p.config.NPMUpstream, pkgName)
	if version != "" {
		upstreamURL = fmt.Sprintf("%s/%s/%s", p.config.NPMUpstream, pkgName, version)
	}

	p.reverseProxy(w, r, upstreamURL)
}

// npmPackageName extracts the full package name (including scope) from mux vars.
func npmPackageName(vars map[string]string) string {
	scope := vars["scope"]
	name := vars["name"]
	if scope != "" {
		return scope + "/" + name
	}
	return name
}

// reverseProxy fetches the upstream URL and streams the response back, preserving
// relevant headers (etag, cache-control, content-type, etc.).
func (p *RegistryProxy) reverseProxy(w http.ResponseWriter, r *http.Request, upstreamURL string) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstreamURL, nil)
	if err != nil {
		logrus.WithError(err).WithField("upstream", upstreamURL).Error("failed to create upstream request")
		http.Error(w, `{"error":"internal proxy error"}`, http.StatusBadGateway)
		return
	}

	// Forward relevant headers from the original request.
	forwardHeaders := []string{"Accept", "Accept-Encoding", "If-None-Match", "Authorization"}
	for _, h := range forwardHeaders {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	req.Header.Set("User-Agent", "falcn-proxy/1.0")

	upstreamStart := time.Now()
	resp, err := p.httpClient.Do(req)
	if err != nil {
		logrus.WithError(err).WithField("upstream", upstreamURL).Error("upstream request failed")
		http.Error(w, `{"error":"upstream registry unavailable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Track upstream latency by registry.
	reg := "unknown"
	if strings.Contains(upstreamURL, "npmjs") {
		reg = "npm"
	} else if strings.Contains(upstreamURL, "pypi") {
		reg = "pypi"
	}
	proxyUpstreamLatency.WithLabelValues(reg).Observe(time.Since(upstreamStart).Seconds())

	// Copy upstream response headers to the client.
	preserveHeaders := []string{
		"Content-Type", "Content-Length", "ETag", "Cache-Control",
		"Last-Modified", "Content-Encoding", "X-Served-By",
	}
	for _, h := range preserveHeaders {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.Header().Set("X-Falcn-Proxy", "true")

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// formatWarningHeader builds a concise warning header value from threat summaries.
func formatWarningHeader(pkgName string, threats []ThreatSummary) string {
	if len(threats) == 0 {
		return fmt.Sprintf("Falcn: potential risks detected for %s", pkgName)
	}
	parts := make([]string, 0, len(threats))
	for _, t := range threats {
		parts = append(parts, fmt.Sprintf("%s(%s)", t.Type, t.Severity))
	}
	return fmt.Sprintf("Falcn: %s — %s", pkgName, strings.Join(parts, ", "))
}
