package proxy

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// registerPyPIRoutes installs the PyPI Simple API proxy routes.
// pip clients hit:
//   - GET /pypi/simple/                — index page
//   - GET /pypi/simple/{package}/      — package detail (HTML with download links)
//   - GET /pypi/packages/{path}        — actual wheel/sdist download
func (p *RegistryProxy) registerPyPIRoutes(r *mux.Router) {
	// Package simple index page.
	r.HandleFunc("/simple/{package}/", p.handlePyPISimple).Methods("GET")
	r.HandleFunc("/simple/{package}", p.handlePyPISimple).Methods("GET")
	// Root simple index (list all packages).
	r.HandleFunc("/simple/", p.handlePyPISimpleIndex).Methods("GET")
	r.HandleFunc("/simple", p.handlePyPISimpleIndex).Methods("GET")
	// Package downloads (.whl, .tar.gz, etc.) — proxy transparently.
	r.PathPrefix("/packages/").HandlerFunc(p.handlePyPIDownload).Methods("GET")
}

// handlePyPISimple intercepts the PyPI Simple API package page, scans the
// package, and either proxies the HTML response or blocks with a 403.
func (p *RegistryProxy) handlePyPISimple(w http.ResponseWriter, r *http.Request) {
	p.totalRequests.Add(1)
	vars := mux.Vars(r)
	rawName := vars["package"]
	pkgName := normalizePyPIName(rawName)

	if !validatePackageName(pkgName, "pypi") {
		http.Error(w, `{"error":"invalid package name"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	decision, threats, _ := p.scanPackage(ctx, "pypi", pkgName, "", clientIP(r))

	switch decision {
	case DecisionBlock:
		writeBlockResponse(w, pkgName, threats)
		return
	case DecisionWarn:
		w.Header().Set("X-Falcn-Warning", formatWarningHeader(pkgName, threats))
	}

	// Proxy to upstream PyPI simple page.
	upstreamURL := fmt.Sprintf("%s/simple/%s/", p.config.PyPIUpstream, rawName)
	p.reverseProxy(w, r, upstreamURL)
}

// handlePyPISimpleIndex proxies the root /simple/ index transparently.
func (p *RegistryProxy) handlePyPISimpleIndex(w http.ResponseWriter, r *http.Request) {
	p.totalRequests.Add(1)
	upstreamURL := fmt.Sprintf("%s/simple/", p.config.PyPIUpstream)
	p.reverseProxy(w, r, upstreamURL)
}

// handlePyPIDownload proxies actual package file downloads (.whl, .tar.gz)
// transparently. The package was already scanned at the simple index stage.
func (p *RegistryProxy) handlePyPIDownload(w http.ResponseWriter, r *http.Request) {
	p.totalRequests.Add(1)
	path := strings.TrimPrefix(r.URL.Path, "/pypi")

	// Extract package name from download path for scan gating.
	// Typical path: /packages/source/r/requests/requests-2.31.0.tar.gz
	pkgName := extractPyPIPackageName(path)
	if pkgName != "" {
		cacheKey := fmt.Sprintf("pypi:%s", normalizePyPIName(pkgName))
		if _, ok := p.cache.Load(cacheKey); !ok {
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			decision, threats, _ := p.scanPackage(ctx, "pypi", normalizePyPIName(pkgName), "", clientIP(r))
			if decision == DecisionBlock {
				writeBlockResponse(w, pkgName, threats)
				return
			}
		}
	}

	upstreamURL := fmt.Sprintf("%s%s", p.config.PyPIUpstream, path)
	p.reverseProxy(w, r, upstreamURL)
}

// extractPyPIPackageName attempts to extract the package name from a PyPI
// download path like /packages/source/r/requests/requests-2.31.0.tar.gz.
func extractPyPIPackageName(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	// Expected: packages/source/<initial>/<name>/<filename>
	if len(parts) >= 4 && parts[0] == "packages" {
		return parts[3]
	}
	return ""
}

// pypiNormalizeRe matches runs of [-_.]+, which PEP 503 says should all be
// treated as equivalent and replaced with a single dash.
var pypiNormalizeRe = regexp.MustCompile(`[-_.]+`)

// normalizePyPIName applies PEP 503 normalization: lowercase and collapse
// any run of hyphens, underscores, and periods into a single hyphen.
func normalizePyPIName(name string) string {
	return pypiNormalizeRe.ReplaceAllString(strings.ToLower(name), "-")
}
