package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// registerGoRoutes installs Go module proxy routes following the GOPROXY protocol.
func (p *RegistryProxy) registerGoRoutes(r *mux.Router) {
	r.PathPrefix("/").HandlerFunc(p.handleGoRequest).Methods("GET")
}

func (p *RegistryProxy) handleGoRequest(w http.ResponseWriter, r *http.Request) {
	p.totalRequests.Add(1)
	path := strings.TrimPrefix(r.URL.Path, "/go")
	if path == "" || path == "/" {
		http.Error(w, `{"error":"invalid go module path"}`, http.StatusBadRequest)
		return
	}

	// Extract module path from GOPROXY URL patterns:
	//   /{module}/@v/list
	//   /{module}/@v/{version}.info
	//   /{module}/@v/{version}.mod
	//   /{module}/@v/{version}.zip
	//   /{module}/@latest
	trimmed := strings.TrimPrefix(path, "/")

	// Find @v or @latest marker
	modulePath := trimmed
	atIdx := strings.Index(trimmed, "/@")
	if atIdx > 0 {
		modulePath = trimmed[:atIdx]
	}

	// Decode module path (uppercase letters encoded as !lowercase in GOPROXY)
	modulePath = decodeModulePath(modulePath)

	if modulePath == "" {
		upstreamURL := fmt.Sprintf("%s%s", p.config.GoProxyUpstream, path)
		p.reverseProxy(w, r, upstreamURL)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	decision, threats, _ := p.scanPackage(ctx, "go", modulePath, "", clientIP(r))

	switch decision {
	case DecisionBlock:
		writeBlockResponse(w, modulePath, threats)
		return
	case DecisionWarn:
		w.Header().Set("X-Falcn-Warning", formatWarningHeader(modulePath, threats))
	}

	upstreamURL := fmt.Sprintf("%s%s", p.config.GoProxyUpstream, path)
	p.reverseProxy(w, r, upstreamURL)
}

// decodeModulePath reverses the GOPROXY encoding where uppercase letters
// are represented as !lowercase (e.g., "github.com/!azure" -> "github.com/Azure").
func decodeModulePath(encoded string) string {
	var b strings.Builder
	b.Grow(len(encoded))
	for i := 0; i < len(encoded); i++ {
		if encoded[i] == '!' && i+1 < len(encoded) {
			b.WriteByte(encoded[i+1] - 32) // lowercase to uppercase
			i++
		} else {
			b.WriteByte(encoded[i])
		}
	}
	return b.String()
}
