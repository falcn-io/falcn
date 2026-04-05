package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// registerMavenRoutes installs Maven Central proxy routes.
// Maven clients use paths like: /maven/com/google/guava/guava/31.1-jre/guava-31.1-jre.jar
func (p *RegistryProxy) registerMavenRoutes(r *mux.Router) {
	// Catch-all for Maven paths
	r.PathPrefix("/").HandlerFunc(p.handleMavenRequest).Methods("GET")
}

func (p *RegistryProxy) handleMavenRequest(w http.ResponseWriter, r *http.Request) {
	p.totalRequests.Add(1)
	path := strings.TrimPrefix(r.URL.Path, "/maven")
	if path == "" || path == "/" {
		http.Error(w, `{"error":"invalid maven path"}`, http.StatusBadRequest)
		return
	}

	// Extract group:artifact from Maven path
	// Maven paths: /com/google/guava/guava/31.1-jre/guava-31.1-jre.jar
	// or metadata: /com/google/guava/guava/maven-metadata.xml
	parts := strings.Split(strings.Trim(path, "/"), "/")

	// Need at least group + artifact (2 parts minimum)
	if len(parts) < 2 {
		upstreamURL := fmt.Sprintf("%s%s", p.config.MavenUpstream, path)
		p.reverseProxy(w, r, upstreamURL)
		return
	}

	// Reconstruct group:artifact
	// The artifact name appears before the version directory
	// Heuristic: version directories typically start with a digit
	artifactIdx := -1
	for i := len(parts) - 1; i >= 1; i-- {
		if len(parts[i]) > 0 && parts[i][0] >= '0' && parts[i][0] <= '9' {
			artifactIdx = i - 1
			break
		}
		if strings.HasSuffix(parts[i], ".xml") || strings.HasSuffix(parts[i], ".jar") || strings.HasSuffix(parts[i], ".pom") {
			continue
		}
	}

	if artifactIdx < 1 {
		// Can't determine artifact — proxy transparently
		upstreamURL := fmt.Sprintf("%s%s", p.config.MavenUpstream, path)
		p.reverseProxy(w, r, upstreamURL)
		return
	}

	groupID := strings.Join(parts[:artifactIdx], ".")
	artifactID := parts[artifactIdx]
	pkgName := groupID + ":" + artifactID

	if !validatePackageName(artifactID, "maven") {
		http.Error(w, `{"error":"invalid artifact name"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	decision, threats, _ := p.scanPackage(ctx, "maven", pkgName, "", clientIP(r))

	switch decision {
	case DecisionBlock:
		writeBlockResponse(w, pkgName, threats)
		return
	case DecisionWarn:
		w.Header().Set("X-Falcn-Warning", formatWarningHeader(pkgName, threats))
	}

	upstreamURL := fmt.Sprintf("%s%s", p.config.MavenUpstream, path)
	p.reverseProxy(w, r, upstreamURL)
}
