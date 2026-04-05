package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// registerCargoRoutes installs Cargo/crates.io proxy routes.
func (p *RegistryProxy) registerCargoRoutes(r *mux.Router) {
	// Crate download
	r.HandleFunc("/api/v1/crates/{name}/{version}/download", p.handleCargoDownload).Methods("GET")
	// Crate metadata
	r.HandleFunc("/api/v1/crates/{name}/{version}", p.handleCargoMetadata).Methods("GET")
	r.HandleFunc("/api/v1/crates/{name}", p.handleCargoMetadata).Methods("GET")
}

func (p *RegistryProxy) handleCargoMetadata(w http.ResponseWriter, r *http.Request) {
	p.totalRequests.Add(1)
	vars := mux.Vars(r)
	name := vars["name"]
	version := vars["version"]

	if !validatePackageName(name, "cargo") {
		http.Error(w, `{"error":"invalid crate name"}`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	decision, threats, _ := p.scanPackage(ctx, "cargo", name, version, clientIP(r))

	switch decision {
	case DecisionBlock:
		writeBlockResponse(w, name, threats)
		return
	case DecisionWarn:
		w.Header().Set("X-Falcn-Warning", formatWarningHeader(name, threats))
	}

	upstreamPath := strings.TrimPrefix(r.URL.Path, "/cargo")
	upstreamURL := fmt.Sprintf("%s%s", p.config.CargoUpstream, upstreamPath)
	p.reverseProxy(w, r, upstreamURL)
}

func (p *RegistryProxy) handleCargoDownload(w http.ResponseWriter, r *http.Request) {
	p.totalRequests.Add(1)
	vars := mux.Vars(r)
	name := vars["name"]

	// Verify crate was scanned
	cacheKey := fmt.Sprintf("cargo:%s", name)
	if _, ok := p.cache.Load(cacheKey); !ok {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		decision, threats, _ := p.scanPackage(ctx, "cargo", name, "", clientIP(r))
		if decision == DecisionBlock {
			writeBlockResponse(w, name, threats)
			return
		}
	}

	upstreamPath := strings.TrimPrefix(r.URL.Path, "/cargo")
	upstreamURL := fmt.Sprintf("%s%s", p.config.CargoUpstream, upstreamPath)
	p.reverseProxy(w, r, upstreamURL)
}
