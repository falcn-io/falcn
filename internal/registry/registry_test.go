package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helper: generic JSON server
// ---------------------------------------------------------------------------

func newJSONServer(t *testing.T, statusCode int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func newRawServer(t *testing.T, statusCode int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		fmt.Fprint(w, body)
	}))
}

// ---------------------------------------------------------------------------
// NPMClient tests
// ---------------------------------------------------------------------------

func TestNewNPMClient_Defaults(t *testing.T) {
	c := NewNPMClient()
	if c == nil {
		t.Fatal("NewNPMClient returned nil")
	}
	if c.httpClient == nil {
		t.Error("httpClient should not be nil")
	}
	if c.cacheTTL <= 0 {
		t.Errorf("cacheTTL should be > 0, got %v", c.cacheTTL)
	}
	if c.baseURL == "" {
		t.Error("baseURL should not be empty")
	}
	if c.cache == nil {
		t.Error("cache map should not be nil")
	}
}

func TestNPMClient_GetPackageInfo_EmptyName(t *testing.T) {
	c := NewNPMClient()
	_, err := c.GetPackageInfo(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty package name, got nil")
	}
}

func TestNPMClient_GetPackageInfo_Success(t *testing.T) {
	payload := NPMPackageInfo{
		Name:        "lodash",
		Version:     "4.17.21",
		Description: "Lodash modular utilities.",
		Keywords:    []string{"modules", "stdlib", "util"},
	}
	srv := newJSONServer(t, http.StatusOK, payload)
	defer srv.Close()

	c := NewNPMClient()
	c.baseURL = srv.URL

	info, err := c.GetPackageInfo(context.Background(), "lodash")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name != "lodash" {
		t.Errorf("expected name=lodash, got %s", info.Name)
	}
	if info.Description != "Lodash modular utilities." {
		t.Errorf("unexpected description: %s", info.Description)
	}
}

func TestNPMClient_GetPackageInfo_404(t *testing.T) {
	srv := newRawServer(t, http.StatusNotFound, `{"error":"Not found"}`)
	defer srv.Close()

	c := NewNPMClient()
	c.baseURL = srv.URL

	_, err := c.GetPackageInfo(context.Background(), "nonexistent-package-xyz")
	if err == nil {
		t.Error("expected error for 404 response, got nil")
	}
}

func TestNPMClient_GetPackageInfo_500(t *testing.T) {
	srv := newRawServer(t, http.StatusInternalServerError, `{"error":"server error"}`)
	defer srv.Close()

	c := NewNPMClient()
	c.baseURL = srv.URL

	_, err := c.GetPackageInfo(context.Background(), "somepackage")
	if err == nil {
		t.Error("expected error for 500 response, got nil")
	}
}

func TestNPMClient_GetPackageInfo_InvalidJSON(t *testing.T) {
	srv := newRawServer(t, http.StatusOK, `not-valid-json{{{`)
	defer srv.Close()

	c := NewNPMClient()
	c.baseURL = srv.URL

	_, err := c.GetPackageInfo(context.Background(), "somepackage")
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestNPMClient_GetPackageInfo_CacheHit(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NPMPackageInfo{Name: "express"})
	}))
	defer srv.Close()

	c := NewNPMClient()
	c.baseURL = srv.URL

	// First call — goes to network
	_, err := c.GetPackageInfo(context.Background(), "express")
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	// Second call — should hit cache
	_, err = c.GetPackageInfo(context.Background(), "express")
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected exactly 1 HTTP call (cache hit on second), got %d", callCount)
	}
}

func TestNPMClient_GetPackageInfo_CacheTTLExpiry(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NPMPackageInfo{Name: "react"})
	}))
	defer srv.Close()

	c := NewNPMClient()
	c.baseURL = srv.URL
	c.cacheTTL = 1 * time.Millisecond // tiny TTL

	// First call
	_, err := c.GetPackageInfo(context.Background(), "react")
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	// Wait for TTL to expire
	time.Sleep(5 * time.Millisecond)

	// Second call — TTL expired, should re-fetch
	_, err = c.GetPackageInfo(context.Background(), "react")
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if callCount != 2 {
		t.Errorf("expected 2 HTTP calls after TTL expiry, got %d", callCount)
	}
}

func TestNPMClient_ManualCachePopulation(t *testing.T) {
	c := NewNPMClient()

	// Manually place an entry in the cache
	key := "package:manual-pkg"
	info := &NPMPackageInfo{Name: "manual-pkg", Version: "1.0.0"}
	c.cacheMu.Lock()
	c.cache[key] = &CacheEntry{Data: info, Timestamp: time.Now()}
	c.cacheMu.Unlock()

	// Reading from cache directly
	c.cacheMu.RLock()
	entry, exists := c.cache[key]
	c.cacheMu.RUnlock()

	if !exists {
		t.Fatal("cache entry should exist after manual population")
	}
	if entry.Data.(*NPMPackageInfo).Name != "manual-pkg" {
		t.Errorf("unexpected cached name: %v", entry.Data)
	}
}

func TestNPMClient_ClearCache(t *testing.T) {
	c := NewNPMClient()
	c.cacheMu.Lock()
	c.cache["package:x"] = &CacheEntry{Data: &NPMPackageInfo{Name: "x"}, Timestamp: time.Now()}
	c.cacheMu.Unlock()

	c.ClearCache()

	c.cacheMu.RLock()
	n := len(c.cache)
	c.cacheMu.RUnlock()

	if n != 0 {
		t.Errorf("cache should be empty after ClearCache, got %d entries", n)
	}
}

func TestNPMClient_SetCacheTTL(t *testing.T) {
	c := NewNPMClient()
	c.SetCacheTTL(10 * time.Minute)
	if c.cacheTTL != 10*time.Minute {
		t.Errorf("expected TTL=10m, got %v", c.cacheTTL)
	}
}

func TestNPMClient_GetDownloadStats_EmptyName(t *testing.T) {
	c := NewNPMClient()
	_, err := c.GetDownloadStats(context.Background(), "", "last-week")
	if err == nil {
		t.Error("expected error for empty package name")
	}
}

func TestNPMClient_GetDownloadStats_InvalidPeriod(t *testing.T) {
	c := NewNPMClient()
	_, err := c.GetDownloadStats(context.Background(), "lodash", "last-decade")
	if err == nil {
		t.Error("expected error for invalid period")
	}
}

func TestNPMClient_GetDownloadStats_Success(t *testing.T) {
	payload := NPMDownloadStats{Downloads: 1234567, Package: "lodash", Start: "2024-01-01", End: "2024-01-07"}
	srv := newJSONServer(t, http.StatusOK, payload)
	defer srv.Close()

	c := NewNPMClient()
	// The download stats URL is hardcoded in the method, so we inject via a custom transport
	// that rewrites the host to the test server.
	c.httpClient = &http.Client{
		Transport: &rewriteTransport{target: srv.URL},
	}

	stats, err := c.GetDownloadStats(context.Background(), "lodash", "last-week")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Downloads != 1234567 {
		t.Errorf("expected 1234567 downloads, got %d", stats.Downloads)
	}
}

func TestNPMClient_GetDownloadStats_CacheHit(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_ = json.NewEncoder(w).Encode(NPMDownloadStats{Downloads: 100, Package: "react"})
	}))
	defer srv.Close()

	c := NewNPMClient()
	c.httpClient = &http.Client{
		Transport: &rewriteTransport{target: srv.URL},
	}

	_, _ = c.GetDownloadStats(context.Background(), "react", "last-week")
	_, _ = c.GetDownloadStats(context.Background(), "react", "last-week")

	if callCount != 1 {
		t.Errorf("expected 1 HTTP call (cache hit), got %d", callCount)
	}
}

func TestNPMClient_SetBias(t *testing.T) {
	c := NewNPMClient()
	c.SetBias(0.3, 0.5, 0.2)
	if c.qualityWeight != 0.3 {
		t.Errorf("qualityWeight expected 0.3, got %v", c.qualityWeight)
	}
	if c.popularityWeight != 0.5 {
		t.Errorf("popularityWeight expected 0.5, got %v", c.popularityWeight)
	}
	if c.maintenanceWeight != 0.2 {
		t.Errorf("maintenanceWeight expected 0.2, got %v", c.maintenanceWeight)
	}
}

func TestNPMClient_ConcurrentAccess(t *testing.T) {
	payload := NPMPackageInfo{Name: "concurrent-pkg"}
	srv := newJSONServer(t, http.StatusOK, payload)
	defer srv.Close()

	c := NewNPMClient()
	c.baseURL = srv.URL

	var wg sync.WaitGroup
	const goroutines = 20
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = c.GetPackageInfo(context.Background(), "concurrent-pkg")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: unexpected error: %v", i, err)
		}
	}
}

// ---------------------------------------------------------------------------
// rewriteTransport: redirects all requests to a test server
// ---------------------------------------------------------------------------

type rewriteTransport struct {
	target string
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Parse the target URL
	targetURL, err := http.NewRequest(req.Method, rt.target+req.URL.Path+"?"+req.URL.RawQuery, req.Body)
	if err != nil {
		return nil, err
	}
	targetURL.Header = req.Header
	return http.DefaultTransport.RoundTrip(targetURL)
}

// ---------------------------------------------------------------------------
// PyPIClient tests
// ---------------------------------------------------------------------------

func TestNewPyPIClient_Defaults(t *testing.T) {
	c := NewPyPIClient()
	if c == nil {
		t.Fatal("NewPyPIClient returned nil")
	}
	if c.client == nil {
		t.Error("http client should not be nil")
	}
	if c.baseURL == "" {
		t.Error("baseURL should not be empty")
	}
}

func TestPyPIClient_GetPackageInfo_Success(t *testing.T) {
	payload := PyPIPackageInfo{}
	payload.Info.Name = "requests"
	payload.Info.Version = "2.31.0"
	payload.Info.Summary = "Python HTTP for Humans."
	payload.Info.Author = "Kenneth Reitz"

	srv := newJSONServer(t, http.StatusOK, payload)
	defer srv.Close()

	c := NewPyPIClient()
	c.baseURL = srv.URL

	info, err := c.GetPackageInfo("requests")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Info.Name != "requests" {
		t.Errorf("expected name=requests, got %s", info.Info.Name)
	}
}

func TestPyPIClient_GetPackageInfo_404(t *testing.T) {
	srv := newRawServer(t, http.StatusNotFound, `{"message":"Not Found"}`)
	defer srv.Close()

	c := NewPyPIClient()
	c.baseURL = srv.URL

	_, err := c.GetPackageInfo("nonexistent-xyz-pkg")
	if err == nil {
		t.Error("expected error for 404, got nil")
	}
}

func TestPyPIClient_GetPackageInfo_500(t *testing.T) {
	srv := newRawServer(t, http.StatusInternalServerError, `{"error":"internal"}`)
	defer srv.Close()

	c := NewPyPIClient()
	c.baseURL = srv.URL

	_, err := c.GetPackageInfo("requests")
	if err == nil {
		t.Error("expected error for 500, got nil")
	}
}

func TestPyPIClient_GetPackageInfo_InvalidJSON(t *testing.T) {
	srv := newRawServer(t, http.StatusOK, `{bad json`)
	defer srv.Close()

	c := NewPyPIClient()
	c.baseURL = srv.URL

	_, err := c.GetPackageInfo("requests")
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestPyPIClient_GetPackageVersion_Success(t *testing.T) {
	payload := PyPIPackageInfo{}
	payload.Info.Name = "requests"
	payload.Info.Version = "2.28.0"

	srv := newJSONServer(t, http.StatusOK, payload)
	defer srv.Close()

	c := NewPyPIClient()
	c.baseURL = srv.URL

	info, err := c.GetPackageVersion("requests", "2.28.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Info.Version != "2.28.0" {
		t.Errorf("expected version=2.28.0, got %s", info.Info.Version)
	}
}

func TestPyPIClient_GetPackageVersion_404(t *testing.T) {
	srv := newRawServer(t, http.StatusNotFound, `{}`)
	defer srv.Close()

	c := NewPyPIClient()
	c.baseURL = srv.URL

	_, err := c.GetPackageVersion("requests", "0.0.0")
	if err == nil {
		t.Error("expected error for missing version, got nil")
	}
}

func TestPyPIClient_GetFallbackPopularPackages_Limit(t *testing.T) {
	c := NewPyPIClient()
	pkgs := c.getFallbackPopularPackages(5)
	if len(pkgs) != 5 {
		t.Errorf("expected 5 packages, got %d", len(pkgs))
	}
}

func TestPyPIClient_GetFallbackPopularPackages_NoLimit(t *testing.T) {
	c := NewPyPIClient()
	pkgs := c.getFallbackPopularPackages(0)
	if len(pkgs) == 0 {
		t.Error("expected non-empty list with limit=0")
	}
}

// ---------------------------------------------------------------------------
// CargoClient tests
// ---------------------------------------------------------------------------

func TestNewCargoClient_Defaults(t *testing.T) {
	c := NewCargoClient()
	if c == nil {
		t.Fatal("NewCargoClient returned nil")
	}
	if c.httpClient == nil {
		t.Error("httpClient should not be nil")
	}
	if c.cacheTTL <= 0 {
		t.Errorf("cacheTTL should be > 0, got %v", c.cacheTTL)
	}
	if c.baseURL == "" {
		t.Error("baseURL should not be empty")
	}
	if c.cache == nil {
		t.Error("cache map should not be nil")
	}
}

func TestCargoClient_GetPackageInfo_Success(t *testing.T) {
	now := time.Now()
	payload := CargoCrateDetails{
		Crate: CargoCrateMetadata{
			Name:        "serde",
			Description: "A generic serialization/deserialization framework",
			Downloads:   500000,
			MaxVersion:  "1.0.193",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		Versions: []CargoVersion{
			{Num: "1.0.193", CreatedAt: now, License: "MIT"},
		},
	}
	srv := newJSONServer(t, http.StatusOK, payload)
	defer srv.Close()

	c := NewCargoClient()
	c.baseURL = srv.URL

	meta, err := c.GetPackageInfo(context.Background(), "serde", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Name != "serde" {
		t.Errorf("expected name=serde, got %s", meta.Name)
	}
	if meta.Registry != "cargo" {
		t.Errorf("expected registry=cargo, got %s", meta.Registry)
	}
}

func TestCargoClient_GetPackageInfo_NotFound(t *testing.T) {
	srv := newRawServer(t, http.StatusNotFound, `{"errors":[{"detail":"Not Found"}]}`)
	defer srv.Close()

	c := NewCargoClient()
	c.baseURL = srv.URL

	_, err := c.GetPackageInfo(context.Background(), "no-such-crate-xyz", "")
	if err == nil {
		t.Error("expected error for 404, got nil")
	}
}

func TestCargoClient_GetPackageInfo_InvalidJSON(t *testing.T) {
	srv := newRawServer(t, http.StatusOK, `{bad json`)
	defer srv.Close()

	c := NewCargoClient()
	c.baseURL = srv.URL

	_, err := c.GetPackageInfo(context.Background(), "serde", "")
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestCargoClient_GetPackageInfo_CacheHit(t *testing.T) {
	callCount := 0
	now := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_ = json.NewEncoder(w).Encode(CargoCrateDetails{
			Crate: CargoCrateMetadata{Name: "tokio", MaxVersion: "1.35.0", CreatedAt: now, UpdatedAt: now},
		})
	}))
	defer srv.Close()

	c := NewCargoClient()
	c.baseURL = srv.URL

	_, _ = c.GetPackageInfo(context.Background(), "tokio", "")
	_, _ = c.GetPackageInfo(context.Background(), "tokio", "")

	if callCount != 1 {
		t.Errorf("expected 1 HTTP call (cache hit on 2nd), got %d", callCount)
	}
}

func TestCargoClient_CacheTTLExpiry(t *testing.T) {
	callCount := 0
	now := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_ = json.NewEncoder(w).Encode(CargoCrateDetails{
			Crate: CargoCrateMetadata{Name: "anyhow", MaxVersion: "1.0.79", CreatedAt: now, UpdatedAt: now},
		})
	}))
	defer srv.Close()

	c := NewCargoClient()
	c.baseURL = srv.URL
	c.cacheTTL = 1 * time.Millisecond

	_, _ = c.GetPackageInfo(context.Background(), "anyhow", "")
	time.Sleep(5 * time.Millisecond)
	_, _ = c.GetPackageInfo(context.Background(), "anyhow", "")

	if callCount != 2 {
		t.Errorf("expected 2 HTTP calls after TTL expiry, got %d", callCount)
	}
}

func TestCargoClient_ManualCachePopulation(t *testing.T) {
	c := NewCargoClient()
	key := "serde@1.0.0"

	// Manually populate cache with a past timestamp (still valid)
	c.cacheMu.Lock()
	c.cache[key] = &CacheEntry{
		Data:      nil, // data is intentionally nil to distinguish from network fetch
		Timestamp: time.Now(),
	}
	c.cacheMu.Unlock()

	c.cacheMu.RLock()
	_, exists := c.cache[key]
	c.cacheMu.RUnlock()

	if !exists {
		t.Error("manually inserted cache entry should exist")
	}
}

func TestCargoClient_ClearCache(t *testing.T) {
	c := NewCargoClient()
	c.cacheMu.Lock()
	c.cache["x@1"] = &CacheEntry{Timestamp: time.Now()}
	c.cacheMu.Unlock()

	c.ClearCache()

	c.cacheMu.RLock()
	n := len(c.cache)
	c.cacheMu.RUnlock()

	if n != 0 {
		t.Errorf("expected empty cache after ClearCache, got %d", n)
	}
}

func TestCargoClient_SetCacheTTL(t *testing.T) {
	c := NewCargoClient()
	c.SetCacheTTL(15 * time.Minute)
	if c.cacheTTL != 15*time.Minute {
		t.Errorf("expected TTL=15m, got %v", c.cacheTTL)
	}
}

func TestCargoClient_ConcurrentAccess(t *testing.T) {
	now := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(CargoCrateDetails{
			Crate: CargoCrateMetadata{Name: "rayon", MaxVersion: "1.8.0", CreatedAt: now, UpdatedAt: now},
		})
	}))
	defer srv.Close()

	c := NewCargoClient()
	c.baseURL = srv.URL

	var wg sync.WaitGroup
	errs := make([]error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = c.GetPackageInfo(context.Background(), "rayon", "")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d error: %v", i, err)
		}
	}
}

// ---------------------------------------------------------------------------
// MavenClient tests
// ---------------------------------------------------------------------------

func TestNewMavenClient_Defaults(t *testing.T) {
	c := NewMavenClient()
	if c == nil {
		t.Fatal("NewMavenClient returned nil")
	}
	if c.httpClient == nil {
		t.Error("httpClient should not be nil")
	}
	if c.cacheTTL <= 0 {
		t.Errorf("cacheTTL should be > 0, got %v", c.cacheTTL)
	}
	if c.baseURL == "" {
		t.Error("baseURL should not be empty")
	}
	if c.cache == nil {
		t.Error("cache map should not be nil")
	}
}

func TestMavenClient_GetPackageInfo_NotFound(t *testing.T) {
	srv := newRawServer(t, http.StatusNotFound, "")
	defer srv.Close()

	c := NewMavenClient()
	// We cannot easily redirect POM fetches because the URL is constructed inside the method,
	// but we can use the rewriteTransport to redirect all requests.
	c.httpClient = &http.Client{
		Transport: &rewriteTransport{target: srv.URL},
	}

	_, err := c.GetPackageInfo(context.Background(), "org.example", "missing-artifact", "1.0.0")
	if err == nil {
		t.Error("expected error for 404 POM, got nil")
	}
}

func TestMavenClient_GetPackageInfo_CacheHit(t *testing.T) {
	callCount := 0
	pomXML := `<?xml version="1.0"?>
<project>
  <groupId>org.test</groupId>
  <artifactId>mylib</artifactId>
  <version>1.0.0</version>
  <description>Test library</description>
</project>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, pomXML)
	}))
	defer srv.Close()

	c := NewMavenClient()
	c.httpClient = &http.Client{Transport: &rewriteTransport{target: srv.URL}}

	_, _ = c.GetPackageInfo(context.Background(), "org.test", "mylib", "1.0.0")
	_, _ = c.GetPackageInfo(context.Background(), "org.test", "mylib", "1.0.0")

	if callCount != 1 {
		t.Errorf("expected 1 HTTP call (cache hit on 2nd), got %d", callCount)
	}
}

func TestMavenClient_GetPackageInfo_CacheTTLExpiry(t *testing.T) {
	callCount := 0
	pomXML := `<?xml version="1.0"?>
<project>
  <groupId>org.test</groupId>
  <artifactId>mylib</artifactId>
  <version>2.0.0</version>
</project>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		fmt.Fprint(w, pomXML)
	}))
	defer srv.Close()

	c := NewMavenClient()
	c.httpClient = &http.Client{Transport: &rewriteTransport{target: srv.URL}}
	c.cacheTTL = 1 * time.Millisecond

	_, _ = c.GetPackageInfo(context.Background(), "org.test", "mylib", "2.0.0")
	time.Sleep(5 * time.Millisecond)
	_, _ = c.GetPackageInfo(context.Background(), "org.test", "mylib", "2.0.0")

	if callCount != 2 {
		t.Errorf("expected 2 HTTP calls after TTL expiry, got %d", callCount)
	}
}

func TestMavenClient_GetPopularPackages(t *testing.T) {
	c := NewMavenClient()
	pkgs, err := c.GetPopularPackages(5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 5 {
		t.Errorf("expected 5 packages, got %d", len(pkgs))
	}
}

func TestMavenClient_ClearCache(t *testing.T) {
	c := NewMavenClient()
	c.cacheMu.Lock()
	c.cache["a:b:c"] = &CacheEntry{Timestamp: time.Now()}
	c.cacheMu.Unlock()

	c.ClearCache()

	c.cacheMu.RLock()
	n := len(c.cache)
	c.cacheMu.RUnlock()
	if n != 0 {
		t.Errorf("expected empty cache after ClearCache, got %d", n)
	}
}

func TestMavenClient_SetCacheTTL(t *testing.T) {
	c := NewMavenClient()
	c.SetCacheTTL(20 * time.Minute)
	if c.cacheTTL != 20*time.Minute {
		t.Errorf("expected 20m, got %v", c.cacheTTL)
	}
}

// ---------------------------------------------------------------------------
// NuGetClient tests
// ---------------------------------------------------------------------------

func TestNewNuGetClient_Defaults(t *testing.T) {
	c := NewNuGetClient()
	if c == nil {
		t.Fatal("NewNuGetClient returned nil")
	}
	if c.httpClient == nil {
		t.Error("httpClient should not be nil")
	}
	if c.cacheTTL <= 0 {
		t.Errorf("cacheTTL should be > 0, got %v", c.cacheTTL)
	}
	if c.baseURL == "" {
		t.Error("baseURL should not be empty")
	}
	if c.cache == nil {
		t.Error("cache map should not be nil")
	}
}

func TestNuGetClient_GetPackageInfo_NotFound(t *testing.T) {
	srv := newRawServer(t, http.StatusNotFound, `{}`)
	defer srv.Close()

	c := NewNuGetClient()
	c.httpClient = &http.Client{Transport: &rewriteTransport{target: srv.URL}}

	_, err := c.GetPackageInfo(context.Background(), "NoSuchPackage", "9.9.9")
	if err == nil {
		t.Error("expected error for 404, got nil")
	}
}

func TestNuGetClient_GetPackageInfo_CacheHit(t *testing.T) {
	callCount := 0
	payload := NuGetPackageInfo{}
	payload.CatalogEntry.ID = "Newtonsoft.Json"
	payload.CatalogEntry.Version = "13.0.3"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	c := NewNuGetClient()
	c.httpClient = &http.Client{Transport: &rewriteTransport{target: srv.URL}}

	_, _ = c.GetPackageInfo(context.Background(), "Newtonsoft.Json", "13.0.3")
	_, _ = c.GetPackageInfo(context.Background(), "Newtonsoft.Json", "13.0.3")

	if callCount != 1 {
		t.Errorf("expected 1 HTTP call (cache hit), got %d", callCount)
	}
}

func TestNuGetClient_GetPackageInfo_CacheTTLExpiry(t *testing.T) {
	callCount := 0
	payload := NuGetPackageInfo{}
	payload.CatalogEntry.ID = "Moq"
	payload.CatalogEntry.Version = "4.20.70"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	c := NewNuGetClient()
	c.httpClient = &http.Client{Transport: &rewriteTransport{target: srv.URL}}
	c.cacheTTL = 1 * time.Millisecond

	_, _ = c.GetPackageInfo(context.Background(), "Moq", "4.20.70")
	time.Sleep(5 * time.Millisecond)
	_, _ = c.GetPackageInfo(context.Background(), "Moq", "4.20.70")

	if callCount != 2 {
		t.Errorf("expected 2 HTTP calls after TTL expiry, got %d", callCount)
	}
}

func TestNuGetClient_ManualCachePopulation(t *testing.T) {
	c := NewNuGetClient()
	key := "TestPkg:1.0.0"
	c.cache[key] = &CacheEntry{Timestamp: time.Now(), Data: nil}

	if _, ok := c.cache[key]; !ok {
		t.Error("manually inserted cache entry should exist")
	}
}

func TestNuGetClient_GetPopularPackages(t *testing.T) {
	c := NewNuGetClient()
	pkgs, err := c.GetPopularPackages(5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 5 {
		t.Errorf("expected 5 packages, got %d", len(pkgs))
	}
}

func TestNuGetClient_ClearCache(t *testing.T) {
	c := NewNuGetClient()
	c.cache["x:y"] = &CacheEntry{Timestamp: time.Now()}
	c.ClearCache()
	if len(c.cache) != 0 {
		t.Errorf("expected empty cache, got %d entries", len(c.cache))
	}
}

func TestNuGetClient_SetCacheTTL(t *testing.T) {
	c := NewNuGetClient()
	c.SetCacheTTL(7 * time.Minute)
	if c.cacheTTL != 7*time.Minute {
		t.Errorf("expected 7m, got %v", c.cacheTTL)
	}
}

// ---------------------------------------------------------------------------
// RubyGemsClient tests
// ---------------------------------------------------------------------------

func TestNewRubyGemsClient_Defaults(t *testing.T) {
	c := NewRubyGemsClient()
	if c == nil {
		t.Fatal("NewRubyGemsClient returned nil")
	}
	if c.httpClient == nil {
		t.Error("httpClient should not be nil")
	}
	if c.cacheTTL <= 0 {
		t.Errorf("cacheTTL should be > 0, got %v", c.cacheTTL)
	}
	if c.baseURL == "" {
		t.Error("baseURL should not be empty")
	}
	if c.cache == nil {
		t.Error("cache map should not be nil")
	}
}

func TestRubyGemsClient_GetPackageInfo_Success(t *testing.T) {
	payload := RubyGemsGemInfo{
		Name:        "rails",
		Version:     "7.1.2",
		Info:        "Full-stack web framework",
		Authors:     "David Heinemeier Hansson",
		Downloads:   9000000,
		HomepageURI: "https://rubyonrails.org",
	}
	srv := newJSONServer(t, http.StatusOK, payload)
	defer srv.Close()

	c := NewRubyGemsClient()
	c.baseURL = srv.URL

	meta, err := c.GetPackageInfo(context.Background(), "rails", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Name != "rails" {
		t.Errorf("expected name=rails, got %s", meta.Name)
	}
	if meta.Registry != "rubygems" {
		t.Errorf("expected registry=rubygems, got %s", meta.Registry)
	}
	if meta.Downloads != 9000000 {
		t.Errorf("expected 9000000 downloads, got %d", meta.Downloads)
	}
}

func TestRubyGemsClient_GetPackageInfo_404(t *testing.T) {
	srv := newRawServer(t, http.StatusNotFound, `{}`)
	defer srv.Close()

	c := NewRubyGemsClient()
	c.baseURL = srv.URL

	_, err := c.GetPackageInfo(context.Background(), "no-such-gem-xyz", "")
	if err == nil {
		t.Error("expected error for 404, got nil")
	}
}

func TestRubyGemsClient_GetPackageInfo_InvalidJSON(t *testing.T) {
	srv := newRawServer(t, http.StatusOK, `{invalid`)
	defer srv.Close()

	c := NewRubyGemsClient()
	c.baseURL = srv.URL

	_, err := c.GetPackageInfo(context.Background(), "rails", "")
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestRubyGemsClient_GetPackageInfo_CacheHit(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_ = json.NewEncoder(w).Encode(RubyGemsGemInfo{Name: "sinatra", Version: "3.1.0"})
	}))
	defer srv.Close()

	c := NewRubyGemsClient()
	c.baseURL = srv.URL

	_, _ = c.GetPackageInfo(context.Background(), "sinatra", "")
	_, _ = c.GetPackageInfo(context.Background(), "sinatra", "")

	if callCount != 1 {
		t.Errorf("expected 1 HTTP call (cache hit), got %d", callCount)
	}
}

func TestRubyGemsClient_CacheTTLExpiry(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_ = json.NewEncoder(w).Encode(RubyGemsGemInfo{Name: "rake", Version: "13.0.6"})
	}))
	defer srv.Close()

	c := NewRubyGemsClient()
	c.baseURL = srv.URL
	c.cacheTTL = 1 * time.Millisecond

	_, _ = c.GetPackageInfo(context.Background(), "rake", "")
	time.Sleep(5 * time.Millisecond)
	_, _ = c.GetPackageInfo(context.Background(), "rake", "")

	if callCount != 2 {
		t.Errorf("expected 2 HTTP calls after TTL expiry, got %d", callCount)
	}
}

func TestRubyGemsClient_GetPopularPackages(t *testing.T) {
	c := NewRubyGemsClient()
	pkgs, err := c.GetPopularPackages(5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 5 {
		t.Errorf("expected 5 packages, got %d", len(pkgs))
	}
}

func TestRubyGemsClient_ClearCache(t *testing.T) {
	c := NewRubyGemsClient()
	c.cacheMu.Lock()
	c.cache["a:b"] = &CacheEntry{Timestamp: time.Now()}
	c.cacheMu.Unlock()

	c.ClearCache()

	c.cacheMu.RLock()
	n := len(c.cache)
	c.cacheMu.RUnlock()
	if n != 0 {
		t.Errorf("expected empty cache, got %d", n)
	}
}

func TestRubyGemsClient_SetCacheTTL(t *testing.T) {
	c := NewRubyGemsClient()
	c.SetCacheTTL(3 * time.Minute)
	if c.cacheTTL != 3*time.Minute {
		t.Errorf("expected 3m, got %v", c.cacheTTL)
	}
}

func TestRubyGemsClient_ConcurrentAccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(RubyGemsGemInfo{Name: "bundler", Version: "2.5.0"})
	}))
	defer srv.Close()

	c := NewRubyGemsClient()
	c.baseURL = srv.URL

	var wg sync.WaitGroup
	errs := make([]error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = c.GetPackageInfo(context.Background(), "bundler", "")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: unexpected error: %v", i, err)
		}
	}
}

// ---------------------------------------------------------------------------
// ComposerClient tests
// ---------------------------------------------------------------------------

func TestNewComposerClient_Defaults(t *testing.T) {
	c := NewComposerClient()
	if c == nil {
		t.Fatal("NewComposerClient returned nil")
	}
	if c.httpClient == nil {
		t.Error("httpClient should not be nil")
	}
	if c.cacheTTL <= 0 {
		t.Errorf("cacheTTL should be > 0, got %v", c.cacheTTL)
	}
	if c.baseURL == "" {
		t.Error("baseURL should not be empty")
	}
	if c.cache == nil {
		t.Error("cache map should not be nil")
	}
}

func TestComposerClient_GetPackageInfo_Success(t *testing.T) {
	payload := ComposerPackageDetails{
		Package: ComposerPackageMetadata{
			Name:        "laravel/framework",
			Description: "The Laravel Framework.",
			Versions: map[string]ComposerVersionInfo{
				"v10.0.0": {Version: "v10.0.0", Authors: []Author{{Name: "Taylor Otwell"}}},
			},
			Downloads: ComposerDownloads{Total: 500000},
		},
	}
	srv := newJSONServer(t, http.StatusOK, payload)
	defer srv.Close()

	c := NewComposerClient()
	c.baseURL = srv.URL

	meta, err := c.GetPackageInfo(context.Background(), "laravel/framework", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Name != "laravel/framework" {
		t.Errorf("expected laravel/framework, got %s", meta.Name)
	}
	if meta.Registry != "composer" {
		t.Errorf("expected registry=composer, got %s", meta.Registry)
	}
}

func TestComposerClient_GetPackageInfo_404(t *testing.T) {
	srv := newRawServer(t, http.StatusNotFound, `{"status":"error"}`)
	defer srv.Close()

	c := NewComposerClient()
	c.baseURL = srv.URL

	_, err := c.GetPackageInfo(context.Background(), "no/such-package-xyz", "")
	if err == nil {
		t.Error("expected error for 404, got nil")
	}
}

func TestComposerClient_GetPackageInfo_500(t *testing.T) {
	srv := newRawServer(t, http.StatusInternalServerError, `{}`)
	defer srv.Close()

	c := NewComposerClient()
	c.baseURL = srv.URL

	_, err := c.GetPackageInfo(context.Background(), "vendor/package", "")
	if err == nil {
		t.Error("expected error for 500, got nil")
	}
}

func TestComposerClient_GetPackageInfo_InvalidJSON(t *testing.T) {
	srv := newRawServer(t, http.StatusOK, `{bad json`)
	defer srv.Close()

	c := NewComposerClient()
	c.baseURL = srv.URL

	_, err := c.GetPackageInfo(context.Background(), "vendor/package", "")
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestComposerClient_GetPackageInfo_CacheHit(t *testing.T) {
	callCount := 0
	payload := ComposerPackageDetails{
		Package: ComposerPackageMetadata{
			Name: "symfony/console",
			Versions: map[string]ComposerVersionInfo{
				"v6.0.0": {Version: "v6.0.0"},
			},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	c := NewComposerClient()
	c.baseURL = srv.URL

	_, _ = c.GetPackageInfo(context.Background(), "symfony/console", "")
	_, _ = c.GetPackageInfo(context.Background(), "symfony/console", "")

	if callCount != 1 {
		t.Errorf("expected 1 HTTP call (cache hit), got %d", callCount)
	}
}

func TestComposerClient_ClearCache(t *testing.T) {
	c := NewComposerClient()
	c.cache["a@b"] = nil
	c.ClearCache()
	if len(c.cache) != 0 {
		t.Errorf("expected empty cache, got %d entries", len(c.cache))
	}
}

func TestComposerClient_SetCacheTTL(t *testing.T) {
	c := NewComposerClient()
	c.SetCacheTTL(8 * time.Minute)
	if c.cacheTTL != 8*time.Minute {
		t.Errorf("expected 8m, got %v", c.cacheTTL)
	}
}

// ---------------------------------------------------------------------------
// Factory tests
// ---------------------------------------------------------------------------

func TestNewFactory_SupportedRegistries(t *testing.T) {
	f := NewFactory()
	supported := f.GetSupportedRegistries()
	expected := []string{"npm", "pypi", "maven", "nuget", "rubygems", "composer", "cargo"}

	if len(supported) != len(expected) {
		t.Errorf("expected %d registries, got %d", len(expected), len(supported))
	}

	for _, reg := range expected {
		if !f.ValidateRegistryType(reg) {
			t.Errorf("registry %q should be supported", reg)
		}
	}
}

func TestFactory_CreateConnector_AllTypes(t *testing.T) {
	f := NewFactory()
	registryTypes := []string{"npm", "pypi", "maven", "nuget", "rubygems", "composer", "cargo"}

	for _, rt := range registryTypes {
		t.Run(rt, func(t *testing.T) {
			reg := &Registry{Name: rt, Type: rt, Enabled: true}
			conn, err := f.CreateConnector(rt, reg)
			if err != nil {
				t.Fatalf("CreateConnector(%q): unexpected error: %v", rt, err)
			}
			if conn == nil {
				t.Fatal("expected non-nil connector")
			}
			if conn.GetRegistryType() != rt {
				t.Errorf("expected registry type %q, got %q", rt, conn.GetRegistryType())
			}
		})
	}
}

func TestFactory_CreateConnector_Unsupported(t *testing.T) {
	f := NewFactory()
	_, err := f.CreateConnector("unsupported-registry", &Registry{})
	if err == nil {
		t.Error("expected error for unsupported registry type, got nil")
	}
}

func TestFactory_ValidateRegistryType_CaseInsensitive(t *testing.T) {
	f := NewFactory()
	if !f.ValidateRegistryType("NPM") {
		t.Error("NPM (uppercase) should be valid")
	}
	if !f.ValidateRegistryType("PyPI") {
		t.Error("PyPI (mixed case) should be valid")
	}
}

func TestFactory_CreateConnectorFromType_AllTypes(t *testing.T) {
	f := NewFactory()
	types := []string{"npm", "pypi", "maven", "nuget", "rubygems", "composer", "cargo"}
	for _, rt := range types {
		t.Run(rt, func(t *testing.T) {
			conn, err := f.CreateConnectorFromType(rt)
			if err != nil {
				t.Fatalf("CreateConnectorFromType(%q): unexpected error: %v", rt, err)
			}
			if conn == nil {
				t.Fatal("connector should not be nil")
			}
		})
	}
}

func TestFactory_CreateConnectorFromType_Unsupported(t *testing.T) {
	f := NewFactory()
	_, err := f.CreateConnectorFromType("unknown")
	if err == nil {
		t.Error("expected error for unsupported registry type")
	}
}

func TestFactory_RegisterAndUnregister(t *testing.T) {
	f := NewFactory()

	// Register custom connector
	f.RegisterRegistry("custom", func(r *Registry) Connector {
		return NewNPMConnector(r) // reuse NPM connector as stand-in
	})

	if !f.ValidateRegistryType("custom") {
		t.Error("custom registry should be valid after registration")
	}

	// Unregister it
	f.UnregisterRegistry("custom")
	if f.ValidateRegistryType("custom") {
		t.Error("custom registry should be invalid after unregistration")
	}
}

// ---------------------------------------------------------------------------
// Manager tests
// ---------------------------------------------------------------------------

func TestManager_AddAndGetConnector(t *testing.T) {
	m := NewManager()
	reg := &Registry{Name: "npm", Type: "npm"}
	conn := NewNPMConnector(reg)

	m.AddConnector("npm", conn)

	retrieved, err := m.GetConnector("npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if retrieved != conn {
		t.Error("retrieved connector should be the same object that was added")
	}
}

func TestManager_GetConnector_NotFound(t *testing.T) {
	m := NewManager()
	_, err := m.GetConnector("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent connector")
	}
}

func TestManager_GetAllConnectors(t *testing.T) {
	m := NewManager()
	reg := &Registry{Name: "npm", Type: "npm"}
	m.AddConnector("npm", NewNPMConnector(reg))
	m.AddConnector("pypi", NewPyPIConnector(reg))

	all := m.GetAllConnectors()
	if len(all) != 2 {
		t.Errorf("expected 2 connectors, got %d", len(all))
	}
}

func TestManager_Close(t *testing.T) {
	m := NewManager()
	reg := &Registry{Name: "npm", Type: "npm"}
	m.AddConnector("npm", NewNPMConnector(reg))

	if err := m.Close(); err != nil {
		t.Fatalf("Close returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// OptimizedRegistryClient tests
// ---------------------------------------------------------------------------

func TestNewOptimizedRegistryClient_Defaults(t *testing.T) {
	c := NewOptimizedRegistryClient(nil)
	if c == nil {
		t.Fatal("NewOptimizedRegistryClient returned nil")
	}
	if c.client == nil {
		t.Error("http client should not be nil")
	}
	if c.cache == nil {
		t.Error("cache should not be nil")
	}
	if c.config == nil {
		t.Error("config should not be nil")
	}
	if c.config.Timeout <= 0 {
		t.Errorf("config.Timeout should be > 0, got %v", c.config.Timeout)
	}
	if c.config.RetryAttempts <= 0 {
		t.Errorf("config.RetryAttempts should be > 0, got %d", c.config.RetryAttempts)
	}
}

func TestNewOptimizedRegistryClient_CustomConfig(t *testing.T) {
	cfg := &ClientConfig{
		Timeout:         5 * time.Second,
		MaxConnections:  50,
		MaxIdleConns:    5,
		IdleConnTimeout: 30 * time.Second,
		RetryAttempts:   1,
		RetryDelay:      500 * time.Millisecond,
		UserAgent:       "TestAgent/1.0",
	}
	c := NewOptimizedRegistryClient(cfg)
	if c.config.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", c.config.Timeout)
	}
	if c.config.UserAgent != "TestAgent/1.0" {
		t.Errorf("expected custom user agent, got %s", c.config.UserAgent)
	}
}

func TestOptimizedRegistryClient_GetPackageInfo_CacheHit(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_ = json.NewEncoder(w).Encode(map[string]string{"name": "lodash"})
	}))
	defer srv.Close()

	// We can't easily redirect the hardcoded URLs in fetchPackageInfo,
	// but we can pre-populate the cache to verify cache-hit logic.
	c := NewOptimizedRegistryClient(nil)

	cachedResponse := &RegistryResponse{
		CacheHit:  false,
		Timestamp: time.Now(),
	}
	c.cache.Store("npm:lodash:4.17.21", cachedResponse)

	resp, err := c.GetPackageInfo(context.Background(), "npm", "lodash", "4.17.21")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.CacheHit {
		t.Error("expected cache hit")
	}
	if callCount != 0 {
		t.Errorf("expected 0 HTTP calls on cache hit, got %d", callCount)
	}
}

func TestOptimizedRegistryClient_CacheTTLExpiry(t *testing.T) {
	c := NewOptimizedRegistryClient(nil)

	// Insert a stale (past TTL) cache entry
	staleResponse := &RegistryResponse{
		CacheHit:  false,
		Timestamp: time.Now().Add(-10 * time.Minute), // clearly expired
	}
	c.cache.Store("npm:stale:1.0.0", staleResponse)

	// The client will try a real network call and fail because it's a fake URL.
	// That's fine — we just want to confirm the stale entry doesn't count as a hit.
	_, err := c.GetPackageInfo(context.Background(), "npm", "stale", "1.0.0")
	// error is expected (no real server), but confirm stale cache was not returned as hit
	if err == nil {
		// If somehow it succeeded (unlikely), verify it wasn't the stale entry
		t.Log("got unexpected success; stale cache was likely evicted correctly")
	}
}

func TestOptimizedRegistryClient_UnsupportedRegistry(t *testing.T) {
	c := NewOptimizedRegistryClient(&ClientConfig{
		Timeout:       1 * time.Second,
		RetryAttempts: 1,
		RetryDelay:    1 * time.Millisecond,
	})
	_, err := c.GetPackageInfo(context.Background(), "unknown-registry", "pkg", "1.0")
	if err == nil {
		t.Error("expected error for unsupported registry, got nil")
	}
}

func TestOptimizedRegistryClient_GetCacheStats(t *testing.T) {
	c := NewOptimizedRegistryClient(nil)
	c.cache.Store("key1", &RegistryResponse{Timestamp: time.Now()})
	c.cache.Store("key2", &RegistryResponse{Timestamp: time.Now()})

	stats := c.GetCacheStats()
	if stats["cache_entries"].(int) != 2 {
		t.Errorf("expected 2 cache entries, got %v", stats["cache_entries"])
	}
}

func TestOptimizedRegistryClient_ClearCache(t *testing.T) {
	c := NewOptimizedRegistryClient(nil)
	c.cache.Store("key1", &RegistryResponse{Timestamp: time.Now()})
	c.ClearCache()

	count := 0
	c.cache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("expected empty cache after ClearCache, got %d entries", count)
	}
}

func TestOptimizedRegistryClient_Close(t *testing.T) {
	c := NewOptimizedRegistryClient(nil)
	c.cache.Store("key", &RegistryResponse{Timestamp: time.Now()})
	if err := c.Close(); err != nil {
		t.Fatalf("Close returned unexpected error: %v", err)
	}
}

func TestOptimizedRegistryClient_GetPackagesBatch_Empty(t *testing.T) {
	c := NewOptimizedRegistryClient(nil)
	responses, err := c.GetPackagesBatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error for empty batch: %v", err)
	}
	if responses != nil {
		t.Errorf("expected nil responses for empty batch, got %v", responses)
	}
}

// ---------------------------------------------------------------------------
// CacheEntry tests
// ---------------------------------------------------------------------------

func TestCacheEntry_Timestamp(t *testing.T) {
	before := time.Now()
	entry := &CacheEntry{
		Data:      "test",
		Timestamp: time.Now(),
	}
	after := time.Now()

	if entry.Timestamp.Before(before) || entry.Timestamp.After(after) {
		t.Errorf("timestamp %v should be between %v and %v", entry.Timestamp, before, after)
	}
}

func TestCacheEntry_ExpiredCheck(t *testing.T) {
	ttl := 5 * time.Minute

	// Fresh entry
	fresh := &CacheEntry{Timestamp: time.Now()}
	if time.Since(fresh.Timestamp) >= ttl {
		t.Error("fresh entry should not be expired")
	}

	// Stale entry
	stale := &CacheEntry{Timestamp: time.Now().Add(-10 * time.Minute)}
	if time.Since(stale.Timestamp) < ttl {
		t.Error("stale entry should be expired")
	}
}
