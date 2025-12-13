package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCLI_ScanOutputsSBOMAndSARIF(t *testing.T) {
	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}

	// Assuming we run this from the project root or tests/e2e dir
	// We need to resolve the project root.
	// If running from 'c:\Users\aliko\Desktop\Typosentinel', cwd is that.
	// If running 'go test ./tests/e2e/...', cwd might be the root or the pkg dir.
	// Let's assume the root is where go.mod is.

	// Calculate root dir (assuming this test is in tests/e2e)
	rootDir := filepath.Join(cwd, "../..")
	// Note: if running from root via `go test ./tests/e2e/sbom_sarif_cli_test.go`, cwd is root.
	// Let's check for go.mod
	if _, err := os.Stat(filepath.Join(cwd, "go.mod")); err == nil {
		rootDir = cwd
	}

	projectPath := filepath.Join(rootDir, "tests", "e2e", "test-projects", "npm-vulnerable")

	// NPM sample - CycloneDX
	cmd := exec.Command("go", "run", ".", "scan", projectPath, "--output", "cyclonedx")
	cmd.Dir = rootDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("scan cyclonedx failed: %v: %s", err, string(out))
	}
	start := bytes.IndexByte(out, '{')
	var obj map[string]interface{}
	if start >= 0 {
		_ = json.Unmarshal(out[start:], &obj)
	}
	if _, ok := obj["components"]; !ok {
		t.Fatalf("cyclonedx missing components. Output: %s", string(out))
	}

	// NPM sample - SARIF
	cmd2 := exec.Command("go", "run", ".", "scan", projectPath, "--output", "sarif")
	cmd2.Dir = rootDir
	out2, err := cmd2.CombinedOutput()
	if err != nil {
		t.Fatalf("scan sarif failed: %v: %s", err, string(out2))
	}
	start2 := bytes.IndexByte(out2, '{')
	var obj2 map[string]interface{}
	if start2 >= 0 {
		_ = json.Unmarshal(out2[start2:], &obj2)
	}
	if _, ok := obj2["runs"]; !ok {
		t.Fatalf("sarif missing runs. Output: %s", string(out2))
	}
}
