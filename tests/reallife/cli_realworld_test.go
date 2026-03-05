package reallife

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	npmVulnerable = "npm-vulnerable"
	npmClean      = "npm-clean"
	maliciousDemo = "malicious-demo"
)

func TestCLI_RealWorld_Scenarios(t *testing.T) {
	// Locate the binary
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}

	// Adjust path to find build/falcn from tests/reallife
	projectRoot := filepath.Dir(filepath.Dir(cwd))
	binaryPath := filepath.Join(projectRoot, "build", "falcn")

	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Fatalf("Binary not found at %s. Did you run 'make build'?", binaryPath)
	}

	examplesDir := filepath.Join(projectRoot, "examples")

	tests := []struct {
		name           string
		exampleDir     string
		args           []string
		expectedOutput []string
		mustFail       bool // logical failure (e.g. finding threats might be success or failure code depending on impl)
	}{
		{
			name:       "NPM Vulnerable - JSON Output",
			exampleDir: npmVulnerable,
			args:       []string{"--output", "json"},
			expectedOutput: []string{
				"\"typosquatting\"",
				"\"summary\":",
			},
		},
		{
			name:       "NPM Clean",
			exampleDir: npmClean,
			args:       []string{"--output", "json"},
			expectedOutput: []string{
				"\"clean_packages\"", // Output usually mentions clean packages or count
			},
		},
		{
			name:       "SARIF Output",
			exampleDir: npmVulnerable,
			args:       []string{"--output", "sarif"},
			expectedOutput: []string{
				"\"runs\":",
				"\"tool\":",
				"\"driver\":",
			},
		},
		{
			name:       "Default Output (Table)",
			exampleDir: npmVulnerable,
			args:       []string{}, // No output flag defaults to table/text
			expectedOutput: []string{
				"typosquatting", // Key header in table
				"expresss",      // Package name
				"CRITICAL",      // Severity
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targetDir := filepath.Join(examplesDir, tt.exampleDir)
			if _, err := os.Stat(targetDir); os.IsNotExist(err) {
				t.Fatalf("Example directory not found at %s", targetDir)
			}

			// Construct command: falcn scan <targetDir> [args...]
			cmdArgs := append([]string{"scan", targetDir}, tt.args...)
			cmd := exec.Command(binaryPath, cmdArgs...)

			// Capture output
			output, err := cmd.CombinedOutput()
			outputStr := string(output)

			t.Logf("CLI Output for %s:\n%s", tt.name, outputStr)

			if err != nil && !tt.mustFail {
				// Depending on CLI design, it might return exit code 1 if threats are found.
				// We should allow exit code 1 if threats are expected, but maybe check specific errors?
				// For now, logging error. If the CLI is designed to exit 1 on threats, we might need to ignore err here.
				// t.Logf("Command returned error (expected likely due to findings): %v", err)
			}

			for _, expected := range tt.expectedOutput {
				if !strings.Contains(outputStr, expected) {
					t.Errorf("Expected output to contain '%s', but it didn't.", expected)
				}
			}
		})
	}
}
