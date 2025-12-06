package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type TestCase struct {
	Name        string
	Args        []string
	ExpectError bool
	Contains    []string
}

func main() {
	start := time.Now()
	fmt.Println("# Falcn CLI Options Test Report")
	fmt.Printf("Date: %s\n\n", start.Format("2006-01-02 15:04:05"))

	target := "tests/benchmark/legitimate/express-sim"
	configFile := "config.yaml"

	// Ensure config exists (created in previous step)
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		fmt.Println("Error: config.yaml not found. Please run API setup first or create it.")
		os.Exit(1)
	}

	tests := []TestCase{
		{
			Name:     "Help Command",
			Args:     []string{"--help"},
			Contains: []string{"Falcn - Precision Supply Chain Security", "Usage:", "Available Commands:"},
		},
		{
			Name:     "Version Command",
			Args:     []string{"version"},
			Contains: []string{"Falcn v1.0.0", "Build:", "Commit:"},
		},
		{
			Name:     "Scan Default (Futuristic)",
			Args:     []string{"scan", target, "--config", configFile},
			Contains: []string{"Scan Complete"},
		},
		{
			Name:     "Scan JSON Output",
			Args:     []string{"scan", target, "--output", "json", "--config", configFile},
			Contains: []string{"\"scan_id\":", "\"summary\":", "\"threats_found\":"},
		},
		{
			Name:     "Scan YAML Output",
			Args:     []string{"scan", target, "--output", "yaml", "--config", configFile},
			Contains: []string{"scan_id:", "summary:", "threats_found:"},
		},
		{
			Name:     "Scan Table Output",
			Args:     []string{"scan", target, "--output", "table", "--config", configFile},
			Contains: []string{"PACKAGE", "VERSION", "THREATS"},
		},
		{
			Name:     "Scan Verbose Mode",
			Args:     []string{"scan", target, "--verbose", "--config", configFile},
			Contains: []string{"DEBUG", "Loading configuration"},
		},
		{
			Name:        "Invalid Output Format",
			Args:        []string{"scan", target, "--output", "invalid_format", "--config", configFile},
			ExpectError: true, // Should fall back or error? RootCmd defaults to futuristic, but validation?
			// If cobra validates validation: oneof=... then error.
			// Falcn usage says default futuristic. Let's see behavior.
		},
		{
			Name:        "Missing Target Directory",
			Args:        []string{"scan", "non/existent/path", "--config", configFile},
			ExpectError: true,
			Contains:    []string{"does not exist", "failed"},
		},
	}

	fmt.Println("| Test Case | Exit Code | Status | Output Snippet |")
	fmt.Println("| :--- | :--- | :--- | :--- |")

	passed := 0
	failed := 0

	// Force disable color for clean report output
	os.Setenv("NO_COLOR", "true")

	for _, tc := range tests {
		runTest(tc, &passed, &failed)
	}

	fmt.Printf("\n**Summary**: %d Passed, %d Failed\n", passed, failed)
	fmt.Printf("Total Time: %v\n", time.Since(start))
}

func runTest(tc TestCase, passed, failed *int) {
	cmd := exec.Command(".\\falcn.exe", tc.Args...)
	// Capture combined output
	output, err := cmd.CombinedOutput()
	outputStr := string(output)
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	status := "✅ PASS"
	if tc.ExpectError {
		if exitCode == 0 {
			status = "❌ FAIL (Expected Error)"
			*failed++
		} else {
			// Check if error output contains expected strings
			if len(tc.Contains) > 0 {
				if checkContains(outputStr, tc.Contains) {
					*passed++
				} else {
					status = "❌ FAIL (Missing Error Message)"
					*failed++
				}
			} else {
				*passed++
			}
		}
	} else {
		if exitCode != 0 {
			status = fmt.Sprintf("❌ FAIL (Exit %d)", exitCode)
			*failed++
		} else {
			if len(tc.Contains) > 0 {
				if checkContains(outputStr, tc.Contains) {
					*passed++
				} else {
					status = "❌ FAIL (Missing Content)"
					*failed++
				}
			} else {
				*passed++
			}
		}
	}

	// Clean output for table
	snippet := strings.ReplaceAll(outputStr, "\n", " ")
	snippet = strings.ReplaceAll(snippet, "\r", "")
	snippet = strings.ReplaceAll(snippet, "|", "\\|")
	if len(snippet) > 50 {
		snippet = snippet[:47] + "..."
	}
	if snippet == "" {
		snippet = "(no output)"
	}

	fmt.Printf("| %s | %d | %s | `%s` |\n", tc.Name, exitCode, status, snippet)
}

func checkContains(output string, sub []string) bool {
	for _, s := range sub {
		if !strings.Contains(output, s) {
			return false
		}
	}
	return true
}
