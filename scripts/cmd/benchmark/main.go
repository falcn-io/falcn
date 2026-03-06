package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/falcn-io/falcn/internal/config"
	"github.com/falcn-io/falcn/internal/scanner"
	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func main() {
	start := time.Now()
	// Configure Logrus
	logrus.SetLevel(logrus.WarnLevel) // Reduce noise
	logrus.SetOutput(os.Stderr)

	// Configure Viper Defaults for Benchmark
	viper.Set("scanner.content.max_file_size", 10485760) // 10MB
	viper.Set("scanner.content.entropy_threshold", 6.0)
	viper.Set("scanner.content.whitelist_extensions", []string{".js", ".ts", ".json", ".lock", ".py", ".go", ".ac", ".sh", ".txt"})
	viper.Set("scanner.registries.npm.enabled", true) // Ensure analyzer is skipped gracefully or used

	// Disable global color
	os.Setenv("NO_COLOR", "true")
	color.NoColor = true

	// Create Scanner
	cfg := config.NewDefaultConfig()
	// Force enable content scanning defaults if needed by manual override in NewContentScanner?
	// NewContentScanner reads from viper directly.

	scanEngine, err := scanner.New(cfg)
	if err != nil {
		fmt.Printf("Failed to initialize scanner: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("# Falcn Real-Life Benchmark Report")
	fmt.Println("")
	fmt.Printf("Date: %s\n", start.Format("2006-01-02 15:04:05"))
	fmt.Println("")

	legitimateDir := "tests/benchmark/legitimate"
	maliciousDir := "tests/benchmark/malicious"

	// 1. Scan Legitimate (Negative Control)
	fmt.Println("## 1. Legitimate Corpus (Specificity Test)")
	fmt.Println("| Package | Threats Detected | Result |")
	fmt.Println("| :--- | :--- | :--- |")

	fpCount := 0
	legitTotal := 0

	filepath.Walk(legitimateDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() && path != legitimateDir {
			threats, runErr := runDirectScan(scanEngine, path)
			result := "✅ PASS"
			if runErr != nil {
				result = fmt.Sprintf("❌ ERROR (%v)", runErr)
			} else if threats > 0 {
				result = "❌ FALSE POSITIVE"
				fpCount++
			}
			fmt.Printf("| %s | %d | %s |\n", filepath.Base(path), threats, result)
			legitTotal++
			return filepath.SkipDir
		}
		return nil
	})

	// 2. Scan Malicious (Sensitivity Test)
	fmt.Println("")
	fmt.Println("## 2. Malicious Corpus (Sensitivity Test)")
	fmt.Println("| Package | Threats Detected | Result |")
	fmt.Println("| :--- | :--- | :--- |")

	tpCount := 0
	malTotal := 0

	filepath.Walk(maliciousDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() && path != maliciousDir {
			threats, runErr := runDirectScan(scanEngine, path)
			result := "✅ BLOCKED"
			if runErr != nil {
				result = fmt.Sprintf("❌ ERROR (%v)", runErr)
			} else if threats == 0 {
				result = "❌ FALSE NEGATIVE"
			} else {
				tpCount++
			}
			fmt.Printf("| %s | %d | %s |\n", filepath.Base(path), threats, result)
			malTotal++
			return filepath.SkipDir
		}
		return nil
	})

	// Stats
	fmt.Println("")
	fmt.Println("## 3. Performance Metrics")

	if legitTotal > 0 {
		fpr := (float64(fpCount) / float64(legitTotal)) * 100
		fmt.Printf("- **False Positive Rate (FPR)**: %.2f%% (%d/%d)\n", fpr, fpCount, legitTotal)
	}
	if malTotal > 0 {
		tpr := (float64(tpCount) / float64(malTotal)) * 100
		fmt.Printf("- **True Positive Rate (TPR)**: %.2f%% (%d/%d)\n", tpr, tpCount, malTotal)
	}

	fmt.Printf("\nTotal Benchmark Time: %v\n", time.Since(start))
}

func runDirectScan(s *scanner.Scanner, path string) (int, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return 0, err
	}

	// Capture/Silence Stdout during library execution to prevent TUI artifacts
	// The scanner or its dependencies (like fatih/color or progress bars) might write to Stdout.
	oldStdout := os.Stdout
	nullFile, _ := os.Open(os.DevNull)
	os.Stdout = nullFile
	defer func() {
		os.Stdout = oldStdout
		nullFile.Close()
	}()

	result, err := s.ScanProject(context.Background(), absPath)

	// Restore immediately to ensure any defer output from function doesn't get lost if we printed there (we don't)
	// But defer LIFO ensures restore happens last.

	if err != nil {
		return 0, err
	}

	return result.Summary.ThreatsFound, nil
}
