package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/falcn-io/falcn/internal/analyzer"
	"github.com/falcn-io/falcn/internal/detector"
)

type FuturisticFormatter struct {
	verbose bool
	json    bool
}

func NewFuturisticFormatter(verbose, json bool) *FuturisticFormatter {
	return &FuturisticFormatter{
		verbose: verbose,
		json:    json,
	}
}

func (f *FuturisticFormatter) PrintVersion(version string) {
	if f.json {
		fmt.Printf(`{"version": "%s"}`+"\n", version)
		return
	}

	// Falcn ASCII Banner
	fmt.Println("\033[38;5;214m   ___       _\033[0m")
	fmt.Println("\033[38;5;214m  / __\\__ _ | |  ___  _ __\033[0m")
	fmt.Println("\033[38;5;214m / _\\ / _` || | / __|| '_ \\\033[0m")
	fmt.Println("\033[38;5;214m/ /  | (_| || || (__ | | | |\033[0m")
	fmt.Println("\033[38;5;214m\\/    \\__,_||_| \\___||_| |_|\033[0m")
	fmt.Println()
	fmt.Println("\033[1mPrecision Supply Chain Security\033[0m")
	fmt.Printf("v%s • falcn.io\n", version)
	fmt.Println(strings.Repeat("=", 60))
}

func (f *FuturisticFormatter) PrintBanner() {
	if f.json {
		return
	}
	fmt.Println("\n\033[38;5;214m◢◣ Falcn\033[0m")
	fmt.Println("   Precision Supply Chain Security")
	fmt.Println(strings.Repeat("-", 40))
}

func (f *FuturisticFormatter) PrintScanStart(path string) {
	if f.json {
		return
	}
	fmt.Printf("Scanning: %s\n", path)
}

func (f *FuturisticFormatter) PrintScanResults(result *analyzer.ScanResult) {
	if f.json {
		b, _ := json.Marshal(result)
		fmt.Println(string(b))
		return
	}
	fmt.Printf("Threats: %d, Warnings: %d\n", len(result.Threats), len(result.Warnings))
}

func (f *FuturisticFormatter) PrintAnalysisResults(result *detector.CheckPackageResult) {
	if f.json {
		b, _ := json.Marshal(result)
		fmt.Println(string(b))
		return
	}
	fmt.Printf("Findings: %d, Warnings: %d\n", len(result.Threats), len(result.Warnings))
}

