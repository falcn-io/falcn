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
	fmt.Println()
	fmt.Println("  Analyzing dependencies... ━━━━━━━━━━━━━━━━━━━━ 100%")
}

func (f *FuturisticFormatter) PrintScanResults(result *analyzer.ScanResult) {
	if f.json {
		b, _ := json.Marshal(result)
		fmt.Println(string(b))
		return
	}

	// ANSI Colors
	// colorReset := "\033[0m"
	// colorRed := "\033[31m"
	// colorGreen := "\033[32m"
	// colorYellow := "\033[33m"
	// colorBlue := "\033[34m"
	// colorCyan := "\033[36m"
	// colorWhite := "\033[37m"
	// colorGray := "\033[90m"

	fmt.Println()
	fmt.Println("\033[90m┌─────────────────────────────────────────────────────────┐\033[0m")
	fmt.Println("\033[90m│\033[0m  SCAN RESULTS                                           \033[90m│\033[0m")
	fmt.Println("\033[90m├─────────────────────────────────────────────────────────┤\033[0m")
	fmt.Printf("\033[90m│\033[0m  Packages scanned:    %-33d \033[90m│\033[0m\n", result.TotalPackages)
	fmt.Printf("\033[90m│\033[0m  Scan time:           %-33v \033[90m│\033[0m\n", result.Duration)
	fmt.Printf("\033[90m│\033[0m  Threats detected:    %-33d \033[90m│\033[0m\n", len(result.Threats))
	fmt.Println("\033[90m└─────────────────────────────────────────────────────────┘\033[0m")
	fmt.Println()

	if len(result.Threats) > 0 {
		fmt.Println("\033[33m⚠  THREATS DETECTED\033[0m")
		fmt.Println()

		for _, threat := range result.Threats {
			severityColor := "\033[34m" // Default/Low
			switch strings.ToUpper(threat.Severity.String()) {
			case "CRITICAL":
				severityColor = "\033[31m"
			case "HIGH":
				severityColor = "\033[38;5;208m"
			case "MEDIUM":
				severityColor = "\033[33m"
			}

			// Reachability badge: shown only for CVE threats with analysis result.
			reachabilityBadge := ""
			if threat.Reachable != nil {
				if *threat.Reachable {
					reachabilityBadge = "  \033[31m[REACHABLE]\033[0m"
				} else {
					reachabilityBadge = "  \033[90m[not reachable]\033[0m"
				}
			}

			fmt.Printf("  %s%s  %s\033[0m%s\n", severityColor, strings.ToUpper(threat.Severity.String()), threat.Package, reachabilityBadge)
			fmt.Printf("  \033[90m│\033[0m Type: %s\n", threat.Type)
			if threat.SimilarTo != "" {
				fmt.Printf("  \033[90m│\033[0m Target: %s (similarity: %.2f)\n", threat.SimilarTo, threat.Confidence)
			}
			fmt.Printf("  \033[90m│\033[0m Risk Score: %.2f\n", threat.Confidence)
			fmt.Printf("  \033[90m│\033[0m Action: %s\n", threat.Recommendation)

			// Show call path when reachable
			if threat.Reachable != nil && *threat.Reachable && len(threat.CallPath) > 0 {
				fmt.Printf("  \033[90m│\033[0m Call path: %s\n", strings.Join(threat.CallPath, " → "))
			}

			if threat.Metadata != nil {
				if explanation, ok := threat.Metadata["ai_explanation"]; ok && explanation != nil {
					fmt.Printf("  \033[90m│\033[0m AI Analysis: %s\n", explanation)
				}
			}

			fmt.Println("  \033[90m│\033[0m")
			fmt.Printf("  \033[90m└─\033[0m Evidence: %s\n", threat.Description)
			fmt.Println()
		}

		fmt.Println("\033[90m────────────────────────────────────────────────────────────\033[0m")
		fmt.Printf("  \033[31m✖ %d threats found\033[0m • Run `falcn report` for full details\n", len(result.Threats))
		fmt.Println("\033[90m────────────────────────────────────────────────────────────\033[0m")
	} else {
		fmt.Println("\033[90m────────────────────────────────────────────────────────────\033[0m")
		fmt.Printf("  \033[32m✔ No threats detected\033[0m • %d packages scanned in %v\n", result.TotalPackages, result.Duration)
		fmt.Println("\033[90m────────────────────────────────────────────────────────────\033[0m")
	}
}

func (f *FuturisticFormatter) PrintAnalysisResults(result *detector.CheckPackageResult) {
	if f.json {
		b, _ := json.Marshal(result)
		fmt.Println(string(b))
		return
	}

	if len(result.Threats) > 0 {
		fmt.Println("\033[33m⚠  THREATS DETECTED\033[0m")
		fmt.Println()

		for _, threat := range result.Threats {
			severityColor := "\033[34m" // Default/Low
			switch strings.ToUpper(threat.Severity.String()) {
			case "CRITICAL":
				severityColor = "\033[31m"
			case "HIGH":
				severityColor = "\033[38;5;208m"
			case "MEDIUM":
				severityColor = "\033[33m"
			}

			fmt.Printf("  %s%s  %s\033[0m\n", severityColor, strings.ToUpper(threat.Severity.String()), result.Name)
			fmt.Printf("  \033[90m│\033[0m Type: %s\n", threat.Type)
			if threat.SimilarTo != "" {
				fmt.Printf("  \033[90m│\033[0m Target: %s (similarity: %.2f)\n", threat.SimilarTo, threat.Confidence)
			}
			fmt.Printf("  \033[90m│\033[0m Risk Score: %.2f\n", threat.Confidence)
			fmt.Println("  \033[90m│\033[0m")
			fmt.Printf("  \033[90m└─\033[0m Evidence: %s\n", threat.Description)
			fmt.Println()
		}

		fmt.Println("\033[90m────────────────────────────────────────────────────────────\033[0m")
		fmt.Printf("  \033[31m✖ %d threats found\033[0m\n", len(result.Threats))
		fmt.Println("\033[90m────────────────────────────────────────────────────────────\033[0m")
	} else {
		fmt.Println("\033[90m────────────────────────────────────────────────────────────\033[0m")
		fmt.Printf("  \033[32m✔ Package appears safe\033[0m • %s\n", result.Name)
		fmt.Println("\033[90m────────────────────────────────────────────────────────────\033[0m")
	}
}
