package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/falcn-io/falcn/pkg/types"
	"github.com/spf13/cobra"
)

var (
	reportFormat string
	reportFile   string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate detailed report from last scan",
	Long:  `Generate a detailed security report from the most recent scan results.`,
	RunE:  runReport,
}

func init() {
	RootCmd.AddCommand(reportCmd)
	reportCmd.Flags().StringVarP(&reportFormat, "format", "f", "html", "Report format (html, json, markdown)")
	reportCmd.Flags().StringVarP(&reportFile, "file", "i", "falcn_report.json", "Input scan result file")
}

func runReport(cmd *cobra.Command, args []string) error {
	// Read scan result
	data, err := os.ReadFile(reportFile)
	if err != nil {
		return fmt.Errorf("failed to read scan result file '%s': %v\nTip: Run 'falcn scan' first to generate a report", reportFile, err)
	}

	var result types.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("failed to parse scan result: %v", err)
	}

	if reportFormat != "json" {
		fmt.Printf("Generating %s report for scan %s...\n", reportFormat, result.ID)
	}

	switch reportFormat {
	case "json":
		// Just pretty print the JSON
		pretty, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(pretty))
	case "markdown":
		printMarkdownReport(&result)
	case "html":
		printHTMLReport(&result)
	default:
		return fmt.Errorf("unsupported format: %s", reportFormat)
	}

	return nil
}

func getAllThreats(result *types.ScanResult) []types.Threat {
	var allThreats []types.Threat
	for _, pkg := range result.Packages {
		allThreats = append(allThreats, pkg.Threats...)
	}
	return allThreats
}

func printMarkdownReport(result *types.ScanResult) {
	fmt.Printf("# Security Scan Report\n\n")
	fmt.Printf("**Project:** %s\n", result.Target)
	fmt.Printf("**Date:** %s\n", result.CreatedAt.Format(time.RFC1123))

	threats := getAllThreats(result)
	fmt.Printf("**Threats Found:** %d\n\n", len(threats))

	if len(threats) > 0 {
		fmt.Printf("## Detected Threats\n\n")
		for _, threat := range threats {
			fmt.Printf("### %s (%s)\n", threat.Type, threat.Severity)
			fmt.Printf("- **Description:** %s\n", threat.Description)
			fmt.Printf("- **Recommendation:** %s\n", threat.Recommendation)
			if len(threat.Evidence) > 0 {
				fmt.Printf("- **Evidence:**\n")
				for _, ev := range threat.Evidence {
					fmt.Printf("  - %s: %v\n", ev.Description, ev.Value)
				}
			}
			fmt.Println()
		}
	} else {
		fmt.Println("No threats detected.")
	}
}

func printHTMLReport(result *types.ScanResult) {
	threats := getAllThreats(result)

	// Simple HTML output
	fmt.Println("<!DOCTYPE html><html><head><title>Security Report</title>")
	fmt.Println("<style>body{font-family:sans-serif;margin:20px}.critical{color:red}.high{color:orange}.medium{color:yellow}.low{color:blue}</style>")
	fmt.Println("</head><body>")
	fmt.Printf("<h1>Security Scan Report</h1>")
	fmt.Printf("<p><strong>Project:</strong> %s</p>", result.Target)
	fmt.Printf("<p><strong>Date:</strong> %s</p>", result.CreatedAt.Format(time.RFC1123))

	if len(threats) > 0 {
		fmt.Printf("<h2>Detected Threats (%d)</h2>", len(threats))
		fmt.Println("<ul>")
		for _, threat := range threats {
			fmt.Printf("<li>")
			fmt.Printf("<h3 class='%s'>%s (%s)</h3>", threat.Severity, threat.Type, threat.Severity)
			fmt.Printf("<p>%s</p>", threat.Description)
			fmt.Printf("<p><strong>Recommendation:</strong> %s</p>", threat.Recommendation)
			if len(threat.Evidence) > 0 {
				fmt.Printf("<ul>")
				for _, ev := range threat.Evidence {
					fmt.Printf("<li>%s: %v</li>", ev.Description, ev.Value)
				}
				fmt.Printf("</ul>")
			}
			fmt.Printf("</li>")
		}
		fmt.Println("</ul>")
	} else {
		fmt.Println("<p>No threats detected.</p>")
	}
	fmt.Println("</body></html>")
}
