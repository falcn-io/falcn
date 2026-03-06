package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/falcn-io/falcn/internal/container"
)

// ── Flags ─────────────────────────────────────────────────────────────────────

var (
	siLight      bool
	siFormat     string
	siOut        string
	siUsername   string
	siPassword   string
	siToken      string
	siInsecure   bool
	siMaxLayerMB int64
	siDockerfile string
)

// ── Command ───────────────────────────────────────────────────────────────────

var scanImagesCmd = &cobra.Command{
	Use:   "scan-images [image...]",
	Short: "Scan OCI/Docker container images for vulnerabilities and misconfigurations",
	Long: `Scan one or more container images for:

  • Known CVEs in installed OS packages (dpkg, apk, rpm, pip, npm)
  • Image configuration security issues (root user, secrets in ENV, etc.)
  • Dockerfile security anti-patterns (fetch-and-pipe, latest tag, etc.)

Image references follow the standard Docker format:

  nginx                    # Docker Hub official image (latest tag)
  nginx:1.27.2             # specific version
  python:3.12-slim         # slim variant
  ghcr.io/owner/repo:v1.0  # GitHub Container Registry
  quay.io/fedora/fedora:40 # Quay.io
  myregistry.corp/app:prod # private registry

Examples:

  falcn scan-images nginx python:3.12 node:20-alpine
  falcn scan-images --light nginx:latest          # fast mode (no layer download)
  falcn scan-images --dockerfile Dockerfile       # scan a Dockerfile
  falcn scan-images --format json myapp:v2 > report.json
  falcn scan-images --username myuser --password mypass registry.corp/app:latest`,

	Args: func(cmd *cobra.Command, args []string) error {
		if siDockerfile == "" && len(args) == 0 {
			return fmt.Errorf("provide at least one image reference or --dockerfile")
		}
		return nil
	},
	RunE: runScanImages,
}

func init() {
	RootCmd.AddCommand(scanImagesCmd)

	scanImagesCmd.Flags().BoolVar(&siLight, "light", false,
		"Skip layer downloads; analyse manifest and config only (faster, less detail)")
	scanImagesCmd.Flags().StringVar(&siFormat, "format", "table",
		"Output format: table, json, sarif")
	scanImagesCmd.Flags().StringVar(&siOut, "out", "",
		"Write output to this file instead of stdout")
	scanImagesCmd.Flags().StringVar(&siUsername, "username", "",
		"Registry username (or set FALCN_REGISTRY_USER env)")
	scanImagesCmd.Flags().StringVar(&siPassword, "password", "",
		"Registry password (or set FALCN_REGISTRY_PASSWORD env)")
	scanImagesCmd.Flags().StringVar(&siToken, "token", "",
		"Pre-issued registry bearer token (or set FALCN_REGISTRY_TOKEN env)")
	scanImagesCmd.Flags().BoolVar(&siInsecure, "insecure", false,
		"Allow plain-HTTP (non-TLS) registry connections")
	scanImagesCmd.Flags().Int64Var(&siMaxLayerMB, "max-layer-mb", 100,
		"Skip layers larger than this many megabytes (default 100)")
	scanImagesCmd.Flags().StringVar(&siDockerfile, "dockerfile", "",
		"Scan a Dockerfile for security anti-patterns (may be combined with images)")
}

// ── Runner ────────────────────────────────────────────────────────────────────

func runScanImages(cmd *cobra.Command, args []string) error {
	// ── Credential fallback from env ────────────────────────────────────────
	if siUsername == "" {
		siUsername = os.Getenv("FALCN_REGISTRY_USER")
	}
	if siPassword == "" {
		siPassword = os.Getenv("FALCN_REGISTRY_PASSWORD")
	}
	if siToken == "" {
		siToken = os.Getenv("FALCN_REGISTRY_TOKEN")
	}

	opts := container.ScanOptions{
		Light:          siLight,
		Username:       siUsername,
		Password:       siPassword,
		Token:          siToken,
		Insecure:       siInsecure,
		MaxLayerSizeMB: siMaxLayerMB,
	}

	sc := container.New()
	ctx := context.Background()

	// Collect all results.
	var (
		imageResults []*container.ImageScanResult
		dfFindings   []container.SecurityFinding
		dfErr        error
	)

	// ── Dockerfile scan ─────────────────────────────────────────────────────
	if siDockerfile != "" {
		dfFindings, dfErr = container.ScanDockerfile(siDockerfile)
		if dfErr != nil {
			fmt.Fprintf(os.Stderr, "warning: Dockerfile scan failed: %v\n", dfErr)
		}
	}

	// ── Image scans ─────────────────────────────────────────────────────────
	for _, imageRef := range args {
		fmt.Fprintf(os.Stderr, "⟳ scanning %s…\n", imageRef)
		result, err := sc.ScanImage(ctx, imageRef, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ %s: %v\n", imageRef, err)
			continue
		}
		imageResults = append(imageResults, result)
	}

	// ── Output ──────────────────────────────────────────────────────────────
	var out strings.Builder
	switch strings.ToLower(siFormat) {
	case "json":
		formatJSON(&out, imageResults, dfFindings, siDockerfile)
	case "sarif":
		formatSARIF(&out, imageResults, dfFindings)
	default:
		formatTable(&out, imageResults, dfFindings, siDockerfile)
	}

	if siOut != "" {
		if err := os.MkdirAll(filepath.Dir(siOut), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(siOut, []byte(out.String()), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "✓ results written to %s\n", siOut)
		return nil
	}

	fmt.Print(out.String())

	// Exit 1 if any critical/high issues found (for CI gates).
	for _, r := range imageResults {
		if r.RiskLevel == "critical" || r.RiskLevel == "high" {
			os.Exit(1)
		}
	}
	return nil
}

// ── Table formatter ───────────────────────────────────────────────────────────

var (
	bold    = color.New(color.Bold)
	red     = color.New(color.FgRed, color.Bold)
	yellow  = color.New(color.FgYellow, color.Bold)
	cyan    = color.New(color.FgCyan)
	green   = color.New(color.FgGreen)
	faint   = color.New(color.Faint)
)

func formatTable(b *strings.Builder, results []*container.ImageScanResult, dfFindings []container.SecurityFinding, dfPath string) {
	// ── Dockerfile section ─────────────────────────────────────────────────
	if len(dfFindings) > 0 {
		bold.Fprintf(b, "\n── Dockerfile: %s ─────────────────────────────────────────────\n\n", dfPath)
		for _, f := range dfFindings {
			sevColor(f.Severity).Fprintf(b, "  [%s] %s (%s)\n", f.ID, f.Title, f.Severity)
			if f.Detail != "" {
				faint.Fprintf(b, "       %s\n", f.Detail)
			}
			if f.Remediation != "" {
				fmt.Fprintf(b, "       → %s\n", f.Remediation)
			}
			fmt.Fprintln(b)
		}
	} else if dfPath != "" {
		green.Fprintf(b, "\n✓ No Dockerfile issues found in %s\n", dfPath)
	}

	// ── Image sections ─────────────────────────────────────────────────────
	for _, r := range results {
		fmt.Fprintln(b)
		bold.Fprintf(b, "━━━ %s ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", r.Ref.Original)

		// Header
		fmt.Fprintf(b, "  Digest:       %s\n", shortDigest(r.ResolvedDigest))
		fmt.Fprintf(b, "  OS/Arch:      %s/%s\n", r.OS, r.Architecture)
		fmt.Fprintf(b, "  Base image:   %s\n", orNA(r.BaseImage))
		fmt.Fprintf(b, "  Layers:       %d\n", r.LayerCount)
		fmt.Fprintf(b, "  Image size:   %.1f MB\n", r.ImageSizeMB)
		fmt.Fprintf(b, "  Packages:     %d\n", r.PackageCount)
		fmt.Fprintf(b, "  Scanned at:   %s  (%.1fs)\n",
			r.ScannedAt.Format(time.RFC3339), float64(r.ScanDurationMs)/1000)
		fmt.Fprintln(b)

		// Risk banner
		riskColor(r.RiskLevel).Fprintf(b, "  Risk: %s (%.2f)\n\n", strings.ToUpper(r.RiskLevel), r.RiskScore)

		// Security findings
		if len(r.SecurityFindings) > 0 {
			bold.Fprintln(b, "  Image Security Findings")
			for _, f := range r.SecurityFindings {
				sevColor(f.Severity).Fprintf(b, "    [%s] %s (%s)\n", f.ID, f.Title, f.Severity)
				if f.Detail != "" {
					faint.Fprintf(b, "           %s\n", f.Detail)
				}
				if f.Remediation != "" {
					fmt.Fprintf(b, "           → %s\n", f.Remediation)
				}
			}
			fmt.Fprintln(b)
		}

		// Vulnerabilities
		if len(r.Vulnerabilities) > 0 {
			bold.Fprintf(b, "  Vulnerabilities (%d affected packages)\n", len(r.Vulnerabilities))
			for _, v := range r.Vulnerabilities {
				cves := "none"
				if len(v.CVEs) > 0 {
					cves = strings.Join(v.CVEs[:min2(3, len(v.CVEs))], ", ")
					if len(v.CVEs) > 3 {
						cves += fmt.Sprintf(" +%d more", len(v.CVEs)-3)
					}
				}
				fix := ""
				if v.FixedIn != "" {
					fix = " → fix: " + v.FixedIn
				}
				sevColor(v.Severity).Fprintf(b, "    %s@%s (%s) %s%s\n",
					v.Package.Name, v.Package.Version, v.Severity, cves, fix)
			}
			fmt.Fprintln(b)
		}

		// Errors
		if len(r.Errors) > 0 {
			faint.Fprintf(b, "  Warnings (%d):\n", len(r.Errors))
			for _, e := range r.Errors {
				faint.Fprintf(b, "    • %s\n", e)
			}
			fmt.Fprintln(b)
		}

		if len(r.SecurityFindings) == 0 && len(r.Vulnerabilities) == 0 {
			green.Fprintln(b, "  ✓ No security issues found")
		}
	}

	// ── Summary ────────────────────────────────────────────────────────────
	if len(results) > 1 {
		bold.Fprintln(b, "\n── Summary ─────────────────────────────────────────────────────────")
		for _, r := range results {
			riskColor(r.RiskLevel).Fprintf(b, "  %-40s %s (%.2f)  vulns:%d  findings:%d\n",
				r.Ref.Original, strings.ToUpper(r.RiskLevel), r.RiskScore,
				len(r.Vulnerabilities), len(r.SecurityFindings))
		}
	}
}

// ── JSON formatter ────────────────────────────────────────────────────────────

type jsonReport struct {
	Timestamp   time.Time                    `json:"timestamp"`
	Images      []*container.ImageScanResult `json:"images,omitempty"`
	Dockerfile  string                       `json:"dockerfile,omitempty"`
	DFFindings  []container.SecurityFinding  `json:"dockerfile_findings,omitempty"`
}

func formatJSON(b *strings.Builder, results []*container.ImageScanResult, dfFindings []container.SecurityFinding, dfPath string) {
	r := jsonReport{
		Timestamp:  time.Now().UTC(),
		Images:     results,
		Dockerfile: dfPath,
		DFFindings: dfFindings,
	}
	enc := json.NewEncoder(b)
	enc.SetIndent("", "  ")
	_ = enc.Encode(r)
}

// ── SARIF formatter ───────────────────────────────────────────────────────────

type sarifOutput struct {
	Version string       `json:"version"`
	Schema  string       `json:"$schema"`
	Runs    []sarifRun   `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
}
type sarifResult struct {
	RuleID  string      `json:"ruleId"`
	Level   string      `json:"level"`
	Message sarifMessage `json:"message"`
}
type sarifMessage struct {
	Text string `json:"text"`
}

func formatSARIF(b *strings.Builder, results []*container.ImageScanResult, dfFindings []container.SecurityFinding) {
	var sarifResults []sarifResult

	for _, r := range results {
		for _, f := range r.SecurityFindings {
			sarifResults = append(sarifResults, sarifResult{
				RuleID:  f.ID,
				Level:   sevToSARIF(f.Severity),
				Message: sarifMessage{Text: fmt.Sprintf("[%s] %s: %s", r.Ref.Original, f.Title, f.Detail)},
			})
		}
		for _, v := range r.Vulnerabilities {
			sarifResults = append(sarifResults, sarifResult{
				RuleID:  "CVE",
				Level:   sevToSARIF(v.Severity),
				Message: sarifMessage{Text: fmt.Sprintf("[%s] %s@%s: %s",
					r.Ref.Original, v.Package.Name, v.Package.Version,
					strings.Join(v.CVEs, ", "))},
			})
		}
	}

	for _, f := range dfFindings {
		sarifResults = append(sarifResults, sarifResult{
			RuleID:  f.ID,
			Level:   sevToSARIF(f.Severity),
			Message: sarifMessage{Text: f.Title + ": " + f.Detail},
		})
	}

	out := sarifOutput{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "falcn", Version: "3.0.0",
			}},
			Results: sarifResults,
		}},
	}
	enc := json.NewEncoder(b)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

// ── Colour helpers ────────────────────────────────────────────────────────────

func sevColor(sev string) *color.Color {
	switch sev {
	case "critical":
		return red
	case "high":
		return color.New(color.FgRed)
	case "medium":
		return yellow
	case "low":
		return cyan
	default:
		return faint
	}
}

func riskColor(level string) *color.Color {
	switch level {
	case "critical", "high":
		return red
	case "medium":
		return yellow
	case "low":
		return cyan
	default:
		return green
	}
}

func sevToSARIF(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func shortDigest(d string) string {
	if len(d) > 19 {
		return d[:19] + "…"
	}
	return d
}

func orNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}
