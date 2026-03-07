package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/falcn-io/falcn/internal/analyzer"
	"github.com/falcn-io/falcn/internal/config"
	"github.com/falcn-io/falcn/pkg/types"
	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(fixCmd)
	fixCmd.Flags().StringP("input", "i", "", "Path to scan JSON output produced by falcn scan --output json (reads stdin if omitted)")
	fixCmd.Flags().BoolP("only-reachable", "r", false, "Show remediation only for vulnerabilities confirmed reachable from entry points")
	fixCmd.Flags().BoolP("script", "s", false, "Emit a shell script of remediation commands (one per line) instead of the full report")
	fixCmd.Flags().StringP("min-severity", "m", "low", "Minimum severity to include: low|medium|high|critical")
	fixCmd.Flags().BoolP("patch-file", "p", false, "Emit a machine-readable patch manifest (JSON) instead of a human report")
	fixCmd.Flags().Bool("apply", false, "Apply fixes directly to manifest files (modifies files in place)")
	fixCmd.Flags().Bool("dry-run", false, "Preview what --apply would change without writing files")
	fixCmd.Flags().String("project", ".", "Project root directory for locating manifest files with --apply")
}

var fixCmd = &cobra.Command{
	Use:   "fix [path]",
	Short: "Generate remediation commands for all fixable vulnerabilities found in a scan",
	Long: `falcn fix reads the JSON output of a previous "falcn scan" and produces
ecosystem-specific upgrade commands for every vulnerability that has a known
fixed version.

  # Pipe scan output directly
  falcn scan . --output json | falcn fix

  # Read from a saved report file
  falcn fix --input scan-report.json

  # Emit a shell script ready to execute
  falcn fix --input scan-report.json --script > fix.sh && bash fix.sh

  # Only show fixes for reachable CVEs (reduce noise)
  falcn fix --input scan-report.json --only-reachable

  # CI gate: fail if any high+ vulnerabilities have available fixes
  falcn fix --input scan-report.json --min-severity high
  echo $?  # non-zero when fixable high+ CVEs exist`,
	PreRunE: validateFixFlags,
	RunE:    runFix,
}

// validateFixFlags performs pre-flight validation before running fix.
func validateFixFlags(cmd *cobra.Command, args []string) error {
	// 1. If --input is provided, the file must exist.
	if inputFile, _ := cmd.Flags().GetString("input"); inputFile != "" {
		if _, err := os.Stat(inputFile); err != nil {
			return fmt.Errorf("input file %q does not exist: %w", inputFile, err)
		}
	}

	// 2. --min-severity must be a known value.
	if sev, _ := cmd.Flags().GetString("min-severity"); sev != "" {
		valid := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
		if !valid[strings.ToLower(sev)] {
			return fmt.Errorf("invalid --min-severity %q: must be one of: low, medium, high, critical", sev)
		}
	}

	// 3. --script and --patch-file are mutually exclusive output modes.
	script, _ := cmd.Flags().GetBool("script")
	patchFile, _ := cmd.Flags().GetBool("patch-file")
	if script && patchFile {
		return fmt.Errorf("--script and --patch-file are mutually exclusive: pick one output format")
	}

	return nil
}

// remediationEntry groups everything we know about one fixable threat.
type remediationEntry struct {
	pkg         string
	version     string
	registry    string
	fixedAt     string
	remediation string
	cves        []string
	severity    string
	reachable   *bool
	threatType  string
}

func runFix(cmd *cobra.Command, args []string) error {
	inputFile, _ := cmd.Flags().GetString("input")
	onlyReachable, _ := cmd.Flags().GetBool("only-reachable")
	scriptMode, _ := cmd.Flags().GetBool("script")
	minSeverityStr, _ := cmd.Flags().GetString("min-severity")
	patchFile, _ := cmd.Flags().GetBool("patch-file")
	apply, _ := cmd.Flags().GetBool("apply")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	projectRoot, _ := cmd.Flags().GetString("project")
	if len(args) > 0 && projectRoot == "." {
		projectRoot = args[0]
	}

	minSev := parseSeverity(minSeverityStr)

	// ------ Load threats -----------------------------------------------
	threats, err := loadThreats(cmd, inputFile, args)
	if err != nil {
		return err
	}

	// ------ Filter & deduplicate ----------------------------------------
	seen := map[string]bool{}
	var entries []remediationEntry

	for _, t := range threats {
		// Remediation command may be on Threat.FixedVersion or in Metadata["remediation"]
		remCmd := extractRemediation(t)
		fixedVer := t.FixedVersion

		if fixedVer == "" && remCmd == "" {
			continue // no known fix
		}
		if severityLevel(t.Severity) < minSev {
			continue
		}
		if onlyReachable && (t.Reachable == nil || !*t.Reachable) {
			continue
		}

		// Deduplicate by pkg+registry+fixedVersion
		key := fmt.Sprintf("%s|%s|%s", t.Package, t.Registry, fixedVer)
		if seen[key] {
			continue
		}
		seen[key] = true

		entries = append(entries, remediationEntry{
			pkg:         t.Package,
			version:     t.Version,
			registry:    t.Registry,
			fixedAt:     fixedVer,
			remediation: remCmd,
			cves:        t.CVEs,
			severity:    t.Severity.String(),
			reachable:   t.Reachable,
			threatType:  string(t.Type),
		})
	}

	// Sort: critical → high → medium → low, then alphabetical
	sort.Slice(entries, func(i, j int) bool {
		si := parseSeverity(entries[i].severity)
		sj := parseSeverity(entries[j].severity)
		if si != sj {
			return si > sj
		}
		return entries[i].pkg < entries[j].pkg
	})

	// ------ Output modes ------------------------------------------------
	if patchFile {
		return emitPatchManifest(entries)
	}
	if scriptMode {
		return emitScript(entries)
	}
	if err := emitHumanReport(entries); err != nil {
		if apply || dryRun {
			if applyErr := applyFixes(entries, projectRoot, dryRun); applyErr != nil {
				fmt.Fprintf(os.Stderr, "apply warning: %v\n", applyErr)
			}
		}
		return err
	}
	if apply || dryRun {
		if applyErr := applyFixes(entries, projectRoot, dryRun); applyErr != nil {
			fmt.Fprintf(os.Stderr, "apply warning: %v\n", applyErr)
		}
	}
	return nil
}

// loadThreats reads threats from a JSON scan report or runs a quick scan.
func loadThreats(cmd *cobra.Command, inputFile string, args []string) ([]types.Threat, error) {
	// Option A: read from file / stdin
	if inputFile != "" || len(args) == 0 {
		var r io.Reader
		if inputFile != "" {
			f, err := os.Open(inputFile)
			if err != nil {
				return nil, fmt.Errorf("open %s: %w", inputFile, err)
			}
			defer f.Close()
			r = f
		} else {
			// Check if stdin has data
			stat, _ := os.Stdin.Stat()
			if stat.Mode()&os.ModeCharDevice != 0 {
				return nil, fmt.Errorf("no input: provide --input <file> or pipe 'falcn scan . --output json | falcn fix'")
			}
			r = os.Stdin
		}
		return parseThreatsFromJSON(r)
	}

	// Option B: run a fresh scan on the supplied path
	projectPath := args[0]
	fmt.Fprintf(os.Stderr, "Running scan on %s...\n", projectPath)
	result, err := runQuickScan(projectPath)
	if err != nil {
		return nil, err
	}
	return result.Threats, nil
}

// parseThreatsFromJSON extracts threats from various JSON shapes the scanner can emit.
func parseThreatsFromJSON(r io.Reader) ([]types.Threat, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}

	// Try analyzer.ScanResult first (most common from falcn scan --output json)
	var ar analyzer.ScanResult
	if err := json.Unmarshal(data, &ar); err == nil && len(ar.Threats) > 0 {
		return ar.Threats, nil
	}

	// Try a flat array of threats
	var threats []types.Threat
	if err := json.Unmarshal(data, &threats); err == nil && len(threats) > 0 {
		return threats, nil
	}

	// Try a generic map with a "threats" key
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err == nil {
		if threatsJSON, ok := raw["threats"]; ok {
			if err := json.Unmarshal(threatsJSON, &threats); err == nil {
				return threats, nil
			}
		}
	}

	return nil, fmt.Errorf("could not parse scan output: unrecognised JSON shape")
}

// runQuickScan does an inline scan when a path is given instead of a report file.
func runQuickScan(projectPath string) (*analyzer.ScanResult, error) {
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	a, err := analyzer.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("create analyzer: %w", err)
	}
	opts := &analyzer.ScanOptions{
		CheckVulnerabilities: true,
		DisableLLM:           true, // fast mode for fix command
		MaxLLMCalls:          0,
	}
	return a.Scan(projectPath, opts)
}

// emitHumanReport prints a rich table report.
func emitHumanReport(entries []remediationEntry) error {
	if len(entries) == 0 {
		fmt.Println("✅  No fixable vulnerabilities found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "\n%s\t%s\t%s\t%s\t%s\n",
		"SEVERITY", "PACKAGE", "CURRENT", "FIXED IN", "CVEs")
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
		strings.Repeat("─", 8),
		strings.Repeat("─", 30),
		strings.Repeat("─", 12),
		strings.Repeat("─", 12),
		strings.Repeat("─", 20))

	for _, e := range entries {
		reachTag := ""
		if e.reachable != nil {
			if *e.reachable {
				reachTag = " [reachable]"
			} else {
				reachTag = " [unreachable]"
			}
		}
		cveStr := strings.Join(e.cves, ", ")
		if len(cveStr) > 30 {
			cveStr = cveStr[:27] + "..."
		}
		fmt.Fprintf(w, "%s%s\t%s\t%s\t%s\t%s\n",
			strings.ToUpper(e.severity), reachTag,
			e.pkg, e.version, e.fixedAt, cveStr)
	}
	w.Flush()

	fmt.Printf("\n📋  %d fixable package(s). Remediation commands:\n\n", len(entries))
	for _, e := range entries {
		if e.remediation != "" {
			fmt.Printf("  %s\n", e.remediation)
		} else if e.fixedAt != "" {
			fmt.Printf("  # upgrade %s to %s\n", e.pkg, e.fixedAt)
		}
	}
	fmt.Println()

	if anyUnfixed := len(entries) > 0; anyUnfixed {
		return fmt.Errorf("found %d fixable vulnerabilities", len(entries))
	}
	return nil
}

// emitScript prints bare remediation commands, one per line — suitable for piping to bash.
func emitScript(entries []remediationEntry) error {
	if len(entries) == 0 {
		return nil
	}
	fmt.Println("#!/usr/bin/env bash")
	fmt.Println("set -euo pipefail")
	fmt.Println("# Auto-generated by falcn fix")
	fmt.Println()
	byRegistry := map[string][]remediationEntry{}
	for _, e := range entries {
		byRegistry[e.registry] = append(byRegistry[e.registry], e)
	}
	for reg, es := range byRegistry {
		fmt.Printf("# --- %s ---\n", reg)
		for _, e := range es {
			if e.remediation != "" {
				fmt.Println(e.remediation)
			}
		}
	}
	return nil
}

// PatchManifest is the machine-readable patch output format.
type PatchManifest struct {
	TotalFixes int           `json:"total_fixes"`
	Fixes      []PatchEntry  `json:"fixes"`
}

// PatchEntry describes a single package upgrade.
type PatchEntry struct {
	Package     string   `json:"package"`
	Registry    string   `json:"registry"`
	FromVersion string   `json:"from_version"`
	ToVersion   string   `json:"to_version"`
	Command     string   `json:"command"`
	CVEs        []string `json:"cves,omitempty"`
	Severity    string   `json:"severity"`
	Reachable   *bool    `json:"reachable,omitempty"`
}

func emitPatchManifest(entries []remediationEntry) error {
	m := PatchManifest{TotalFixes: len(entries)}
	for _, e := range entries {
		m.Fixes = append(m.Fixes, PatchEntry{
			Package:     e.pkg,
			Registry:    e.registry,
			FromVersion: e.version,
			ToVersion:   e.fixedAt,
			Command:     e.remediation,
			CVEs:        e.cves,
			Severity:    e.severity,
			Reachable:   e.reachable,
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// extractRemediation returns the ecosystem-specific remediation command for a threat.
// The command may live in t.Metadata["remediation"] (set by the analyzer) or can be
// derived on the fly from t.FixedVersion when that field is populated.
func extractRemediation(t types.Threat) string {
	// Primary source: metadata["remediation"] written by analyzer.go
	if t.Metadata != nil {
		if v, ok := t.Metadata["remediation"]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	// Fallback: derive from FixedVersion if present
	if t.FixedVersion == "" {
		return ""
	}
	pkg, ver, reg := t.Package, t.FixedVersion, strings.ToLower(t.Registry)
	switch reg {
	case "npm":
		return fmt.Sprintf("npm install %s@%s", pkg, ver)
	case "pypi":
		return fmt.Sprintf("pip install \"%s==%s\"", pkg, ver)
	case "go":
		return fmt.Sprintf("go get %s@v%s", pkg, ver)
	case "maven":
		return fmt.Sprintf("# Update %s to %s in pom.xml / build.gradle", pkg, ver)
	case "nuget":
		return fmt.Sprintf("dotnet add package %s --version %s", pkg, ver)
	case "rubygems":
		return fmt.Sprintf("gem install %s -v %s", pkg, ver)
	case "crates.io":
		return fmt.Sprintf("# Update %s to \"%s\" in Cargo.toml", pkg, ver)
	case "packagist":
		return fmt.Sprintf("composer require %s:%s", pkg, ver)
	default:
		return fmt.Sprintf("# Upgrade %s to %s", pkg, ver)
	}
}

func parseSeverity(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func severityLevel(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 4
	case types.SeverityHigh:
		return 3
	case types.SeverityMedium:
		return 2
	default:
		return 1
	}
}


// applyFixes writes package version updates directly to manifest files.
func applyFixes(entries []remediationEntry, projectRoot string, dryRun bool) error {
	if len(entries) == 0 {
		return nil
	}

	absRoot, err := filepath.Abs(projectRoot)
	if err != nil {
		return fmt.Errorf("resolve project root: %w", err)
	}

	mode := "Applying"
	if dryRun {
		mode = "Dry-run"
	}
	fmt.Printf("\n%s fixes in %s:\n", mode, absRoot)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	var applied int
	var errs []string

	for _, e := range entries {
		if e.fixedAt == "" {
			continue
		}
		registry := strings.ToLower(e.registry)
		var manifestFile, changeDesc string
		var applyErr error

		switch registry {
		case "npm", "node", "nodejs":
			manifestFile = "package.json"
			changeDesc, applyErr = applyNPMFix(absRoot, e.pkg, e.fixedAt, dryRun)
		case "pypi", "python", "pip":
			manifestFile = "requirements.txt"
			changeDesc, applyErr = applyPyPIFix(absRoot, e.pkg, e.fixedAt, dryRun)
		case "go", "golang":
			manifestFile = "go.mod"
			changeDesc, applyErr = applyGoFix(absRoot, e.pkg, e.fixedAt, dryRun)
		case "cargo", "rust", "crates.io":
			manifestFile = "Cargo.toml"
			changeDesc, applyErr = applyCargoFix(absRoot, e.pkg, e.fixedAt, dryRun)
		default:
			// For other ecosystems, just print the remediation command
			manifestFile = "(manual)"
			changeDesc = e.remediation
			if !dryRun && e.remediation != "" && !strings.HasPrefix(e.remediation, "#") {
				applyErr = runShellCommand(absRoot, e.remediation)
			}
		}

		if applyErr != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", e.pkg, applyErr))
			fmt.Fprintf(w, "  \u2716\t%s\t%s %s \u2192 %s\t%v\n", manifestFile, e.pkg, e.version, e.fixedAt, applyErr)
		} else {
			_ = changeDesc
			fmt.Fprintf(w, "  \u2714\t%s\t%s %s \u2192 %s\n", manifestFile, e.pkg, e.version, e.fixedAt)
			applied++
		}
	}
	w.Flush()

	if dryRun {
		fmt.Printf("\n%d fix(es) would be applied. Run without --dry-run to write changes.\n", applied)
	} else {
		fmt.Printf("\n%d fix(es) applied.\n", applied)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d fix(es) failed: %s", len(errs), strings.Join(errs, "; "))
	}
	return nil
}

// applyNPMFix updates a package version in package.json.
func applyNPMFix(root, pkg, fixedAt string, dryRun bool) (string, error) {
	pkgFile := filepath.Join(root, "package.json")
	data, err := os.ReadFile(pkgFile)
	if err != nil {
		return "", fmt.Errorf("read package.json: %w", err)
	}

	var manifest map[string]interface{}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", fmt.Errorf("parse package.json: %w", err)
	}

	updated := false
	depSections := []string{"dependencies", "devDependencies", "peerDependencies", "optionalDependencies"}
	for _, section := range depSections {
		if deps, ok := manifest[section].(map[string]interface{}); ok {
			if _, exists := deps[pkg]; exists {
				deps[pkg] = "^" + fixedAt
				updated = true
			}
		}
	}
	if !updated {
		return "", fmt.Errorf("package %q not found in package.json", pkg)
	}
	if dryRun {
		return fmt.Sprintf("package.json: %s \u2192 ^%s", pkg, fixedAt), nil
	}
	out, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal package.json: %w", err)
	}
	return "", os.WriteFile(pkgFile, append(out, '\n'), 0600)
}

// applyPyPIFix updates a package version in requirements.txt.
func applyPyPIFix(root, pkg, fixedAt string, dryRun bool) (string, error) {
	// Try requirements.txt first, then requirements-*.txt
	candidates := []string{"requirements.txt", "requirements-prod.txt", "requirements-base.txt"}
	for _, filename := range candidates {
		reqFile := filepath.Join(root, filename)
		data, err := os.ReadFile(reqFile)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		// Match: package, Package, PACKAGE (case-insensitive), with or without version spec
		re := regexp.MustCompile(`(?i)^(` + regexp.QuoteMeta(pkg) + `)\s*([>=<~!].*)$`)
		rePlain := regexp.MustCompile(`(?i)^(` + regexp.QuoteMeta(pkg) + `)\s*$`)
		updated := false
		for i, line := range lines {
			if re.MatchString(line) {
				lines[i] = pkg + "==" + fixedAt
				updated = true
			} else if rePlain.MatchString(line) {
				lines[i] = pkg + "==" + fixedAt
				updated = true
			}
		}
		if updated {
			if dryRun {
				return fmt.Sprintf("%s: %s \u2192 ==%s", filename, pkg, fixedAt), nil
			}
			return "", os.WriteFile(reqFile, []byte(strings.Join(lines, "\n")), 0600)
		}
	}
	return "", fmt.Errorf("package %q not found in requirements files", pkg)
}

// applyGoFix runs `go get pkg@vFixedAt` in the project root.
func applyGoFix(root, pkg, fixedAt string, dryRun bool) (string, error) {
	target := pkg + "@v" + fixedAt
	if dryRun {
		return fmt.Sprintf("go get %s", target), nil
	}
	return "", runShellCommand(root, "go get "+target)
}

// applyCargoFix updates a package version in Cargo.toml using sed-style replacement.
func applyCargoFix(root, pkg, fixedAt string, dryRun bool) (string, error) {
	cargoFile := filepath.Join(root, "Cargo.toml")
	data, err := os.ReadFile(cargoFile)
	if err != nil {
		return "", fmt.Errorf("read Cargo.toml: %w", err)
	}
	re := regexp.MustCompile(`(?m)^(` + regexp.QuoteMeta(pkg) + `\s*=\s*)".+"`)
	newContent := re.ReplaceAllString(string(data), `${1}"`+fixedAt+`"`)
	if newContent == string(data) {
		return "", fmt.Errorf("package %q not found in Cargo.toml", pkg)
	}
	if dryRun {
		return fmt.Sprintf("Cargo.toml: %s \u2192 %s", pkg, fixedAt), nil
	}
	return "", os.WriteFile(cargoFile, []byte(newContent), 0600)
}

// runShellCommand executes a shell command in the given directory.
func runShellCommand(dir, command string) error {
	cmd := exec.Command("sh", "-c", command)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
