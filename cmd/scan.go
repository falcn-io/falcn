package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/falcn-io/falcn/internal/analyzer"
	"github.com/falcn-io/falcn/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Scan command constants — avoid magic numbers in flag definitions.
const (
	defaultSimilarityThreshold = 0.8 // typosquatting detection similarity threshold
	defaultMaxLLMCalls         = 0   // 0 = unlimited LLM explanation calls
)

func init() {
	RootCmd.AddCommand(scanCmd)
}

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a project for typosquatting and malicious packages (auto-detects project types)",
	Long: `Scan a project directory for typosquatting and malicious packages.

Falcn automatically detects project types (Node.js, Python, Go, Rust, Java, .NET, PHP, Ruby)
based on manifest files and creates appropriate registry connectors. Use --recursive for monorepos
and multi-project directories. Specify --package-manager to limit scanning to specific ecosystems.`,
	Args:    cobra.MaximumNArgs(1),
	PreRunE: validateScanFlags,
	RunE:    runScan,
}

// validateScanFlags performs pre-flight validation before the scan runs.
func validateScanFlags(cmd *cobra.Command, args []string) error {
	// 1. Validate the target path (if provided).
	if len(args) > 0 {
		fi, err := os.Stat(args[0])
		if err != nil {
			return fmt.Errorf("path %q does not exist or is not accessible: %w", args[0], err)
		}
		specificFile, _ := cmd.Flags().GetString("file")
		if !fi.IsDir() && specificFile == "" {
			return fmt.Errorf("path %q is a file, not a directory — use --file to scan a specific manifest file", args[0])
		}
	}

	// 2. Validate --file flag (if set, the file must exist).
	if specificFile, _ := cmd.Flags().GetString("file"); specificFile != "" {
		if _, err := os.Stat(specificFile); err != nil {
			return fmt.Errorf("manifest file %q does not exist: %w", specificFile, err)
		}
	}

	// 3. Validate --sbom-format value.
	if sbomFmt, _ := cmd.Flags().GetString("sbom-format"); sbomFmt != "" {
		validFormats := map[string]bool{"spdx": true, "cyclonedx": true}
		if !validFormats[strings.ToLower(sbomFmt)] {
			return fmt.Errorf("invalid --sbom-format %q: must be one of: spdx, cyclonedx", sbomFmt)
		}
	}

	// 4. Validate --threshold range.
	if t, _ := cmd.Flags().GetFloat64("threshold"); t < 0.0 || t > 1.0 {
		return fmt.Errorf("invalid --threshold %.2f: must be between 0.0 and 1.0", t)
	}

	// 5. Validate --registry value.
	validRegistries := map[string]bool{
		"npm": true, "pypi": true, "go": true, "maven": true,
		"cargo": true, "rubygems": true, "composer": true, "nuget": true, "": true,
	}
	if reg, _ := cmd.Flags().GetString("registry"); !validRegistries[strings.ToLower(reg)] {
		return fmt.Errorf("invalid --registry %q: must be one of: npm, pypi, go, maven, cargo, rubygems, composer, nuget", reg)
	}

	// 6. Validate --local-db path when --offline is set.
	if offline, _ := cmd.Flags().GetBool("offline"); offline {
		if localDB, _ := cmd.Flags().GetString("local-db"); localDB != "" {
			if _, err := os.Stat(localDB); err != nil {
				return fmt.Errorf("local CVE database %q does not exist (required for --offline mode): %w", localDB, err)
			}
		}
	}

	return nil
}

func init() {
	// Scan command flags
	scanCmd.Flags().Bool("deep", false, "Enable deep analysis")
	scanCmd.Flags().Bool("include-dev", false, "Include development dependencies")
	scanCmd.Flags().Float64("threshold", defaultSimilarityThreshold, "Similarity threshold for detection")
	scanCmd.Flags().StringSlice("exclude", []string{}, "Packages to exclude from scan")
	scanCmd.Flags().String("file", "", "Specific dependency file to scan")
	scanCmd.Flags().Bool("check-vulnerabilities", false, "Enable vulnerability checking")
	scanCmd.Flags().StringSlice("vulnerability-db", []string{"osv", "nvd"}, "Vulnerability databases to use (osv, github, nvd)")
	scanCmd.Flags().String("vuln-config", "config/vulnerability_databases.yaml", "Path to vulnerability database configuration")
	// Recursive scanning flags
	scanCmd.Flags().Bool("recursive", false, "Enable recursive scanning for monorepos and multi-project directories")
	scanCmd.Flags().Bool("workspace-aware", false, "Enable workspace-aware scanning for monorepos")
	scanCmd.Flags().Bool("consolidate-report", false, "Generate consolidated report for multi-project scans")
	scanCmd.Flags().StringSlice("package-manager", []string{}, "Specific package managers to scan (npm, pypi, maven, nuget, rubygems, go, cargo, composer). Auto-detects if not specified")
	scanCmd.Flags().String("registry", "", "Force registry/package manager (npm, pypi, go, maven, cargo, rubygems, composer)")
	// SBOM generation flags
	scanCmd.Flags().String("sbom-format", "", "Generate SBOM in specified format (spdx, cyclonedx)")
	scanCmd.Flags().String("sbom-output", "", "Output file path for SBOM (if not specified, prints to stdout)")
	// Enhanced supply chain analysis flags
	scanCmd.Flags().Bool("supply-chain", false, "Enable enhanced supply chain analysis")
	scanCmd.Flags().Bool("advanced", false, "Enable advanced analysis features")
	// Content scanning flags
	scanCmd.Flags().Float64("content-entropy-threshold", 0, "Content scanning entropy threshold (override)")
	scanCmd.Flags().Int("content-entropy-window", 0, "Content scanning entropy window size")
	scanCmd.Flags().StringSlice("content-include", []string{}, "Content scanning include globs")
	scanCmd.Flags().StringSlice("content-exclude", []string{}, "Content scanning exclude globs")
	scanCmd.Flags().StringSlice("content-whitelist", []string{}, "Content scanning whitelist extensions")
	scanCmd.Flags().Int("content-max-files", 0, "Content scanning max files to process")
	scanCmd.Flags().Int("content-max-workers", 0, "Content scanning max workers")
	// Reliability & Control flags
	scanCmd.Flags().Bool("no-llm", false, "Disable LLM (AI) explanations")
	scanCmd.Flags().Int("max-llm-calls", 10, "Maximum number of LLM explanations to generate")
	scanCmd.Flags().Bool("no-sandbox", false, "Disable dynamic analysis (sandboxing)")
	// Offline / air-gap flags
	scanCmd.Flags().Bool("offline", false, "Use local SQLite CVE database instead of live network APIs (air-gap mode). Also activated by FALCN_OFFLINE=true env var.")
	scanCmd.Flags().String("local-db", "", "Path to local CVE database for --offline mode (default: ~/.local/share/falcn/cve.db)")
}

func runScan(cmd *cobra.Command, args []string) error {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	// Load configuration
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		// Create default config if loading fails
		cfg = createDefaultConfig()
		if verbose {
			log.Printf("Using default config: %v", err)
		}
	}

	// Create analyzer
	analyzerInstance, err := analyzer.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create analyzer: %v", err)
	}

	// Get scan options from flags
	deepAnalysis, _ := cmd.Flags().GetBool("deep")
	includeDevDeps, _ := cmd.Flags().GetBool("include-dev")
	threshold, _ := cmd.Flags().GetFloat64("threshold")
	excludePackages, _ := cmd.Flags().GetStringSlice("exclude")
	specificFile, _ := cmd.Flags().GetString("file")
	checkVulnerabilities, _ := cmd.Flags().GetBool("check-vulnerabilities")
	vulnerabilityDBs, _ := cmd.Flags().GetStringSlice("vulnerability-db")
	vulnConfig, _ := cmd.Flags().GetString("vuln-config")
	sbomFormat, _ := cmd.Flags().GetString("sbom-format")
	sbomOutput, _ := cmd.Flags().GetString("sbom-output")
	// Recursive scanning options
	recursive, _ := cmd.Flags().GetBool("recursive")
	workspaceAware, _ := cmd.Flags().GetBool("workspace-aware")
	consolidateReport, _ := cmd.Flags().GetBool("consolidate-report")
	packageManagers, _ := cmd.Flags().GetStringSlice("package-manager")
	registryOverride, _ := cmd.Flags().GetString("registry")
	// Enhanced supply chain analysis options
	enableSupplyChain, _ := cmd.Flags().GetBool("supply-chain")
	advancedAnalysis, _ := cmd.Flags().GetBool("advanced")
	// Content flags mapping to config
	if v, _ := cmd.Flags().GetFloat64("content-entropy-threshold"); v > 0 {
		viper.Set("scanner.content.entropy_threshold", v)
	}
	if v, _ := cmd.Flags().GetInt("content-entropy-window"); v > 0 {
		viper.Set("scanner.content.entropy_window", v)
	}
	if v, _ := cmd.Flags().GetStringSlice("content-include"); len(v) > 0 {
		viper.Set("scanner.content.include_globs", v)
	}
	if v, _ := cmd.Flags().GetStringSlice("content-exclude"); len(v) > 0 {
		viper.Set("scanner.content.exclude_globs", v)
	}
	if v, _ := cmd.Flags().GetStringSlice("content-whitelist"); len(v) > 0 {
		viper.Set("scanner.content.whitelist_extensions", v)
	}
	if v, _ := cmd.Flags().GetInt("content-max-files"); v > 0 {
		viper.Set("scanner.content.max_files", v)
	}
	if v, _ := cmd.Flags().GetInt("content-max-workers"); v > 0 {
		viper.Set("scanner.content.max_workers", v)
	}

	// Get reliability options
	disableLLM, _ := cmd.Flags().GetBool("no-llm")
	maxLLMCalls, _ := cmd.Flags().GetInt("max-llm-calls")
	disableSandbox, _ := cmd.Flags().GetBool("no-sandbox")

	// Get offline / air-gap options
	offlineMode, _ := cmd.Flags().GetBool("offline")
	localDBPath, _ := cmd.Flags().GetString("local-db")

	options := &analyzer.ScanOptions{
		OutputFormat:           outputFormat,
		SpecificFile:           specificFile,
		DeepAnalysis:           deepAnalysis,
		IncludeDevDependencies: includeDevDeps,
		SimilarityThreshold:    threshold,
		ExcludePackages:        excludePackages,
		AllowEmptyProjects:     true,
		CheckVulnerabilities:   checkVulnerabilities,
		VulnerabilityDBs:       vulnerabilityDBs,
		VulnConfigPath:         vulnConfig,
		Recursive:              recursive,
		WorkspaceAware:         workspaceAware,
		ConsolidateReport:      consolidateReport,
		PackageManagers:        packageManagers,
		EnableSupplyChain:      enableSupplyChain,
		AdvancedAnalysis:       advancedAnalysis,
		DisableLLM:             disableLLM,
		MaxLLMCalls:            maxLLMCalls,
		DisableSandbox:         disableSandbox,
		OfflineMode:            offlineMode,
		LocalDBPath:            localDBPath,
	}

	// Map registry override to packageManagers if provided
	if registryOverride != "" {
		options.PackageManagers = []string{strings.ToLower(registryOverride)}
	}

	// Suppress logrus output for graph formats to prevent pollution
	graphFormats := []string{"dot", "svg", "mermaid"}
	for _, format := range graphFormats {
		if outputFormat == format {
			logrus.SetLevel(logrus.FatalLevel)
			break
		}
	}

	// Perform scan
	result, err := analyzerInstance.Scan(path, options)
	if err != nil {
		return fmt.Errorf("scan failed: %v", err)
	}

	// Save scan results to database if database is configured
	if dbErr := saveScanToDatabase(result, path); dbErr != nil {
		log.Printf("Warning: Failed to save scan to database: %v", dbErr)
	}

	// Always save to local JSON for report command
	if jsonBytes, err := json.MarshalIndent(result, "", "  "); err == nil {
		_ = os.WriteFile("falcn_report.json", jsonBytes, 0600)
	}

	// Handle SBOM generation if requested
	if sbomFormat != "" {
		outputSBOMWithFile(result, sbomFormat, sbomOutput)
		return nil
	}

	// Output results
	outputScanResult(result, outputFormat)
	return nil
}
