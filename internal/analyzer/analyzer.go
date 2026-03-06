package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/falcn-io/falcn/internal/cache"
	"github.com/falcn-io/falcn/internal/config"
	"github.com/falcn-io/falcn/internal/detector"
	"github.com/falcn-io/falcn/internal/edge"
	"github.com/falcn-io/falcn/internal/llm"
	"github.com/falcn-io/falcn/internal/registry"
	"github.com/falcn-io/falcn/internal/scanner"
	"github.com/falcn-io/falcn/internal/vulnerability"
	"github.com/falcn-io/falcn/pkg/types"
	"github.com/sirupsen/logrus"
)

// explanationCache is a minimal interface so we don't import the full cache package here.
type explanationCache interface {
	Get(key string) (interface{}, bool)
	Set(key string, value interface{}, ttl time.Duration)
}

// Analyzer orchestrates the security scanning process
type Analyzer struct {
	config       *config.Config
	detector     *detector.Engine
	registries   map[string]registry.Connector
	resolver     *DependencyResolver
	autoDetector *scanner.AutoDetector
	factory      *registry.Factory
	stubRepo     *StubRepo
	llmProvider  llm.Provider
	explainCache explanationCache // explanation cache keyed by {pkg}:{ver}:{type}
}

// ScanOptions contains options for scanning
type ScanOptions struct {
	OutputFormat           string
	SpecificFile           string
	DeepAnalysis           bool
	IncludeDevDependencies bool
	SimilarityThreshold    float64
	ExcludePackages        []string
	AllowEmptyProjects     bool
	CheckVulnerabilities   bool
	VulnerabilityDBs       []string
	VulnConfigPath         string
	// Recursive scanning options
	Recursive         bool
	WorkspaceAware    bool
	ConsolidateReport bool
	PackageManagers   []string
	// Supply chain analysis options
	// Supply chain analysis options
	EnableSupplyChain bool
	AdvancedAnalysis  bool
	// Reliability & Control options
	DisableLLM     bool // Force disable LLM even if configured
	MaxLLMCalls    int  // Max number of explanations to generate (rate limit)
	DisableSandbox bool // Force disable active sandboxing
	// Offline / air-gap options
	OfflineMode bool   // Use local SQLite CVE database instead of network calls
	LocalDBPath string // Path to local CVE database; DefaultLocalDBPath() used if empty
}

// ScanResult contains the results of a security scan
type ScanResult struct {
	ScanID        string                 `json:"scan_id"`
	Timestamp     time.Time              `json:"timestamp"`
	Duration      time.Duration          `json:"duration"`
	Path          string                 `json:"path"`
	TotalPackages int                    `json:"total_packages"`
	Packages      []types.Package        `json:"packages,omitempty"` // Added for architecture unification
	Threats       []types.Threat         `json:"threats"`
	Warnings      []types.Warning        `json:"warnings"`
	Resolution    *ResolutionResult      `json:"resolution,omitempty"`
	Summary       ScanSummary            `json:"summary"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ScanSummary provides a high-level overview of scan results
type ScanSummary struct {
	CriticalThreats int `json:"critical_threats"`
	HighThreats     int `json:"high_threats"`
	MediumThreats   int `json:"medium_threats"`
	LowThreats      int `json:"low_threats"`
	TotalWarnings   int `json:"total_warnings"`
	CleanPackages   int `json:"clean_packages"`
	ConflictCount   int `json:"conflict_count"`
}

// New creates a new analyzer instance
func New(cfg *config.Config) (*Analyzer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Initialize detector engine
	detectorEngine := detector.New(cfg)

	// Initialize dependency resolver
	resolver := NewDependencyResolver(cfg.Scanner)

	// Initialize registry factory and auto-detector
	factory := registry.NewFactory()
	autoDetector := scanner.NewAutoDetector()

	// Initialize LLM provider with guardrails
	var llmProvider llm.Provider
	if cfg.LLM != nil && cfg.LLM.Enabled {
		rawProvider, err := llm.NewProvider(*cfg.LLM)
		if err != nil {
			logrus.Warnf("Failed to initialize LLM provider: %v. AI explanations disabled.", err)
		} else {
			llmProvider = llm.NewSafeProvider(rawProvider)
			logrus.Infof("LLM Provider (%s) initialized with Guardrails", rawProvider.ID())
		}
	}

	return &Analyzer{
		config:       cfg,
		detector:     detectorEngine,
		resolver:     resolver,
		autoDetector: autoDetector,
		factory:      factory,
		registries:   make(map[string]registry.Connector),
		llmProvider:    llmProvider,
		explainCache:  cache.NewMemoryCache(),
	}, nil
}

// Scan performs a security scan of the specified path
func (a *Analyzer) Scan(path string, options *ScanOptions) (*ScanResult, error) {
	start := time.Now()
	scanID := generateScanID()

	logrus.Infof("Starting scan %s for path: %s", scanID, path)

	// Handle enhanced supply chain scanning
	if options.EnableSupplyChain {
		return a.scanWithSupplyChain(path, options)
	}

	// Initialize scan result
	result := &ScanResult{
		ScanID:    scanID,
		Timestamp: start,
		Path:      path,
		Metadata:  make(map[string]interface{}),
	}

	// Handle recursive scanning
	if options.Recursive {
		return a.scanRecursive(path, options, result)
	}

	// Use Scanner for discovery and parsing (Architecture Unification)
	scannerInstance, err := scanner.New(a.config)
	if err != nil {
		return nil, fmt.Errorf("failed to create scanner: %w", err)
	}

	// Check if the path is a valid project (using the public DetectProject)
	if _, err := scannerInstance.DetectProject(path); err != nil {
		if options.AllowEmptyProjects {
			logrus.Infof("No project detected in %s: %v", path, err)
			result.TotalPackages = 0
			result.Duration = time.Since(start)
			return result, nil
		}
		return nil, fmt.Errorf("no supported project found in %s: %w", path, err)
	}

	// Run ScanProject to get packages
	scanRes, err := scannerInstance.ScanProject(context.Background(), path)
	if err != nil {
		return nil, fmt.Errorf("scanner failed: %w", err)
	}

	// Map generic Packages to Analyzer's flow
	// ScanProject returns *types.ScanResult which has Packages []*types.Package
	// We need to convert []*types.Package to []types.Dependency for Resolver/Detector validation logic
	// But Scanner.ScanProject ALREADY runs threat detection (it calls analyzePackageThreats).
	// Currently Analyzer also runs `detectThreats` using `a.detector`.
	// Analyzer's detector might have different logic?
	// `Scanner` uses `detectors` (not `internal/detector`?)
	// `Scanner` calls `s.analyzePackageThreats`.

	// IF we rely on Scanner, we take its results.
	// But Analyzer has `Resolver`. Scanner does not run resolver.
	// So we should extract packages, run resolver, then maybe run EXTRA detection if needed.

	// Extract packages from scan result
	var packages []types.Package
	var dependencies []types.Dependency

	for _, pkg := range scanRes.Packages {
		packages = append(packages, *pkg)

		// Create Dependency representation for compatibility with legacy Analyzer logic
		dep := types.Dependency{
			Name:     pkg.Name,
			Version:  pkg.Version,
			Registry: pkg.Registry,
			Source:   "scanner", // unknown source file if not provided by package
			Direct:   true,      // assume direct for now or check metadata
		}
		dependencies = append(dependencies, dep)
	}

	result.TotalPackages = len(packages)
	result.Packages = packages
	logrus.Infof("Scanner found %d packages", len(packages))

	// Filter excluded packages
	filteredDeps := a.filterDependencies(dependencies, options.ExcludePackages)

	// Resolve dependencies and detect conflicts
	var resolution *ResolutionResult
	if a.resolver != nil {
		resolution, err = a.resolver.ResolveDependencies(filteredDeps)
		if err != nil {
			logrus.Warnf("Dependency resolution failed: %v", err)
		} else {
			result.Resolution = resolution
			result.Summary.ConflictCount = len(resolution.Conflicts)
		}
	}

	// Detect threats using Analyzer's detector (if separate from Scanner's)
	// Scanner.ScanProject already populates Threats in Packages.
	// We should merge them or just trust Scanner?
	// Analyzer uses `a.detectThreats`. This uses `internal/detector`.
	// Scanner uses `analyzers` and simple heuristics?
	// `Scanner` structure has `analyzers`.

	// Let's run Analyzer's `detectThreats` as well for now to ensure we don't lose coverage.
	// But we should use the dependencies.
	threats, warnings, err := a.detectThreats(context.Background(), filteredDeps, options)
	if err != nil {
		return nil, fmt.Errorf("threat detection failed: %w", err)
	}

	// Merge threats from Scanner?
	// scanRes.Packages has threats.
	for _, pkg := range scanRes.Packages {
		if len(pkg.Threats) > 0 {
			result.Threats = append(result.Threats, pkg.Threats...)
		}
	}

	result.Threats = append(result.Threats, threats...)
	result.Warnings = append(result.Warnings, warnings...)

	result.Duration = time.Since(start)
	result.Summary = a.calculateSummary(result.Threats, result.Warnings, result.TotalPackages)

	// Populate resolution in summary if available
	if resolution != nil {
		result.Summary.ConflictCount = len(resolution.Conflicts)
	}

	logrus.Infof("Scan completed in %v", result.Duration)
	return result, nil
}

// ScanPackage performs a security scan on a single package (for integration tests)
func (a *Analyzer) ScanPackage(ctx context.Context, pkg *types.Package) (*types.ScanResult, error) {
	start := time.Now()
	scanID := generateScanID()

	logrus.Infof("Starting package scan %s for package: %s@%s", scanID, pkg.Name, pkg.Version)

	// Create dependency from package
	var metadata types.PackageMetadata
	if pkg.Metadata != nil {
		metadata = *pkg.Metadata
	} else {
		metadata = types.PackageMetadata{
			Name:     pkg.Name,
			Version:  pkg.Version,
			Registry: pkg.Registry,
		}
	}

	dep := types.Dependency{
		Name:     pkg.Name,
		Version:  pkg.Version,
		Registry: pkg.Registry,
		Direct:   true,
		Metadata: metadata,
	}

	// Perform threat detection on single package
	threats, warnings, err := a.detectThreats(ctx, []types.Dependency{dep}, &ScanOptions{
		DeepAnalysis:           true,
		IncludeDevDependencies: false,
		SimilarityThreshold:    0.8,
		CheckVulnerabilities:   true,
		VulnerabilityDBs:       []string{"osv"}, // Use OSV database for testing
	})
	if err != nil {
		return nil, fmt.Errorf("threat detection failed: %w", err)
	}

	// Calculate risk score
	riskScore := a.calculateRiskScore(threats, 1)
	overallRisk := a.determineOverallRisk(riskScore)

	// Create summary with engines used
	enginesUsed := []string{"typosquatting", "homoglyph", "semantic"}
	if len(threats) > 0 {
		enginesUsed = append(enginesUsed, "vulnerability")
	}

	summary := &types.ScanSummary{
		TotalPackages:   1,
		ScannedPackages: 1,
		CleanPackages:   0,
		TotalThreats:    len(threats),
		TotalWarnings:   len(warnings),
		ThreatsFound:    len(threats),
		EnginesUsed:     enginesUsed,
	}

	if len(threats) == 0 {
		summary.CleanPackages = 1
	}

	// Count threats by severity
	for _, threat := range threats {
		switch threat.Severity {
		case types.SeverityCritical:
			summary.CriticalThreats++
		case types.SeverityHigh:
			summary.HighThreats++
		case types.SeverityMedium:
			summary.MediumThreats++
		case types.SeverityLow:
			summary.LowThreats++
		}
	}

	// Generate recommendations based on threats
	recommendations := []string{}
	if len(threats) > 0 {
		recommendations = append(recommendations, "Consider using alternative packages with better security reputation")
		recommendations = append(recommendations, "Review package dependencies for potential security issues")
		if riskScore > 0.7 {
			recommendations = append(recommendations, "Avoid using this package in production environments")
		}
	}

	// Create scan result
	result := &types.ScanResult{
		ID:              scanID,
		Target:          pkg.Name,
		Type:            "package",
		Status:          "completed",
		OverallRisk:     overallRisk,
		RiskScore:       riskScore,
		Packages:        []*types.Package{pkg},
		Summary:         summary,
		Duration:        time.Since(start),
		Recommendations: recommendations,
		CreatedAt:       start,
	}

	logrus.Infof("Package scan %s completed in %v. Found %d threats, %d warnings",
		scanID, result.Duration, len(threats), len(warnings))

	return result, nil
}

// calculateRiskScore calculates a risk score based on threats
func (a *Analyzer) calculateRiskScore(threats []types.Threat, packageCount int) float64 {
	if len(threats) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, threat := range threats {
		switch threat.Severity {
		case types.SeverityCritical:
			totalScore += 1.0
		case types.SeverityHigh:
			totalScore += 0.8
		case types.SeverityMedium:
			totalScore += 0.5
		case types.SeverityLow:
			totalScore += 0.2
		}
	}

	// Normalize by package count and cap at 1.0
	score := totalScore / float64(packageCount)
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// determineOverallRisk determines overall risk level from score
func (a *Analyzer) determineOverallRisk(score float64) string {
	if score >= 0.8 {
		return "critical"
	} else if score >= 0.6 {
		return "high"
	} else if score >= 0.4 {
		return "medium"
	} else if score > 0.0 {
		return "low"
	}
	return "minimal"
}

// filterDependencies removes excluded packages from the dependency list
func (a *Analyzer) filterDependencies(deps []types.Dependency, excludePackages []string) []types.Dependency {
	if deps == nil {
		return []types.Dependency{}
	}
	if len(excludePackages) == 0 {
		return deps
	}

	excludeMap := make(map[string]bool)
	for _, pkg := range excludePackages {
		excludeMap[pkg] = true
	}

	filtered := make([]types.Dependency, 0, len(deps))
	for _, dep := range deps {
		if !excludeMap[dep.Name] {
			filtered = append(filtered, dep)
		}
	}

	return filtered
}

// detectThreats performs threat detection on the given dependencies
func (a *Analyzer) detectThreats(ctx context.Context, deps []types.Dependency, options *ScanOptions) ([]types.Threat, []types.Warning, error) {
	logrus.Infof("Starting threat analysis for %d dependencies", len(deps))
	start := time.Now()

	var allThreats []types.Threat
	var allWarnings []types.Warning

	// Initialize enhanced supply chain detector if enabled
	var enhancedDetector *detector.EnhancedSupplyChainDetector
	if options.EnableSupplyChain {
		logrus.Info("Enhanced supply chain detection enabled")
		enhancedDetector = detector.NewEnhancedSupplyChainDetector()
	}

	// Determine whether to run in offline mode.
	// Offline mode is activated by --offline flag OR the FALCN_OFFLINE=true env var.
	offlineMode := options.OfflineMode || os.Getenv("FALCN_OFFLINE") == "true"

	// Initialize vulnerability manager if vulnerability checking is enabled
	var vulnManager *vulnerability.Manager
	if options.CheckVulnerabilities {
		if offlineMode {
			// Offline path: use the local SQLite CVE database only — no HTTP calls.
			logrus.Info("Offline mode: using local CVE database for vulnerability checking")
			managerConfig := &vulnerability.ManagerConfig{
				ParallelQueries: false,
				Timeout:         10 * time.Second,
				CacheEnabled:    true,
				CacheTTL:        1 * time.Hour,
				MergeResults:    false,
				DeduplicateByID: true,
				Priority:        []string{"local"},
			}
			vulnManager = vulnerability.NewManager(managerConfig)
			dbPath := options.LocalDBPath
			if dbPath == "" {
				dbPath = vulnerability.DefaultLocalDBPath()
			}
			if err := vulnManager.UseLocalDB(dbPath); err != nil {
				logrus.Warnf("Failed to open local CVE database at %s: %v — vulnerability checking skipped", dbPath, err)
				vulnManager = nil
			} else {
				logrus.Infof("Local CVE database opened: %s", dbPath)
			}
		} else {
			logrus.Info("Vulnerability checking enabled, initializing vulnerability manager")

			// Validate vulnerability database names
			validDBs := map[string]bool{
				"osv":    true,
				"github": true,
				"nvd":    true,
			}

			var validatedDBs []string
			for _, dbName := range options.VulnerabilityDBs {
				if validDBs[dbName] {
					validatedDBs = append(validatedDBs, dbName)
				} else {
					return nil, nil, fmt.Errorf("invalid vulnerability database: %s. Valid options are: osv, github, nvd", dbName)
				}
			}

			if len(validatedDBs) == 0 {
				return nil, nil, fmt.Errorf("no valid vulnerability databases specified")
			}

			// Create manager configuration
			managerConfig := &vulnerability.ManagerConfig{
				ParallelQueries: true,
				Timeout:         30 * time.Second,
				CacheEnabled:    true,
				CacheTTL:        1 * time.Hour,
				MergeResults:    true,
				DeduplicateByID: true,
				Priority:        validatedDBs,
			}

			// Create database configurations based on user selection
			for _, dbName := range validatedDBs {
				dbConfig := types.VulnerabilityDatabaseConfig{
					Type:    dbName,
					Enabled: true,
				}
				managerConfig.Databases = append(managerConfig.Databases, dbConfig)
			}

			vulnManager = vulnerability.NewManager(managerConfig)
			logrus.Infof("Vulnerability manager initialized with %d databases", len(validatedDBs))
		}
	}

	// Analyze each dependency individually using CheckPackage for better threat detection
	for _, dep := range deps {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		// Use CheckPackage which compares against popular packages
		// Check if detector is initialized
		if a.detector == nil {
			logrus.Warnf("Detector not initialized, skipping threat detection for %s", dep.Name)
			continue
		}

		result, err := a.detector.CheckPackage(ctx, dep.Name, dep.Registry)
		if err != nil {
			logrus.Warnf("Failed to check package %s: %v", dep.Name, err)
			continue
		}

		// Add threats and warnings from the result
		allThreats = append(allThreats, result.Threats...)
		allWarnings = append(allWarnings, result.Warnings...)

		// Perform enhanced supply chain analysis if enabled
		if enhancedDetector != nil {
			// Convert dependency to package for enhanced analysis
			pkg := &types.Package{
				Name:     dep.Name,
				Version:  dep.Version,
				Registry: dep.Registry,
				Type:     dep.Registry,
			}

			// Perform enhanced threat detection
			enhancedResults, err := enhancedDetector.DetectThreats(ctx, []types.Package{*pkg})
			if err != nil {
				logrus.Warnf("Enhanced supply chain analysis failed for %s: %v", dep.Name, err)
			} else if len(enhancedResults) > 0 {
				enhancedResult := enhancedResults[0]

				// Convert enhanced result to standard threat if not filtered
				if !enhancedResult.IsFiltered && enhancedResult.ConfidenceScore > 0.5 {
					threat := types.Threat{
						Package:         enhancedResult.Package,
						Registry:        enhancedResult.Registry,
						Type:            types.ThreatType(enhancedResult.ThreatType),
						Severity:        a.convertStringSeverity(enhancedResult.Severity),
						Description:     fmt.Sprintf("Enhanced supply chain threat detected: %s", enhancedResult.ThreatType),
						Recommendation:  strings.Join(enhancedResult.Recommendations, "; "),
						Confidence:      enhancedResult.ConfidenceScore,
						DetectedAt:      time.Now(),
						DetectionMethod: "enhanced_supply_chain",
						Metadata: map[string]interface{}{
							"supply_chain_risk":   enhancedResult.SupplyChainRisk,
							"false_positive_risk": enhancedResult.FalsePositiveRisk,
							"filter_reasons":      enhancedResult.FilterReasons,
							"evidence":            enhancedResult.Evidence,
						},
					}
					allThreats = append(allThreats, threat)
					logrus.Infof("Enhanced supply chain threat detected for %s: %s (confidence: %.2f)",
						dep.Name, enhancedResult.ThreatType, enhancedResult.ConfidenceScore)
				} else if enhancedResult.IsFiltered {
					logrus.Debugf("Package %s filtered by enhanced supply chain analysis: %v",
						dep.Name, enhancedResult.FilterReasons)
				}
			}
		}

		// Check for vulnerabilities if enabled
		if vulnManager != nil {
			// Create package object for vulnerability checking
			pkg := &types.Package{
				Name:     dep.Name,
				Version:  dep.Version,
				Type:     dep.Registry, // Set the package type to the registry
				Registry: dep.Registry,
			}

			vulns, err := vulnManager.CheckVulnerabilities(pkg)
			if err != nil {
				logrus.Warnf("Failed to check vulnerabilities for %s@%s: %v", dep.Name, dep.Version, err)
				continue
			}

			// Convert vulnerabilities to threats
			for _, vuln := range vulns {
				// Extract affected versions from vulnerability data
				affectedVersions := ""
				fixedVersion := ""
				if len(vuln.AffectedPackages) > 0 {
					for _, affected := range vuln.AffectedPackages {
						if affected.Name == dep.Name {
							affectedVersions = affected.VersionRange
							break
						}
					}
				}

				// Generate proposed correction
				proposedCorrection := fmt.Sprintf("Update %s to a patched version that addresses %s", dep.Name, vuln.ID)
				if fixedVersion != "" {
					proposedCorrection = fmt.Sprintf("Update %s from version %s to %s or later", dep.Name, dep.Version, fixedVersion)
				}

				threat := types.Threat{
					Package:            dep.Name,
					Version:            dep.Version,
					Registry:           dep.Registry,
					Type:               types.ThreatTypeVulnerable,
					Severity:           vuln.Severity,
					Description:        vuln.Description,
					Recommendation:     fmt.Sprintf("Update to a version that fixes %s", vuln.ID),
					Confidence:         1.0, // High confidence for known vulnerabilities
					DetectedAt:         time.Now(),
					DetectionMethod:    "vulnerability_database",
					CVEs:               []string{vuln.CVE},
					References:         vuln.References,
					AffectedVersions:   affectedVersions,
					FixedVersion:       fixedVersion,
					ProposedCorrection: proposedCorrection,
					CVE:                vuln.CVE,
					Metadata: map[string]interface{}{
						"vulnerability_id": vuln.ID,
						"cvss_score":       vuln.CVSSScore,
						"published":        vuln.Published,
						"modified":         vuln.Modified,
						"source":           vuln.Source,
						"aliases":          vuln.Aliases,
					},
				}
				allThreats = append(allThreats, threat)
			}

			if len(vulns) > 0 {
				logrus.Infof("Found %d vulnerabilities for %s@%s", len(vulns), dep.Name, dep.Version)
			}
		}
	}

	// AI Explanation Step — structured JSON explanations via prompts.go templates.
	if a.llmProvider != nil && len(allThreats) > 0 && !options.DisableLLM {
		logrus.Infof("Generating AI explanations for threats (max LLM calls: %d)...", options.MaxLLMCalls)
		llmCallCount := 0

		for i := range allThreats {
			if options.MaxLLMCalls > 0 && llmCallCount >= options.MaxLLMCalls {
				logrus.Debugf("Max LLM calls (%d) reached, skipping remaining explanations", options.MaxLLMCalls)
				break
			}
			t := &allThreats[i]
			// Only explain High/Critical/Medium threats to conserve tokens.
			if t.Severity != types.SeverityCritical &&
				t.Severity != types.SeverityHigh &&
				t.Severity != types.SeverityMedium {
				continue
			}

			// Cache key: {package}:{version}:{threat_type}
			cacheKey := fmt.Sprintf("explain:%s:%s:%s", t.Package, t.Version, string(t.Type))
			if a.explainCache != nil {
				if cached, ok := a.explainCache.Get(cacheKey); ok {
					if expl, ok := cached.(*types.ThreatExplanation); ok {
						hit := *expl
						hit.CacheHit = true
						t.Explanation = &hit
						// Cache hits do not count against the LLM call limit.
						continue
					}
				}
			}

			// Build structured prompt with per-threat-type guidance and evidence.
			req := llm.ExplanationRequest{
				Threat:        *t,
				DIRTScore:     0,   // populated by DIRT if available
				PackageAge:    0,
				DownloadCount: 0,
			}
			prompt := llm.BuildExplanationPrompt(req)

			response, err := a.llmProvider.GenerateExplanation(ctx, prompt)
			if err != nil {
				logrus.Warnf("LLM explanation failed for %s: %v", t.Package, err)
				continue
			}
			llmCallCount++

			expl := llm.ParseStructuredExplanation(response, a.llmProvider.ID(), t.Confidence)
			expl.GeneratedAt = time.Now()
			t.Explanation = expl

			// Also keep backward-compatible metadata field.
			if t.Metadata == nil {
				t.Metadata = make(map[string]interface{})
			}
			t.Metadata["ai_explanation"] = expl.What + " " + expl.Why

			// Store in explanation cache.
			if a.explainCache != nil {
				a.explainCache.Set(cacheKey, expl, 24*time.Hour)
			}
		}
	}

	duration := time.Since(start)
	logrus.Infof("Threat analysis completed in %v. Found %d threats, %d warnings", duration, len(allThreats), len(allWarnings))

	return allThreats, allWarnings, nil
}

// calculateSummary generates a summary of scan results
func (a *Analyzer) calculateSummary(threats []types.Threat, warnings []types.Warning, totalPackages int) ScanSummary {
	summary := ScanSummary{
		TotalWarnings: len(warnings),
		CleanPackages: totalPackages,
		ConflictCount: 0, // Will be updated by caller if resolution data is available
	}

	for _, threat := range threats {
		switch threat.Severity {
		case types.SeverityCritical:
			summary.CriticalThreats++
		case types.SeverityHigh:
			summary.HighThreats++
		case types.SeverityMedium:
			summary.MediumThreats++
		case types.SeverityLow:
			summary.LowThreats++
		}
		summary.CleanPackages--
	}

	return summary
}

// AnalyzeDependency analyzes a single dependency for threats
func (a *Analyzer) AnalyzeDependency(dep types.Dependency, popularPackages []string) ([]types.Threat, []types.Warning) {
	if a.detector == nil {
		return []types.Threat{}, []types.Warning{}
	}

	// Use detector engine to analyze the dependency
	options := &detector.Options{
		SimilarityThreshold: 0.8, // Default threshold
		DeepAnalysis:        true,
	}

	threats, warnings := a.detector.AnalyzeDependency(dep, popularPackages, options)
	if len(threats) == 0 && a.stubRepo != nil {
		st, sw := a.stubRepo.Generate(dep)
		threats = append(threats, st...)
		warnings = append(warnings, sw...)
	}
	return threats, warnings
}

// generateScanID generates a unique scan identifier
// scanRecursive performs recursive scanning of directories
func (a *Analyzer) scanRecursive(rootPath string, options *ScanOptions, result *ScanResult) (*ScanResult, error) {
	start := time.Now()
	logrus.Infof("Starting recursive scan for path: %s", rootPath)

	// Find all project directories
	projectDirs, err := a.findProjectDirectories(rootPath, options)
	if err != nil {
		return nil, fmt.Errorf("failed to find project directories: %w", err)
	}

	logrus.Infof("Found %d project directories for recursive scan", len(projectDirs))

	// Scan each project directory
	var allPackages []types.Package
	allThreats := make([]types.Threat, 0)
	allWarnings := make([]types.Warning, 0)
	projectResults := make(map[string]*ScanResult)

	for _, projectDir := range projectDirs {
		logrus.Infof("Scanning project directory: %s", projectDir)

		// Create a copy of options without recursive flag to avoid infinite recursion
		projectOptions := *options
		projectOptions.Recursive = false

		// Scan individual project
		projectResult, err := a.Scan(projectDir, &projectOptions)
		if err != nil {
			logrus.Warnf("Failed to scan project %s: %v", projectDir, err)
			continue
		}

		// Store project result for consolidated reporting
		projectResults[projectDir] = projectResult

		// Aggregate results
		if projectResult.Threats != nil {
			allThreats = append(allThreats, projectResult.Threats...)
		}
		if projectResult.Warnings != nil {
			allWarnings = append(allWarnings, projectResult.Warnings...)
		}
		if projectResult.Packages != nil {
			allPackages = append(allPackages, projectResult.Packages...)
		}
	}

	// Update result with aggregated data
	result.Packages = allPackages
	result.TotalPackages = len(allPackages)
	result.Threats = allThreats
	result.Warnings = allWarnings
	result.Duration = time.Since(start)
	result.Summary = a.calculateSummary(allThreats, allWarnings, len(allPackages))

	// Add metadata for recursive scan
	result.Metadata["recursive_scan"] = true
	result.Metadata["projects_scanned"] = len(projectDirs)
	result.Metadata["project_directories"] = projectDirs

	// Add consolidated report if requested
	if options.ConsolidateReport {
		result.Metadata["project_results"] = projectResults
	}

	logrus.Infof("Recursive scan completed. Scanned %d projects, found %d threats", len(projectDirs), len(allThreats))
	return result, nil
}

// findProjectDirectories discovers all project directories in the given path
func (a *Analyzer) findProjectDirectories(rootPath string, options *ScanOptions) ([]string, error) {
	var projectDirs []string
	manifestFiles := []string{
		"package.json",     // npm
		"requirements.txt", // pip
		"Pipfile",          // pipenv
		"pyproject.toml",   // poetry
		"pom.xml",          // maven
		"build.gradle",     // gradle
		"*.csproj",         // nuget
		"packages.config",  // nuget
		"Gemfile",          // rubygems
		"go.mod",           // go modules
		"Cargo.toml",       // cargo
		"composer.json",    // composer
	}

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking despite errors
		}

		// Skip hidden directories and common non-project directories
		if info.IsDir() {
			dirName := filepath.Base(path)
			if strings.HasPrefix(dirName, ".") ||
				dirName == "node_modules" ||
				dirName == "vendor" ||
				dirName == "target" ||
				dirName == "build" ||
				dirName == "dist" {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if this is a manifest file
		fileName := filepath.Base(path)
		for _, manifestFile := range manifestFiles {
			if fileName == manifestFile {
				// Filter by package manager if specified
				if len(options.PackageManagers) > 0 {
					registry := a.getRegistryFromFile(fileName)
					if !a.isRegistryAllowed(registry, options.PackageManagers) {
						continue
					}
				}

				projectDir := filepath.Dir(path)
				// Avoid duplicate directories
				if !a.containsPath(projectDirs, projectDir) {
					projectDirs = append(projectDirs, projectDir)
				}
				break
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory tree: %w", err)
	}

	return projectDirs, nil
}

// getRegistryFromFile maps file names to registry types
func (a *Analyzer) getRegistryFromFile(fileName string) string {
	switch fileName {
	case "package.json":
		return "npm"
	case "requirements.txt", "Pipfile", "pyproject.toml":
		return "pypi"
	case "pom.xml", "build.gradle":
		return "maven"
	case "packages.config":
		return "nuget"
	case "Gemfile":
		return "rubygems"
	case "go.mod":
		return "go"
	case "Cargo.toml":
		return "cargo"
	case "composer.json":
		return "composer"
	default:
		return "unknown"
	}
}

// isRegistryAllowed checks if a registry is in the allowed list
func (a *Analyzer) isRegistryAllowed(registry string, allowedRegistries []string) bool {
	for _, allowed := range allowedRegistries {
		if registry == allowed {
			return true
		}
	}
	return false
}

// containsPath checks if a path is already in the slice
func (a *Analyzer) containsPath(paths []string, path string) bool {
	for _, p := range paths {
		if p == path {
			return true
		}
	}
	return false
}

// convertStringSeverity converts string severity to types.Severity
func (a *Analyzer) convertStringSeverity(severity string) types.Severity {
	switch strings.ToLower(severity) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	default:
		return types.SeverityUnknown
	}
}

// scanWithSupplyChain performs enhanced supply chain scanning
func (a *Analyzer) scanWithSupplyChain(path string, options *ScanOptions) (*ScanResult, error) {
	logrus.Infof("Starting enhanced supply chain scan for path: %s", path)

	// Create a base scanner first
	baseScanner, err := scanner.New(a.config)
	if err != nil {
		return nil, fmt.Errorf("failed to create base scanner: %w", err)
	}

	// Create enhanced scanner with supply chain config
	enhancedScanner, err := scanner.NewEnhancedScanner(baseScanner, a.config.SupplyChain)
	if err != nil {
		return nil, fmt.Errorf("failed to create enhanced scanner: %w", err)
	}

	// Initialize DIRT Algorithm (Edge)
	// We use default configuration for now
	dirtAlgo := edge.NewDIRTAlgorithm(nil)
	enhancedScanner.SetDIRTDetector(dirtAlgo)

	// Initialize GTR Algorithm (Edge)
	gtrAlgo := edge.NewGTRAlgorithm(nil)
	enhancedScanner.SetGTRDetector(gtrAlgo)

	// Initialize RUNT Algorithm (Edge)
	runtAlgo := edge.NewRUNTAlgorithm(nil)
	enhancedScanner.SetRUNTDetector(runtAlgo)

	// Perform enhanced scan
	ctx := context.Background()
	enhancedResult, err := enhancedScanner.ScanWithSupplyChainAnalysis(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("enhanced supply chain scan failed: %w", err)
	}

	// Convert enhanced result to analyzer ScanResult format
	result := &ScanResult{
		ScanID:        enhancedResult.ScanMetadata.ScanID,
		Timestamp:     enhancedResult.ScanMetadata.Timestamp,
		Duration:      enhancedResult.ScanMetadata.ScanDuration,
		Path:          path,
		TotalPackages: 0, // Will be calculated from enhanced findings
		Threats:       []types.Threat{},
		Warnings:      []types.Warning{},
		Metadata:      make(map[string]interface{}),
	}

	// Extract threats and warnings from enhanced result packages
	if enhancedResult.ScanResult != nil && enhancedResult.ScanResult.Packages != nil {
		result.TotalPackages = len(enhancedResult.ScanResult.Packages)
		for _, pkg := range enhancedResult.ScanResult.Packages {
			if pkg.Threats != nil {
				result.Threats = append(result.Threats, pkg.Threats...)
			}
			if pkg.Warnings != nil {
				result.Warnings = append(result.Warnings, pkg.Warnings...)
			}
		}
	}

	// Enriched metadata
	if result.Metadata == nil {
		result.Metadata = make(map[string]interface{})
	}
	result.Metadata["supply_chain_analysis"] = true
	result.Metadata["supply_chain_risk_score"] = enhancedResult.SupplyChainRisk.OverallScore
	result.Metadata["supply_chain_risk_level"] = enhancedResult.SupplyChainRisk.RiskLevel
	result.Metadata["build_integrity_findings"] = len(enhancedResult.BuildIntegrityFindings)
	result.Metadata["zero_day_findings"] = len(enhancedResult.ZeroDayFindings)
	result.Metadata["threat_intel_findings"] = len(enhancedResult.ThreatIntelFindings)
	result.Metadata["honeypot_detections"] = len(enhancedResult.HoneypotDetections)
	result.Metadata["dependency_graph"] = enhancedResult.DependencyGraph
	result.Metadata["dirt_assessments"] = enhancedResult.DIRTAssessments
	result.Metadata["gtr_results"] = enhancedResult.GTRResults
	result.Metadata["runt_results"] = enhancedResult.RUNTResults

	// Create summary with threat and warning counts
	result.Summary = ScanSummary{
		TotalWarnings: len(result.Warnings),
		CleanPackages: result.TotalPackages - len(result.Threats),
	}

	// Count threats by severity
	for _, threat := range result.Threats {
		switch threat.Severity {
		case types.SeverityCritical:
			result.Summary.CriticalThreats++
		case types.SeverityHigh:
			result.Summary.HighThreats++
		case types.SeverityMedium:
			result.Summary.MediumThreats++
		case types.SeverityLow:
			result.Summary.LowThreats++
		}
	}

	logrus.Infof("Enhanced supply chain scan completed with %d packages, %d threats and %d warnings", result.TotalPackages, len(result.Threats), len(result.Warnings))
	return result, nil
}

func generateScanID() string {
	return fmt.Sprintf("scan_%d", time.Now().UnixNano())
}

// OutputJSON outputs scan results in JSON format
func (r *ScanResult) OutputJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

// OutputConsole outputs scan results in human-readable console format
func (r *ScanResult) OutputConsole(w io.Writer) error {
	fmt.Fprintf(w, "\n🔍 Falcn Security Scan Results\n")
	fmt.Fprintf(w, "═══════════════════════════════════════\n\n")
	fmt.Fprintf(w, "📊 Scan Summary:\n")
	fmt.Fprintf(w, "   • Scan ID: %s\n", r.ScanID)
	fmt.Fprintf(w, "   • Duration: %v\n", r.Duration)
	fmt.Fprintf(w, "   • Packages Analyzed: %d\n", r.TotalPackages)
	fmt.Fprintf(w, "   • Clean Packages: %d\n", r.Summary.CleanPackages)

	if len(r.Threats) == 0 {
		fmt.Fprintf(w, "\n✅ No security threats detected!\n")
	} else {
		fmt.Fprintf(w, "\n⚠️  Security Threats Detected:\n")
		fmt.Fprintf(w, "   • Critical: %d\n", r.Summary.CriticalThreats)
		fmt.Fprintf(w, "   • High: %d\n", r.Summary.HighThreats)
		fmt.Fprintf(w, "   • Medium: %d\n", r.Summary.MediumThreats)
		fmt.Fprintf(w, "   • Low: %d\n", r.Summary.LowThreats)

		// Sort threats by severity
		sort.Slice(r.Threats, func(i, j int) bool {
			return r.Threats[i].Severity > r.Threats[j].Severity
		})

		fmt.Fprintf(w, "\n🚨 Threat Details:\n")
		for i, threat := range r.Threats {
			fmt.Fprintf(w, "\n%d. %s (%s)\n", i+1, threat.Package, threat.Severity)
			fmt.Fprintf(w, "   Type: %s\n", threat.Type)
			fmt.Fprintf(w, "   Description: %s\n", threat.Description)
			if threat.SimilarTo != "" {
				fmt.Fprintf(w, "   Similar to: %s (%.1f%% similarity)\n", threat.SimilarTo, threat.Confidence*100)
			}
			if threat.Recommendation != "" {
				fmt.Fprintf(w, "   💡 Recommendation: %s\n", threat.Recommendation)
			}

			// AI Agent View
			if explanation, ok := threat.Metadata["ai_explanation"]; ok {
				fmt.Fprintf(w, "\n   🤖 Falcn AI Agent Analysis:\n")
				fmt.Fprintf(w, "   ┌──────────────────────────────────────────────────────────┐\n")

				// Basic word wrapping for clean display
				words := strings.Fields(fmt.Sprintf("%v", explanation))
				line := "   │"
				for _, word := range words {
					if len(line)+len(word)+1 > 60 {
						fmt.Fprintf(w, "%-62s│\n", line)
						line = "   │ " + word
					} else {
						line += " " + word
					}
				}
				fmt.Fprintf(w, "%-62s│\n", line)

				fmt.Fprintf(w, "   └──────────────────────────────────────────────────────────┘\n")
			}
		}
	}

	if len(r.Warnings) > 0 {
		fmt.Fprintf(w, "\n⚠️  Warnings (%d):\n", len(r.Warnings))
		for i, warning := range r.Warnings {
			fmt.Fprintf(w, "%d. %s: %s\n", i+1, warning.Package, warning.Message)
		}
	}

	fmt.Fprintf(w, "\n")
	return nil
}

// OutputHTML outputs scan results in HTML format
func (r *ScanResult) OutputHTML(w io.Writer) error {
	html := `<!DOCTYPE html>
<html>
<head>
	<title>Falcn Scan Results</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 20px; }
		.header { background: #f4f4f4; padding: 15px; border-radius: 5px; }
		.summary { margin: 20px 0; }
		.threat { background: #ffe6e6; padding: 10px; margin: 10px 0; border-left: 4px solid #ff4444; }
		.safe { background: #e6ffe6; padding: 10px; margin: 10px 0; border-left: 4px solid #44ff44; }
		.package { margin: 15px 0; padding: 10px; border: 1px solid #ddd; }
		.metadata { color: #666; font-size: 0.9em; }
	</style>
</head>
<body>
	<div class="header">
		<h1>Falcn Security Scan Report</h1>
		<p>Generated: %s</p>
		<p>Duration: %v</p>
	</div>
	
	<div class="summary">
		<h2>Summary</h2>
		<p>Packages Scanned: %d</p>
		<p>Threats Found: %d</p>
		<p>Risk Level: %s</p>
	</div>
	
	<div class="packages">
		<h2>Package Details</h2>
`

	// Write header with summary information
	_, err := fmt.Fprintf(w, html,
		time.Now().Format("2006-01-02 15:04:05"),
		r.Duration,
		r.TotalPackages,
		r.Summary.CriticalThreats+r.Summary.HighThreats+r.Summary.MediumThreats+r.Summary.LowThreats,
		"Medium")
	if err != nil {
		return err
	}

	// Write threat details
	for _, threat := range r.Threats {
		className := "threat"

		_, err := fmt.Fprintf(w, `		<div class="package %s">
			<h3>%s</h3>
			<div class="metadata">Severity: %s</div>
`,
			className, threat.Type, threat.Severity)
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(w, "\t\t\t<h4>Threat Details:</h4>\n\t\t\t<ul>\n")
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(w, "\t\t\t\t<li><strong>%s</strong> (%s): %s</li>\n",
			threat.Type, threat.Severity, threat.Description)
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(w, "\t\t\t</ul>\n")
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(w, "\t\t</div>\n")
		if err != nil {
			return err
		}
	}

	// Close HTML
	_, err = fmt.Fprintf(w, `	</div>
</body>
</html>`)
	return err
}
