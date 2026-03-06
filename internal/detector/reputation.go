package detector

import (
	"context"
	"io"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/falcn-io/falcn/internal/config"
	"github.com/falcn-io/falcn/internal/ml"
	"github.com/falcn-io/falcn/internal/registry"
	"github.com/falcn-io/falcn/pkg/types"
	"github.com/sirupsen/logrus"
)

// ReputationEngine analyzes package reputation using multiple data sources
type ReputationEngine struct {
	client          *http.Client
	npmClient       *registry.NPMClient
	pypiClient      *registry.PyPIClient
	inferenceEngine *ml.InferenceEngine
	cacheTimeout    time.Duration
	reputationCache map[string]*ReputationData
	cacheMu         sync.RWMutex
	lastCacheUpdate time.Time
}

// ReputationData holds reputation information for a package
type ReputationData struct {
	PackageName     string                 `json:"package_name"`
	Registry        string                 `json:"registry"`
	ReputationScore float64                `json:"reputation_score"`
	TrustLevel      string                 `json:"trust_level"`
	DownloadCount   int64                  `json:"download_count"`
	MaintainerCount int                    `json:"maintainer_count"`
	LastUpdated     time.Time              `json:"last_updated"`
	CreatedAt       time.Time              `json:"created_at"`
	Vulnerabilities []VulnerabilityInfo    `json:"vulnerabilities"`
	MalwareReports  []MalwareReport        `json:"malware_reports"`
	CommunityFlags  []CommunityFlag        `json:"community_flags"`
	Metadata        map[string]interface{} `json:"metadata"`
	CachedAt        time.Time              `json:"cached_at"`
}

// VulnerabilityInfo represents a known vulnerability
type VulnerabilityInfo struct {
	CVE         string    `json:"cve"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	PublishedAt time.Time `json:"published_at"`
	FixedIn     string    `json:"fixed_in"`
}

// MalwareReport represents a malware detection report
type MalwareReport struct {
	Source      string    `json:"source"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Confidence  float64   `json:"confidence"`
	ReportedAt  time.Time `json:"reported_at"`
}

// CommunityFlag represents community-reported issues
type CommunityFlag struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Reporter    string    `json:"reporter"`
	ReportedAt  time.Time `json:"reported_at"`
	Verified    bool      `json:"verified"`
}

// NewReputationEngine creates a new reputation engine
func NewReputationEngine(cfg *config.Config) *ReputationEngine {
	engine := &ReputationEngine{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		npmClient:       registry.NewNPMClient(),
		pypiClient:      registry.NewPyPIClient(),
		inferenceEngine: ml.NewInferenceEngine(),
		cacheTimeout:    1 * time.Hour,
		reputationCache: make(map[string]*ReputationData),
	}

	// Try to load ML model
	// Determine usage of config or default path. For now default.
	modelPath := "resources/models/reputation_model.onnx"
	if err := engine.inferenceEngine.LoadModel(modelPath); err != nil {
		logrus.Warnf("Failed to load ML model from %s: %v. Using heuristics fallback.", modelPath, err)
	} else {
		logrus.Infof("ML Reputation Model loaded successfully from %s", modelPath)
	}

	return engine
}

// Analyze analyzes the reputation of a package (alias for AnalyzeReputation)
func (re *ReputationEngine) Analyze(dep types.Dependency) []types.Threat {
	return re.AnalyzeReputation(dep)
}

// AnalyzeReputation analyzes the reputation of a package
func (re *ReputationEngine) AnalyzeReputation(dep types.Dependency) []types.Threat {
	var threats []types.Threat

	// Get reputation data
	reputationData, err := re.getReputationData(dep)
	if err != nil {
		// If we can't get reputation data, create a warning
		threats = append(threats, types.Threat{
			ID:              generateThreatID(),
			Package:         dep.Name,
			Version:         dep.Version,
			Registry:        dep.Registry,
			Type:            types.ThreatTypeUnknownPackage,
			Severity:        types.SeverityLow,
			Confidence:      0.3,
			Description:     fmt.Sprintf("Unable to verify reputation for package '%s'", dep.Name),
			Recommendation:  "Manually verify this package before use",
			DetectedAt:      time.Now(),
			DetectionMethod: "reputation_analysis",
			Evidence: []types.Evidence{{
				Type:        "reputation_check_failed",
				Description: fmt.Sprintf("Failed to retrieve reputation data: %v", err),
				Value:       map[string]interface{}{"error": err.Error()},
				Score:       0.3,
			}},
		})
		return threats
	}

	// Enhanced reputation analysis with multiple threat vectors

	// 1. Analyze reputation score with graduated thresholds
	if reputationData.ReputationScore < 0.2 {
		threats = append(threats, re.createReputationThreat(dep, reputationData, "very_low_reputation"))
	} else if reputationData.ReputationScore < 0.4 {
		threats = append(threats, re.createReputationThreat(dep, reputationData, "low_reputation"))
	} else if reputationData.ReputationScore < 0.6 {
		threats = append(threats, re.createReputationThreat(dep, reputationData, "questionable_reputation"))
	}

	// 2. Check for malware reports
	if len(reputationData.MalwareReports) > 0 {
		threats = append(threats, re.createMalwareThreat(dep, reputationData))
	}

	// 3. Check for vulnerabilities with severity analysis
	if len(reputationData.Vulnerabilities) > 0 {
		threats = append(threats, re.createVulnerabilityThreat(dep, reputationData))
	}

	// 4. Enhanced suspicious pattern detection
	if re.isSuspiciousPackage(reputationData) {
		threats = append(threats, re.createSuspiciousThreat(dep, reputationData))
	}

	// 5. Check for community flags
	if len(reputationData.CommunityFlags) > 0 {
		threats = append(threats, re.createCommunityFlagThreat(dep, reputationData))
	}

	// 6. New: Check for zero-day indicators
	if zeroThreats := re.detectZeroDayIndicators(dep, reputationData); len(zeroThreats) > 0 {
		threats = append(threats, zeroThreats...)
	}

	// 7. New: Check for supply chain attack indicators
	if supplyChainThreats := re.detectSupplyChainIndicators(dep, reputationData); len(supplyChainThreats) > 0 {
		threats = append(threats, supplyChainThreats...)
	}

	// 8. New: Check for enterprise security violations
	if enterpriseThreats := re.detectEnterpriseSecurityViolations(dep, reputationData); len(enterpriseThreats) > 0 {
		threats = append(threats, enterpriseThreats...)
	}

	return threats
}

// getReputationData retrieves reputation data for a package
func (re *ReputationEngine) getReputationData(dep types.Dependency) (*ReputationData, error) {
	cacheKey := fmt.Sprintf("%s:%s:%s", dep.Registry, dep.Name, dep.Version)

	// Check cache first
	re.cacheMu.RLock()
	cached, exists := re.reputationCache[cacheKey]
	re.cacheMu.RUnlock()

	if exists && time.Since(cached.CachedAt) < re.cacheTimeout {
		return cached, nil
	}

	// Fetch fresh data
	reputationData, err := re.fetchReputationData(dep)
	if err != nil {
		return nil, err
	}

	// Cache the result
	reputationData.CachedAt = time.Now()
	re.cacheMu.Lock()
	re.reputationCache[cacheKey] = reputationData
	re.cacheMu.Unlock()

	return reputationData, nil
}

// fetchReputationData fetches reputation data from external sources
func (re *ReputationEngine) fetchReputationData(dep types.Dependency) (*ReputationData, error) {
	// Initialize reputation data
	reputationData := &ReputationData{
		PackageName:     dep.Name,
		Registry:        dep.Registry,
		ReputationScore: 0.5, // Default neutral score
		TrustLevel:      "unknown",
		Metadata:        make(map[string]interface{}),
	}

	// Fetch registry-specific data
	switch dep.Registry {
	case "npm":
		err := re.fetchNPMData(reputationData)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch NPM data: %w", err)
		}
	case "pypi":
		err := re.fetchPyPIData(reputationData)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch PyPI data: %w", err)
		}
	case "go":
		err := re.fetchGoData(reputationData)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch Go data: %w", err)
		}
	default:
		// For unknown registries, use generic analysis
		re.performGenericAnalysis(reputationData)
	}

	// Fetch vulnerability data
	err := re.fetchVulnerabilityData(reputationData)
	if err != nil {
		// Log error but don't fail the entire operation
		logrus.Warnf("Failed to fetch vulnerability data: %v", err)
	}

	// Fetch malware data
	err = re.fetchMalwareData(reputationData)
	if err != nil {
		// Log error but don't fail the entire operation
		logrus.Warnf("Failed to fetch malware data: %v", err)
	}

	// Calculate final reputation score
	re.calculateReputationScore(reputationData)

	return reputationData, nil
}

// fetchNPMData fetches NPM-specific reputation data
func (re *ReputationEngine) fetchNPMData(data *ReputationData) error {
	if data.Metadata == nil {
		data.Metadata = make(map[string]interface{})
	}
	data.Metadata["registry_api"] = "npm"

	ctx := context.Background()

	// 1. Get Package Metadata
	pkgInfo, err := re.npmClient.GetPackageInfo(ctx, data.PackageName)
	if err != nil {
		return fmt.Errorf("failed to fetch npm package info: %w", err)
	}

	// Map Metadata
	data.Metadata["description"] = pkgInfo.Description
	data.Metadata["homepage"] = pkgInfo.Homepage
	data.Metadata["license"] = pkgInfo.License
	data.MaintainerCount = len(pkgInfo.Maintainers)

	// Parse timestamps
	if createdStr, ok := pkgInfo.Time["created"]; ok {
		if t, err := time.Parse(time.RFC3339, createdStr); err == nil {
			data.CreatedAt = t
		}
	} else {
		// Fallback if not found (very rare)
		data.CreatedAt = time.Now()
	}

	if modifiedStr, ok := pkgInfo.Time["modified"]; ok {
		if t, err := time.Parse(time.RFC3339, modifiedStr); err == nil {
			data.LastUpdated = t
		}
	} else {
		data.LastUpdated = time.Now()
	}

	// 2. Get Real Download Stats
	stats, err := re.npmClient.GetDownloadStats(ctx, data.PackageName, "last-month")
	if err == nil {
		data.DownloadCount = int64(stats.Downloads)
		data.Metadata["downloads_last_month"] = stats.Downloads
	} else {
		// Log warning but don't fail, use 0
		logrus.Warnf("Failed to fetch download stats for %s: %v", data.PackageName, err)
		data.DownloadCount = 0
	}

	return nil
}

// fetchPyPIData fetches PyPI-specific reputation data
func (re *ReputationEngine) fetchPyPIData(data *ReputationData) error {
	if data.Metadata == nil {
		data.Metadata = make(map[string]interface{})
	}
	data.Metadata["registry_api"] = "pypi"

	info, err := re.pypiClient.GetPackageInfo(data.PackageName)
	if err != nil {
		return fmt.Errorf("failed to fetch pypi package info: %w", err)
	}

	data.Metadata["description"] = info.Info.Summary
	data.Metadata["author"] = info.Info.Author
	data.Metadata["license"] = info.Info.License
	data.MaintainerCount = 1 // Default, as PyPI returns single Maintainer string usually

	// Derive dates from releases
	var latest time.Time
	var earliest time.Time
	first := true

	for _, releases := range info.Releases {
		for _, r := range releases {
			if r.UploadTime == "" {
				continue
			}
			t, err := time.Parse(time.RFC3339, r.UploadTime)
			if err != nil {
				continue
			}

			if first {
				latest = t
				earliest = t
				first = false
			} else {
				if t.After(latest) {
					latest = t
				}
				if t.Before(earliest) {
					earliest = t
				}
			}
		}
	}

	data.LastUpdated = latest
	data.CreatedAt = earliest
	data.DownloadCount = 0 // PyPI API does not provide download stats

	return nil
}

// fetchGoData fetches Go-specific reputation data by querying proxy.golang.org.
func (re *ReputationEngine) fetchGoData(data *ReputationData) error {
	if data.PackageName == "" {
		return nil
	}
	if data.Metadata == nil {
		data.Metadata = make(map[string]interface{})
	}
	data.Metadata["registry_api"] = "go"

	// Guard against engines created without an HTTP client (e.g. in tests).
	if re.client == nil {
		data.ReputationScore = 0.5
		data.TrustLevel = "unknown"
		return nil
	}

	// Query Go module proxy for the version list.
	listURL := fmt.Sprintf("https://proxy.golang.org/%s/@v/list", data.PackageName)
	resp, err := re.client.Get(listURL)
	if err != nil {
		// Network failure — degrade gracefully.
		data.ReputationScore = 0.5
		data.TrustLevel = "unknown"
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Module not found in proxy — suspicious.
		data.ReputationScore = 0.3
		data.TrustLevel = "low"
		data.Metadata["go_proxy_status"] = "not_found"
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		data.ReputationScore = 0.5
		data.TrustLevel = "unknown"
		return nil
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		data.ReputationScore = 0.5
		data.TrustLevel = "unknown"
		return nil
	}

	versions := strings.Fields(strings.TrimSpace(string(bodyBytes)))
	versionCount := len(versions)

	// Score based on version history depth.
	switch {
	case versionCount >= 10:
		data.ReputationScore = 0.85
		data.TrustLevel = "high"
	case versionCount >= 3:
		data.ReputationScore = 0.7
		data.TrustLevel = "medium"
	case versionCount >= 1:
		data.ReputationScore = 0.5
		data.TrustLevel = "medium"
	default:
		data.ReputationScore = 0.3
		data.TrustLevel = "low"
	}

	data.Metadata["go_version_count"] = versionCount
	data.Metadata["go_proxy_status"] = "found"
	return nil
}

// performGenericAnalysis performs generic reputation analysis
func (re *ReputationEngine) performGenericAnalysis(data *ReputationData) {
	if data.Metadata == nil {
		data.Metadata = make(map[string]interface{})
	}
	data.Metadata["analysis_type"] = "generic"
	data.ReputationScore = 0.5 // Neutral score for unknown packages
	data.TrustLevel = "unknown"
}

// fetchVulnerabilityData queries the OSV API for known vulnerabilities affecting the package.
func (re *ReputationEngine) fetchVulnerabilityData(data *ReputationData) error {
	if data.PackageName == "" {
		return nil
	}

	// Map registry to OSV ecosystem
	ecosystem := re.mapRegistryToOSVEcosystem(data.Registry)
	if ecosystem == "" {
		return nil // unsupported ecosystem, skip silently
	}

	reqBody := fmt.Sprintf(
		`{"package":{"name":%q,"ecosystem":%q}}`,
		data.PackageName, ecosystem,
	)

	resp, err := re.client.Post(
		"https://api.osv.dev/v1/query",
		"application/json",
		strings.NewReader(reqBody),
	)
	if err != nil {
		return fmt.Errorf("OSV query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil // non-200 — tolerate silently
	}

	var osvResp struct {
		Vulns []struct {
			ID       string `json:"id"`
			Summary  string `json:"summary"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			Published string `json:"published"`
			Modified  string `json:"modified"`
		} `json:"vulns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil // parse failure — tolerate silently
	}

	for _, v := range osvResp.Vulns {
		severity := "medium"
		for _, s := range v.Severity {
			if s.Type == "CVSS_V3" {
				severity = re.cvssScoreToSeverityString(s.Score)
				break
			}
		}
		published := time.Time{}
		if v.Published != "" {
			if t, err2 := time.Parse(time.RFC3339, v.Published); err2 == nil {
				published = t
			}
		}
		data.Vulnerabilities = append(data.Vulnerabilities, VulnerabilityInfo{
			CVE:         v.ID,
			Severity:    severity,
			Description: v.Summary,
			PublishedAt: published,
		})
	}
	return nil
}

// cvssScoreToSeverityString converts a CVSS v3 vector string to a severity label.
func (re *ReputationEngine) cvssScoreToSeverityString(vector string) string {
	if strings.HasPrefix(vector, "CVSS:3") {
		parts := strings.Split(vector, "/")
		score := 0
		for _, p := range parts {
			switch p {
			case "AV:N":
				score += 3
			case "AV:A":
				score += 2
			case "AV:L":
				score += 1
			case "AC:L":
				score += 2
			case "AC:H":
				score += 1
			case "PR:N":
				score += 2
			case "PR:L":
				score += 1
			case "S:C":
				score += 1
			case "C:H", "I:H", "A:H":
				score += 3
			case "C:L", "I:L", "A:L":
				score += 1
			}
		}
		normalized := float64(score) / 17.0 * 10.0
		switch {
		case normalized >= 9.0:
			return "critical"
		case normalized >= 7.0:
			return "high"
		case normalized >= 4.0:
			return "medium"
		default:
			return "low"
		}
	}
	return "medium"
}

// mapRegistryToOSVEcosystem maps a registry name to an OSV ecosystem identifier.
func (re *ReputationEngine) mapRegistryToOSVEcosystem(registry string) string {
	switch strings.ToLower(registry) {
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "go":
		return "Go"
	case "maven":
		return "Maven"
	case "nuget":
		return "NuGet"
	case "packagist":
		return "Packagist"
	case "rubygems":
		return "RubyGems"
	case "crates.io":
		return "crates.io"
	default:
		return ""
	}
}

// fetchMalwareData checks the package against a curated list of known-malicious packages
// (sourced from the OpenSSF malicious-packages dataset and public removal notices).
func (re *ReputationEngine) fetchMalwareData(data *ReputationData) error {
	if data.PackageName == "" {
		return nil
	}

	// Curated list of confirmed-malicious package names by registry.
	// Sourced from OpenSSF malicious-packages, PyPI/npm removal notices.
	knownMalicious := map[string][]string{
		"npm": {
			"event-stream",    // 2018 cryptocurrency theft
			"flatmap-stream",  // injected into event-stream
			"eslint-scope",    // 2018 npm credentials theft
			"getcookies",      // browser cookie theft
			"bootstrap-sass",  // backdoored 2019
			"electron-native-notify", // malicious 2018
			"nodemon",         // typosquat (real is nodemon, not node-mon)
			"crossenv",        // typosquat of cross-env
			"coffe-script",    // typosquat of coffee-script
			"babelcli",        // typosquat of babel-cli
			"d3.js",           // typosquat of d3
			"jquery.js",       // typosquat of jquery
			"momnet",          // typosquat of moment
			"monment",         // typosquat of moment
			"loadyaml",        // malicious 2022
			"node-ipc",        // sabotage/wiperware 2022
			"peacenotwar",     // dependency of node-ipc wiperware
			"colors",          // sabotage 2022 (>=1.4.1)
		},
		"pypi": {
			"colourama",       // typosquat of colorama
			"python-sqlite",   // malicious 2021
			"loguru-config",   // malicious 2022
			"noblesse",        // credential theft 2020
			"genesistools",    // credential theft 2020
			"humanfriendly-enc", // malicious 2021
			"py-jwt",          // typosquat of PyJWT
			"pycryp",          // typosquat of pycryptodome
			"aiohttp-socks5",  // malicious 2022
			"request-session", // malicious 2022
			"browserdebug",    // malicious 2022
			"pymasker",        // malicious 2022
		},
	}

	ecosystem := strings.ToLower(data.Registry)
	maliciousList, ok := knownMalicious[ecosystem]
	if !ok {
		return nil
	}

	pkgLower := strings.ToLower(data.PackageName)
	for _, bad := range maliciousList {
		if pkgLower == bad {
			data.MalwareReports = append(data.MalwareReports, MalwareReport{
				Source:      "falcn-known-bad-db",
				Type:        "confirmed_malicious",
				Description: fmt.Sprintf("Package '%s' matches a confirmed-malicious package in the Falcn threat database", data.PackageName),
				Confidence:  0.95,
				ReportedAt:  time.Now(),
			})
			break
		}
	}
	return nil
}

// calculateReputationScore calculates the final reputation score
func (re *ReputationEngine) calculateReputationScore(data *ReputationData) {
	if data.Metadata == nil {
		data.Metadata = make(map[string]interface{})
	}
	// Try ML-based scoring first
	input := ml.InputData{
		DownloadCount:      data.DownloadCount,
		MaintainerCount:    data.MaintainerCount,
		CreatedAt:          data.CreatedAt,
		LastUpdated:        data.LastUpdated,
		VulnerabilityCount: len(data.Vulnerabilities),
		MalwareReportCount: len(data.MalwareReports),
	}
	verifiedFlags := 0
	for _, flag := range data.CommunityFlags {
		if flag.Verified {
			verifiedFlags++
		}
	}
	input.VerifiedFlagCount = verifiedFlags

	features := ml.ExtractFeatures(input)
	maliciousProb, err := re.inferenceEngine.Predict(features)

	if err == nil {
		// Model success
		// Model predicts probability of being MALICIOUS (0..1)
		// ReputationScore represents TRUST (0..1), so we invert it.
		data.ReputationScore = 1.0 - maliciousProb
		data.Metadata["scoring_method"] = "ml_model"
		data.Metadata["malicious_probability"] = maliciousProb

		re.assignTrustLevel(data)
		return
	}

	// Fallback to heuristic scoring if ML fails
	re.calculateHeuristicScore(data)
}

func (re *ReputationEngine) assignTrustLevel(data *ReputationData) {
	// Set trust level based on score
	if data.ReputationScore >= 0.8 {
		data.TrustLevel = "high"
	} else if data.ReputationScore >= 0.6 {
		data.TrustLevel = "medium"
	} else if data.ReputationScore >= 0.4 {
		data.TrustLevel = "low"
	} else {
		data.TrustLevel = "very_low"
	}
}

// calculateHeuristicScore (legacy/fallback logic)
func (re *ReputationEngine) calculateHeuristicScore(data *ReputationData) {
	score := 0.5 // Base score
	data.Metadata["scoring_method"] = "heuristic_fallback"

	// Adjust based on download count
	if data.DownloadCount > 100000 {
		score += 0.2
	} else if data.DownloadCount > 10000 {
		score += 0.1
	} else if data.DownloadCount < 100 {
		score -= 0.2
	}

	// Adjust based on age
	age := time.Since(data.CreatedAt)
	if age > 2*365*24*time.Hour { // > 2 years
		score += 0.1
	} else if age < 30*24*time.Hour { // < 30 days
		score -= 0.3
	}

	// Adjust based on maintenance
	lastUpdate := time.Since(data.LastUpdated)
	if lastUpdate < 30*24*time.Hour { // Updated within 30 days
		score += 0.1
	} else if lastUpdate > 365*24*time.Hour { // Not updated for over a year
		score -= 0.2
	}

	// Adjust based on maintainer count
	if data.MaintainerCount > 3 {
		score += 0.1
	} else if data.MaintainerCount == 0 {
		score -= 0.3
	}

	// Penalize for vulnerabilities
	for _, vuln := range data.Vulnerabilities {
		switch strings.ToLower(vuln.Severity) {
		case "critical":
			score -= 0.4
		case "high":
			score -= 0.3
		case "medium":
			score -= 0.2
		case "low":
			score -= 0.1
		}
	}

	// Penalize for malware reports
	for _, malware := range data.MalwareReports {
		score -= 0.5 * malware.Confidence
	}

	// Penalize for community flags
	for _, flag := range data.CommunityFlags {
		if flag.Verified {
			score -= 0.3
		} else {
			score -= 0.1
		}
	}

	// Ensure score is within bounds
	if score > 1.0 {
		score = 1.0
	} else if score < 0.0 {
		score = 0.0
	}

	data.ReputationScore = score
	re.assignTrustLevel(data)
}

// isSuspiciousPackage checks for suspicious patterns
func (re *ReputationEngine) isSuspiciousPackage(data *ReputationData) bool {
	// Very new package with high download count (potential fake downloads)
	age := time.Since(data.CreatedAt)
	if age < 7*24*time.Hour && data.DownloadCount > 10000 {
		return true
	}

	// Package with no maintainers
	if data.MaintainerCount == 0 {
		return true
	}

	// Package not updated for a very long time but still being downloaded
	lastUpdate := time.Since(data.LastUpdated)
	if lastUpdate > 2*365*24*time.Hour && data.DownloadCount > 1000 {
		return true
	}

	return false
}

// createReputationThreat creates a threat based on reputation analysis
func (re *ReputationEngine) createReputationThreat(dep types.Dependency, data *ReputationData, threatType string) types.Threat {
	severity := types.SeverityMedium
	confidence := 0.7

	if data.ReputationScore < 0.2 {
		severity = types.SeverityHigh
		confidence = 0.9
	} else if data.ReputationScore < 0.1 {
		severity = types.SeverityCritical
		confidence = 0.95
	}

	return types.Threat{
		ID:              generateThreatID(),
		Package:         dep.Name,
		Version:         dep.Version,
		Registry:        dep.Registry,
		Type:            types.ThreatTypeLowReputation,
		Severity:        severity,
		Confidence:      confidence,
		Description:     fmt.Sprintf("Package '%s' has a low reputation score (%.2f)", dep.Name, data.ReputationScore),
		Recommendation:  "Consider using a more reputable alternative or thoroughly audit this package",
		DetectedAt:      time.Now(),
		DetectionMethod: "reputation_analysis",
		Evidence: []types.Evidence{{
			Type:        "reputation_score",
			Description: fmt.Sprintf("Reputation score: %.2f, Trust level: %s", data.ReputationScore, data.TrustLevel),
			Value: map[string]interface{}{
				"reputation_score": data.ReputationScore,
				"trust_level":      data.TrustLevel,
				"download_count":   data.DownloadCount,
				"maintainer_count": data.MaintainerCount,
				"age_days":         int(time.Since(data.CreatedAt).Hours() / 24),
				"scoring_method":   data.Metadata["scoring_method"],
				"ml_prob":          data.Metadata["malicious_probability"],
			},
			Score: confidence,
		}},
	}
}

// createMalwareThreat creates a threat based on malware reports
func (re *ReputationEngine) createMalwareThreat(dep types.Dependency, data *ReputationData) types.Threat {
	highestConfidence := 0.0
	for _, report := range data.MalwareReports {
		if report.Confidence > highestConfidence {
			highestConfidence = report.Confidence
		}
	}

	severity := types.SeverityCritical
	if highestConfidence < 0.7 {
		severity = types.SeverityHigh
	}

	evidence := make([]types.Evidence, len(data.MalwareReports))
	for i, report := range data.MalwareReports {
		evidence[i] = types.Evidence{
			Type:        "malware_report",
			Description: fmt.Sprintf("Malware detected by %s: %s", report.Source, report.Description),
			Value: map[string]interface{}{
				"source":      report.Source,
				"type":        report.Type,
				"confidence":  report.Confidence,
				"reported_at": report.ReportedAt,
			},
			Score: report.Confidence,
		}
	}

	return types.Threat{
		ID:              generateThreatID(),
		Package:         dep.Name,
		Version:         dep.Version,
		Registry:        dep.Registry,
		Type:            types.ThreatTypeMalicious,
		Severity:        severity,
		Confidence:      highestConfidence,
		Description:     fmt.Sprintf("Package '%s' has been reported as malware by %d source(s)", dep.Name, len(data.MalwareReports)),
		Recommendation:  "DO NOT USE this package. Remove it immediately from your dependencies.",
		DetectedAt:      time.Now(),
		DetectionMethod: "malware_database",
		Evidence:        evidence,
	}
}

// createVulnerabilityThreat creates a threat based on known vulnerabilities
func (re *ReputationEngine) createVulnerabilityThreat(dep types.Dependency, data *ReputationData) types.Threat {
	highestSeverity := "low"
	for _, vuln := range data.Vulnerabilities {
		if re.compareSeverity(vuln.Severity, highestSeverity) > 0 {
			highestSeverity = vuln.Severity
		}
	}

	severity := re.mapVulnSeverity(highestSeverity)
	evidence := make([]types.Evidence, len(data.Vulnerabilities))
	for i, vuln := range data.Vulnerabilities {
		evidence[i] = types.Evidence{
			Type:        "vulnerability",
			Description: fmt.Sprintf("CVE %s (%s): %s", vuln.CVE, vuln.Severity, vuln.Description),
			Value: map[string]interface{}{
				"cve":          vuln.CVE,
				"severity":     vuln.Severity,
				"published_at": vuln.PublishedAt,
				"fixed_in":     vuln.FixedIn,
			},
			Score: re.vulnSeverityToScore(vuln.Severity),
		}
	}

	return types.Threat{
		ID:              generateThreatID(),
		Package:         dep.Name,
		Version:         dep.Version,
		Registry:        dep.Registry,
		Type:            types.ThreatTypeVulnerable,
		Severity:        severity,
		Confidence:      0.95,
		Description:     fmt.Sprintf("Package '%s' has %d known vulnerabilit(ies), highest severity: %s", dep.Name, len(data.Vulnerabilities), highestSeverity),
		Recommendation:  "Update to a patched version or find an alternative package",
		DetectedAt:      time.Now(),
		DetectionMethod: "vulnerability_database",
		Evidence:        evidence,
	}
}

// createSuspiciousThreat creates a threat for suspicious patterns
func (re *ReputationEngine) createSuspiciousThreat(dep types.Dependency, data *ReputationData) types.Threat {
	return types.Threat{
		ID:              generateThreatID(),
		Package:         dep.Name,
		Version:         dep.Version,
		Registry:        dep.Registry,
		Type:            types.ThreatTypeSuspicious,
		Severity:        types.SeverityMedium,
		Confidence:      0.6,
		Description:     fmt.Sprintf("Package '%s' exhibits suspicious patterns", dep.Name),
		Recommendation:  "Manually review this package before use",
		DetectedAt:      time.Now(),
		DetectionMethod: "pattern_analysis",
		Evidence: []types.Evidence{{
			Type:        "suspicious_pattern",
			Description: "Package exhibits unusual download/maintenance patterns",
			Value: map[string]interface{}{
				"download_count":    data.DownloadCount,
				"maintainer_count":  data.MaintainerCount,
				"age_days":          int(time.Since(data.CreatedAt).Hours() / 24),
				"days_since_update": int(time.Since(data.LastUpdated).Hours() / 24),
			},
			Score: 0.6,
		}},
	}
}

// createCommunityFlagThreat creates a threat based on community flags
func (re *ReputationEngine) createCommunityFlagThreat(dep types.Dependency, data *ReputationData) types.Threat {
	verifiedFlags := 0
	for _, flag := range data.CommunityFlags {
		if flag.Verified {
			verifiedFlags++
		}
	}

	severity := types.SeverityLow
	confidence := 0.4
	if verifiedFlags > 0 {
		severity = types.SeverityMedium
		confidence = 0.7
	}
	if verifiedFlags > 2 {
		severity = types.SeverityHigh
		confidence = 0.9
	}

	evidence := make([]types.Evidence, len(data.CommunityFlags))
	for i, flag := range data.CommunityFlags {
		evidence[i] = types.Evidence{
			Type:        "community_flag",
			Description: fmt.Sprintf("Community flag (%s): %s", flag.Type, flag.Description),
			Value: map[string]interface{}{
				"type":        flag.Type,
				"reporter":    flag.Reporter,
				"verified":    flag.Verified,
				"reported_at": flag.ReportedAt,
			},
			Score: map[bool]float64{true: 0.8, false: 0.4}[flag.Verified],
		}
	}

	return types.Threat{
		ID:              generateThreatID(),
		Package:         dep.Name,
		Version:         dep.Version,
		Registry:        dep.Registry,
		Type:            types.ThreatTypeCommunityFlag,
		Severity:        severity,
		Confidence:      confidence,
		Description:     fmt.Sprintf("Package '%s' has been flagged by the community (%d verified flags)", dep.Name, verifiedFlags),
		Recommendation:  "Review community concerns before using this package",
		DetectedAt:      time.Now(),
		DetectionMethod: "community_reports",
		Evidence:        evidence,
	}
}

// Helper functions

func (re *ReputationEngine) compareSeverity(sev1, sev2 string) int {
	severityOrder := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	val1, ok1 := severityOrder[strings.ToLower(sev1)]
	val2, ok2 := severityOrder[strings.ToLower(sev2)]

	if !ok1 {
		val1 = 0
	}
	if !ok2 {
		val2 = 0
	}

	return val1 - val2
}

// (Simulation functions removed)

func (re *ReputationEngine) mapVulnSeverity(vulnSev string) types.Severity {
	switch strings.ToLower(vulnSev) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	default:
		return types.SeverityLow
	}
}

func (re *ReputationEngine) vulnSeverityToScore(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 0.95
	case "high":
		return 0.85
	case "medium":
		return 0.65
	default:
		return 0.45
	}
}

// ClearCache clears the reputation cache
func (re *ReputationEngine) ClearCache() {
	re.cacheMu.Lock()
	re.reputationCache = make(map[string]*ReputationData)
	re.lastCacheUpdate = time.Time{}
	re.cacheMu.Unlock()
}

// GetCacheStats returns cache statistics
func (re *ReputationEngine) GetCacheStats() map[string]interface{} {
	re.cacheMu.RLock()
	size := len(re.reputationCache)
	last := re.lastCacheUpdate
	re.cacheMu.RUnlock()
	return map[string]interface{}{
		"cache_size":        size,
		"last_cache_update": last,
		"cache_timeout":     re.cacheTimeout,
	}
}

// detectZeroDayIndicators detects potential zero-day attack indicators
func (re *ReputationEngine) detectZeroDayIndicators(dep types.Dependency, data *ReputationData) []types.Threat {
	var threats []types.Threat

	// Check for extremely new packages with high version numbers
	if data.CreatedAt.After(time.Now().AddDate(0, 0, -7)) { // Less than 7 days old
		if strings.Contains(dep.Version, "1.0") || strings.Contains(dep.Version, "2.0") {
			threats = append(threats, types.Threat{
				ID:              generateThreatID(),
				Package:         dep.Name,
				Version:         dep.Version,
				Registry:        dep.Registry,
				Type:            types.ThreatTypeZeroDay,
				Severity:        types.SeverityHigh,
				Confidence:      0.7,
				Description:     fmt.Sprintf("Package '%s' is extremely new but has mature version number - potential zero-day attack vector", dep.Name),
				Recommendation:  "Exercise extreme caution - verify package authenticity and monitor for suspicious behavior",
				DetectedAt:      time.Now(),
				DetectionMethod: "zero_day_timing_analysis",
				Evidence: []types.Evidence{
					{
						Type:        "timing_anomaly",
						Description: "New package with mature version number",
						Value:       map[string]interface{}{"created_at": data.CreatedAt, "version": dep.Version},
						Score:       0.7,
					},
				},
			})
		}
	}

	// Check for packages with suspicious download spikes
	if data.DownloadCount > 100000 && data.CreatedAt.After(time.Now().AddDate(0, -1, 0)) {
		threats = append(threats, types.Threat{
			ID:              generateThreatID(),
			Package:         dep.Name,
			Version:         dep.Version,
			Registry:        dep.Registry,
			Type:            types.ThreatTypeZeroDay,
			Severity:        types.SeverityMedium,
			Confidence:      0.6,
			Description:     fmt.Sprintf("Package '%s' has unusually high downloads for its age - potential coordinated attack", dep.Name),
			Recommendation:  "Investigate download patterns and verify package legitimacy",
			DetectedAt:      time.Now(),
			DetectionMethod: "download_spike_analysis",
			Evidence: []types.Evidence{
				{
					Type:        "download_anomaly",
					Description: "Unusual download count for package age",
					Value:       map[string]interface{}{"downloads": data.DownloadCount, "age_days": int(time.Since(data.CreatedAt).Hours() / 24)},
					Score:       0.6,
				},
			},
		})
	}

	return threats
}

// detectSupplyChainIndicators detects supply chain attack indicators
func (re *ReputationEngine) detectSupplyChainIndicators(dep types.Dependency, data *ReputationData) []types.Threat {
	var threats []types.Threat

	// Check for packages with no maintainer information
	if data.MaintainerCount == 0 {
		threats = append(threats, types.Threat{
			ID:              generateThreatID(),
			Package:         dep.Name,
			Version:         dep.Version,
			Registry:        dep.Registry,
			Type:            types.ThreatTypeSupplyChain,
			Severity:        types.SeverityMedium,
			Confidence:      0.5,
			Description:     fmt.Sprintf("Package '%s' has no identifiable maintainers - supply chain risk", dep.Name),
			Recommendation:  "Verify package ownership and maintenance before use",
			DetectedAt:      time.Now(),
			DetectionMethod: "maintainer_analysis",
			Evidence: []types.Evidence{
				{
					Type:        "maintainer_absence",
					Description: "No maintainer information available",
					Value:       data.MaintainerCount,
					Score:       0.5,
				},
			},
		})
	}

	// Check for packages that haven't been updated in a long time but are still being downloaded
	if time.Since(data.LastUpdated) > 365*24*time.Hour && data.DownloadCount > 1000 {
		threats = append(threats, types.Threat{
			ID:              generateThreatID(),
			Package:         dep.Name,
			Version:         dep.Version,
			Registry:        dep.Registry,
			Type:            types.ThreatTypeSupplyChain,
			Severity:        types.SeverityLow,
			Confidence:      0.4,
			Description:     fmt.Sprintf("Package '%s' is unmaintained but still popular - potential supply chain takeover target", dep.Name),
			Recommendation:  "Consider alternatives or verify current maintainer status",
			DetectedAt:      time.Now(),
			DetectionMethod: "abandonment_analysis",
			Evidence: []types.Evidence{
				{
					Type:        "maintenance_gap",
					Description: "Long gap since last update despite popularity",
					Value:       map[string]interface{}{"last_updated": data.LastUpdated, "downloads": data.DownloadCount},
					Score:       0.4,
				},
			},
		})
	}

	return threats
}

// detectEnterpriseSecurityViolations detects enterprise security policy violations
func (re *ReputationEngine) detectEnterpriseSecurityViolations(dep types.Dependency, data *ReputationData) []types.Threat {
	var threats []types.Threat

	// Check for packages with very low reputation scores (enterprise threshold)
	if data.ReputationScore < 0.7 {
		threats = append(threats, types.Threat{
			ID:              generateThreatID(),
			Package:         dep.Name,
			Version:         dep.Version,
			Registry:        dep.Registry,
			Type:            types.ThreatTypeEnterprisePolicy,
			Severity:        types.SeverityMedium,
			Confidence:      0.8,
			Description:     fmt.Sprintf("Package '%s' does not meet enterprise security standards (reputation: %.2f)", dep.Name, data.ReputationScore),
			Recommendation:  "Package requires security review before enterprise deployment",
			DetectedAt:      time.Now(),
			DetectionMethod: "enterprise_policy_check",
			Evidence: []types.Evidence{
				{
					Type:        "reputation_threshold",
					Description: "Below enterprise reputation threshold",
					Value:       data.ReputationScore,
					Score:       0.8,
				},
			},
		})
	}

	// Check for packages with insufficient download history (enterprise stability requirement)
	if data.DownloadCount > 0 && data.DownloadCount < 10000 {
		threats = append(threats, types.Threat{
			ID:              generateThreatID(),
			Package:         dep.Name,
			Version:         dep.Version,
			Registry:        dep.Registry,
			Type:            types.ThreatTypeEnterprisePolicy,
			Severity:        types.SeverityLow,
			Confidence:      0.6,
			Description:     fmt.Sprintf("Package '%s' has insufficient adoption for enterprise use (%d downloads)", dep.Name, data.DownloadCount),
			Recommendation:  "Consider more established alternatives for enterprise deployment",
			DetectedAt:      time.Now(),
			DetectionMethod: "enterprise_adoption_check",
			Evidence: []types.Evidence{
				{
					Type:        "adoption_threshold",
					Description: "Below enterprise adoption threshold",
					Value:       data.DownloadCount,
					Score:       0.6,
				},
			},
		})
	}

	// Check for packages that are too new for enterprise use
	if data.CreatedAt.After(time.Now().AddDate(0, -6, 0)) { // Less than 6 months old
		threats = append(threats, types.Threat{
			ID:              generateThreatID(),
			Package:         dep.Name,
			Version:         dep.Version,
			Registry:        dep.Registry,
			Type:            types.ThreatTypeEnterprisePolicy,
			Severity:        types.SeverityLow,
			Confidence:      0.7,
			Description:     fmt.Sprintf("Package '%s' is too new for enterprise deployment (created %v ago)", dep.Name, time.Since(data.CreatedAt).Truncate(24*time.Hour)),
			Recommendation:  "Allow package to mature before enterprise adoption",
			DetectedAt:      time.Now(),
			DetectionMethod: "enterprise_maturity_check",
			Evidence: []types.Evidence{
				{
					Type:        "maturity_threshold",
					Description: "Package too new for enterprise standards",
					Value:       data.CreatedAt,
					Score:       0.7,
				},
			},
		})
	}

	return threats
}

