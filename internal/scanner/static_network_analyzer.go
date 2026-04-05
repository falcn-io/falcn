package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/falcn-io/falcn/pkg/types"
	"github.com/sirupsen/logrus"
)

// Pre-compiled regexes for detectExfiltrationPatterns
var (
	reGitHubAPI    = regexp.MustCompile(`https?://api\.github\.com`)
	reGitLabAPI    = regexp.MustCompile(`https?://gitlab\.com/api`)
	reJSEnvPost    = regexp.MustCompile(`(fetch|axios|request)\s*\([^)]*method\s*:\s*['"]POST['"]`)
	rePyPost       = regexp.MustCompile(`requests\.(post|put)\s*\(`)
	rePyUrllib     = regexp.MustCompile(`urllib\.request\.(urlopen|Request)\s*\(`)
	rePyHTTP       = regexp.MustCompile(`http\.client\.HTTP(S)?Connection`)
	reJSEnvData    = regexp.MustCompile(`process\.env`)
	rePyEnvData    = regexp.MustCompile(`os\.(environ|getenv)`)
	reCredPath     = regexp.MustCompile(`(?i)(\.ssh|\.aws|\.kube|\.npmrc|\.pypirc|\.gnupg|\.netrc)`)
	reShellCurlExfil   = regexp.MustCompile(`(?i)curl\s+[^\n]{0,200}(-d|--data|--data-binary|--data-urlencode|-F)\s`)
	reShellWgetPost    = regexp.MustCompile(`(?i)wget\s+[^\n]{0,200}--post-(data|file)`)
	reShellEnvDump     = regexp.MustCompile(`(?i)(printenv|env\b|set\b|\$[A-Z_]+)`)
	reShellPipe        = regexp.MustCompile(`(?i)(curl|wget)\s+[^\n]{0,200}\|\s*(sh|bash|python|node|perl)`)
	reShellBase64Pipe  = regexp.MustCompile(`(?i)(base64\s+-d|base64\s+--decode)\s*\|\s*(sh|bash)`)
	reShellNc          = regexp.MustCompile(`(?i)\bnc\b[^\n]{0,200}-e\s+/(bin/)?(sh|bash)`)
	reShellDevTcp      = regexp.MustCompile(`/dev/tcp/`)
	reRubyNetHTTP      = regexp.MustCompile(`Net::HTTP\.(post|start|new)`)
	reRubyOpenURI      = regexp.MustCompile(`(open-uri|URI\.open|Net::HTTP\.get)`)
	reRubyEnvAccess    = regexp.MustCompile(`ENV\[`)
)

// Pre-compiled regexes for detectEnvironmentAwareness
var (
	reEnvCICheck         = regexp.MustCompile(`process\.env\.CI`)
	reEnvGitHubActions   = regexp.MustCompile(`process\.env\.GITHUB_ACTIONS`)
	reEnvGitLabCI        = regexp.MustCompile(`process\.env\.GITLAB_CI`)
	reEnvJenkins         = regexp.MustCompile(`process\.env\.JENKINS_URL`)
	reEnvTravis          = regexp.MustCompile(`process\.env\.TRAVIS`)
	reEnvConditional     = regexp.MustCompile(`if\s*\(\s*process\.env\.(CI|GITHUB_ACTIONS|GITLAB_CI)`)
	rePyCIEnvCheck       = regexp.MustCompile(`os\.(environ|getenv)\s*[\[(]\s*['"]?(CI|GITHUB_ACTIONS|GITLAB_CI|JENKINS_URL|TRAVIS)['"]?`)
	rePyConditionalCI    = regexp.MustCompile(`if\s+os\.(environ|getenv)\s*[\[(]\s*['"]?(CI|GITHUB_ACTIONS)['"]?`)
)

// Pre-compiled regexes for detectBeaconPatterns
var (
	reSNASetInterval = regexp.MustCompile(`setInterval\s*\(`)
	reSNANetworkCall = regexp.MustCompile(`(fetch|axios|http\.request|https\.request|XMLHttpRequest)`)
)

// Pre-compiled regex for extractSuspiciousDomains
var reURLDomain = regexp.MustCompile(`https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)

// StaticNetworkAnalyzer analyzes code for network patterns without runtime execution
type StaticNetworkAnalyzer struct {
	projectPath string
}

// NewStaticNetworkAnalyzer creates a new static network analyzer
func NewStaticNetworkAnalyzer(projectPath string) *StaticNetworkAnalyzer {
	return &StaticNetworkAnalyzer{
		projectPath: projectPath,
	}
}

// ScanDirectory scans a directory for network threats
func (sna *StaticNetworkAnalyzer) ScanDirectory(root string) ([]types.Threat, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sna.AnalyzeProject(files)
}

// AnalyzeProject scans project files for network exfiltration patterns
func (sna *StaticNetworkAnalyzer) AnalyzeProject(files []string) ([]types.Threat, error) {
	var threats []types.Threat

	for _, file := range files {
		// Analyze JS, Python, TypeScript, Shell, Ruby, and Go files
		ext := strings.ToLower(filepath.Ext(file))
		supportedExts := map[string]bool{
			".js": true, ".ts": true, ".mjs": true, ".cjs": true,
			".py": true,
			".sh": true, ".bash": true,
			".rb": true,
			".go": true,
		}
		if !supportedExts[ext] {
			continue
		}

		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		contentStr := string(content)
		relPath, _ := filepath.Rel(sna.projectPath, file)

		// Check for various network patterns
		if exfil := sna.detectExfiltrationPatterns(contentStr, relPath); exfil != nil {
			threats = append(threats, *exfil)
		}

		if envAware := sna.detectEnvironmentAwareness(contentStr, relPath); envAware != nil {
			threats = append(threats, *envAware)
		}

		if beacon := sna.detectBeaconPatterns(contentStr, relPath); beacon != nil {
			threats = append(threats, *beacon)
		}
	}

	logrus.Debugf("[StaticNetworkAnalyzer] Found %d runtime behavior threats", len(threats))
	return threats, nil
}

// detectExfiltrationPatterns detects data exfiltration to external services
func (sna *StaticNetworkAnalyzer) detectExfiltrationPatterns(content, filePath string) *types.Threat {
	var indicators []string

	// Pattern 1: GitHub/GitLab API calls (Shai-Hulud pattern)
	if reGitHubAPI.MatchString(content) {
		indicators = append(indicators, "GitHub API calls detected")
	}

	if reGitLabAPI.MatchString(content) {
		indicators = append(indicators, "GitLab API calls detected")
	}

	// Pattern 2: POST requests with environment data (JS)
	if reJSEnvPost.MatchString(content) && reJSEnvData.MatchString(content) {
		indicators = append(indicators, "POST requests with environment data")
	}
	// Python exfiltration: POST/urllib + os.environ/getenv
	if (rePyPost.MatchString(content) || rePyUrllib.MatchString(content) || rePyHTTP.MatchString(content)) && rePyEnvData.MatchString(content) {
		indicators = append(indicators, "Python HTTP requests with environment data access")
	}
	// Python credential harvesting + network (reads credential files then exfiltrates)
	if reCredPath.MatchString(content) && (rePyPost.MatchString(content) || rePyUrllib.MatchString(content) || rePyHTTP.MatchString(content)) {
		indicators = append(indicators, "Python credential path access combined with network calls (exfiltration)")
	}

	// Shell script exfiltration patterns (the #1 npm install hook attack vector)
	if reShellCurlExfil.MatchString(content) && reShellEnvDump.MatchString(content) {
		indicators = append(indicators, "Shell script sends data via curl with environment access")
	}
	if reShellWgetPost.MatchString(content) && reShellEnvDump.MatchString(content) {
		indicators = append(indicators, "Shell script sends data via wget POST with environment access")
	}
	if reShellPipe.MatchString(content) {
		indicators = append(indicators, "Shell script pipes download directly to interpreter (curl|sh pattern)")
	}
	if reShellBase64Pipe.MatchString(content) {
		indicators = append(indicators, "Shell script decodes base64 and pipes to shell")
	}
	if reShellNc.MatchString(content) || reShellDevTcp.MatchString(content) {
		indicators = append(indicators, "Shell reverse shell pattern detected (netcat -e or /dev/tcp)")
	}
	if reCredPath.MatchString(content) && (reShellCurlExfil.MatchString(content) || reShellWgetPost.MatchString(content)) {
		indicators = append(indicators, "Shell script accesses credential paths and sends data externally")
	}

	// Ruby exfiltration patterns
	if reRubyNetHTTP.MatchString(content) && reRubyEnvAccess.MatchString(content) {
		indicators = append(indicators, "Ruby Net::HTTP POST with environment variable access")
	}
	if reRubyOpenURI.MatchString(content) && reCredPath.MatchString(content) {
		indicators = append(indicators, "Ruby network calls with credential path access")
	}

	// Pattern 3: External domain connections
	suspiciousDomains := sna.extractSuspiciousDomains(content)
	if len(suspiciousDomains) > 0 {
		indicators = append(indicators, fmt.Sprintf("Connections to unknown domains: %s", strings.Join(suspiciousDomains, ", ")))
	}

	if len(indicators) == 0 {
		return nil
	}

	return &types.Threat{
		Type:            types.ThreatTypeRuntimeExfiltration,
		Severity:        types.SeverityHigh,
		Confidence:      0.8,
		Description:     fmt.Sprintf("File '%s' contains potential data exfiltration patterns", filepath.Base(filePath)),
		DetectionMethod: "static_network_analysis",
		Recommendation:  "Review network calls for unauthorized data exfiltration. Packages should not make external API calls during installation.",
		Evidence: []types.Evidence{
			{
				Type:        "network_patterns",
				Description: "Detected network indicators",
				Value:       strings.Join(indicators, "; "),
			},
			{
				Type:        "file",
				Description: "Source file",
				Value:       filepath.Base(filePath),
			},
		},
		Metadata: map[string]interface{}{
			"file_path":  filePath,
			"indicators": indicators,
		},
		DetectedAt: time.Now(),
	}
}

// detectEnvironmentAwareness detects CI/environment-aware behavior
func (sna *StaticNetworkAnalyzer) detectEnvironmentAwareness(content, filePath string) *types.Threat {
	// Patterns for CI environment checks (JS + Python)
	patterns := map[string]*regexp.Regexp{
		"CI environment check":          reEnvCICheck,
		"GitHub Actions check":          reEnvGitHubActions,
		"GitLab CI check":               reEnvGitLabCI,
		"Jenkins check":                 reEnvJenkins,
		"Travis CI check":               reEnvTravis,
		"Environment-based conditional": reEnvConditional,
		"Python CI env check":           rePyCIEnvCheck,
		"Python conditional CI check":   rePyConditionalCI,
	}

	var detectedPatterns []string
	for name, pattern := range patterns {
		if pattern.MatchString(content) {
			detectedPatterns = append(detectedPatterns, name)
		}
	}

	// Only flag if multiple CI checks (indicates targeted behavior)
	if len(detectedPatterns) < 2 {
		return nil
	}

	return &types.Threat{
		Type:            types.ThreatTypeEnvironmentAware,
		Severity:        types.SeverityMedium,
		Confidence:      0.75,
		Description:     fmt.Sprintf("File '%s' contains CI/environment-aware behavior (may only activate in specific environments)", filepath.Base(filePath)),
		DetectionMethod: "static_network_analysis",
		Recommendation:  "Malware that only activates in CI environments can evade local testing. Review all environment-based conditionals.",
		Evidence: []types.Evidence{
			{
				Type:        "environment_checks",
				Description: "Detected CI/environment checks",
				Value:       strings.Join(detectedPatterns, "; "),
			},
			{
				Type:        "file",
				Description: "Source file",
				Value:       filepath.Base(filePath),
			},
		},
		Metadata: map[string]interface{}{
			"file_path": filePath,
			"patterns":  detectedPatterns,
		},
		DetectedAt: time.Now(),
	}
}

// detectBeaconPatterns detects periodic network activity (C2 beacons)
func (sna *StaticNetworkAnalyzer) detectBeaconPatterns(content, filePath string) *types.Threat {
	// Must have both interval and network call
	if !reSNASetInterval.MatchString(content) || !reSNANetworkCall.MatchString(content) {
		return nil
	}

	return &types.Threat{
		Type:            types.ThreatTypeBeaconActivity,
		Severity:        types.SeverityHigh,
		Confidence:      0.7,
		Description:     fmt.Sprintf("File '%s' contains potential beacon/C2 pattern (periodic network activity)", filepath.Base(filePath)),
		DetectionMethod: "static_network_analysis",
		Recommendation:  "Packages should not make periodic network requests. This pattern is often used for command-and-control communication.",
		Evidence: []types.Evidence{
			{
				Type:        "beacon_pattern",
				Description: "setInterval + network calls",
				Value:       "Detected",
			},
			{
				Type:        "file",
				Description: "Source file",
				Value:       filepath.Base(filePath),
			},
		},
		Metadata: map[string]interface{}{
			"file_path": filePath,
		},
		DetectedAt: time.Now(),
	}
}

// extractSuspiciousDomains extracts external domains from HTTP calls
func (sna *StaticNetworkAnalyzer) extractSuspiciousDomains(content string) []string {
	// Extract URLs from fetch/axios calls
	matches := reURLDomain.FindAllStringSubmatch(content, -1)

	// Whitelist known-good domains
	whitelist := map[string]bool{
		"registry.npmjs.org": true,
		"pypi.org":           true,
		"pypi.python.org":    true,
		"api.github.com":     false, // Suspicious if used in install scripts
		"gitlab.com":         false, // Suspicious if used in install scripts
	}

	var suspicious []string
	seen := make(map[string]bool)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		domain := match[1]
		if seen[domain] {
			continue
		}
		seen[domain] = true

		// Check whitelist
		if isGood, exists := whitelist[domain]; exists {
			if !isGood {
				suspicious = append(suspicious, domain)
			}
			continue
		}

		// Check for brand impersonation (known vendor names in non-standard TLDs)
		flagged := false
		brandNames := []string{"checkmarx", "snyk", "sonarqube", "github", "gitlab", "npmjs", "pypi", "litellm", "anthropic", "openai"}
		trustedTLDs := map[string]bool{".com": true, ".io": true, ".org": true, ".dev": true, ".net": true, ".co": true}
		domainLower := strings.ToLower(domain)
		for _, brand := range brandNames {
			if strings.Contains(domainLower, brand) {
				// Extract TLD
				lastDot := strings.LastIndex(domain, ".")
				if lastDot >= 0 {
					tld := domain[lastDot:]
					if !trustedTLDs[tld] {
						suspicious = append(suspicious, domain+" (brand impersonation: "+brand+" with non-standard TLD)")
						flagged = true
						break
					}
				}
			}
		}

		// Check for high-consonant random domains (catches C2 like sfrclak.com)
		if !flagged {
			parts := strings.Split(domain, ".")
			if len(parts) >= 2 {
				sld := strings.ToLower(parts[len(parts)-2]) // second-level domain
				if len(sld) >= 4 {
					vowels := 0
					for _, ch := range sld {
						if ch == 'a' || ch == 'e' || ch == 'i' || ch == 'o' || ch == 'u' {
							vowels++
						}
					}
					consonantRatio := float64(len(sld)-vowels) / float64(len(sld))
					if consonantRatio >= 0.80 && vowels <= 1 {
						suspicious = append(suspicious, domain+" (random-looking domain name)")
						flagged = true
					}
				}
			}
		}

		// Any other external domain that wasn't already flagged by specific checks
		if !flagged {
			suspicious = append(suspicious, domain)
		}
	}

	return suspicious
}
