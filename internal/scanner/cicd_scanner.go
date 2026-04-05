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
	"gopkg.in/yaml.v3"
)

// CICDScanner scans CI/CD configuration files for vulnerabilities
type CICDScanner struct {
	projectPath string
}

// NewCICDScanner creates a new CI/CD scanner
func NewCICDScanner(projectPath string) *CICDScanner {
	return &CICDScanner{
		projectPath: projectPath,
	}
}

// ScanProject scans project for CI/CD vulnerabilities
func (cs *CICDScanner) ScanProject() ([]types.Threat, error) {
	var threats []types.Threat

	// Scan GitHub Actions workflows
	ghThreats, err := cs.scanGitHubActions()
	if err != nil {
		logrus.Debugf("[CICDScanner] Error scanning GitHub Actions: %v", err)
	}
	threats = append(threats, ghThreats...)

	// Scan GitLab CI pipelines
	glThreats, err := cs.scanGitLabCI()
	if err != nil {
		logrus.Debugf("[CICDScanner] Error scanning GitLab CI: %v", err)
	}
	threats = append(threats, glThreats...)

	logrus.Infof("[CICDScanner] Found %d CI/CD vulnerabilities", len(threats))
	return threats, nil
}

// scanGitHubActions scans .github/workflows for vulnerabilities
func (cs *CICDScanner) scanGitHubActions() ([]types.Threat, error) {
	var threats []types.Threat

	workflowDir := filepath.Join(cs.projectPath, ".github", "workflows")
	if _, err := os.Stat(workflowDir); os.IsNotExist(err) {
		return threats, nil
	}

	files, err := os.ReadDir(workflowDir)
	if err != nil {
		return threats, err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// Only scan YAML files
		ext := strings.ToLower(filepath.Ext(file.Name()))
		if ext != ".yml" && ext != ".yaml" {
			continue
		}

		filePath := filepath.Join(workflowDir, file.Name())
		fileThreats, err := cs.scanGitHubWorkflow(filePath, file.Name())
		if err != nil {
			logrus.Warnf("[CICDScanner] Error scanning %s: %v", file.Name(), err)
			continue
		}

		threats = append(threats, fileThreats...)
	}

	return threats, nil
}

// scanGitHubWorkflow scans a single GitHub Actions workflow file
func (cs *CICDScanner) scanGitHubWorkflow(filePath, fileName string) ([]types.Threat, error) {
	var threats []types.Threat

	content, err := os.ReadFile(filePath)
	if err != nil {
		return threats, err
	}

	contentStr := string(content)

	// Parse YAML
	var workflow map[string]interface{}
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		logrus.Debugf("[CICDScanner] Failed to parse %s as YAML: %v", fileName, err)
		return threats, nil
	}

	// 1. Detect self-hosted runners (Shai-Hulud red flag)
	if cs.hasSelfHostedRunner(workflow) {
		threats = append(threats, cs.createSelfHostedRunnerThreat(fileName, filePath))
	}

	// 2. Detect injection vulnerabilities
	injections := cs.detectInjectionVulnerabilities(contentStr)
	if len(injections) > 0 {
		threats = append(threats, cs.createInjectionThreat(fileName, filePath, injections))
	}

	// 3. Detect C2 channel patterns (Discussion/Issue triggers WITH injection-vulnerable expressions)
	// Only flag if the workflow both has issue/discussion triggers AND uses injectable expressions
	if cs.hasC2ChannelTrigger(workflow) && len(injections) > 0 {
		threats = append(threats, cs.createC2ChannelThreat(fileName, filePath))
	}

	// 4. Detect unpinned actions (supply chain risk — using @main/@master instead of SHA)
	if unpinned := cs.detectUnpinnedActions(contentStr); len(unpinned) > 0 {
		threats = append(threats, cs.createUnpinnedActionsThreat(fileName, filePath, unpinned))
	}

	// 5. Detect dangerous pull_request_target + checkout combination
	threats = append(threats, cs.detectPRTargetCheckout(workflow, fileName)...)

	return threats, nil
}

// hasSelfHostedRunner checks if workflow uses self-hosted runners
func (cs *CICDScanner) hasSelfHostedRunner(workflow map[string]interface{}) bool {
	jobs, ok := workflow["jobs"].(map[string]interface{})
	if !ok {
		return false
	}

	for _, job := range jobs {
		jobMap, ok := job.(map[string]interface{})
		if !ok {
			continue
		}

		runsOn, ok := jobMap["runs-on"]
		if !ok {
			continue
		}

		// Check if runs-on is "self-hosted" (string or array)
		switch v := runsOn.(type) {
		case string:
			if v == "self-hosted" || strings.Contains(v, "self-hosted") {
				return true
			}
		case []interface{}:
			for _, runner := range v {
				if runnerStr, ok := runner.(string); ok {
					if runnerStr == "self-hosted" || strings.Contains(runnerStr, "self-hosted") {
						return true
					}
				}
			}
		}
	}

	return false
}

// detectInjectionVulnerabilities detects code injection patterns
func (cs *CICDScanner) detectInjectionVulnerabilities(content string) []string {
	var injections []string

	// Dangerous injection patterns (Shai-Hulud used github.event.discussion.body)
	patterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{
			name:    "github.event.discussion.body",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.discussion\.body\s*\}\}`),
		},
		{
			name:    "github.event.issue.title",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.issue\.title\s*\}\}`),
		},
		{
			name:    "github.event.issue.body",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.issue\.body\s*\}\}`),
		},
		{
			name:    "github.event.comment.body",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.comment\.body\s*\}\}`),
		},
		{
			name:    "github.event.pull_request.title",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.pull_request\.title\s*\}\}`),
		},
		{
			name:    "github.event.pull_request.body",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.pull_request\.body\s*\}\}`),
		},
		{
			name:    "github.event.head_commit.message",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.head_commit\.message\s*\}\}`),
		},
		{
			name:    "github.event.head_commit.author.name",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.head_commit\.author\.(name|email)\s*\}\}`),
		},
		{
			name:    "github.event.commits[*].message",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.commits\[?\*?\]?\.message\s*\}\}`),
		},
		{
			name:    "github.event.workflow_run.head_branch",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.workflow_run\.head_branch\s*\}\}`),
		},
		{
			name:    "github.event.pages[*].page_name",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.pages\[?\*?\]?\.page_name\s*\}\}`),
		},
		{
			name:    "github.head_ref (branch name injection)",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.head_ref\s*\}\}`),
		},
	}

	for _, p := range patterns {
		if p.pattern.MatchString(content) {
			injections = append(injections, p.name)
		}
	}

	return injections
}

// hasC2ChannelTrigger detects workflows triggered by Discussions/Issues (C2 red flag)
func (cs *CICDScanner) hasC2ChannelTrigger(workflow map[string]interface{}) bool {
	on, ok := workflow["on"]
	if !ok {
		return false
	}

	// "on" can be string, array, or map
	switch v := on.(type) {
	case string:
		return v == "discussion" || v == "issues" || v == "issue_comment"
	case []interface{}:
		for _, trigger := range v {
			if triggerStr, ok := trigger.(string); ok {
				if triggerStr == "discussion" || triggerStr == "issues" || triggerStr == "issue_comment" {
					return true
				}
			}
		}
	case map[string]interface{}:
		if _, hasDiscussion := v["discussion"]; hasDiscussion {
			return true
		}
		if _, hasIssues := v["issues"]; hasIssues {
			return true
		}
		if _, hasIssueComment := v["issue_comment"]; hasIssueComment {
			return true
		}
	}

	return false
}

// detectUnpinnedActions finds GitHub Actions referenced by mutable tags instead of SHA pins.
// Using @main/@master/@v1 instead of @sha256 allows supply chain attacks if the action is compromised.
func (cs *CICDScanner) detectUnpinnedActions(content string) []string {
	var unpinned []string

	// Match "uses: owner/repo@ref" patterns
	usesPattern := regexp.MustCompile(`uses:\s*([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@([^\s#]+)`)
	matches := usesPattern.FindAllStringSubmatch(content, -1)

	// Mutable refs that should be pinned to SHA
	mutableRefs := map[string]bool{
		"main": true, "master": true, "dev": true, "develop": true,
		"latest": true, "nightly": true, "canary": true,
	}

	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		action := m[1]
		ref := m[2]

		// Skip actions/* official actions (lower risk, frequently updated)
		// Still flag third-party actions
		isOfficial := strings.HasPrefix(action, "actions/")

		// SHA pins are 40 hex chars
		isSHA := len(ref) == 40 && regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(ref)
		if isSHA {
			continue
		}

		// Flag mutable branch refs (main, master, dev)
		if mutableRefs[ref] {
			unpinned = append(unpinned, fmt.Sprintf("%s@%s (mutable branch)", action, ref))
			continue
		}

		// Flag non-official actions using semver tags without SHA
		// e.g., third-party/action@v1 is risky because v1 tag can be force-pushed
		if !isOfficial && strings.HasPrefix(ref, "v") {
			unpinned = append(unpinned, fmt.Sprintf("%s@%s (tag, not SHA-pinned)", action, ref))
		}
	}

	return unpinned
}

// detectPRTargetCheckout detects the dangerous pattern where a workflow uses
// pull_request_target (which runs with write permissions) and checks out the
// PR's untrusted head code. This allows an attacker to run arbitrary code with
// write access by opening a PR.
func (cs *CICDScanner) detectPRTargetCheckout(workflow map[string]interface{}, fileName string) []types.Threat {
	var threats []types.Threat

	// Check if pull_request_target is a trigger.
	on, ok := workflow["on"]
	if !ok {
		return threats
	}

	hasPRTarget := false
	switch v := on.(type) {
	case string:
		hasPRTarget = v == "pull_request_target"
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == "pull_request_target" {
				hasPRTarget = true
			}
		}
	case map[string]interface{}:
		if _, ok := v["pull_request_target"]; ok {
			hasPRTarget = true
		}
	}

	if !hasPRTarget {
		return threats
	}

	// Check for checkout of PR head in any job step.
	jobs, ok := workflow["jobs"].(map[string]interface{})
	if !ok {
		return threats
	}

	for jobName, job := range jobs {
		jobMap, ok := job.(map[string]interface{})
		if !ok {
			continue
		}
		steps, ok := jobMap["steps"].([]interface{})
		if !ok {
			continue
		}
		for _, step := range steps {
			stepMap, ok := step.(map[string]interface{})
			if !ok {
				continue
			}
			uses, _ := stepMap["uses"].(string)
			if !strings.HasPrefix(uses, "actions/checkout") {
				continue
			}
			with, ok := stepMap["with"].(map[string]interface{})
			if !ok {
				continue
			}
			ref, _ := with["ref"].(string)
			// Dangerous: checking out PR head with pull_request_target permissions.
			if strings.Contains(ref, "github.event.pull_request.head") ||
				strings.Contains(ref, "github.event.pull_request.head.sha") ||
				strings.Contains(ref, "github.event.pull_request.head.ref") {
				threats = append(threats, types.Threat{
					Type:            types.ThreatTypeCICDInjection,
					Severity:        types.SeverityCritical,
					Confidence:      0.95,
					Package:         fileName,
					Description:     fmt.Sprintf("Dangerous pull_request_target + checkout combination in job %q: workflow runs with write permissions but checks out untrusted PR code from %s", jobName, ref),
					DetectionMethod: "cicd_analysis",
					Recommendation:  "Never checkout untrusted PR code in a pull_request_target workflow. Either use pull_request trigger (read-only) or avoid checking out the PR head. If you must, run only pre-approved actions on the checked-out code.",
					Evidence: []types.Evidence{{
						Type:        "cicd_pattern",
						Description: "pull_request_target with PR head checkout",
						Value:       fmt.Sprintf("pull_request_target trigger with checkout ref: %s", ref),
					}},
					Metadata: map[string]interface{}{
						"file_name": fileName,
						"job_name":  jobName,
						"ref":       ref,
					},
					DetectedAt: time.Now(),
				})
			}
		}
	}

	return threats
}

func (cs *CICDScanner) createUnpinnedActionsThreat(fileName, filePath string, unpinned []string) types.Threat {
	return types.Threat{
		Type:            types.ThreatTypeSuspiciousPattern,
		Severity:        types.SeverityMedium,
		Confidence:      0.85,
		Description:     fmt.Sprintf("Workflow '%s' uses unpinned GitHub Actions: %s — mutable tags/branches can be hijacked", fileName, strings.Join(unpinned, "; ")),
		DetectionMethod: "cicd_analysis",
		Recommendation:  "Pin all third-party GitHub Actions to full commit SHA (e.g., uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29). Mutable tags like @v1 or @main can be force-pushed by attackers. Use StepSecurity or Scorecard to automate pinning.",
		Evidence: []types.Evidence{
			{
				Type:        "workflow_file",
				Description: "GitHub Actions workflow",
				Value:       fileName,
			},
			{
				Type:        "unpinned_actions",
				Description: "Actions not pinned to SHA",
				Value:       strings.Join(unpinned, "; "),
			},
		},
		Metadata: map[string]interface{}{
			"file_path":       filePath,
			"file_name":       fileName,
			"unpinned_actions": unpinned,
		},
		DetectedAt: time.Now(),
	}
}

// scanGitLabCI scans .gitlab-ci.yml for vulnerabilities
func (cs *CICDScanner) scanGitLabCI() ([]types.Threat, error) {
	var threats []types.Threat

	ciFilePath := filepath.Join(cs.projectPath, ".gitlab-ci.yml")
	if _, err := os.Stat(ciFilePath); os.IsNotExist(err) {
		return threats, nil
	}

	content, err := os.ReadFile(ciFilePath)
	if err != nil {
		return threats, err
	}

	contentStr := string(content)

	// Parse YAML
	var pipeline map[string]interface{}
	if err := yaml.Unmarshal(content, &pipeline); err != nil {
		logrus.Debugf("[CICDScanner] Failed to parse .gitlab-ci.yml: %v", err)
		return threats, nil
	}

	// 1. Detect custom Docker images from unknown registries
	if unknownImages := cs.detectUnknownDockerImages(pipeline); len(unknownImages) > 0 {
		threats = append(threats, cs.createUnknownImageThreat(unknownImages))
	}

	// 2. Detect secrets in variables
	if cs.hasSecretsInVariables(contentStr) {
		threats = append(threats, cs.createSecretsInVariablesThreat())
	}

	return threats, nil
}

// detectUnknownDockerImages detects custom Docker images from non-standard registries
func (cs *CICDScanner) detectUnknownDockerImages(pipeline map[string]interface{}) []string {
	var unknownImages []string
	knownRegistries := []string{"docker.io", "gcr.io", "ghcr.io", "registry.gitlab.com"}

	// Check global image
	if image, ok := pipeline["image"].(string); ok {
		if !cs.isKnownRegistry(image, knownRegistries) {
			unknownImages = append(unknownImages, image)
		}
	}

	// Check job-level images
	for key, value := range pipeline {
		if strings.HasPrefix(key, ".") || key == "stages" || key == "variables" {
			continue
		}

		if jobMap, ok := value.(map[string]interface{}); ok {
			if image, ok := jobMap["image"].(string); ok {
				if !cs.isKnownRegistry(image, knownRegistries) {
					unknownImages = append(unknownImages, image)
				}
			}
		}
	}

	return unknownImages
}

// isKnownRegistry checks if Docker image is from a known/trusted registry
func (cs *CICDScanner) isKnownRegistry(image string, knownRegistries []string) bool {
	// If no registry prefix, assume docker.io
	if !strings.Contains(image, "/") {
		return true
	}

	for _, registry := range knownRegistries {
		if strings.HasPrefix(image, registry) {
			return true
		}
	}

	return false
}

// hasSecretsInVariables detects hardcoded secrets in GitLab CI variables.
// Distinguishes between safe vault references ($CI_VARIABLE, ${SECRET_VAR})
// and actual hardcoded values.
func (cs *CICDScanner) hasSecretsInVariables(content string) bool {
	// Match "KEY: VALUE" patterns where KEY looks like a secret name
	secretKeyPattern := regexp.MustCompile(`(?im)^\s*(password|secret|token|api_key|api_secret|private_key|access_key|auth_token)\s*:\s*(.+)$`)
	matches := secretKeyPattern.FindAllStringSubmatch(content, -1)

	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		value := strings.TrimSpace(m[2])

		// Safe patterns — references to CI variables or vaults
		if strings.HasPrefix(value, "$") || // $CI_VARIABLE or ${VAR}
			strings.HasPrefix(value, "\"$") || // "$CI_VARIABLE"
			strings.HasPrefix(value, "'$") || // '$CI_VARIABLE'
			strings.Contains(value, "vault://") || // HashiCorp Vault
			strings.Contains(value, "op://") || // 1Password
			value == "" || value == "''" || value == `""` {
			continue
		}

		// If value looks like a real secret (8+ chars, not a placeholder), flag it
		cleanValue := strings.Trim(value, `"'`)
		if len(cleanValue) >= 8 && cleanValue != "changeme" && cleanValue != "placeholder" {
			return true
		}
	}

	return false
}

// Threat creation helpers

func (cs *CICDScanner) createSelfHostedRunnerThreat(fileName, filePath string) types.Threat {
	return types.Threat{
		Type:            types.ThreatTypeSelfHostedRunner,
		Severity:        types.SeverityHigh,
		Confidence:      0.9,
		Description:     fmt.Sprintf("Workflow '%s' uses self-hosted runners (Shai-Hulud attack vector)", fileName),
		DetectionMethod: "cicd_analysis",
		Recommendation:  "Self-hosted runners can be compromised to register backdoors. Review runner configuration and ensure it's legitimate. Consider using GitHub-hosted runners unless self-hosting is required.",
		Evidence: []types.Evidence{
			{
				Type:        "workflow_file",
				Description: "GitHub Actions workflow",
				Value:       fileName,
			},
			{
				Type:        "runner_type",
				Description: "Runner configuration",
				Value:       "self-hosted",
			},
		},
		Metadata: map[string]interface{}{
			"file_path": filePath,
			"file_name": fileName,
		},
		DetectedAt: time.Now(),
	}
}

func (cs *CICDScanner) createInjectionThreat(fileName, filePath string, injections []string) types.Threat {
	return types.Threat{
		Type:            types.ThreatTypeCICDInjection,
		Severity:        types.SeverityCritical,
		Confidence:      0.95,
		Description:     fmt.Sprintf("Workflow '%s' contains code injection vulnerabilities: %s", fileName, strings.Join(injections, ", ")),
		DetectionMethod: "cicd_analysis",
		Recommendation:  "CRITICAL: Code injection detected. Attackers can execute arbitrary commands via GitHub Discussions/Issues. Use ${{ toJSON(github.event) }} piped to a safe parser instead of using event fields directly in 'run' steps.",
		Evidence: []types.Evidence{
			{
				Type:        "workflow_file",
				Description: "GitHub Actions workflow",
				Value:       fileName,
			},
			{
				Type:        "injection_patterns",
				Description: "Vulnerable expressions",
				Value:       strings.Join(injections, "; "),
			},
		},
		Metadata: map[string]interface{}{
			"file_path":  filePath,
			"file_name":  fileName,
			"injections": injections,
		},
		DetectedAt: time.Now(),
	}
}

func (cs *CICDScanner) createC2ChannelThreat(fileName, filePath string) types.Threat {
	return types.Threat{
		Type:            types.ThreatTypeC2Channel,
		Severity:        types.SeverityHigh,
		Confidence:      0.8,
		Description:     fmt.Sprintf("Workflow '%s' is triggered by Discussions/Issues (potential C2 channel like Shai-Hulud)", fileName),
		DetectionMethod: "cicd_analysis",
		Recommendation:  "Workflows triggered by 'discussion' or 'issues' events can be used as command-and-control channels. Review workflow purpose and ensure it's legitimate.",
		Evidence: []types.Evidence{
			{
				Type:        "workflow_file",
				Description: "GitHub Actions workflow",
				Value:       fileName,
			},
			{
				Type:        "trigger_type",
				Description: "Workflow trigger",
				Value:       "discussion/issues",
			},
		},
		Metadata: map[string]interface{}{
			"file_path": filePath,
			"file_name": fileName,
		},
		DetectedAt: time.Now(),
	}
}

func (cs *CICDScanner) createUnknownImageThreat(images []string) types.Threat {
	return types.Threat{
		Type:            types.ThreatTypeSuspiciousPattern,
		Severity:        types.SeverityMedium,
		Confidence:      0.7,
		Description:     fmt.Sprintf("GitLab CI uses Docker images from unknown registries: %s", strings.Join(images, ", ")),
		DetectionMethod: "cicd_analysis",
		Recommendation:  "Verify Docker images are from trusted sources. Unknown registries may host malicious images.",
		Evidence: []types.Evidence{
			{
				Type:        "ci_file",
				Description: "GitLab CI configuration",
				Value:       ".gitlab-ci.yml",
			},
			{
				Type:        "docker_images",
				Description: "Unknown registry images",
				Value:       strings.Join(images, "; "),
			},
		},
		Metadata: map[string]interface{}{
			"images": images,
		},
		DetectedAt: time.Now(),
	}
}

func (cs *CICDScanner) createSecretsInVariablesThreat() types.Threat {
	return types.Threat{
		Type:            types.ThreatTypeEmbeddedSecret,
		Severity:        types.SeverityHigh,
		Confidence:      0.75,
		Description:     "GitLab CI configuration may contain hardcoded secrets in variables",
		DetectionMethod: "cicd_analysis",
		Recommendation:  "Use GitLab CI/CD variables with masking and protection enabled instead of hardcoding secrets in .gitlab-ci.yml.",
		Evidence: []types.Evidence{
			{
				Type:        "ci_file",
				Description: "GitLab CI configuration",
				Value:       ".gitlab-ci.yml",
			},
		},
		Metadata:   map[string]interface{}{},
		DetectedAt: time.Now(),
	}
}
