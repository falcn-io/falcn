package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	pkgtypes "github.com/falcn-io/falcn/pkg/types"
	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(ciCmd)
	ciCmd.Flags().String("input", "", "Scan result JSON file (default: falcn_report.json)")
	ciCmd.Flags().String("github-token", "", "GitHub API token (or GITHUB_TOKEN env var)")
	ciCmd.Flags().String("github-repo", "", "Repository in owner/repo format (or GITHUB_REPOSITORY env var)")
	ciCmd.Flags().String("github-sha", "", "Commit SHA to annotate (or GITHUB_SHA env var)")
	ciCmd.Flags().String("manifest-path", "package.json", "Manifest file to annotate in GitHub (e.g. package.json)")
	ciCmd.Flags().Bool("dry-run", false, "Print the check-run payload without posting to GitHub")
	ciCmd.Flags().String("fail-on", "high", "Minimum severity that causes a non-zero exit: low|medium|high|critical|none")
}

var ciCmd = &cobra.Command{
	Use:   "ci",
	Short: "Post scan results to GitHub Checks API with inline PR annotations",
	Long: `Post Falcn scan results to the GitHub Checks API.

Creates a check run with annotations for each CRITICAL/HIGH threat,
enabling inline PR review comments and blocking merge on failures.

Required: --github-token (or GITHUB_TOKEN env), --github-repo, --github-sha`,
	RunE: runCI,
}

// githubCheckRun is the payload for POST /repos/{owner}/{repo}/check-runs.
type githubCheckRun struct {
	Name        string            `json:"name"`
	HeadSHA     string            `json:"head_sha"`
	Status      string            `json:"status"`
	Conclusion  string            `json:"conclusion,omitempty"`
	StartedAt   string            `json:"started_at"`
	CompletedAt string            `json:"completed_at,omitempty"`
	Output      githubCheckOutput `json:"output"`
}

type githubCheckOutput struct {
	Title       string                  `json:"title"`
	Summary     string                  `json:"summary"`
	Annotations []githubCheckAnnotation `json:"annotations,omitempty"`
}

type githubCheckAnnotation struct {
	Path            string `json:"path"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`
	AnnotationLevel string `json:"annotation_level"` // failure|warning|notice
	Message         string `json:"message"`
	Title           string `json:"title"`
	RawDetails      string `json:"raw_details,omitempty"`
}

func runCI(cmd *cobra.Command, args []string) error {
	// Resolve inputs
	inputFile, _ := cmd.Flags().GetString("input")
	if inputFile == "" {
		inputFile = "falcn_report.json"
	}
	token := firstNonEmpty(mustGetString(cmd, "github-token"), os.Getenv("GITHUB_TOKEN"))
	repo := firstNonEmpty(mustGetString(cmd, "github-repo"), os.Getenv("GITHUB_REPOSITORY"))
	sha := firstNonEmpty(mustGetString(cmd, "github-sha"), os.Getenv("GITHUB_SHA"))
	manifestPath, _ := cmd.Flags().GetString("manifest-path")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	failOn, _ := cmd.Flags().GetString("fail-on")

	if !dryRun {
		if token == "" {
			return fmt.Errorf("--github-token or GITHUB_TOKEN is required")
		}
		if repo == "" {
			return fmt.Errorf("--github-repo or GITHUB_REPOSITORY is required (format: owner/repo)")
		}
		if sha == "" {
			return fmt.Errorf("--github-sha or GITHUB_SHA is required")
		}
	}

	// Load scan result
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("read scan result %q: %w", inputFile, err)
	}

	var scanResult struct {
		Threats []pkgtypes.Threat `json:"threats"`
	}
	if err := json.Unmarshal(data, &scanResult); err != nil {
		return fmt.Errorf("parse scan result: %w", err)
	}

	threats := scanResult.Threats
	critCount := countBySeverity(threats, pkgtypes.SeverityCritical)
	highCount := countBySeverity(threats, pkgtypes.SeverityHigh)
	medCount := countBySeverity(threats, pkgtypes.SeverityMedium)

	// Build annotations (max 50 — GitHub API limit per request).
	var annotations []githubCheckAnnotation
	for _, t := range threats {
		if t.Severity < pkgtypes.SeverityMedium {
			continue
		}
		if len(annotations) >= 50 {
			break
		}
		level := "notice"
		switch {
		case t.Severity == pkgtypes.SeverityCritical:
			level = "failure"
		case t.Severity == pkgtypes.SeverityHigh:
			level = "failure"
		case t.Severity == pkgtypes.SeverityMedium:
			level = "warning"
		}
		msg := t.Description
		if msg == "" {
			msg = fmt.Sprintf("%s threat in %s@%s", strings.ToUpper(string(t.Type)), t.Package, t.Version)
		}
		if t.FixedVersion != "" {
			msg += fmt.Sprintf(" Fix: upgrade to %s.", t.FixedVersion)
		}
		annotations = append(annotations, githubCheckAnnotation{
			Path:            manifestPath,
			StartLine:       1,
			EndLine:         1,
			AnnotationLevel: level,
			Title:           fmt.Sprintf("[%s] %s@%s", strings.ToUpper(t.Severity.String()), t.Package, t.Version),
			Message:         msg,
			RawDetails:      strings.Join(t.CVEs, ", "),
		})
	}

	// Determine conclusion based on fail-on threshold.
	conclusion := "success"
	shouldFail := false
	switch strings.ToLower(failOn) {
	case "critical":
		shouldFail = critCount > 0
	case "high":
		shouldFail = critCount > 0 || highCount > 0
	case "medium":
		shouldFail = critCount > 0 || highCount > 0 || medCount > 0
	case "low", "any":
		shouldFail = len(threats) > 0
	case "none", "off":
		shouldFail = false
	default:
		// Default to high threshold
		shouldFail = critCount > 0 || highCount > 0
	}
	if shouldFail {
		conclusion = "failure"
	}

	now := time.Now().UTC().Format(time.RFC3339)
	summary := fmt.Sprintf(
		"**Falcn Supply Chain Scan**\n\n"+
			"| Severity | Count |\n|----------|-------|\n"+
			"| Critical | %d |\n| High | %d |\n| Medium | %d |\n\n"+
			"Total threats: %d",
		critCount, highCount, medCount, len(threats),
	)
	if len(annotations) == 0 && !shouldFail {
		summary = "No significant threats detected."
	}

	checkRun := githubCheckRun{
		Name:        "Falcn Supply Chain Security",
		HeadSHA:     sha,
		Status:      "completed",
		Conclusion:  conclusion,
		StartedAt:   now,
		CompletedAt: now,
		Output: githubCheckOutput{
			Title:       fmt.Sprintf("Falcn: %d threat(s) detected", len(threats)),
			Summary:     summary,
			Annotations: annotations,
		},
	}

	payload, err := json.MarshalIndent(checkRun, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal check run payload: %w", err)
	}

	if dryRun {
		fmt.Println("=== GitHub Check Run Payload (dry-run) ===")
		fmt.Println(string(payload))
		fmt.Printf("\nConclusion: %s (%d CRITICAL, %d HIGH)\n", conclusion, critCount, highCount)
		return nil
	}

	// POST to GitHub Checks API
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid --github-repo format, expected owner/repo, got %q", repo)
	}
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/check-runs", parts[0], parts[1])

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GitHub API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var body map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck
		return fmt.Errorf("GitHub API error %d: %v", resp.StatusCode, body["message"])
	}

	fmt.Printf("Check run created (conclusion: %s, %d annotations)\n", conclusion, len(annotations))

	if shouldFail {
		return fmt.Errorf("scan gate: %d CRITICAL, %d HIGH threats exceed --fail-on=%s threshold", critCount, highCount, failOn)
	}
	return nil
}

// countBySeverity returns the number of threats with the given severity.
func countBySeverity(threats []pkgtypes.Threat, sev pkgtypes.Severity) int {
	n := 0
	for _, t := range threats {
		if t.Severity == sev {
			n++
		}
	}
	return n
}

// mustGetString retrieves a string flag value, returning "" on error.
func mustGetString(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

// firstNonEmpty returns the first non-empty string from the provided values.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
