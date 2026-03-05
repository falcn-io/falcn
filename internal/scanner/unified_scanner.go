package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/falcn-io/falcn/pkg/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// ScanProjectUnified replaces the sequential triple-walk in ScanProject with
// concurrent execution. It collects all file paths in a single WalkDir pass,
// then fans out to ContentScanner, StaticNetworkAnalyzer, and CICDScanner
// in parallel goroutines, reducing wall-clock scan time by up to 3×.
//
// fastMode disables network I/O, heavy YAML parsing, and external DB queries.
// In fast mode only lightweight heuristics run; target wall-clock: <100ms.
func (s *Scanner) ScanProjectUnified(projectPath string, fastMode bool) ([]types.Threat, error) {
	start := time.Now()
	root, err := filepath.Abs(projectPath)
	if err != nil {
		root = projectPath
	}

	// --- Step 1: Single directory walk to collect file list ---
	files, err := collectFiles(root)
	if err != nil {
		logrus.Warnf("unified scanner walk error: %v", err)
	}
	logrus.Debugf("UnifiedScanner: collected %d files in %v", len(files), time.Since(start))

	// --- Step 2: Fan-out to sub-scanners in parallel ---
	type scanResult struct {
		threats []types.Threat
		name    string
	}

	resultCh := make(chan scanResult, 3)

	// ContentScanner — runs full analysis on the collected file set.
	// ContentScanner.ScanDirectory re-walks internally, but we can pass the
	// pre-collected file list to its AnalyzeFiles helper for future use.
	// For now we call ScanDirectory concurrently to avoid sequential stalls.
	go func() {
		cs := NewContentScanner()
		var threats []types.Threat
		if !fastMode {
			t, scanErr := cs.ScanDirectory(root)
			if scanErr != nil {
				logrus.Warnf("content scanner error: %v", scanErr)
			}
			threats = t
		} else {
			threats = fastContentScan(files)
		}
		resultCh <- scanResult{threats: threats, name: "content"}
	}()

	// StaticNetworkAnalyzer — already accepts a pre-collected file list.
	go func() {
		var threats []types.Threat
		if !fastMode {
			sna := NewStaticNetworkAnalyzer(root)
			// Pass pre-collected files instead of doing a second walk
			networkFiles := filterByExtension(files, ".js", ".ts", ".mjs", ".cjs", ".py")
			t, analyzeErr := sna.AnalyzeProject(networkFiles)
			if analyzeErr != nil {
				logrus.Warnf("network analyzer error: %v", analyzeErr)
			}
			threats = t
		}
		resultCh <- scanResult{threats: threats, name: "network"}
	}()

	// CICDScanner — targets specific paths, minimal I/O.
	go func() {
		var threats []types.Threat
		if !fastMode {
			cicd := NewCICDScanner(root)
			t, cicdErr := cicd.ScanProject()
			if cicdErr != nil {
				logrus.Warnf("cicd scanner error: %v", cicdErr)
			}
			threats = t
		} else {
			threats = fastCheckCICD(root)
		}
		resultCh <- scanResult{threats: threats, name: "cicd"}
	}()

	// --- Step 3: Collect results ---
	var allThreats []types.Threat
	for i := 0; i < 3; i++ {
		r := <-resultCh
		allThreats = append(allThreats, r.threats...)
		logrus.Debugf("UnifiedScanner: %s returned %d threats", r.name, len(r.threats))
	}
	close(resultCh)

	logrus.Debugf("UnifiedScanner: %d total threats in %v (fastMode=%v)", len(allThreats), time.Since(start), fastMode)
	return allThreats, nil
}

// collectFiles walks root and returns all regular file paths, skipping
// common noise directories (node_modules, .git, vendor, build artifacts)
// and files larger than 10 MB.
func collectFiles(root string) ([]string, error) {
	var files []string
	var mu sync.Mutex

	skipDirs := map[string]bool{
		"node_modules": true,
		".git":         true,
		"vendor":       true,
		"__pycache__":  true,
		".venv":        true,
		"venv":         true,
		"dist":         true,
		"build":        true,
		".tox":         true,
		".nyc_output":  true,
		"coverage":     true,
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil || info.Size() > 10*1024*1024 {
			return nil
		}
		mu.Lock()
		files = append(files, path)
		mu.Unlock()
		return nil
	})
	return files, err
}

// filterByExtension returns only the paths that match one of the given extensions.
func filterByExtension(files []string, exts ...string) []string {
	extSet := make(map[string]bool, len(exts))
	for _, e := range exts {
		extSet[strings.ToLower(e)] = true
	}
	var out []string
	for _, f := range files {
		if extSet[strings.ToLower(filepath.Ext(f))] {
			out = append(out, f)
		}
	}
	return out
}

// fastContentScan is the lightweight heuristic-only content analysis for fast mode.
// It checks for the highest-signal patterns without full entropy analysis.
func fastContentScan(files []string) []types.Threat {
	// High-signal patterns: base64 blobs, eval+obfuscation, shell commands in scripts
	suspiciousPatterns := []string{
		"eval(atob(", "eval(Buffer.from(", "require('child_process')",
		`exec("bash`, `exec('bash`, "subprocess.call(", "os.system(",
		"__import__('os')", `curl -s http`, `wget -q http`,
	}

	var threats []types.Threat
	for _, path := range files {
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".js" && ext != ".py" && ext != ".sh" && ext != ".ts" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)
		for _, pat := range suspiciousPatterns {
			if strings.Contains(content, pat) {
				threats = append(threats, types.Threat{
					ID:              fmt.Sprintf("fast_%s", uuid.New().String()),
					Type:            types.ThreatTypeSuspiciousPattern,
					Severity:        types.SeverityHigh,
					Confidence:      0.7,
					Description:     "Suspicious code pattern detected (fast mode)",
					Recommendation:  "Review file for malicious behaviour",
					DetectionMethod: "fast_content_scan",
					DetectedAt:      time.Now(),
					Evidence: []types.Evidence{{
						Type:        "pattern",
						Description: pat,
						Value:       path,
					}},
				})
				break // one threat per file in fast mode
			}
		}
	}
	return threats
}

// fastCheckCICD does a minimal check for suspicious CI/CD artifacts without
// deep YAML parsing. Suitable for fast mode (<1ms overhead per file).
func fastCheckCICD(root string) []types.Threat {
	var threats []types.Threat

	workflowDir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		return nil
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		wfPath := filepath.Join(workflowDir, name)
		data, readErr := os.ReadFile(wfPath)
		if readErr != nil {
			continue
		}
		content := string(data)
		if strings.Contains(content, "self-hosted") {
			threats = append(threats, types.Threat{
				ID:              fmt.Sprintf("cicd_fast_%s", uuid.New().String()),
				Type:            types.ThreatTypeSelfHostedRunner,
				Severity:        types.SeverityMedium,
				Confidence:      0.6,
				Description:     "Self-hosted runner detected in GitHub Actions workflow",
				Recommendation:  "Review self-hosted runner configuration for supply chain risks",
				DetectionMethod: "fast_cicd_check",
				DetectedAt:      time.Now(),
				Evidence: []types.Evidence{{
					Type:        "workflow_file",
					Description: "Workflow file contains self-hosted runner",
					Value:       name,
				}},
			})
		}
	}
	return threats
}
