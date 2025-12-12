package detector

import (
	"context"
	"fmt"
	"time"

	"github.com/falcn-io/falcn/internal/sandbox"
	"github.com/falcn-io/falcn/pkg/types"
	"github.com/sirupsen/logrus"
)

type BehavioralEngine struct {
	sandbox       sandbox.Sandbox
	traceAnalyzer *sandbox.TraceAnalyzer
	image         string
}

func NewBehavioralEngine(sb sandbox.Sandbox) *BehavioralEngine {
	return &BehavioralEngine{
		sandbox:       sb,
		traceAnalyzer: sandbox.NewTraceAnalyzer(),
		image:         "node:18-alpine", // Default for NPM, can parameterize
	}
}

func (be *BehavioralEngine) AnalyzeBehavior(ctx context.Context, dep types.Dependency) ([]types.Threat, error) {
	logrus.Infof("Starting behavioral analysis for %s@%s", dep.Name, dep.Version)

	// 1. Start Sandbox
	// Use a fresh container for each analysis
	// Note: In production this would be pooled.
	// For this POC, we start/stop per request.
	if err := be.sandbox.Start(ctx, be.image); err != nil {
		return nil, fmt.Errorf("failed to start sandbox: %w", err)
	}
	defer be.sandbox.Stop(ctx)

	// 2. Install Package (triggers install scripts)
	// We want to capture what happens during install.
	// Command: npm install <package>@<version>
	cmd := []string{"npm", "install", fmt.Sprintf("%s@%s", dep.Name, dep.Version)}

	logrus.Debugf("Executing in sandbox: %v", cmd)
	result, err := be.sandbox.Execute(ctx, cmd, nil)
	if err != nil {
		logrus.Warnf("Sandbox execution failed: %v", err)
		// We process partial logs even if it failed (malware often crashes or returns exit 1)
	}

	// 3. Analyze Logs
	findings := be.traceAnalyzer.AnalyzeLogs(result.Stdout, result.Stderr)

	var threats []types.Threat
	if len(findings) > 0 {
		evidenceList := []types.Evidence{}
		for keyword, desc := range findings {
			evidenceList = append(evidenceList, types.Evidence{
				Type:        "behavioral_indicator",
				Description: desc,
				Value:       keyword,
				Score:       0.8, // High confidence if we see it in logs
			})
		}

		threats = append(threats, types.Threat{
			ID:              generateThreatID(),
			Package:         dep.Name,
			Version:         dep.Version,
			Registry:        dep.Registry,
			Type:            types.ThreatTypeMalicious, // Behavioral implies malice usually
			Severity:        types.SeverityHigh,
			Confidence:      0.85,
			Description:     fmt.Sprintf("Suspicious behavior detected during installation of %s", dep.Name),
			Recommendation:  "Review install scripts and sandbox logs",
			DetectedAt:      time.Now(),
			DetectionMethod: "sandbox_behavioral_analysis",
			Evidence:        evidenceList,
		})
	}

	// If exit code was non-zero and we didn't find keywords, might be just a broken package
	if result.ExitCode != 0 && len(threats) == 0 {
		logrus.Infof("Package install failed but no suspicious indicators found.")
	}

	return threats, nil
}
