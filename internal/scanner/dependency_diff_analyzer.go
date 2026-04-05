// Package scanner provides the dependency diff analyzer.
package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/falcn-io/falcn/internal/detector"
	"github.com/falcn-io/falcn/pkg/types"
)

// DependencyDiffAnalyzer detects suspicious changes in a package's dependency list.
// It catches attacks like Axios (March 2026) where a trojanized dependency
// (plain-crypto-js, typosquat of crypto-js) was added to a stable package.
type DependencyDiffAnalyzer struct {
	engine *detector.Engine
}

// NewDependencyDiffAnalyzer creates a new dependency diff analyzer.
func NewDependencyDiffAnalyzer(engine *detector.Engine) *DependencyDiffAnalyzer {
	return &DependencyDiffAnalyzer{engine: engine}
}

// DiffResult holds the analysis of dependency changes between versions.
type DiffResult struct {
	Added   []string
	Removed []string
	Threats []types.Threat
}

// AnalyzeDiff compares current dependencies against previous version dependencies
// and flags suspicious additions.
func (d *DependencyDiffAnalyzer) AnalyzeDiff(currentDeps, previousDeps []string, packageName, registry string) *DiffResult {
	result := &DiffResult{}

	prevSet := make(map[string]bool, len(previousDeps))
	for _, dep := range previousDeps {
		prevSet[strings.ToLower(dep)] = true
	}
	currSet := make(map[string]bool, len(currentDeps))
	for _, dep := range currentDeps {
		currSet[strings.ToLower(dep)] = true
	}

	// Find newly added dependencies
	for _, dep := range currentDeps {
		if !prevSet[strings.ToLower(dep)] {
			result.Added = append(result.Added, dep)
		}
	}
	// Find removed dependencies
	for _, dep := range previousDeps {
		if !currSet[strings.ToLower(dep)] {
			result.Removed = append(result.Removed, dep)
		}
	}

	if len(result.Added) == 0 {
		return result
	}

	// Analyze each new dependency for suspicious signals
	for _, newDep := range result.Added {
		var evidence []types.Evidence
		severity := types.SeverityMedium
		confidence := 0.60

		evidence = append(evidence, types.Evidence{
			Type:        "dependency_added",
			Description: fmt.Sprintf("New dependency '%s' added to '%s'", newDep, packageName),
			Score:       0.5,
		})

		// Check if new dep is a typosquat of a popular package
		if d.engine != nil {
			checkResult, err := d.engine.CheckPackage(context.Background(), newDep, registry)
			if err == nil && checkResult != nil && len(checkResult.Threats) > 0 {
				for _, t := range checkResult.Threats {
					if t.Type == types.ThreatTypeTyposquatting || t.Type == types.ThreatTypeHomoglyph || t.Type == types.ThreatTypeSlopsquatting {
						severity = types.SeverityHigh
						confidence = 0.88
						evidence = append(evidence, types.Evidence{
							Type:        "typosquat_in_new_dep",
							Description: fmt.Sprintf("New dependency '%s' is a potential typosquat (similar to '%s')", newDep, t.SimilarTo),
							Score:       t.Confidence,
						})
					}
				}
			}
		}

		// Flag: a stable package suddenly adding a new unknown dependency
		if len(previousDeps) > 3 && len(result.Added) <= 2 {
			// Stable package (had deps before) adding just 1-2 new ones — targeted addition
			evidence = append(evidence, types.Evidence{
				Type:        "targeted_addition",
				Description: fmt.Sprintf("Stable package with %d existing deps added only %d new dep(s)", len(previousDeps), len(result.Added)),
				Score:       0.7,
			})
			if confidence < 0.70 {
				confidence = 0.70
			}
		}

		result.Threats = append(result.Threats, types.Threat{
			Type:            types.ThreatTypeDependencyDiffAnomaly,
			Severity:        severity,
			Confidence:      confidence,
			Package:         packageName,
			Registry:        registry,
			Description:     fmt.Sprintf("New dependency '%s' added to '%s' — newly introduced dependencies in established packages can indicate supply chain compromise (Axios-style attack)", newDep, packageName),
			DetectionMethod: "dependency_diff_analysis",
			Recommendation:  fmt.Sprintf("Verify that '%s' is a legitimate dependency. Check its registry page, maintainer, download count, and repository. If this dependency was not intentionally added, the package may be compromised.", newDep),
			Evidence:        evidence,
			Metadata: map[string]interface{}{
				"new_dependency":    newDep,
				"parent_package":    packageName,
				"total_added":       len(result.Added),
				"previous_dep_count": len(previousDeps),
			},
			DetectedAt: time.Now(),
		})
	}

	return result
}
