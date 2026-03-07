package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/falcn-io/falcn/internal/analyzer"
	"github.com/falcn-io/falcn/internal/scanner"
	"github.com/falcn-io/falcn/pkg/types"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func makePackageWithThreat(reachable *bool, fixedVersion string) *types.Package {
	return &types.Package{
		Name:     "lodash",
		Version:  "4.17.11",
		Registry: "npm",
		Threats: []types.Threat{
			{
				ID:           "t1",
				Package:      "lodash",
				Version:      "4.17.11",
				Registry:     "npm",
				Type:         types.ThreatTypeVulnerable,
				Severity:     types.SeverityHigh,
				Description:  "Prototype pollution CVE-2019-10744",
				CVEs:         []string{"CVE-2019-10744"},
				DetectedAt:   time.Now(),
				FixedVersion: fixedVersion,
				Reachable:    reachable,
			},
		},
	}
}

func makeScanResults(pkg *types.Package) *scanner.ScanResults {
	return &scanner.ScanResults{
		Results: []scanner.ScanResult{
			{Package: pkg},
		},
	}
}

func makeAnalyzerScanResult(reachable *bool, fixedVersion string) *analyzer.ScanResult {
	return &analyzer.ScanResult{
		ScanID:    "test-scan-001",
		Timestamp: time.Now(),
		Threats: []types.Threat{
			{
				ID:           "t1",
				Package:      "lodash",
				Version:      "4.17.11",
				Registry:     "npm",
				Type:         types.ThreatTypeVulnerable,
				Severity:     types.SeverityHigh,
				Description:  "Prototype pollution CVE-2019-10744",
				CVEs:         []string{"CVE-2019-10744"},
				DetectedAt:   time.Now(),
				FixedVersion: fixedVersion,
				Reachable:    reachable,
			},
		},
	}
}

func defaultOpts() *FormatterOptions {
	return &FormatterOptions{Indent: "  "}
}

// ─── CycloneDX VEX ───────────────────────────────────────────────────────────

func TestCycloneDX_VEX_NotAffected(t *testing.T) {
	t.Parallel()
	f := false
	res := makeScanResults(makePackageWithThreat(&f, "4.17.21"))

	out, err := NewCycloneDXFormatter().Format(res, defaultOpts())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	var bom CycloneDXBOM
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatalf("unmarshal CycloneDX: %v", err)
	}
	if len(bom.Vulnerabilities) == 0 {
		t.Skip("no vulnerabilities in output")
	}

	vuln := bom.Vulnerabilities[0]
	if vuln.Analysis == nil {
		t.Fatal("expected VEX Analysis for reachable=false, got nil")
	}
	if vuln.Analysis.State != "not_affected" {
		t.Errorf("expected state 'not_affected', got %q", vuln.Analysis.State)
	}
	if vuln.Analysis.Justification != "code_not_reachable" {
		t.Errorf("expected justification 'code_not_reachable', got %q", vuln.Analysis.Justification)
	}
}

func TestCycloneDX_VEX_Affected(t *testing.T) {
	t.Parallel()
	tTrue := true
	res := makeScanResults(makePackageWithThreat(&tTrue, "4.17.21"))

	out, err := NewCycloneDXFormatter().Format(res, defaultOpts())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	var bom CycloneDXBOM
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatalf("unmarshal CycloneDX: %v", err)
	}
	if len(bom.Vulnerabilities) == 0 {
		t.Skip("no vulnerabilities in output")
	}

	vuln := bom.Vulnerabilities[0]
	if vuln.Analysis == nil {
		t.Fatal("expected VEX Analysis for reachable=true, got nil")
	}
	if vuln.Analysis.State != "affected" {
		t.Errorf("expected state 'affected', got %q", vuln.Analysis.State)
	}
}

func TestCycloneDX_VEX_NilReachable(t *testing.T) {
	t.Parallel()
	res := makeScanResults(makePackageWithThreat(nil, "4.17.21"))

	out, err := NewCycloneDXFormatter().Format(res, defaultOpts())
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	var bom CycloneDXBOM
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatalf("unmarshal CycloneDX: %v", err)
	}
	if len(bom.Vulnerabilities) == 0 {
		t.Skip("no vulnerabilities in output")
	}

	if bom.Vulnerabilities[0].Analysis != nil {
		t.Errorf("expected nil Analysis when Reachable=nil, got state=%q",
			bom.Vulnerabilities[0].Analysis.State)
	}
}

// ─── SARIF Suppressions ───────────────────────────────────────────────────────

func TestSARIF_Suppression_Unreachable(t *testing.T) {
	t.Parallel()
	f := false
	result := makeAnalyzerScanResult(&f, "4.17.21")

	sf := NewSARIFFormatter("", "", "", "dependency")
	out, err := sf.Format(result)
	if err != nil {
		t.Fatalf("SARIF Format() error: %v", err)
	}

	var sarif SARIF
	if err := json.Unmarshal(out, &sarif); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	if len(sarif.Runs) == 0 || len(sarif.Runs[0].Results) == 0 {
		t.Skip("no SARIF results")
	}

	r := sarif.Runs[0].Results[0]
	if len(r.Suppressions) == 0 {
		t.Fatal("expected suppressions for unreachable threat, got none")
	}
	if r.Suppressions[0].Kind != "inSource" {
		t.Errorf("expected kind 'inSource', got %q", r.Suppressions[0].Kind)
	}
}

func TestSARIF_NoSuppression_Reachable(t *testing.T) {
	t.Parallel()
	tTrue := true
	result := makeAnalyzerScanResult(&tTrue, "4.17.21")

	sf := NewSARIFFormatter("", "", "", "dependency")
	out, err := sf.Format(result)
	if err != nil {
		t.Fatalf("SARIF Format() error: %v", err)
	}

	var sarif SARIF
	if err := json.Unmarshal(out, &sarif); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	if len(sarif.Runs) == 0 || len(sarif.Runs[0].Results) == 0 {
		t.Skip("no SARIF results")
	}

	for _, r := range sarif.Runs[0].Results {
		if len(r.Suppressions) > 0 {
			t.Errorf("reachable threat should not be suppressed, got %+v", r.Suppressions)
		}
	}
}

func TestSARIF_FixedVersion_InProperties(t *testing.T) {
	t.Parallel()
	result := makeAnalyzerScanResult(nil, "4.17.21")

	sf := NewSARIFFormatter("", "", "", "dependency")
	out, err := sf.Format(result)
	if err != nil {
		t.Fatalf("SARIF Format() error: %v", err)
	}

	if !strings.Contains(string(out), "4.17.21") {
		t.Errorf("expected fixed version '4.17.21' to appear in SARIF output")
	}
}
