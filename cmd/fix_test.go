package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/falcn-io/falcn/internal/analyzer"
	"github.com/falcn-io/falcn/pkg/types"
)

// ─── parseThreatsFromJSON ─────────────────────────────────────────────────────

func TestParseThreatsFromJSON_ScanResult(t *testing.T) {
	tTrue := true
	result := analyzer.ScanResult{
		Threats: []types.Threat{
			{
				Package:      "lodash",
				Version:      "4.17.11",
				Registry:     "npm",
				Type:         types.ThreatTypeVulnerable,
				Severity:     types.SeverityHigh,
				Description:  "Prototype pollution",
				FixedVersion: "4.17.21",
				CVEs:         []string{"CVE-2019-10744"},
				Reachable:    &tTrue,
			},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}

	threats, err := parseThreatsFromJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(threats) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(threats))
	}
	if threats[0].Package != "lodash" {
		t.Errorf("expected package 'lodash', got %q", threats[0].Package)
	}
	if threats[0].FixedVersion != "4.17.21" {
		t.Errorf("expected FixedVersion '4.17.21', got %q", threats[0].FixedVersion)
	}
}

func TestParseThreatsFromJSON_FlatArray(t *testing.T) {
	threats := []types.Threat{
		{Package: "requests", Version: "2.25.0", Registry: "pypi", FixedVersion: "2.31.0"},
	}
	data, _ := json.Marshal(threats)
	got, err := parseThreatsFromJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Package != "requests" {
		t.Errorf("unexpected result: %+v", got)
	}
}

func TestParseThreatsFromJSON_GenericMap(t *testing.T) {
	threats := []types.Threat{
		{Package: "express", Version: "4.17.0", Registry: "npm", FixedVersion: "4.19.0"},
	}
	data, _ := json.Marshal(map[string]interface{}{"threats": threats, "other": "ignored"})
	got, err := parseThreatsFromJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Package != "express" {
		t.Errorf("unexpected result: %+v", got)
	}
}

func TestParseThreatsFromJSON_Invalid(t *testing.T) {
	_, err := parseThreatsFromJSON(strings.NewReader(`{"not": "threats"}`))
	if err == nil {
		t.Error("expected error for unrecognised JSON shape, got nil")
	}
}

// ─── extractRemediation ───────────────────────────────────────────────────────

func TestExtractRemediation_FromMetadata(t *testing.T) {
	t.Parallel()
	threat := types.Threat{
		Package:      "lodash",
		Version:      "4.17.11",
		Registry:     "npm",
		FixedVersion: "4.17.21",
		Metadata:     map[string]interface{}{"remediation": "npm install lodash@4.17.21"},
	}
	got := extractRemediation(threat)
	if got != "npm install lodash@4.17.21" {
		t.Errorf("unexpected remediation: %q", got)
	}
}

func TestExtractRemediation_Derived_npm(t *testing.T) {
	t.Parallel()
	threat := types.Threat{Package: "express", Registry: "npm", FixedVersion: "4.19.0"}
	got := extractRemediation(threat)
	if !strings.HasPrefix(got, "npm install express@") {
		t.Errorf("unexpected: %q", got)
	}
}

func TestExtractRemediation_Derived_pypi(t *testing.T) {
	t.Parallel()
	threat := types.Threat{Package: "requests", Registry: "pypi", FixedVersion: "2.31.0"}
	got := extractRemediation(threat)
	if !strings.Contains(got, "pip install") {
		t.Errorf("unexpected: %q", got)
	}
}

func TestExtractRemediation_Derived_go(t *testing.T) {
	t.Parallel()
	threat := types.Threat{Package: "golang.org/x/net", Registry: "go", FixedVersion: "0.17.0"}
	got := extractRemediation(threat)
	if !strings.HasPrefix(got, "go get") {
		t.Errorf("unexpected: %q", got)
	}
}

func TestExtractRemediation_NoFix(t *testing.T) {
	t.Parallel()
	threat := types.Threat{Package: "bad-pkg", Registry: "npm"}
	if got := extractRemediation(threat); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// ─── severity helpers ─────────────────────────────────────────────────────────

func TestSeverityLevel_Order(t *testing.T) {
	t.Parallel()
	if severityLevel(types.SeverityCritical) <= severityLevel(types.SeverityHigh) {
		t.Error("critical must rank above high")
	}
	if severityLevel(types.SeverityHigh) <= severityLevel(types.SeverityMedium) {
		t.Error("high must rank above medium")
	}
	if severityLevel(types.SeverityMedium) <= severityLevel(types.SeverityLow) {
		t.Error("medium must rank above low")
	}
}

func TestParseSeverity(t *testing.T) {
	t.Parallel()
	cases := []struct{ in string; want int }{
		{"critical", 4},
		{"CRITICAL", 4},
		{"high", 3},
		{"medium", 2},
		{"low", 1},
		{"unknown", 1},
	}
	for _, c := range cases {
		if got := parseSeverity(c.in); got != c.want {
			t.Errorf("parseSeverity(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// ─── emitScript ──────────────────────────────────────────────────────────────

func TestEmitScript_Empty(t *testing.T) {
	// Should not return an error for zero entries
	if err := emitScript(nil); err != nil {
		t.Errorf("unexpected error for empty entries: %v", err)
	}
}
