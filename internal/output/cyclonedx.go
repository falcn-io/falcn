package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/falcn-io/falcn/internal/scanner"

	"github.com/sirupsen/logrus"
)

// CycloneDXBOM represents a CycloneDX 1.5 Software Bill of Materials.
type CycloneDXBOM struct {
	BomFormat      string                 `json:"bomFormat"`
	SpecVersion    string                 `json:"specVersion"`
	SerialNumber   string                 `json:"serialNumber"`
	Version        int                    `json:"version"`
	Metadata       CycloneDXMetadata      `json:"metadata"`
	Components     []CycloneDXComponent   `json:"components"`
	Vulnerabilities []CycloneDXVuln       `json:"vulnerabilities,omitempty"`
}

// CycloneDXMetadata holds BOM-level metadata required by CycloneDX 1.5.
type CycloneDXMetadata struct {
	Timestamp string              `json:"timestamp"`
	Tools     []CycloneDXTool    `json:"tools,omitempty"`
	Component *CycloneDXComponent `json:"component,omitempty"`
}

// CycloneDXTool identifies the tool that produced the BOM.
type CycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CycloneDXComponent represents a single package in the BOM.
type CycloneDXComponent struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Purl       string `json:"purl,omitempty"`
	BomRef     string `json:"bom-ref,omitempty"`
}

// CycloneDXVuln represents a vulnerability affecting a BOM component.
type CycloneDXVuln struct {
	ID          string              `json:"id"`
	Source      CycloneDXVulnSource `json:"source,omitempty"`
	Ratings     []CycloneDXRating  `json:"ratings,omitempty"`
	Description string             `json:"description,omitempty"`
	Affects     []CycloneDXAffect  `json:"affects,omitempty"`
	Analysis    *CycloneDXAnalysis  `json:"analysis,omitempty"`
}

// CycloneDXAnalysis represents a VEX (Vulnerability Exploitability eXchange) analysis
// statement for a single vulnerability, per CycloneDX 1.5 specification.
// State values: "affected" | "not_affected" | "fixed" | "in_triage" | "false_positive" | "not_applicable"
type CycloneDXAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

// CycloneDXVulnSource identifies the vulnerability database.
type CycloneDXVulnSource struct {
	Name string `json:"name,omitempty"`
}

// CycloneDXRating holds severity information.
type CycloneDXRating struct {
	Severity string `json:"severity"`
}

// CycloneDXAffect links a vulnerability to an affected component by bom-ref.
type CycloneDXAffect struct {
	Ref string `json:"ref"`
}

// CycloneDXFormatter produces CycloneDX 1.5-compliant JSON output.
type CycloneDXFormatter struct{}

func NewCycloneDXFormatter() *CycloneDXFormatter { return &CycloneDXFormatter{} }

// buildPURL constructs a Package URL for a component given its registry.
// Format: pkg:<type>/<name>@<version>
func buildPURL(registry, name, version string) string {
	purlType := strings.ToLower(registry)
	// Map common registry names to purl type identifiers
	switch purlType {
	case "npm":
		// npm scoped packages: @scope/name → pkg:npm/%40scope%2Fname@ver
		if strings.HasPrefix(name, "@") {
			name = strings.Replace(name, "@", "%40", 1)
			name = strings.Replace(name, "/", "%2F", 1)
		}
	case "pypi":
		purlType = "pypi"
	case "go":
		purlType = "golang"
	case "maven":
		purlType = "maven"
		// Maven names are typically group:artifact — convert to group/artifact
		name = strings.Replace(name, ":", "/", 1)
	case "nuget":
		purlType = "nuget"
	case "rubygems":
		purlType = "gem"
	case "crates.io":
		purlType = "cargo"
	case "packagist":
		purlType = "composer"
	}
	if version != "" {
		return fmt.Sprintf("pkg:%s/%s@%s", purlType, name, version)
	}
	return fmt.Sprintf("pkg:%s/%s", purlType, name)
}

func (f *CycloneDXFormatter) Format(res *scanner.ScanResults, opts *FormatterOptions) ([]byte, error) {
	now := time.Now().UTC()
	bom := CycloneDXBOM{
		BomFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: fmt.Sprintf("urn:uuid:falcn-%d", now.UnixNano()),
		Version:      1,
		Metadata: CycloneDXMetadata{
			Timestamp: now.Format(time.RFC3339),
			Tools: []CycloneDXTool{
				{Vendor: "Falcn Security", Name: "falcn-scanner", Version: "3.0.0"},
			},
			Component: &CycloneDXComponent{
				Type: "application",
				Name: "scanned-project",
			},
		},
	}

	seen := make(map[string]bool)
	var vulns []CycloneDXVuln

	for _, r := range res.Results {
		if r.Package == nil {
			continue
		}
		key := r.Package.Name + "@" + r.Package.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		bomRef := fmt.Sprintf("%s@%s", r.Package.Name, r.Package.Version)
		purl := buildPURL(r.Package.Registry, r.Package.Name, r.Package.Version)

		bom.Components = append(bom.Components, CycloneDXComponent{
			Type:    "library",
			Name:    r.Package.Name,
			Version: r.Package.Version,
			Purl:    purl,
			BomRef:  bomRef,
		})

		// Collect vulnerabilities from package threats
		for _, threat := range r.Package.Threats {
			vulnID := string(threat.Type)
			if len(threat.CVEs) > 0 {
				vulnID = threat.CVEs[0]
			} else if threat.ID != "" {
				vulnID = threat.ID
			}
			vuln := CycloneDXVuln{
				ID:          vulnID,
				Source:      CycloneDXVulnSource{Name: "falcn"},
				Ratings:     []CycloneDXRating{{Severity: strings.ToLower(threat.Severity.String())}},
				Description: threat.Description,
				Affects:     []CycloneDXAffect{{Ref: bomRef}},
			}

			// Populate VEX analysis from reachability annotation.
			if threat.Reachable != nil {
				if !*threat.Reachable {
					vuln.Analysis = &CycloneDXAnalysis{
						State:         "not_affected",
						Justification: "code_not_reachable",
						Response:      []string{"will_not_fix"},
						Detail:        "Static reachability analysis determined this vulnerability's code path is not called from any entry point.",
					}
				} else {
					vuln.Analysis = &CycloneDXAnalysis{
						State:  "affected",
						Detail: "Reachability analysis confirmed this vulnerability is callable from production entry points.",
					}
				}
			}

			vulns = append(vulns, vuln)
		}
	}

	if len(vulns) > 0 {
		bom.Vulnerabilities = vulns
	}

	if errs := ValidateCycloneDX(&bom); errs.HasErrors() {
		logrus.Warnf("CycloneDX document validation: %v", errs)
	}
	return json.MarshalIndent(bom, "", opts.Indent)
}
