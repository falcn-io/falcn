package output

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/falcn-io/falcn/internal/scanner"
	"github.com/google/uuid"

	"github.com/sirupsen/logrus"
)

// SPDXDocument represents an SPDX 2.3 Software Bill of Materials document.
type SPDXDocument struct {
	SPDXVersion          string            `json:"spdxVersion"`
	DataLicense          string            `json:"dataLicense"`
	SPDXID               string            `json:"SPDXID"`
	DocumentName         string            `json:"name"`
	DocumentNamespace    string            `json:"documentNamespace"`
	CreationInfo         SPDXCreationInfo  `json:"creationInfo"`
	Packages             []SPDXPackage     `json:"packages"`
	Relationships        []SPDXRelationship `json:"relationships"`
}

// SPDXCreationInfo holds document creation metadata required by SPDX 2.3.
type SPDXCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// SPDXPackage represents a single package entry in the SPDX document.
type SPDXPackage struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	Version          string `json:"versionInfo,omitempty"`
	LicenseConcluded string `json:"licenseConcluded,omitempty"`
	DownloadLocation string `json:"downloadLocation"`
	FilesAnalyzed    bool   `json:"filesAnalyzed"`
}

// SPDXRelationship captures the SPDX relationship between elements.
type SPDXRelationship struct {
	SpdxElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
}

// SPDXFormatter produces SPDX 2.3-compliant JSON output.
type SPDXFormatter struct{}

func NewSPDXFormatter() *SPDXFormatter { return &SPDXFormatter{} }

func (f *SPDXFormatter) Format(res *scanner.ScanResults, opts FormatterOptions) ([]byte, error) {
	now := time.Now().UTC()
	doc := SPDXDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		DocumentName:      "Falcn-sbom",
		DocumentNamespace: fmt.Sprintf("https://falcn.io/sbom/%s", uuid.New().String()),
		CreationInfo: SPDXCreationInfo{
			Created:  now.Format(time.RFC3339),
			Creators: []string{"Tool: Falcn-scanner"},
		},
	}

	seen := make(map[string]bool)
	for _, r := range res.Results {
		if r.Package == nil {
			continue
		}
		key := r.Package.Name + "@" + r.Package.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		spdxID := "SPDXRef-Package-" + r.Package.Name
		doc.Packages = append(doc.Packages, SPDXPackage{
			SPDXID:           spdxID,
			Name:             r.Package.Name,
			Version:          r.Package.Version,
			LicenseConcluded: "NOASSERTION",
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
		})
		// Each package DESCRIBES the document
		doc.Relationships = append(doc.Relationships, SPDXRelationship{
			SpdxElementID:      "SPDXRef-DOCUMENT",
			RelationshipType:   "DESCRIBES",
			RelatedSpdxElement: spdxID,
		})
	}

	if errs := ValidateSPDX(&doc); errs.HasErrors() {
		logrus.Warnf("SPDX document validation: %v", errs)
	}
	return json.MarshalIndent(doc, "", opts.Indent)
}
