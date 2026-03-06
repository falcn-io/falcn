package output

import (
	"strings"
	"testing"
)

// ─── SARIF validation tests ────────────────────────────────────────────────

func TestValidateSARIF_Valid(t *testing.T) {
	doc := &SARIF{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []Run{
			{
				Tool: Tool{Driver: Driver{Name: "Falcn"}},
				Results: []Result{
					{
						RuleID:  "TYPO_SQUATTING",
						Message: Message{Text: "typosquatting detected"},
						Locations: []Location{
							{LogicalLocations: []LogicalLocation{{Name: "pkg"}}},
						},
					},
				},
			},
		},
	}
	if errs := ValidateSARIF(doc); errs.HasErrors() {
		t.Errorf("expected no errors, got: %v", errs)
	}
}

func TestValidateSARIF_Nil(t *testing.T) {
	errs := ValidateSARIF(nil)
	if !errs.HasErrors() {
		t.Fatal("expected error for nil document")
	}
	if !strings.Contains(errs.Error(), "nil") {
		t.Errorf("expected nil message, got: %v", errs)
	}
}

func TestValidateSARIF_WrongVersion(t *testing.T) {
	doc := &SARIF{
		Version: "1.0.0",
		Schema:  "https://example.com/schema",
		Runs:    []Run{{Tool: Tool{Driver: Driver{Name: "Falcn"}}}},
	}
	errs := ValidateSARIF(doc)
	if !errs.HasErrors() {
		t.Fatal("expected version error")
	}
	found := false
	for _, e := range errs {
		if e.Field == "version" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'version' field error, got: %v", errs)
	}
}

func TestValidateSARIF_MissingSchema(t *testing.T) {
	doc := &SARIF{
		Version: "2.1.0",
		Schema:  "", // missing
		Runs:    []Run{{Tool: Tool{Driver: Driver{Name: "Falcn"}}}},
	}
	errs := ValidateSARIF(doc)
	if !errs.HasErrors() {
		t.Fatal("expected schema error")
	}
	found := false
	for _, e := range errs {
		if e.Field == "$schema" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected '$schema' field error, got: %v", errs)
	}
}

func TestValidateSARIF_MissingDriverName(t *testing.T) {
	doc := &SARIF{
		Version: "2.1.0",
		Schema:  "https://example.com/schema",
		Runs: []Run{
			{
				Tool: Tool{Driver: Driver{Name: ""}}, // empty name
			},
		},
	}
	errs := ValidateSARIF(doc)
	if !errs.HasErrors() {
		t.Fatal("expected driver name error")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Field, "driver.name") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'driver.name' error, got: %v", errs)
	}
}

func TestValidateSARIF_MissingRuleID(t *testing.T) {
	doc := &SARIF{
		Version: "2.1.0",
		Schema:  "https://example.com/schema",
		Runs: []Run{
			{
				Tool: Tool{Driver: Driver{Name: "Falcn"}},
				Results: []Result{
					{RuleID: "", Message: Message{Text: "some message"}},
				},
			},
		},
	}
	errs := ValidateSARIF(doc)
	if !errs.HasErrors() {
		t.Fatal("expected ruleId error")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Field, "ruleId") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'ruleId' error, got: %v", errs)
	}
}

func TestValidateSARIF_MissingMessageText(t *testing.T) {
	doc := &SARIF{
		Version: "2.1.0",
		Schema:  "https://example.com/schema",
		Runs: []Run{
			{
				Tool: Tool{Driver: Driver{Name: "Falcn"}},
				Results: []Result{
					{RuleID: "VULN", Message: Message{Text: ""}},
				},
			},
		},
	}
	errs := ValidateSARIF(doc)
	if !errs.HasErrors() {
		t.Fatal("expected message.text error")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Field, "message.text") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'message.text' error, got: %v", errs)
	}
}

func TestValidateSARIF_EmptyLocation(t *testing.T) {
	doc := &SARIF{
		Version: "2.1.0",
		Schema:  "https://example.com/schema",
		Runs: []Run{
			{
				Tool: Tool{Driver: Driver{Name: "Falcn"}},
				Results: []Result{
					{
						RuleID:  "VULN",
						Message: Message{Text: "msg"},
						Locations: []Location{
							// both physicalLocation and logicalLocations are nil/empty
							{PhysicalLocation: nil, LogicalLocations: nil},
						},
					},
				},
			},
		},
	}
	errs := ValidateSARIF(doc)
	if !errs.HasErrors() {
		t.Fatal("expected location error for empty location entry")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Field, "locations[0]") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'locations[0]' error, got: %v", errs)
	}
}

// ─── SPDX validation tests ────────────────────────────────────────────────

func validSPDXDoc() *SPDXDocument {
	return &SPDXDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		DocumentName:      "test-sbom",
		DocumentNamespace: "https://falcn.io/sbom/test",
		Packages: []SPDXPackage{
			{
				SPDXID:           "SPDXRef-Package-lodash",
				Name:             "lodash",
				DownloadLocation: "https://registry.npmjs.org/lodash",
			},
		},
	}
}

func TestValidateSPDX_Valid(t *testing.T) {
	doc := validSPDXDoc()
	if errs := ValidateSPDX(doc); errs.HasErrors() {
		t.Errorf("expected no errors, got: %v", errs)
	}
}

func TestValidateSPDX_Nil(t *testing.T) {
	errs := ValidateSPDX(nil)
	if !errs.HasErrors() {
		t.Fatal("expected error for nil document")
	}
}

func TestValidateSPDX_WrongVersion(t *testing.T) {
	doc := validSPDXDoc()
	doc.SPDXVersion = "2.3" // missing "SPDX-" prefix
	errs := ValidateSPDX(doc)
	if !errs.HasErrors() {
		t.Fatal("expected spdxVersion error")
	}
	found := false
	for _, e := range errs {
		if e.Field == "spdxVersion" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'spdxVersion' error, got: %v", errs)
	}
}

func TestValidateSPDX_WrongDataLicense(t *testing.T) {
	doc := validSPDXDoc()
	doc.DataLicense = "MIT"
	errs := ValidateSPDX(doc)
	if !errs.HasErrors() {
		t.Fatal("expected dataLicense error")
	}
	found := false
	for _, e := range errs {
		if e.Field == "dataLicense" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'dataLicense' error, got: %v", errs)
	}
}

func TestValidateSPDX_WrongSPDXID(t *testing.T) {
	doc := validSPDXDoc()
	doc.SPDXID = "SPDXRef-WRONG"
	errs := ValidateSPDX(doc)
	if !errs.HasErrors() {
		t.Fatal("expected SPDXID error")
	}
	found := false
	for _, e := range errs {
		if e.Field == "SPDXID" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'SPDXID' error, got: %v", errs)
	}
}

func TestValidateSPDX_InvalidNamespace(t *testing.T) {
	doc := validSPDXDoc()
	doc.DocumentNamespace = "ftp://not-http.example.com"
	errs := ValidateSPDX(doc)
	if !errs.HasErrors() {
		t.Fatal("expected documentNamespace error")
	}
	found := false
	for _, e := range errs {
		if e.Field == "documentNamespace" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'documentNamespace' error, got: %v", errs)
	}
}

func TestValidateSPDX_EmptyDocumentName(t *testing.T) {
	doc := validSPDXDoc()
	doc.DocumentName = ""
	errs := ValidateSPDX(doc)
	if !errs.HasErrors() {
		t.Fatal("expected name error")
	}
	found := false
	for _, e := range errs {
		if e.Field == "name" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'name' error, got: %v", errs)
	}
}

func TestValidateSPDX_PackageMissingFields(t *testing.T) {
	doc := validSPDXDoc()
	doc.Packages = []SPDXPackage{
		{SPDXID: "", Name: "", DownloadLocation: ""},
	}
	errs := ValidateSPDX(doc)
	if !errs.HasErrors() {
		t.Fatal("expected package field errors")
	}
	fieldSet := map[string]bool{}
	for _, e := range errs {
		fieldSet[e.Field] = true
	}
	for _, expected := range []string{"packages[0].SPDXID", "packages[0].name", "packages[0].downloadLocation"} {
		if !fieldSet[expected] {
			t.Errorf("expected error for field %q, got: %v", expected, errs)
		}
	}
}

// ─── CycloneDX validation tests ───────────────────────────────────────────

func validCycloneDXBOM() *CycloneDXBOM {
	return &CycloneDXBOM{
		BomFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Components: []CycloneDXComponent{
			{Type: "library", Name: "lodash"},
		},
	}
}

func TestValidateCycloneDX_Valid(t *testing.T) {
	bom := validCycloneDXBOM()
	if errs := ValidateCycloneDX(bom); errs.HasErrors() {
		t.Errorf("expected no errors, got: %v", errs)
	}
}

func TestValidateCycloneDX_Nil(t *testing.T) {
	errs := ValidateCycloneDX(nil)
	if !errs.HasErrors() {
		t.Fatal("expected error for nil document")
	}
}

func TestValidateCycloneDX_WrongBomFormat(t *testing.T) {
	bom := validCycloneDXBOM()
	bom.BomFormat = "SBOM"
	errs := ValidateCycloneDX(bom)
	if !errs.HasErrors() {
		t.Fatal("expected bomFormat error")
	}
	found := false
	for _, e := range errs {
		if e.Field == "bomFormat" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'bomFormat' error, got: %v", errs)
	}
}

func TestValidateCycloneDX_WrongSpecVersion(t *testing.T) {
	bom := validCycloneDXBOM()
	bom.SpecVersion = "2.0"
	errs := ValidateCycloneDX(bom)
	if !errs.HasErrors() {
		t.Fatal("expected specVersion error")
	}
	found := false
	for _, e := range errs {
		if e.Field == "specVersion" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'specVersion' error, got: %v", errs)
	}
}

func TestValidateCycloneDX_AllValidSpecVersions(t *testing.T) {
	for _, v := range []string{"1.4", "1.5", "1.6"} {
		bom := validCycloneDXBOM()
		bom.SpecVersion = v
		if errs := ValidateCycloneDX(bom); errs.HasErrors() {
			t.Errorf("specVersion %q should be valid, got: %v", v, errs)
		}
	}
}

func TestValidateCycloneDX_ZeroVersion(t *testing.T) {
	bom := validCycloneDXBOM()
	bom.Version = 0
	errs := ValidateCycloneDX(bom)
	if !errs.HasErrors() {
		t.Fatal("expected version error")
	}
	found := false
	for _, e := range errs {
		if e.Field == "version" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'version' error, got: %v", errs)
	}
}

func TestValidateCycloneDX_NegativeVersion(t *testing.T) {
	bom := validCycloneDXBOM()
	bom.Version = -1
	errs := ValidateCycloneDX(bom)
	if !errs.HasErrors() {
		t.Fatal("expected version error for negative version")
	}
}

func TestValidateCycloneDX_ComponentMissingType(t *testing.T) {
	bom := validCycloneDXBOM()
	bom.Components = []CycloneDXComponent{
		{Type: "", Name: "lodash"},
	}
	errs := ValidateCycloneDX(bom)
	if !errs.HasErrors() {
		t.Fatal("expected component type error")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Field, "components[0].type") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'components[0].type' error, got: %v", errs)
	}
}

func TestValidateCycloneDX_ComponentMissingName(t *testing.T) {
	bom := validCycloneDXBOM()
	bom.Components = []CycloneDXComponent{
		{Type: "library", Name: ""},
	}
	errs := ValidateCycloneDX(bom)
	if !errs.HasErrors() {
		t.Fatal("expected component name error")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Field, "components[0].name") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'components[0].name' error, got: %v", errs)
	}
}

func TestValidateCycloneDX_NoComponents(t *testing.T) {
	bom := validCycloneDXBOM()
	bom.Components = nil
	if errs := ValidateCycloneDX(bom); errs.HasErrors() {
		t.Errorf("empty component list should be valid, got: %v", errs)
	}
}

// ─── ValidationErrors helper tests ────────────────────────────────────────

func TestValidationErrors_HasErrors_Empty(t *testing.T) {
	var ve ValidationErrors
	if ve.HasErrors() {
		t.Error("empty ValidationErrors should not HasErrors()")
	}
}

func TestValidationErrors_Error_Empty(t *testing.T) {
	var ve ValidationErrors
	if ve.Error() != "" {
		t.Errorf("empty ValidationErrors.Error() should return '', got %q", ve.Error())
	}
}

func TestValidationErrors_Error_MultipleErrors(t *testing.T) {
	ve := ValidationErrors{
		{Field: "foo", Message: "bar"},
		{Field: "baz", Message: "qux"},
	}
	s := ve.Error()
	if !strings.Contains(s, "foo") || !strings.Contains(s, "baz") {
		t.Errorf("Error() should contain all field names, got: %s", s)
	}
}

func TestValidationError_Error_Format(t *testing.T) {
	e := ValidationError{Field: "version", Message: "must be '2.1.0'"}
	s := e.Error()
	if !strings.Contains(s, "version") {
		t.Errorf("error string should contain field name, got: %s", s)
	}
	if !strings.Contains(s, "must be '2.1.0'") {
		t.Errorf("error string should contain message, got: %s", s)
	}
}
