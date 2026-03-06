package output

import (
	"fmt"
	"strings"
)

// ValidationError represents a schema validation error for a specific field.
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error: field %q — %s", e.Field, e.Message)
}

// ValidationErrors is a collection of validation errors.
type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	if len(ve) == 0 {
		return ""
	}
	msgs := make([]string, len(ve))
	for i, e := range ve {
		msgs[i] = e.Error()
	}
	return strings.Join(msgs, "; ")
}

// HasErrors reports whether there are any validation errors.
func (ve ValidationErrors) HasErrors() bool { return len(ve) > 0 }

// ValidateSARIF validates a SARIF document against the 2.1.0 schema requirements.
// It checks: version, schema presence, driver name, and per-result ruleId/message.
func ValidateSARIF(doc *SARIF) ValidationErrors {
	var errs ValidationErrors
	if doc == nil {
		return append(errs, ValidationError{"document", "must not be nil"})
	}
	if doc.Version != "2.1.0" {
		errs = append(errs, ValidationError{
			"version",
			fmt.Sprintf("must be '2.1.0', got %q", doc.Version),
		})
	}
	if doc.Schema == "" {
		errs = append(errs, ValidationError{"$schema", "should be present"})
	}
	for i, run := range doc.Runs {
		prefix := fmt.Sprintf("runs[%d]", i)
		if run.Tool.Driver.Name == "" {
			errs = append(errs, ValidationError{
				prefix + ".tool.driver.name",
				"must not be empty",
			})
		}
		for j, result := range run.Results {
			rPrefix := fmt.Sprintf("%s.results[%d]", prefix, j)
			if result.RuleID == "" {
				errs = append(errs, ValidationError{
					rPrefix + ".ruleId",
					"must not be empty",
				})
			}
			if result.Message.Text == "" {
				errs = append(errs, ValidationError{
					rPrefix + ".message.text",
					"must not be empty",
				})
			}
			// locations must be non-empty if the field is present and non-nil
			for k, loc := range result.Locations {
				lPrefix := fmt.Sprintf("%s.locations[%d]", rPrefix, k)
				if loc.PhysicalLocation == nil && len(loc.LogicalLocations) == 0 {
					errs = append(errs, ValidationError{
						lPrefix,
						"location must have at least a physicalLocation or logicalLocations entry",
					})
				}
			}
		}
	}
	return errs
}

// ValidateSPDX validates an SPDX 2.x document against the core required fields.
// It checks: spdxVersion prefix, dataLicense, SPDXID, documentNamespace URL, name,
// and per-package SPDXID/name/downloadLocation.
func ValidateSPDX(doc *SPDXDocument) ValidationErrors {
	var errs ValidationErrors
	if doc == nil {
		return append(errs, ValidationError{"document", "must not be nil"})
	}
	if !strings.HasPrefix(doc.SPDXVersion, "SPDX-") {
		errs = append(errs, ValidationError{
			"spdxVersion",
			fmt.Sprintf("must start with 'SPDX-', got %q", doc.SPDXVersion),
		})
	}
	if doc.DataLicense != "CC0-1.0" {
		errs = append(errs, ValidationError{
			"dataLicense",
			fmt.Sprintf("must be 'CC0-1.0', got %q", doc.DataLicense),
		})
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		errs = append(errs, ValidationError{
			"SPDXID",
			fmt.Sprintf("must be 'SPDXRef-DOCUMENT', got %q", doc.SPDXID),
		})
	}
	if !strings.HasPrefix(doc.DocumentNamespace, "http://") &&
		!strings.HasPrefix(doc.DocumentNamespace, "https://") {
		errs = append(errs, ValidationError{
			"documentNamespace",
			"must be a valid URL starting with http:// or https://",
		})
	}
	if doc.DocumentName == "" {
		errs = append(errs, ValidationError{"name", "must not be empty"})
	}
	for i, pkg := range doc.Packages {
		prefix := fmt.Sprintf("packages[%d]", i)
		if pkg.SPDXID == "" {
			errs = append(errs, ValidationError{prefix + ".SPDXID", "must not be empty"})
		}
		if pkg.Name == "" {
			errs = append(errs, ValidationError{prefix + ".name", "must not be empty"})
		}
		if pkg.DownloadLocation == "" {
			errs = append(errs, ValidationError{prefix + ".downloadLocation", "must not be empty"})
		}
	}
	return errs
}

// ValidateCycloneDX validates a CycloneDX BOM document.
// It checks: bomFormat, specVersion (must be 1.4/1.5/1.6), version >= 1,
// and per-component type/name.
func ValidateCycloneDX(doc *CycloneDXBOM) ValidationErrors {
	var errs ValidationErrors
	if doc == nil {
		return append(errs, ValidationError{"document", "must not be nil"})
	}
	if doc.BomFormat != "CycloneDX" {
		errs = append(errs, ValidationError{
			"bomFormat",
			fmt.Sprintf("must be 'CycloneDX', got %q", doc.BomFormat),
		})
	}
	validVersions := map[string]bool{"1.4": true, "1.5": true, "1.6": true}
	if !validVersions[doc.SpecVersion] {
		errs = append(errs, ValidationError{
			"specVersion",
			fmt.Sprintf("must be one of '1.4', '1.5', '1.6', got %q", doc.SpecVersion),
		})
	}
	if doc.Version < 1 {
		errs = append(errs, ValidationError{
			"version",
			fmt.Sprintf("must be >= 1, got %d", doc.Version),
		})
	}
	for i, comp := range doc.Components {
		prefix := fmt.Sprintf("components[%d]", i)
		if comp.Type == "" {
			errs = append(errs, ValidationError{prefix + ".type", "must not be empty"})
		}
		if comp.Name == "" {
			errs = append(errs, ValidationError{prefix + ".name", "must not be empty"})
		}
	}
	return errs
}
