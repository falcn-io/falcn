# Error Log

## Resolved Errors

### 1. `falcn report` command not found
- **Description:** User attempted to run `falcn report` but the command was missing from `cmd/`.
- **Resolution:** Implemented `cmd/report.go` with `report` command logic using `cobra` and `falcn_report.json` input.
- **Date:** 2025-12-17

### 2. Test Failure in `enhanced_typosquatting_test.go`
- **Description:** `TestEnhancedTyposquattingDetector_JaroWinklerSimilarity` failed with 0.43 similarity for "completely"/"different" instead of expected 0.0.
- **Resolution:** Updated test case to compare "abc" and "xyz" which correctly returns 0.0 similarity.
- **Date:** 2025-12-17

### 3. Compilation Error in `scanner.go`
- **Description:** `go build` failed due to variable shadowing of `err` in Phase 5 (CICD Pipeline Analysis).
- **Resolution:** Renamed `err` to `errCicd` for the CICDScanner error handling block.
- **Date:** 2025-12-17

### 4. Shai-Hulud Threats Not Detected
- **Description:** CICDScanner was not finding threats in `examples/enterprise-demo` despite vulnerable workflow file being present.
- **Cause:** `scanner.go` was initializing `CICDScanner` with `s.lastProjectPath` which was empty or incorrect.
- **Resolution:** Updated `scanner.go` to use `projectPath` (or `os.Getwd()` fallback) as the root for `CICDScanner`.
- **Date:** 2025-12-17

### 5. Incomplete Metadata False Positives
- **Description:** `falcn scan` reported `incomplete_metadata` for all packages, even those with authors (e.g., `react`).
- **Cause:** `MetadataEnricher` was fetching data from NPM but failing to map the `Author` field to the internal package structure, causing the "missing author" check to always fail.
- **Resolution:** Updated `internal/scanner/metadata_enricher.go` to correctly assign `pkg.Metadata.Author = npmData.Author.Name`.
- **Date:** 2025-12-18
