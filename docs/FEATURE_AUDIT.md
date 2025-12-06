# Feature Audit: Documented vs Implemented

Legend:
- ✅ Fully implemented and tested
- ⚠️ Partially implemented
- 🚧 Scaffolded/demo mode
- ❌ Documented but not implemented

## Core Features

| Feature | Documented | Actual Status | Action |
|--------|------------|---------------|--------|
| CLI scan command | Yes | ✅ Works | None |
| CLI analyze command | Yes | ✅ Works | None |
| JSON output | Yes | ✅ Works | None |
| SARIF output | Yes | ⚠️ Needs testing | Verify |
| npm support | Yes | ✅ Works | None |
| PyPI support | Yes | ✅ Works | None |
| Go modules | Yes | ✅ Parser implemented | Add more tests |
| Maven support | Yes | ✅ Parser implemented | Add more tests |
| Levenshtein detection | Yes | ✅ Works | None |
| Jaro-Winkler detection | Yes | ✅ Works | None |
| Homoglyph detection | Yes | ✅ Stabilized | None |
| ML-based detection | Yes | ❌ Removed claims | See DECISIONS.md |

## API Endpoints

| Endpoint | Documented | Actual Status | Action |
|---------|------------|---------------|--------|
| /health | Yes | ✅ Works | None |
| /ready | Yes | ✅ Works | None |
| /v1/analyze | Yes | ✅ Works | None |
| /v1/analyze/batch | Yes | ✅ Works | None |
| /v1/status | Yes | ✅ Works | None |
| /v1/stats | Yes | 🚧 Demo mode | Documented |
| /api/v1/vulnerabilities | Yes | 🚧 501 Not Implemented | Documented |
| /api/v1/dashboard/metrics | Yes | 🚧 501 Not Implemented | Documented |
| /api/v1/scans | Yes | ⚠️ Not present | Decide |

## Performance Claims

| Claim | Documented Value | Measured Value | Status |
|------|------------------|----------------|--------|
| DetectEnhanced per op | N/A | ~246µs/op | Added |
| Homoglyph per op | N/A | ~157µs/op | Added |
| Small project throughput | N/A | ~6.75ms/run | Added |
| Medium project throughput | N/A | ~33.6ms/run | Added |

## Next Steps
1. Verify SARIF output and missing package manager tests
2. Add E2E test suites (CLI and API) under build tag `e2e`
3. Complete API reference and user guide


