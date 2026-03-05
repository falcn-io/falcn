//go:build !fips

// Package security — non-FIPS build.
// In standard builds, FIPS enforcement is disabled and all hash algorithms are available.
// To enable FIPS mode, build with: go build -tags fips .
package security

const FIPSEnabled = false

// FIPSHashNotAllowed is a no-op in non-FIPS builds.
// The same call site in fips.go panics when built with -tags fips.
func FIPSHashNotAllowed(_ string) {}

// FIPSAssertApprovedHash is a no-op in non-FIPS builds.
func FIPSAssertApprovedHash(_ string) {}

// FIPSInfo returns an empty FIPS status in non-FIPS builds.
func FIPSInfo() map[string]interface{} {
	return map[string]interface{}{
		"fips_enabled": false,
	}
}
