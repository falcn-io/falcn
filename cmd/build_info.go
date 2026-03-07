package cmd

// Build-time variables injected via -ldflags.
// Set by Makefile: -X github.com/falcn-io/falcn/cmd.Version=...
var (
	// Version is the semantic version string (e.g. "v2.3.0").
	Version = "dev"

	// BuildTime is the RFC-3339 UTC timestamp of the build (e.g. "2026-03-07_12:00:00").
	BuildTime = "unknown"

	// Commit is the short git SHA of the build (e.g. "abc1234").
	Commit = "unknown"
)
