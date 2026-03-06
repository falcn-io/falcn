// Package reachability determines whether vulnerable code paths in third-party
// dependencies are actually callable from a project's own entry points.
//
// Traditional SCA tools flag every dependency whose version matches a CVE range,
// producing ~88% false-positive rates. Reachability analysis reduces this by
// up to 98%: a CVE only matters if the affected symbol is imported AND called
// from a reachable code path.
//
// Supported languages (v1):
//   - Go     — stdlib go/ast + go/packages call-graph walk
//   - Python — import + call-site regex analysis
//   - JavaScript / TypeScript — require/import + call-site regex analysis
package reachability

import "time"

// Language represents a source-code ecosystem.
type Language string

const (
	LangGo         Language = "go"
	LangPython      Language = "python"
	LangJavaScript  Language = "javascript"
	LangTypeScript  Language = "typescript"
	LangUnknown     Language = "unknown"
)

// ImportRef records a single import of an external package in a source file.
type ImportRef struct {
	// PackageName is the canonical external package name, e.g. "requests" or
	// "github.com/gin-gonic/gin".
	PackageName string
	// Alias is the local alias used in this file, e.g. "req" for "import req as requests".
	Alias string
	// File is the source file path (relative to project root).
	File string
	// Line is the 1-based line number of the import statement.
	Line int
}

// CallSite records one location where an imported symbol is used.
type CallSite struct {
	// Symbol is the qualified name that was called, e.g. "requests.get" or
	// "gin.New".
	Symbol string
	// File is the source file containing the call.
	File string
	// Line is the 1-based line number.
	Line int
	// CallerFunc is the name of the enclosing function/method.
	CallerFunc string
	// IsEntryPoint is true when CallerFunc is itself an entry point (main,
	// exported HTTP handler, etc.).
	IsEntryPoint bool
}

// EntryPoint is a function that can be called without any other application
// code calling it first — i.e., it is a root of the call graph.
type EntryPoint struct {
	// Name is the function name as it appears in source.
	Name string
	// File is the source file.
	File string
	// Line is the 1-based line number.
	Line int
	// Kind classifies why this is an entry point.
	Kind EntryPointKind
}

// EntryPointKind classifies entry-point origin.
type EntryPointKind string

const (
	EntryPointMain        EntryPointKind = "main"         // func main()
	EntryPointInit        EntryPointKind = "init"         // func init()
	EntryPointExported    EntryPointKind = "exported"     // Exported function in a lib package
	EntryPointHTTPHandler EntryPointKind = "http_handler" // http.HandlerFunc-compatible signature
	EntryPointTest        EntryPointKind = "test"         // TestXxx functions
	EntryPointCLICommand  EntryPointKind = "cli_command"  // cobra/click command handlers
)

// ReachabilityResult is the output of analysing one project against one
// vulnerable package.
type ReachabilityResult struct {
	// PackageName is the vulnerable dependency being checked.
	PackageName string
	// Reachable is true when at least one call site for the package is
	// reachable from an entry point.
	Reachable bool
	// CallPath is the shortest chain from an entry point to the first
	// call site, e.g. ["main()", "setupRouter()", "gin.New()"].
	CallPath []string
	// CallSites lists all detected call sites for the package.
	CallSites []CallSite
	// Imports lists all import statements for the package.
	Imports []ImportRef
	// Language is the detected source language.
	Language Language
	// AnalysedAt is when the analysis was performed.
	AnalysedAt time.Time
	// Error is set when analysis could not be completed (e.g. parse failure).
	// A non-nil error does not mean the package is unreachable; the caller
	// should treat it as "unknown".
	Error error
}

// boolPtr is a helper to take the address of a bool literal.
func boolPtr(b bool) *bool { return &b }
