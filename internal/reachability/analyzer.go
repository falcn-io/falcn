package reachability

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Analyzer is the top-level reachability engine. It detects the project
// language, finds entry points, and determines whether a given vulnerable
// package is actually reachable from those entry points.
type Analyzer struct {
	projectRoot string
	lang        Language
	entryPoints []EntryPoint
}

// New creates an Analyzer rooted at projectRoot.
// Language detection is automatic; entry points are discovered lazily on
// first call to Check.
func New(projectRoot string) (*Analyzer, error) {
	abs, err := filepath.Abs(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("reachability: resolve project root: %w", err)
	}
	lang := detectLanguage(abs)
	return &Analyzer{
		projectRoot: abs,
		lang:        lang,
	}, nil
}

// Check determines whether packageName is reachable from the project's entry
// points. It returns a ReachabilityResult regardless of errors; when analysis
// fails the result's Error field is set and Reachable is false.
func (a *Analyzer) Check(packageName string) ReachabilityResult {
	result := ReachabilityResult{
		PackageName: packageName,
		Language:    a.lang,
		AnalysedAt:  time.Now(),
	}

	// Lazy entry-point detection
	if a.entryPoints == nil {
		eps, err := newEntryPointDetector(a.projectRoot, a.lang).Detect()
		if err != nil {
			result.Error = fmt.Errorf("entry point detection: %w", err)
			return result
		}
		a.entryPoints = eps
	}

	// Language-specific import + call-site analysis
	var imports []ImportRef
	var callSites []CallSite
	var err error

	switch a.lang {
	case LangGo:
		imports, callSites, err = newGoAnalyzer(a.projectRoot).Analyse(packageName)
	case LangPython:
		imports, callSites, err = newPythonAnalyzer(a.projectRoot).Analyse(packageName)
	case LangJavaScript, LangTypeScript:
		imports, callSites, err = newJSAnalyzer(a.projectRoot).Analyse(packageName)
	default:
		// For unknown languages, conservatively assume reachable if there are
		// any source files (no false negatives).
		result.Reachable = hasSomeSourceFiles(a.projectRoot)
		result.CallPath = []string{"<unknown-language>"}
		return result
	}

	result.Imports = imports
	result.CallSites = callSites
	if err != nil {
		result.Error = err
	}

	// ── Reachability determination ────────────────────────────────────────────
	//
	// Step 1: If the package is not even imported, it cannot be reached.
	if len(imports) == 0 {
		result.Reachable = false
		return result
	}

	// Step 2: If the package is imported but never called, it might still be
	// used as a type or side-effect import. We flag it as reachable with lower
	// confidence to avoid false negatives.
	if len(callSites) == 0 {
		// Side-effect import (e.g. "import _ 'pkg'" in Go, or "import 'pkg'" in JS)
		// counts as a usage. Conservative: mark as reachable.
		hasSideEffect := false
		for _, imp := range imports {
			if imp.Alias == "_" || imp.Alias == "<side-effect>" {
				hasSideEffect = true
				break
			}
		}
		result.Reachable = hasSideEffect
		if hasSideEffect {
			result.CallPath = buildImportPath(imports[0])
		}
		return result
	}

	// Step 3: Build the shortest call path from an entry point to a call site.
	// For MVP we use a heuristic: if any call site's CallerFunc matches (or is
	// transitively reachable from) an entry point, the package is reachable.
	callPath, reachable := a.findCallPath(callSites)
	result.Reachable = reachable
	result.CallPath = callPath

	return result
}

// CheckMultiple checks reachability for multiple packages and returns a map of
// packageName → ReachabilityResult. Entry points are shared across all checks.
func (a *Analyzer) CheckMultiple(packageNames []string) map[string]ReachabilityResult {
	// Trigger entry-point detection once
	if a.entryPoints == nil {
		eps, _ := newEntryPointDetector(a.projectRoot, a.lang).Detect()
		a.entryPoints = eps
	}

	results := make(map[string]ReachabilityResult, len(packageNames))
	for _, pkg := range packageNames {
		results[pkg] = a.Check(pkg)
	}
	return results
}

// ── helpers ───────────────────────────────────────────────────────────────────

// findCallPath attempts to find a call path from an entry point to a call site.
// It returns the path and whether the package is reachable.
func (a *Analyzer) findCallPath(callSites []CallSite) ([]string, bool) {
	if len(callSites) == 0 {
		return nil, false
	}

	// Build a set of entry-point function names for quick lookup.
	epSet := make(map[string]EntryPoint)
	for _, ep := range a.entryPoints {
		epSet[ep.Name] = ep
		// Also match without "()"
		epSet[strings.TrimSuffix(ep.Name, "()")] = ep
	}

	// Check if any call site is directly inside a *production* entry-point function.
	// Test entry points (TestXxx, test suites) are excluded — a package used
	// only in tests is not reachable from production code.
	for _, cs := range callSites {
		callerBase := strings.TrimSuffix(cs.CallerFunc, "()")
		for _, key := range []string{cs.CallerFunc, callerBase} {
			ep, ok := epSet[key]
			if !ok {
				continue
			}
			if ep.Kind == EntryPointTest {
				continue // skip test entry points
			}
			return []string{ep.Name, cs.Symbol + " (" + cs.File + ":" + fmt.Sprint(cs.Line) + ")"}, true
		}
	}

	// No direct match found. For Go and compiled languages this means the
	// caller is an internal helper. We conservatively mark as reachable since
	// we don't have the full inter-procedural call graph — avoiding false
	// negatives is more important than minimising true positives.
	//
	// Exception: if the only callers are in test files, mark as non-reachable
	// from production entry points.
	allCalledFromTests := true
	for _, cs := range callSites {
		if !strings.HasSuffix(cs.File, "_test.go") &&
			!strings.Contains(cs.File, "/test/") &&
			!strings.Contains(cs.File, "/tests/") &&
			!strings.HasPrefix(cs.CallerFunc, "Test") &&
			!strings.HasPrefix(cs.CallerFunc, "test_") {
			allCalledFromTests = false
			break
		}
	}

	if allCalledFromTests {
		return []string{"[test-only]", callSites[0].Symbol}, false
	}

	// Build a representative call path from the first call site.
	best := callSites[0]
	path := []string{
		best.CallerFunc,
		best.Symbol + " (" + best.File + ":" + fmt.Sprint(best.Line) + ")",
	}
	return path, true
}

// buildImportPath creates a minimal call path for a side-effect import.
func buildImportPath(imp ImportRef) []string {
	return []string{
		"import \"" + imp.PackageName + "\" (" + imp.File + ":" + fmt.Sprint(imp.Line) + ")",
	}
}

// ── Language detection ────────────────────────────────────────────────────────

// detectLanguage infers the primary language of a project by looking for
// canonical manifest files.
func detectLanguage(root string) Language {
	manifests := []struct {
		files []string
		lang  Language
	}{
		{[]string{"go.mod", "go.sum"}, LangGo},
		{[]string{"package.json"}, LangJavaScript},
		{[]string{"tsconfig.json"}, LangTypeScript},
		{[]string{"requirements.txt", "setup.py", "pyproject.toml", "Pipfile"}, LangPython},
	}

	for _, m := range manifests {
		for _, f := range m.files {
			if _, err := os.Stat(filepath.Join(root, f)); err == nil {
				return m.lang
			}
		}
	}
	return LangUnknown
}

// hasSomeSourceFiles returns true if the directory contains at least one
// recognisable source file.
func hasSomeSourceFiles(root string) bool {
	exts := map[string]bool{
		".go": true, ".py": true, ".js": true, ".ts": true,
		".java": true, ".rb": true, ".rs": true,
	}
	found := false
	_ = filepath.WalkDir(root, func(path string, de os.DirEntry, err error) error {
		if err != nil || de.IsDir() || found {
			return nil
		}
		if exts[filepath.Ext(path)] {
			found = true
		}
		return nil
	})
	return found
}
