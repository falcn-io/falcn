package reachability

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultMaxDepth is the default maximum number of transitive hops to walk.
const DefaultMaxDepth = 5

// Analyzer is the top-level reachability engine. It detects the project
// language, finds entry points, and determines whether a given vulnerable
// package is actually reachable from those entry points.
type Analyzer struct {
	projectRoot  string
	lang         Language
	entryPoints  []EntryPoint
	maxDepth     int
	includeTests bool
	cache        *fileCache
}

// fileCache caches parsed file data to avoid re-parsing unchanged files.
type fileCache struct {
	mu      sync.RWMutex
	imports map[string][]ImportRef // file path → imports
	calls   map[string][]CallSite // file path → call sites
	modTime map[string]time.Time  // file path → last modified
}

func newFileCache() *fileCache {
	return &fileCache{
		imports: make(map[string][]ImportRef),
		calls:   make(map[string][]CallSite),
		modTime: make(map[string]time.Time),
	}
}

// get returns cached imports and call sites for a file if the file has not
// been modified since it was cached. Returns (imports, calls, true) on hit.
// The os.Stat call is performed outside the lock to avoid a TOCTOU race where
// a slow stat could hold the read-lock while another goroutine needs the
// write-lock.
func (c *fileCache) get(path string) ([]ImportRef, []CallSite, bool) {
	c.mu.RLock()
	cached, ok := c.modTime[path]
	imports := c.imports[path]
	calls := c.calls[path]
	c.mu.RUnlock()

	if !ok {
		return nil, nil, false
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, false
	}
	if !info.ModTime().Equal(cached) {
		return nil, nil, false
	}
	return imports, calls, true
}

// put stores parsed data for a file.
func (c *fileCache) put(path string, imports []ImportRef, calls []CallSite) {
	c.mu.Lock()
	defer c.mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		return
	}
	c.imports[path] = imports
	c.calls[path] = calls
	c.modTime[path] = info.ModTime()
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
		maxDepth:    DefaultMaxDepth,
		cache:       newFileCache(),
	}, nil
}

// SetMaxDepth sets the maximum transitive hop depth for call graph walking.
func (a *Analyzer) SetMaxDepth(depth int) {
	if depth < 1 {
		depth = 1
	}
	if depth > 20 {
		depth = 20
	}
	a.maxDepth = depth
}

// SetIncludeTests controls whether test entry points are considered.
func (a *Analyzer) SetIncludeTests(include bool) {
	a.includeTests = include
}

// Language returns the detected project language.
func (a *Analyzer) Language() Language {
	return a.lang
}

// SetLanguage overrides auto-detected language.
func (a *Analyzer) SetLanguage(lang Language) {
	a.lang = lang
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
			result.Depth = 0
		}
		return result
	}

	// Step 3: Build the call graph and do transitive BFS reachability.
	callGraph := a.buildCallGraph()
	result.GraphSize = len(callGraph)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	transPath, reachable := a.findTransitiveCallPath(ctx, callSites, callGraph)
	result.Reachable = reachable
	if reachable && len(transPath) > 0 {
		result.TransitivePath = transPath
		result.Depth = len(transPath) - 1 // first hop is the entry point itself
		if result.Depth < 0 {
			result.Depth = 0
		}
		// Build legacy CallPath from TransitivePath for backward compatibility
		result.CallPath = make([]string, len(transPath))
		for i, hop := range transPath {
			if hop.File != "" {
				result.CallPath[i] = hop.Function + " [" + hop.File + ":" + fmt.Sprint(hop.Line) + "]"
			} else {
				result.CallPath[i] = hop.Function
			}
		}
	} else if !reachable {
		// Fall back to the old heuristic for backward compatibility
		callPath, fallbackReachable := a.findCallPath(callSites)
		result.Reachable = fallbackReachable
		result.CallPath = callPath
	}

	return result
}

// CheckMultiple checks reachability for multiple packages and returns a map of
// packageName → ReachabilityResult. Entry points and call graph are shared
// across all checks.
func (a *Analyzer) CheckMultiple(packageNames []string) map[string]ReachabilityResult {
	// Trigger entry-point detection once
	if a.entryPoints == nil {
		eps, _ := newEntryPointDetector(a.projectRoot, a.lang).Detect()
		a.entryPoints = eps
	}

	// Build the call graph once for all packages
	callGraph := a.buildCallGraph()

	results := make(map[string]ReachabilityResult, len(packageNames))
	for _, pkg := range packageNames {
		result := a.checkWithGraph(pkg, callGraph)
		results[pkg] = result
	}
	return results
}

// checkWithGraph performs a Check using a pre-built call graph.
func (a *Analyzer) checkWithGraph(packageName string, callGraph map[string][]string) ReachabilityResult {
	result := ReachabilityResult{
		PackageName: packageName,
		Language:    a.lang,
		AnalysedAt:  time.Now(),
		GraphSize:   len(callGraph),
	}

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
		result.Reachable = hasSomeSourceFiles(a.projectRoot)
		result.CallPath = []string{"<unknown-language>"}
		return result
	}

	result.Imports = imports
	result.CallSites = callSites
	if err != nil {
		result.Error = err
	}

	if len(imports) == 0 {
		result.Reachable = false
		return result
	}

	if len(callSites) == 0 {
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	transPath, reachable := a.findTransitiveCallPath(ctx, callSites, callGraph)
	result.Reachable = reachable
	if reachable && len(transPath) > 0 {
		result.TransitivePath = transPath
		result.Depth = len(transPath) - 1
		if result.Depth < 0 {
			result.Depth = 0
		}
		result.CallPath = make([]string, len(transPath))
		for i, hop := range transPath {
			if hop.File != "" {
				result.CallPath[i] = hop.Function + " [" + hop.File + ":" + fmt.Sprint(hop.Line) + "]"
			} else {
				result.CallPath[i] = hop.Function
			}
		}
	} else if !reachable {
		callPath, fallbackReachable := a.findCallPath(callSites)
		result.Reachable = fallbackReachable
		result.CallPath = callPath
	}

	return result
}

// ── Call graph construction ──────────────────────────────────────────────────

// buildCallGraph constructs a function-level call graph for the project.
// Returns map[callerFunc][]calleeFunc where function names match the
// CallerFunc format used by language analyzers (e.g. "main()", "helper()").
func (a *Analyzer) buildCallGraph() map[string][]string {
	switch a.lang {
	case LangGo:
		return a.buildGoCallGraph()
	case LangPython:
		return a.buildPythonCallGraph()
	case LangJavaScript, LangTypeScript:
		return a.buildJSCallGraph()
	default:
		return make(map[string][]string)
	}
}

// buildGoCallGraph builds a call graph for Go projects using go/ast.
func (a *Analyzer) buildGoCallGraph() map[string][]string {
	graph := make(map[string][]string)
	ga := newGoAnalyzer(a.projectRoot)

	_ = filepath.WalkDir(a.projectRoot, func(path string, de os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if de.IsDir() {
			base := de.Name()
			if base == "vendor" || base == "testdata" || strings.HasPrefix(base, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if !a.includeTests && strings.HasSuffix(path, "_test.go") {
			return nil
		}

		funcCalls := ga.extractFunctionCalls(path)
		for caller, callees := range funcCalls {
			graph[caller] = append(graph[caller], callees...)
		}
		return nil
	})
	return graph
}

// buildPythonCallGraph builds a call graph for Python projects using regex.
func (a *Analyzer) buildPythonCallGraph() map[string][]string {
	graph := make(map[string][]string)

	_ = filepath.WalkDir(a.projectRoot, func(path string, de os.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".py") {
			return nil
		}
		if !a.includeTests && (strings.Contains(path, "/test") || strings.Contains(path, "/tests")) {
			return nil
		}

		funcCalls := extractPythonFunctionCalls(path)
		for caller, callees := range funcCalls {
			graph[caller] = append(graph[caller], callees...)
		}
		return nil
	})
	return graph
}

// buildJSCallGraph builds a call graph for JS/TS projects using regex.
func (a *Analyzer) buildJSCallGraph() map[string][]string {
	graph := make(map[string][]string)

	_ = filepath.WalkDir(a.projectRoot, func(path string, de os.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return nil
		}
		if !jsSourceExts[filepath.Ext(path)] {
			return nil
		}
		if strings.Contains(path, "node_modules") || strings.Contains(path, "/dist/") {
			return nil
		}
		if !a.includeTests && (strings.Contains(path, "__tests__") || strings.HasSuffix(path, ".test.js") || strings.HasSuffix(path, ".spec.js")) {
			return nil
		}

		funcCalls := extractJSFunctionCalls(path)
		for caller, callees := range funcCalls {
			graph[caller] = append(graph[caller], callees...)
		}
		return nil
	})
	return graph
}

// ── Transitive reachability via BFS ──────────────────────────────────────────

// funcLocation stores file + line for a function, used in path reconstruction.
type funcLocation struct {
	File string
	Line int
}

// findTransitiveCallPath performs BFS from entry points through the call graph
// to find the shortest path to any call site of the target package.
// Returns the path as CallPathHops and whether it is reachable.
// The context controls the BFS timeout; on cancellation the function
// conservatively returns reachable=true to avoid false negatives.
func (a *Analyzer) findTransitiveCallPath(ctx context.Context, callSites []CallSite, callGraph map[string][]string) ([]CallPathHop, bool) {
	if len(callSites) == 0 {
		return nil, false
	}

	// Build a set of target functions (functions that call the target package).
	targetFuncs := make(map[string]CallSite)
	for _, cs := range callSites {
		targetFuncs[cs.CallerFunc] = cs
		// Also try without trailing "()"
		targetFuncs[strings.TrimSuffix(cs.CallerFunc, "()")] = cs
	}

	// Build entry point set for BFS roots.
	type bfsNode struct {
		funcName string
		depth    int
	}

	// Collect function locations for path reconstruction.
	funcLocs := make(map[string]funcLocation)
	for _, ep := range a.entryPoints {
		funcLocs[ep.Name] = funcLocation{File: ep.File, Line: ep.Line}
		funcLocs[strings.TrimSuffix(ep.Name, "()")] = funcLocation{File: ep.File, Line: ep.Line}
	}
	for _, cs := range callSites {
		funcLocs[cs.CallerFunc] = funcLocation{File: cs.File, Line: cs.Line}
	}

	// BFS from each non-test entry point.
	var queue []bfsNode
	visited := make(map[string]bool)
	parent := make(map[string]string) // child → parent for path reconstruction

	for _, ep := range a.entryPoints {
		if ep.Kind == EntryPointTest && !a.includeTests {
			continue
		}
		name := ep.Name
		if !visited[name] {
			visited[name] = true
			queue = append(queue, bfsNode{funcName: name, depth: 0})
		}
		// Also enqueue without "()" suffix
		nameBase := strings.TrimSuffix(name, "()")
		if nameBase != name && !visited[nameBase] {
			visited[nameBase] = true
			queue = append(queue, bfsNode{funcName: nameBase, depth: 0})
			parent[nameBase] = name
		}
	}

	for len(queue) > 0 {
		// Check for context cancellation (timeout) — conservatively mark as
		// reachable to avoid false negatives on very large call graphs.
		select {
		case <-ctx.Done():
			return nil, true
		default:
		}

		current := queue[0]
		queue = queue[1:]

		// Check if current function is a target (calls the target package).
		if cs, ok := targetFuncs[current.funcName]; ok {
			// Reconstruct the path from entry point to this function.
			path := a.reconstructPath(current.funcName, parent, funcLocs)
			// Append the actual call site as the final hop.
			path = append(path, CallPathHop{
				Function: cs.Symbol,
				File:     cs.File,
				Line:     cs.Line,
			})
			return path, true
		}

		if current.depth >= a.maxDepth {
			continue
		}

		// Expand callees from the call graph.
		callees := callGraph[current.funcName]
		// Also try with "()" suffix
		if len(callees) == 0 {
			callees = callGraph[current.funcName+"()"]
		}

		for _, callee := range callees {
			if !visited[callee] {
				visited[callee] = true
				parent[callee] = current.funcName
				queue = append(queue, bfsNode{funcName: callee, depth: current.depth + 1})
			}
			// Also check base name
			calleeBase := strings.TrimSuffix(callee, "()")
			if calleeBase != callee && !visited[calleeBase] {
				visited[calleeBase] = true
				parent[calleeBase] = current.funcName
				queue = append(queue, bfsNode{funcName: calleeBase, depth: current.depth + 1})
			}
		}
	}

	return nil, false
}

// reconstructPath walks the parent map backward from target to an entry point,
// then reverses the result.
func (a *Analyzer) reconstructPath(target string, parent map[string]string, locs map[string]funcLocation) []CallPathHop {
	var path []CallPathHop

	current := target
	seen := make(map[string]bool)
	for {
		if seen[current] {
			break // safety: avoid infinite loops from circular references
		}
		seen[current] = true

		loc := locs[current]
		path = append(path, CallPathHop{
			Function: current,
			File:     loc.File,
			Line:     loc.Line,
		})

		p, ok := parent[current]
		if !ok {
			break // reached an entry point (BFS root)
		}
		current = p
	}

	// Reverse to get entry-point-first order.
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return path
}

// ── helpers ───────────────────────────────────────────────────────────────────

// findCallPath attempts to find a call path from an entry point to a call site.
// It returns the path and whether the package is reachable.
// This is the legacy single-hop heuristic, kept for backward compatibility.
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
			if ep.Kind == EntryPointTest && !a.includeTests {
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
