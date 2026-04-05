package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// pythonAnalyzer analyses Python source files for imports and call sites of a
// target package using regex-based parsing. Full AST analysis is avoided to
// keep binary size and build complexity low.
type pythonAnalyzer struct {
	projectRoot string
}

func newPythonAnalyzer(root string) *pythonAnalyzer {
	return &pythonAnalyzer{projectRoot: root}
}

// Regexes for Python import forms:
//   import requests
//   import requests as req
//   from requests import Session
//   from requests.adapters import HTTPAdapter
var (
	pyImportRe     = regexp.MustCompile(`^import\s+([\w.]+)(?:\s+as\s+(\w+))?`)
	pyFromImportRe = regexp.MustCompile(`^from\s+([\w.]+)\s+import\s+(.+)`)

	// Function/method definition for enclosing context.
	pyFuncDefRe = regexp.MustCompile(`^(?:    )*def\s+(\w+)\s*\(`)
)

// Analyse scans the Python project for imports and call sites of packageName.
func (a *pythonAnalyzer) Analyse(packageName string) (imports []ImportRef, callSites []CallSite, err error) {
	// Normalise: Python packages often use hyphens in PyPI but underscores in code.
	normPkg := strings.ReplaceAll(packageName, "-", "_")
	basePkg := strings.SplitN(normPkg, ".", 2)[0] // "requests.adapters" → "requests"

	err = filepath.WalkDir(a.projectRoot, func(path string, de os.DirEntry, walkErr error) error {
		if walkErr != nil || de.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".py") {
			return nil
		}
		fi, fi_err := os.Stat(path)
		if fi_err != nil || fi.Size() > 2<<20 { // skip files > 2 MB
			return nil
		}

		fileImports, fileCalls := a.analyseFile(path, basePkg)
		imports = append(imports, fileImports...)
		callSites = append(callSites, fileCalls...)
		return nil
	})
	return
}

// pyCallRe matches function calls like foo(), bar.baz(), self.method()
var pyCallRe = regexp.MustCompile(`\b(\w+(?:\.\w+)?)\s*\(`)

// extractPythonFunctionCalls parses a Python file and returns a map of
// callerFunc → []calleeFunc for building the project-wide call graph.
func extractPythonFunctionCalls(path string) map[string][]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	graph := make(map[string][]string)
	currentFunc := "<module>"

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Track enclosing function
		if m := pyFuncDefRe.FindStringSubmatch(line); m != nil {
			currentFunc = m[1] + "()"
		}

		// Find all function calls on this line
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, m := range pyCallRe.FindAllStringSubmatch(trimmed, -1) {
			callee := m[1] + "()"
			// Skip common keywords that look like calls
			base := strings.Split(m[1], ".")[0]
			switch base {
			case "if", "for", "while", "return", "print", "range", "len", "str", "int", "float", "list", "dict", "set", "tuple", "type", "isinstance", "hasattr", "getattr", "super":
				continue
			}
			graph[currentFunc] = append(graph[currentFunc], callee)
		}
	}
	return graph
}

func (a *pythonAnalyzer) analyseFile(path, basePkg string) ([]ImportRef, []CallSite) {
	rel, _ := filepath.Rel(a.projectRoot, path)

	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	var fileImports []ImportRef
	// localAliases maps alias → bool (true = whole-package import, false = symbol import)
	localAliases := map[string]bool{}

	// ── Pass 1: collect imports ───────────────────────────────────────────────
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if m := pyImportRe.FindStringSubmatch(trimmed); m != nil {
			pkg := m[1]
			rootPkg := strings.SplitN(pkg, ".", 2)[0]
			if rootPkg != basePkg {
				continue
			}
			alias := rootPkg
			if m[2] != "" {
				alias = m[2]
			}
			localAliases[alias] = true
			fileImports = append(fileImports, ImportRef{
				PackageName: pkg, Alias: alias, File: rel, Line: i + 1,
			})
			continue
		}

		if m := pyFromImportRe.FindStringSubmatch(trimmed); m != nil {
			pkg := m[1]
			rootPkg := strings.SplitN(pkg, ".", 2)[0]
			if rootPkg != basePkg {
				continue
			}
			// "from requests import Session, get" — each symbol becomes an alias.
			symbols := strings.Split(m[2], ",")
			for _, sym := range symbols {
				sym = strings.TrimSpace(sym)
				// Handle "Session as s"
				parts := strings.Fields(sym)
				alias := parts[0]
				if len(parts) == 3 && parts[1] == "as" {
					alias = parts[2]
				}
				localAliases[alias] = false // symbol import, not whole package
				fileImports = append(fileImports, ImportRef{
					PackageName: pkg, Alias: alias, File: rel, Line: i + 1,
				})
			}
		}
	}

	if len(localAliases) == 0 {
		return fileImports, nil
	}

	// ── Pass 2: find call sites ───────────────────────────────────────────────
	var callSites []CallSite
	currentFunc := "<module>"

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track enclosing function
		if m := pyFuncDefRe.FindStringSubmatch(line); m != nil {
			currentFunc = m[1] + "()"
		}

		for alias, isWholePackage := range localAliases {
			var matched bool
			if isWholePackage {
				// Look for alias.something(
				matched = strings.Contains(trimmed, alias+".")
			} else {
				// Look for alias( or alias as a standalone call
				matched = strings.Contains(trimmed, alias+"(") || strings.Contains(trimmed, alias+" ")
			}
			if matched {
				callSites = append(callSites, CallSite{
					Symbol:     alias,
					File:       rel,
					Line:       i + 1,
					CallerFunc: currentFunc,
				})
			}
		}
	}

	return fileImports, callSites
}
