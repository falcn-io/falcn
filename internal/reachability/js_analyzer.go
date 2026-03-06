package reachability

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// jsAnalyzer analyses JavaScript and TypeScript source files for imports and
// call sites of a target package using regex-based parsing.
type jsAnalyzer struct {
	projectRoot string
}

func newJSAnalyzer(root string) *jsAnalyzer {
	return &jsAnalyzer{projectRoot: root}
}

var (
	// CommonJS: const x = require('pkg')  / const { a, b } = require('pkg')
	jsRequireRe = regexp.MustCompile(`(?:const|let|var)\s+(?:(\w+)|\{([^}]+)\})\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	// ESM default: import x from 'pkg'
	jsImportDefaultRe = regexp.MustCompile(`import\s+(\w+)\s+from\s+['"]([^'"]+)['"]`)
	// ESM named: import { a, b } from 'pkg'  / import * as x from 'pkg'
	jsImportNamedRe = regexp.MustCompile(`import\s+(?:\*\s+as\s+(\w+)|\{([^}]+)\})\s+from\s+['"]([^'"]+)['"]`)
	// ESM side-effect: import 'pkg'
	jsImportSideEffectRe = regexp.MustCompile(`^import\s+['"]([^'"]+)['"]`)

	// Function boundaries for enclosing-function tracking.
	jsFuncRe = regexp.MustCompile(`(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\())`)
)

var jsSourceExts = map[string]bool{
	".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".mjs": true, ".cjs": true,
}

// Analyse scans JS/TS source for imports and call sites of packageName.
func (a *jsAnalyzer) Analyse(packageName string) (imports []ImportRef, callSites []CallSite, err error) {
	err = filepath.WalkDir(a.projectRoot, func(path string, de os.DirEntry, walkErr error) error {
		if walkErr != nil || de.IsDir() {
			return nil
		}
		if !jsSourceExts[filepath.Ext(path)] {
			return nil
		}
		if strings.Contains(path, "node_modules") ||
			strings.Contains(path, "/dist/") ||
			strings.Contains(path, "/.next/") {
			return nil
		}
		fi, fi_err := os.Stat(path)
		if fi_err != nil || fi.Size() > 2<<20 {
			return nil
		}

		fileImports, fileCalls := a.analyseFile(path, packageName)
		imports = append(imports, fileImports...)
		callSites = append(callSites, fileCalls...)
		return nil
	})
	return
}

func (a *jsAnalyzer) analyseFile(path, targetPkg string) ([]ImportRef, []CallSite) {
	rel, _ := filepath.Rel(a.projectRoot, path)

	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}

	var fileImports []ImportRef
	localAliases := map[string]struct{}{} // alias → present

	// ── Pass 1: imports ───────────────────────────────────────────────────────
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// CommonJS require
		if m := jsRequireRe.FindStringSubmatch(trimmed); m != nil {
			pkg := m[3]
			if !pkgMatches(pkg, targetPkg) {
				continue
			}
			if m[1] != "" {
				// const alias = require(...)
				localAliases[m[1]] = struct{}{}
				fileImports = append(fileImports, ImportRef{
					PackageName: pkg, Alias: m[1], File: rel, Line: i + 1,
				})
			} else if m[2] != "" {
				// const { a, b } = require(...)
				for _, sym := range splitSymbols(m[2]) {
					localAliases[sym] = struct{}{}
					fileImports = append(fileImports, ImportRef{
						PackageName: pkg, Alias: sym, File: rel, Line: i + 1,
					})
				}
			}
			continue
		}

		// ESM default import
		if m := jsImportDefaultRe.FindStringSubmatch(trimmed); m != nil {
			if pkgMatches(m[2], targetPkg) {
				localAliases[m[1]] = struct{}{}
				fileImports = append(fileImports, ImportRef{
					PackageName: m[2], Alias: m[1], File: rel, Line: i + 1,
				})
			}
			continue
		}

		// ESM named / namespace import
		if m := jsImportNamedRe.FindStringSubmatch(trimmed); m != nil {
			pkg := m[3]
			if !pkgMatches(pkg, targetPkg) {
				continue
			}
			if m[1] != "" {
				// import * as alias
				localAliases[m[1]] = struct{}{}
				fileImports = append(fileImports, ImportRef{
					PackageName: pkg, Alias: m[1], File: rel, Line: i + 1,
				})
			} else if m[2] != "" {
				// import { a, b as c }
				for _, sym := range splitSymbols(m[2]) {
					localAliases[sym] = struct{}{}
					fileImports = append(fileImports, ImportRef{
						PackageName: pkg, Alias: sym, File: rel, Line: i + 1,
					})
				}
			}
			continue
		}

		// ESM side-effect import (counts as a usage signal)
		if m := jsImportSideEffectRe.FindStringSubmatch(trimmed); m != nil {
			if pkgMatches(m[1], targetPkg) {
				fileImports = append(fileImports, ImportRef{
					PackageName: m[1], Alias: "<side-effect>", File: rel, Line: i + 1,
				})
			}
		}
	}

	if len(localAliases) == 0 && len(fileImports) == 0 {
		return fileImports, nil
	}

	// ── Pass 2: call sites ────────────────────────────────────────────────────
	var callSites []CallSite
	currentFunc := "<module>"

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track enclosing function
		if m := jsFuncRe.FindStringSubmatch(line); m != nil {
			if m[1] != "" {
				currentFunc = m[1] + "()"
			} else if m[2] != "" {
				currentFunc = m[2] + "()"
			}
		}

		for alias := range localAliases {
			if strings.Contains(trimmed, alias) {
				callSites = append(callSites, CallSite{
					Symbol:     alias,
					File:       rel,
					Line:       i + 1,
					CallerFunc: currentFunc,
				})
				break // one call site per line per alias is enough
			}
		}
	}

	return fileImports, callSites
}

// ── helpers ───────────────────────────────────────────────────────────────────

// pkgMatches returns true when importedPkg refers to targetPkg.
// Handles exact match, scoped packages (@scope/name), and trailing path
// segments (e.g. "lodash/get" matching "lodash").
func pkgMatches(importedPkg, targetPkg string) bool {
	if importedPkg == targetPkg {
		return true
	}
	// Strip path suffix from scoped package: "@scope/name" vs "name"
	base := importedPkg
	if strings.Contains(importedPkg, "/") {
		// For scoped packages keep the full @scope/name
		if strings.HasPrefix(importedPkg, "@") {
			parts := strings.SplitN(importedPkg, "/", 3)
			if len(parts) >= 2 {
				base = parts[0] + "/" + parts[1]
			}
		} else {
			// "lodash/get" → "lodash"
			base = strings.SplitN(importedPkg, "/", 2)[0]
		}
	}
	return base == targetPkg
}

// splitSymbols splits "a, b as c, d" → ["a", "c", "d"].
func splitSymbols(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		subParts := strings.Fields(part) // handle "b as c"
		switch len(subParts) {
		case 3: // "b as c"
			out = append(out, subParts[2])
		case 1:
			out = append(out, subParts[0])
		}
	}
	return out
}
