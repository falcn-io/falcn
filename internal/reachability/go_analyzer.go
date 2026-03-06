package reachability

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// goAnalyzer performs call-graph reachability for Go projects using the
// standard library's go/ast package. It avoids heavy type-checking so it
// works on projects that are not fully buildable (missing dependencies, etc.).
type goAnalyzer struct {
	projectRoot string
	fset        *token.FileSet
}

func newGoAnalyzer(root string) *goAnalyzer {
	return &goAnalyzer{projectRoot: root, fset: token.NewFileSet()}
}

// Analyse checks whether packageName is imported and used in the project, and
// returns all detected imports and call sites.
func (a *goAnalyzer) Analyse(packageName string) (imports []ImportRef, callSites []CallSite, err error) {
	err = filepath.WalkDir(a.projectRoot, func(path string, de os.DirEntry, walkErr error) error {
		if walkErr != nil {
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

		fileImports, fileCallSites := a.analyseFile(path, packageName)
		imports = append(imports, fileImports...)
		callSites = append(callSites, fileCallSites...)
		return nil
	})
	return
}

// analyseFile parses one Go source file and extracts imports and call sites
// for the target package.
func (a *goAnalyzer) analyseFile(path, targetPkg string) ([]ImportRef, []CallSite) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	f, err := parser.ParseFile(a.fset, path, src, 0)
	if err != nil {
		return nil, nil
	}
	rel, _ := filepath.Rel(a.projectRoot, path)

	// ── Step 1: find imports that match targetPkg ─────────────────────────────
	// The target package may be specified as a full path ("github.com/foo/bar")
	// or a short name ("bar"). We match on either the full import path or the
	// last path segment.
	targetBaseName := lastSegment(targetPkg)

	var localAliases []string // local names this file uses for the package
	var fileImports []ImportRef

	for _, imp := range f.Imports {
		importPath := strings.Trim(imp.Path.Value, `"`)

		if !matchesPackage(importPath, targetPkg) {
			continue
		}

		pos := a.fset.Position(imp.Pos())
		alias := targetBaseName
		if imp.Name != nil {
			alias = imp.Name.Name
		}
		localAliases = append(localAliases, alias)
		fileImports = append(fileImports, ImportRef{
			PackageName: importPath,
			Alias:       alias,
			File:        rel,
			Line:        pos.Line,
		})
	}

	if len(localAliases) == 0 {
		return fileImports, nil // package not imported in this file
	}

	// ── Step 2: find call sites using the imported aliases ────────────────────
	var callSites []CallSite

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}

		for _, alias := range localAliases {
			if ident.Name != alias {
				continue
			}
			pos := a.fset.Position(call.Pos())
			symbolName := alias + "." + sel.Sel.Name
			callerFunc := enclosingFunc(f, call.Pos(), a.fset)

			callSites = append(callSites, CallSite{
				Symbol:     symbolName,
				File:       rel,
				Line:       pos.Line,
				CallerFunc: callerFunc,
			})
		}
		return true
	})

	return fileImports, callSites
}

// enclosingFunc returns the name of the innermost function declaration that
// contains pos. Returns "<top-level>" if no enclosing function is found.
func enclosingFunc(f *ast.File, pos token.Pos, fset *token.FileSet) string {
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Body == nil {
			continue
		}
		if fn.Body.Lbrace <= pos && pos <= fn.Body.Rbrace {
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				recv := exprString(fn.Recv.List[0].Type)
				return recv + "." + fn.Name.Name + "()"
			}
			return fn.Name.Name + "()"
		}
	}
	return "<top-level>"
}

// ── helpers ───────────────────────────────────────────────────────────────────

// lastSegment returns the last slash-separated component of a package path.
func lastSegment(pkg string) string {
	parts := strings.Split(pkg, "/")
	return parts[len(parts)-1]
}

// matchesPackage returns true if importPath refers to targetPkg. Handles:
//   - exact full path match: "github.com/foo/bar" == "github.com/foo/bar"
//   - short name match: importPath ends with "/bar" and targetPkg is "bar"
//   - targetPkg is a full path and importPath ends with that path
func matchesPackage(importPath, targetPkg string) bool {
	if importPath == targetPkg {
		return true
	}
	// e.g. targetPkg = "requests" and importPath = "github.com/xxx/requests"
	if strings.HasSuffix(importPath, "/"+targetPkg) {
		return true
	}
	// e.g. targetPkg = "github.com/foo/bar" and importPath ends with the same
	if strings.HasSuffix(importPath, targetPkg) {
		return true
	}
	// short-name match on last segment
	if lastSegment(importPath) == lastSegment(targetPkg) {
		return true
	}
	return false
}
