package reachability

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// entryPointDetector finds all entry points in a project.
type entryPointDetector struct {
	projectRoot string
	lang        Language
}

func newEntryPointDetector(projectRoot string, lang Language) *entryPointDetector {
	return &entryPointDetector{projectRoot: projectRoot, lang: lang}
}

// Detect returns all entry points found in the project.
func (d *entryPointDetector) Detect() ([]EntryPoint, error) {
	switch d.lang {
	case LangGo:
		return d.detectGo()
	case LangPython:
		return d.detectPython()
	case LangJavaScript, LangTypeScript:
		return d.detectJS()
	default:
		return d.detectGeneric()
	}
}

// ── Go ────────────────────────────────────────────────────────────────────────

func (d *entryPointDetector) detectGo() ([]EntryPoint, error) {
	var entries []EntryPoint
	fset := token.NewFileSet()

	err := filepath.WalkDir(d.projectRoot, func(path string, de os.DirEntry, err error) error {
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

		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return nil // skip unparseable files
		}

		rel, _ := filepath.Rel(d.projectRoot, path)

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			name := fn.Name.Name
			pos := fset.Position(fn.Pos())

			switch {
			case name == "main" && f.Name.Name == "main":
				entries = append(entries, EntryPoint{
					Name: "main()", File: rel, Line: pos.Line, Kind: EntryPointMain,
				})

			case name == "init":
				entries = append(entries, EntryPoint{
					Name: "init()", File: rel, Line: pos.Line, Kind: EntryPointInit,
				})

			case strings.HasPrefix(name, "Test") && fn.Type != nil:
				// TestXxx(t *testing.T)
				entries = append(entries, EntryPoint{
					Name: name, File: rel, Line: pos.Line, Kind: EntryPointTest,
				})

			case isGoHTTPHandler(fn):
				entries = append(entries, EntryPoint{
					Name: name, File: rel, Line: pos.Line, Kind: EntryPointHTTPHandler,
				})

			case ast.IsExported(name):
				entries = append(entries, EntryPoint{
					Name: name, File: rel, Line: pos.Line, Kind: EntryPointExported,
				})
			}
		}
		return nil
	})
	return entries, err
}

// isGoHTTPHandler returns true for func(w http.ResponseWriter, r *http.Request).
func isGoHTTPHandler(fn *ast.FuncDecl) bool {
	if fn.Type == nil || fn.Type.Params == nil {
		return false
	}
	params := fn.Type.Params.List
	if len(params) != 2 {
		return false
	}
	// Check second param ends with *Request
	second := exprString(params[1].Type)
	return strings.Contains(second, "Request")
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.StarExpr:
		return "*" + exprString(v.X)
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.Ident:
		return v.Name
	default:
		return ""
	}
}

// ── Python ────────────────────────────────────────────────────────────────────

var (
	pyDefRe     = regexp.MustCompile(`(?m)^def\s+(\w+)\s*\(`)
	pyMainRe    = regexp.MustCompile(`(?m)if\s+__name__\s*==\s*['"]__main__['"]`)
	pyClickRe   = regexp.MustCompile(`@(?:click|app)\.(?:command|route|get|post|put|delete|patch)`)
	pyFlaskRe   = regexp.MustCompile(`@(?:app|blueprint)\.route`)
	pyDjangoRe  = regexp.MustCompile(`urlpatterns\s*=`)
	pyFastAPIRe = regexp.MustCompile(`@(?:app|router)\.(?:get|post|put|delete|patch|options|head)`)
)

func (d *entryPointDetector) detectPython() ([]EntryPoint, error) {
	var entries []EntryPoint

	err := filepath.WalkDir(d.projectRoot, func(path string, de os.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".py") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		rel, _ := filepath.Rel(d.projectRoot, path)
		text := string(src)

		// if __name__ == "__main__" block → main entry
		if pyMainRe.MatchString(text) {
			entries = append(entries, EntryPoint{
				Name: "__main__", File: rel, Line: 0, Kind: EntryPointMain,
			})
		}

		// All top-level defs
		for _, m := range pyDefRe.FindAllStringSubmatchIndex(text, -1) {
			name := text[m[2]:m[3]]
			line := strings.Count(text[:m[0]], "\n") + 1
			kind := EntryPointExported
			switch {
			case strings.HasPrefix(name, "test_"):
				kind = EntryPointTest
			case pyClickRe.MatchString(getLinesBefore(text, m[0], 3)):
				kind = EntryPointCLICommand
			case pyFlaskRe.MatchString(getLinesBefore(text, m[0], 3)) ||
				pyFastAPIRe.MatchString(getLinesBefore(text, m[0], 3)):
				kind = EntryPointHTTPHandler
			case strings.HasPrefix(name, "_"):
				continue // skip private helpers
			}
			entries = append(entries, EntryPoint{
				Name: name, File: rel, Line: line, Kind: kind,
			})
		}
		return nil
	})
	return entries, err
}

// ── JavaScript / TypeScript ───────────────────────────────────────────────────

var (
	jsExportedFuncRe   = regexp.MustCompile(`(?m)^export\s+(?:default\s+)?(?:async\s+)?function\s+(\w+)`)
	jsArrowExportRe    = regexp.MustCompile(`(?m)^export\s+(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(`)
	jsExpressHandlerRe = regexp.MustCompile(`app\.(?:get|post|put|delete|patch|use)\s*\(`)
	jsModuleMainRe     = regexp.MustCompile(`(?m)if\s*\(\s*require\.main\s*===\s*module\s*\)`)
	jsTestFuncRe       = regexp.MustCompile(`(?m)(?:it|test|describe)\s*\(\s*['"\x60]`)
)

func (d *entryPointDetector) detectJS() ([]EntryPoint, error) {
	var entries []EntryPoint
	exts := map[string]bool{".js": true, ".ts": true, ".mjs": true, ".cjs": true, ".jsx": true, ".tsx": true}

	err := filepath.WalkDir(d.projectRoot, func(path string, de os.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return nil
		}
		if !exts[filepath.Ext(path)] {
			return nil
		}
		// Skip node_modules and dist
		if strings.Contains(path, "node_modules") || strings.Contains(path, "/dist/") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		rel, _ := filepath.Rel(d.projectRoot, path)
		text := string(src)

		if jsModuleMainRe.MatchString(text) {
			entries = append(entries, EntryPoint{
				Name: "__main__", File: rel, Kind: EntryPointMain,
			})
		}
		for _, m := range jsExportedFuncRe.FindAllStringSubmatchIndex(text, -1) {
			name := text[m[2]:m[3]]
			line := strings.Count(text[:m[0]], "\n") + 1
			kind := EntryPointExported
			if jsExpressHandlerRe.MatchString(getLinesBefore(text, m[0], 3)) {
				kind = EntryPointHTTPHandler
			}
			entries = append(entries, EntryPoint{Name: name, File: rel, Line: line, Kind: kind})
		}
		for _, m := range jsArrowExportRe.FindAllStringSubmatchIndex(text, -1) {
			name := text[m[2]:m[3]]
			line := strings.Count(text[:m[0]], "\n") + 1
			entries = append(entries, EntryPoint{Name: name, File: rel, Line: line, Kind: EntryPointExported})
		}
		if jsTestFuncRe.MatchString(text) {
			entries = append(entries, EntryPoint{
				Name: "test-suite", File: rel, Kind: EntryPointTest,
			})
		}
		return nil
	})
	return entries, err
}

// ── Generic fallback ──────────────────────────────────────────────────────────

func (d *entryPointDetector) detectGeneric() ([]EntryPoint, error) {
	// For unknown languages, treat the whole project as one logical entry point.
	return []EntryPoint{{Name: "project", File: ".", Kind: EntryPointExported}}, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// getLinesBefore returns the n lines immediately before offset in text.
func getLinesBefore(text string, offset, n int) string {
	if offset <= 0 {
		return ""
	}
	sub := text[:offset]
	lines := strings.Split(sub, "\n")
	if len(lines) < n {
		return sub
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}
