package reachability

import (
	"os"
	"path/filepath"
	"testing"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// writeFile creates a file with given content inside dir, returning the path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// ── Go reachability tests ─────────────────────────────────────────────────────

func TestGoAnalyzer_Reachable(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/test\n\ngo 1.21\n")
	writeFile(t, dir, "main.go", `package main

import "github.com/foo/vuln"

func main() {
	vuln.DoSomethingDangerous()
}
`)
	a, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	result := a.Check("github.com/foo/vuln")
	if !result.Reachable {
		t.Errorf("expected Reachable=true, got false; callSites=%v imports=%v", result.CallSites, result.Imports)
	}
	if len(result.CallPath) == 0 {
		t.Error("expected non-empty CallPath")
	}
}

func TestGoAnalyzer_NotImported(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/test\n\ngo 1.21\n")
	writeFile(t, dir, "main.go", `package main

import "fmt"

func main() {
	fmt.Println("hello")
}
`)
	a, _ := New(dir)
	result := a.Check("github.com/some/vuln")
	if result.Reachable {
		t.Error("expected Reachable=false for unimported package")
	}
}

func TestGoAnalyzer_ImportedButOnlyInTests(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/test\n\ngo 1.21\n")
	writeFile(t, dir, "main.go", `package main

import "fmt"

func main() {
	fmt.Println("hello")
}
`)
	writeFile(t, dir, "main_test.go", `package main

import (
	"testing"
	"github.com/foo/vuln"
)

func TestSomething(t *testing.T) {
	vuln.DoSomethingDangerous()
}
`)
	a, _ := New(dir)
	result := a.Check("github.com/foo/vuln")
	// Test-only usage should yield Reachable=false from production entry points
	if result.Reachable {
		t.Errorf("expected Reachable=false for test-only import; callPath=%v", result.CallPath)
	}
}

func TestGoAnalyzer_AliasedImport(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/test\n\ngo 1.21\n")
	writeFile(t, dir, "server.go", `package main

import (
	vulnerable "github.com/bad/pkg"
)

func main() {
	vulnerable.Attack()
}
`)
	a, _ := New(dir)
	result := a.Check("github.com/bad/pkg")
	if !result.Reachable {
		t.Error("expected Reachable=true for aliased import")
	}
}

// ── Python reachability tests ─────────────────────────────────────────────────

func TestPythonAnalyzer_Reachable(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "requests==2.28.0\n")
	writeFile(t, dir, "app.py", `import requests

def main():
    resp = requests.get("http://example.com")
    print(resp.text)

if __name__ == "__main__":
    main()
`)
	a, _ := New(dir)
	result := a.Check("requests")
	if !result.Reachable {
		t.Errorf("expected Reachable=true; imports=%v callSites=%v", result.Imports, result.CallSites)
	}
}

func TestPythonAnalyzer_AliasImport(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "numpy==1.24.0\n")
	writeFile(t, dir, "compute.py", `import numpy as np

def run():
    arr = np.array([1, 2, 3])
    return arr.sum()
`)
	a, _ := New(dir)
	result := a.Check("numpy")
	if !result.Reachable {
		t.Errorf("expected Reachable=true for aliased numpy; imports=%v callSites=%v", result.Imports, result.CallSites)
	}
}

func TestPythonAnalyzer_FromImport(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "flask==2.3.0\n")
	writeFile(t, dir, "web.py", `from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def index():
    return "hello"
`)
	a, _ := New(dir)
	result := a.Check("flask")
	if !result.Reachable {
		t.Errorf("expected Reachable=true for from-flask import; imports=%v callSites=%v", result.Imports, result.CallSites)
	}
}

// ── JavaScript reachability tests ─────────────────────────────────────────────

func TestJSAnalyzer_RequireReachable(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"name":"test","version":"1.0.0"}`)
	writeFile(t, dir, "index.js", `const axios = require('axios');

async function fetchData() {
  const res = await axios.get('https://example.com');
  return res.data;
}

module.exports = { fetchData };
`)
	a, _ := New(dir)
	result := a.Check("axios")
	if !result.Reachable {
		t.Errorf("expected Reachable=true for require('axios'); imports=%v callSites=%v", result.Imports, result.CallSites)
	}
}

func TestJSAnalyzer_ESMImportReachable(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"name":"test","version":"1.0.0","type":"module"}`)
	writeFile(t, dir, "app.mjs", `import express from 'express';

const app = express();

app.get('/', (req, res) => {
  res.send('hello');
});

app.listen(3000);
`)
	a, _ := New(dir)
	result := a.Check("express")
	if !result.Reachable {
		t.Errorf("expected Reachable=true for ESM import express; imports=%v callSites=%v", result.Imports, result.CallSites)
	}
}

func TestJSAnalyzer_NotImported(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"name":"test","version":"1.0.0"}`)
	writeFile(t, dir, "index.js", `const fs = require('fs');
fs.readFileSync('/tmp/test');
`)
	a, _ := New(dir)
	result := a.Check("lodash")
	if result.Reachable {
		t.Error("expected Reachable=false for package not imported")
	}
}

// ── Language detection tests ──────────────────────────────────────────────────

func TestLanguageDetection(t *testing.T) {
	cases := []struct {
		manifest string
		want     Language
	}{
		{"go.mod", LangGo},
		{"package.json", LangJavaScript},
		{"tsconfig.json", LangTypeScript},
		{"requirements.txt", LangPython},
		{"Pipfile", LangPython},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		writeFile(t, dir, tc.manifest, "")
		got := detectLanguage(dir)
		if got != tc.want {
			t.Errorf("detectLanguage with %s: got %s, want %s", tc.manifest, got, tc.want)
		}
	}
}

// ── packageMatches helper tests ───────────────────────────────────────────────

func TestMatchesPackage(t *testing.T) {
	cases := []struct {
		importPath string
		targetPkg  string
		want       bool
	}{
		{"github.com/foo/bar", "github.com/foo/bar", true},
		{"github.com/foo/bar", "bar", true},
		{"github.com/foo/requests", "requests", true},
		{"github.com/foo/bar", "baz", false},
		{"requests", "requests", true},
	}
	for _, tc := range cases {
		got := matchesPackage(tc.importPath, tc.targetPkg)
		if got != tc.want {
			t.Errorf("matchesPackage(%q, %q): got %v, want %v", tc.importPath, tc.targetPkg, got, tc.want)
		}
	}
}
