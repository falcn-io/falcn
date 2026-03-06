package container

import (
	"strings"
	"testing"
	"time"
)

// ─── ParseImageRef ────────────────────────────────────────────────────────────

func TestParseImageRef_OfficialShortName(t *testing.T) {
	ref, err := ParseImageRef("nginx")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Registry != "index.docker.io" {
		t.Errorf("registry = %q, want index.docker.io", ref.Registry)
	}
	if ref.Name != "library/nginx" {
		t.Errorf("name = %q, want library/nginx", ref.Name)
	}
	if ref.Tag != "latest" {
		t.Errorf("tag = %q, want latest", ref.Tag)
	}
}

func TestParseImageRef_OfficialWithTag(t *testing.T) {
	ref, err := ParseImageRef("nginx:1.27.2")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Name != "library/nginx" {
		t.Errorf("name = %q, want library/nginx", ref.Name)
	}
	if ref.Tag != "1.27.2" {
		t.Errorf("tag = %q, want 1.27.2", ref.Tag)
	}
}

func TestParseImageRef_UserOrg(t *testing.T) {
	ref, err := ParseImageRef("myorg/myapp:v2")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Registry != "index.docker.io" {
		t.Errorf("registry = %q, want index.docker.io", ref.Registry)
	}
	if ref.Name != "myorg/myapp" {
		t.Errorf("name = %q, want myorg/myapp", ref.Name)
	}
	if ref.Tag != "v2" {
		t.Errorf("tag = %q, want v2", ref.Tag)
	}
}

func TestParseImageRef_GHCR(t *testing.T) {
	ref, err := ParseImageRef("ghcr.io/owner/repo:sha-abc123")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Registry != "ghcr.io" {
		t.Errorf("registry = %q, want ghcr.io", ref.Registry)
	}
	if ref.Name != "owner/repo" {
		t.Errorf("name = %q, want owner/repo", ref.Name)
	}
	if ref.Tag != "sha-abc123" {
		t.Errorf("tag = %q, want sha-abc123", ref.Tag)
	}
}

func TestParseImageRef_Digest(t *testing.T) {
	ref, err := ParseImageRef("nginx@sha256:deadbeef1234")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Name != "library/nginx" {
		t.Errorf("name = %q, want library/nginx", ref.Name)
	}
	if ref.Digest != "sha256:deadbeef1234" {
		t.Errorf("digest = %q, want sha256:deadbeef1234", ref.Digest)
	}
	if ref.Tag != "" {
		t.Errorf("tag should be empty, got %q", ref.Tag)
	}
}

func TestParseImageRef_DockerHubNormalized(t *testing.T) {
	ref, err := ParseImageRef("docker.io/library/ubuntu:22.04")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Registry != "index.docker.io" {
		t.Errorf("registry = %q, want index.docker.io", ref.Registry)
	}
}

func TestParseImageRef_EmptyName_Error(t *testing.T) {
	_, err := ParseImageRef("")
	if err == nil {
		t.Error("expected error for empty ref, got nil")
	}
}

// ─── parseWWWAuthenticate ─────────────────────────────────────────────────────

func TestParseWWWAuthenticate(t *testing.T) {
	header := `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"`
	params := parseWWWAuthenticate(header)
	if params["realm"] != "https://auth.docker.io/token" {
		t.Errorf("realm = %q", params["realm"])
	}
	if params["service"] != "registry.docker.io" {
		t.Errorf("service = %q", params["service"])
	}
	if params["scope"] != "repository:library/nginx:pull" {
		t.Errorf("scope = %q", params["scope"])
	}
}

// ─── parseDpkgStatus ─────────────────────────────────────────────────────────

func TestParseDpkgStatus_Basic(t *testing.T) {
	input := `Package: bash
Status: install ok installed
Version: 5.2.15-2+b7
Architecture: amd64
Installed-Size: 1536
Description: GNU Bourne Again SHell

Package: libc6
Status: install ok installed
Version: 2.36-9+deb12u9
Architecture: amd64
Description: GNU C Library: Shared libraries

`
	pkgs := parseDpkgStatus(strings.NewReader(input), "sha256:abc")
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	if pkgs[0].Name != "bash" {
		t.Errorf("pkgs[0].Name = %q", pkgs[0].Name)
	}
	if pkgs[0].Version != "5.2.15-2+b7" {
		t.Errorf("pkgs[0].Version = %q", pkgs[0].Version)
	}
	if pkgs[0].Arch != "amd64" {
		t.Errorf("pkgs[0].Arch = %q", pkgs[0].Arch)
	}
	if pkgs[0].InstalledSize != 1536*1024 {
		t.Errorf("pkgs[0].InstalledSize = %d", pkgs[0].InstalledSize)
	}
	if pkgs[0].Ecosystem != EcosystemDpkg {
		t.Errorf("pkgs[0].Ecosystem = %q", pkgs[0].Ecosystem)
	}
}

func TestParseDpkgStatus_SkipsNonInstalled(t *testing.T) {
	input := `Package: vim
Status: deinstall ok config-files
Version: 9.0

`
	pkgs := parseDpkgStatus(strings.NewReader(input), "")
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages, got %d", len(pkgs))
	}
}

// ─── parseApkInstalled ────────────────────────────────────────────────────────

func TestParseApkInstalled_Basic(t *testing.T) {
	input := `C:Q1...
P:musl
V:1.2.4-r2
A:x86_64
S:397502
T:the musl c library (libc) implementation

C:Q2...
P:busybox
V:1.36.1-r29
A:x86_64
S:544782
T:Size optimized toolbox of many common UNIX utilities

`
	pkgs := parseApkInstalled(strings.NewReader(input), "sha256:alpine")
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	if pkgs[0].Name != "musl" {
		t.Errorf("pkgs[0].Name = %q", pkgs[0].Name)
	}
	if pkgs[0].Version != "1.2.4-r2" {
		t.Errorf("pkgs[0].Version = %q", pkgs[0].Version)
	}
	if pkgs[0].Arch != "x86_64" {
		t.Errorf("pkgs[0].Arch = %q", pkgs[0].Arch)
	}
	if pkgs[0].Ecosystem != EcosystemApk {
		t.Errorf("pkgs[0].Ecosystem = %q", pkgs[0].Ecosystem)
	}
}

// ─── parsePythonMetadata ──────────────────────────────────────────────────────

func TestMatchPythonMetadata(t *testing.T) {
	cases := []struct {
		path  string
		match bool
	}{
		{"usr/local/lib/python3.12/dist-packages/requests-2.32.3.dist-info/METADATA", true},
		{"usr/local/lib/python3.12/dist-packages/setuptools-70.0.0.dist-info/METADATA", true},
		{"usr/local/lib/python2.7/dist-packages/pip.egg-info/PKG-INFO", true},
		{"etc/os-release", false},
		{"usr/local/lib/node_modules/express/package.json", false},
	}
	for _, tc := range cases {
		got := matchPythonMetadata(tc.path)
		if got != tc.match {
			t.Errorf("matchPythonMetadata(%q) = %v, want %v", tc.path, got, tc.match)
		}
	}
}

func TestParsePythonMetadata_Basic(t *testing.T) {
	input := `Metadata-Version: 2.1
Name: requests
Version: 2.32.3
Summary: Python HTTP for Humans.
Author-email: Kenneth Reitz <me@kennethreitz.org>

Long description here...
`
	pkg := parsePythonMetadata(strings.NewReader(input), "sha256:py")
	if pkg == nil {
		t.Fatal("got nil")
	}
	if pkg.Name != "requests" {
		t.Errorf("Name = %q", pkg.Name)
	}
	if pkg.Version != "2.32.3" {
		t.Errorf("Version = %q", pkg.Version)
	}
	if pkg.Ecosystem != EcosystemPip {
		t.Errorf("Ecosystem = %q", pkg.Ecosystem)
	}
}

// ─── matchNpmPackageJSON ──────────────────────────────────────────────────────

func TestMatchNpmPackageJSON(t *testing.T) {
	cases := []struct {
		path  string
		match bool
	}{
		{"usr/local/lib/node_modules/express/package.json", true},
		{"usr/lib/node_modules/npm/package.json", true},
		// nested dependency — should NOT match
		{"usr/local/lib/node_modules/express/node_modules/qs/package.json", false},
		// not a package.json
		{"usr/local/lib/node_modules/express/index.js", false},
		{"etc/package.json", false},
	}
	for _, tc := range cases {
		got := matchNpmPackageJSON(tc.path)
		if got != tc.match {
			t.Errorf("matchNpmPackageJSON(%q) = %v, want %v", tc.path, got, tc.match)
		}
	}
}

func TestParseNpmPackageJSON_Basic(t *testing.T) {
	input := `{
  "name": "express",
  "version": "4.19.2",
  "description": "Fast, unopinionated, minimalist web framework"
}`
	pkg := parseNpmPackageJSON(strings.NewReader(input), "sha256:node")
	if pkg == nil {
		t.Fatal("got nil")
	}
	if pkg.Name != "express" {
		t.Errorf("Name = %q", pkg.Name)
	}
	if pkg.Version != "4.19.2" {
		t.Errorf("Version = %q", pkg.Version)
	}
	if pkg.Ecosystem != EcosystemNpm {
		t.Errorf("Ecosystem = %q", pkg.Ecosystem)
	}
}

// ─── Dockerfile scanner ───────────────────────────────────────────────────────

func TestScanDockerfileReader_RunsAsRoot(t *testing.T) {
	df := `FROM ubuntu:22.04
RUN apt-get update
CMD ["/bin/bash"]
`
	findings, err := ScanDockerfileReader(strings.NewReader(df))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.ID == "IMG001" {
			found = true
		}
	}
	if !found {
		t.Error("expected IMG001 (runs as root) finding")
	}
}

func TestScanDockerfileReader_NonRootUser_NoIMG001(t *testing.T) {
	df := `FROM node:20-alpine
USER 1000:1000
CMD ["node", "server.js"]
`
	findings, err := ScanDockerfileReader(strings.NewReader(df))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.ID == "IMG001" {
			t.Error("unexpected IMG001 (runs as root) finding — non-root USER was set")
		}
	}
}

func TestScanDockerfileReader_FetchAndPipe(t *testing.T) {
	df := `FROM debian:12
RUN curl -sSL https://example.com/install.sh | bash
`
	findings, err := ScanDockerfileReader(strings.NewReader(df))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.ID == "IMG003" {
			found = true
		}
	}
	if !found {
		t.Error("expected IMG003 (fetch-and-pipe) finding")
	}
}

func TestScanDockerfileReader_SecretInEnv(t *testing.T) {
	df := `FROM python:3.12
ENV API_KEY=supersecretvalue123
CMD ["python", "app.py"]
`
	findings, err := ScanDockerfileReader(strings.NewReader(df))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.ID == "IMG002" {
			found = true
		}
	}
	if !found {
		t.Error("expected IMG002 (secret in ENV) finding")
	}
}

func TestScanDockerfileReader_LatestTag(t *testing.T) {
	df := `FROM node:latest
USER node
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
CMD ["node", "server.js"]
`
	findings, err := ScanDockerfileReader(strings.NewReader(df))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.ID == "IMG004" {
			found = true
		}
	}
	if !found {
		t.Error("expected IMG004 (latest tag) finding")
	}
}

func TestScanDockerfileReader_CleanDockerfile_MinimalFindings(t *testing.T) {
	df := `FROM node:20.14-alpine3.20
USER 1000:1000
HEALTHCHECK CMD curl -f http://localhost:3000/ || exit 1
EXPOSE 3000
CMD ["node", "server.js"]
`
	findings, err := ScanDockerfileReader(strings.NewReader(df))
	if err != nil {
		t.Fatal(err)
	}
	// A clean Dockerfile may still trigger IMG007 (healthcheck is present, so not that)
	// but should NOT trigger IMG001, IMG002, IMG003.
	for _, f := range findings {
		switch f.ID {
		case "IMG001", "IMG002", "IMG003":
			t.Errorf("unexpected finding %s in clean Dockerfile", f.ID)
		}
	}
}

func TestScanDockerfileReader_ContinuationLines(t *testing.T) {
	df := `FROM debian:12
RUN curl -sSL \
    https://example.com/install.sh | \
    bash
`
	findings, err := ScanDockerfileReader(strings.NewReader(df))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.ID == "IMG003" {
			found = true
		}
	}
	if !found {
		t.Error("expected IMG003 (fetch-and-pipe) in multi-line RUN")
	}
}

// ─── Risk scoring ─────────────────────────────────────────────────────────────

func TestComputeRisk_NoFindings(t *testing.T) {
	r := &ImageScanResult{}
	score, level := computeRisk(r)
	if score != 0.0 {
		t.Errorf("score = %v, want 0", score)
	}
	if level != "minimal" {
		t.Errorf("level = %q, want minimal", level)
	}
}

func TestComputeRisk_CriticalFinding(t *testing.T) {
	r := &ImageScanResult{
		SecurityFindings: []SecurityFinding{{ID: "IMG003", Severity: "critical"}},
	}
	score, level := computeRisk(r)
	if score < 0.25 {
		t.Errorf("score = %v, expected >= 0.25 for critical finding", score)
	}
	_ = level
}

func TestComputeRisk_CapsAt1(t *testing.T) {
	r := &ImageScanResult{
		SecurityFindings: []SecurityFinding{
			{Severity: "critical"}, {Severity: "critical"}, {Severity: "critical"},
			{Severity: "critical"}, {Severity: "critical"},
		},
		Vulnerabilities: []PackageVuln{
			{Severity: "critical"}, {Severity: "critical"},
		},
	}
	score, _ := computeRisk(r)
	if score > 1.0 {
		t.Errorf("score %v exceeds 1.0", score)
	}
}

// ─── analyzeConfig ────────────────────────────────────────────────────────────

func TestAnalyzeConfig_RootUser(t *testing.T) {
	sc := New()
	cfg := &ImageConfig{Config: ContainerConfig{User: ""}}
	manifest := &ImageManifest{}
	findings := sc.analyzeConfig(cfg, manifest)
	found := false
	for _, f := range findings {
		if f.ID == "IMG001" {
			found = true
		}
	}
	if !found {
		t.Error("expected IMG001 for empty user")
	}
}

func TestAnalyzeConfig_SecretInEnv(t *testing.T) {
	sc := New()
	cfg := &ImageConfig{
		Config: ContainerConfig{
			User: "1000",
			Env:  []string{"PATH=/usr/bin", "API_KEY=supersecret", "HOME=/home/app"},
		},
	}
	findings := sc.analyzeConfig(cfg, &ImageManifest{})
	found := false
	for _, f := range findings {
		if f.ID == "IMG002" {
			found = true
		}
	}
	if !found {
		t.Error("expected IMG002 for secret-like ENV var")
	}
}

func TestAnalyzeConfig_OversizedImage(t *testing.T) {
	sc := New()
	cfg := &ImageConfig{Config: ContainerConfig{User: "1000"}}
	manifest := &ImageManifest{
		Layers: []ManifestDescr{
			{Size: 600 * 1024 * 1024},
			{Size: 600 * 1024 * 1024},
		},
	}
	findings := sc.analyzeConfig(cfg, manifest)
	found := false
	for _, f := range findings {
		if f.ID == "IMG009" {
			found = true
		}
	}
	if !found {
		t.Error("expected IMG009 (oversized image)")
	}
}

// ─── Helper functions ─────────────────────────────────────────────────────────

func TestPickHigher(t *testing.T) {
	tests := []struct{ a, b, want string }{
		{"low", "critical", "critical"},
		{"critical", "low", "critical"},
		{"medium", "high", "high"},
		{"", "medium", "medium"},
	}
	for _, tc := range tests {
		got := pickHigher(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("pickHigher(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCvssScore(t *testing.T) {
	tests := []struct {
		vector string
		want   string
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "high"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "low"},
	}
	for _, tc := range tests {
		got := cvssScore(tc.vector)
		if got != tc.want {
			t.Errorf("cvssScore(%q) = %q, want %q", tc.vector, got, tc.want)
		}
	}
}

func TestMaskSecret(t *testing.T) {
	got := maskSecret("API_KEY=supersecret123")
	if got != "API_KEY=***" {
		t.Errorf("maskSecret = %q", got)
	}
}

func TestExtractBaseImage(t *testing.T) {
	now := time.Now()
	cfg := &ImageConfig{
		History: []HistoryEntry{
			{CreatedBy: "/bin/sh -c FROM ubuntu:22.04", Created: &now},
			{CreatedBy: "/bin/sh -c #(nop) RUN apt-get update"},
		},
	}
	base := extractBaseImage(cfg)
	if !strings.Contains(base, "ubuntu") {
		t.Errorf("extractBaseImage = %q, expected to contain 'ubuntu'", base)
	}
}

func TestTruncate(t *testing.T) {
	short := truncate("hello", 10)
	if short != "hello" {
		t.Errorf("truncate = %q", short)
	}
	long := truncate("hello world", 5)
	if !strings.HasPrefix(long, "hello") {
		t.Errorf("truncate = %q", long)
	}
}

func TestLayerHistoryCommands_FiltersEmpty(t *testing.T) {
	cfg := &ImageConfig{
		History: []HistoryEntry{
			{CreatedBy: "FROM ubuntu:22.04", EmptyLayer: false},
			{CreatedBy: "#(nop) ENV foo=bar", EmptyLayer: true},
			{CreatedBy: "/bin/sh -c apt-get update", EmptyLayer: false},
		},
	}
	cmds := layerHistoryCommands(cfg)
	// Only non-empty layers should appear.
	if len(cmds) != 2 {
		t.Errorf("layerHistoryCommands len = %d, want 2", len(cmds))
	}
}
