package container

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"io"
	"path/filepath"
	"strconv"
	"strings"
)

// analyzeLayer reads a gzip-compressed tar stream and extracts installed-package
// information from well-known package manager database paths.
//
// Supported package managers:
//   - dpkg  (Debian/Ubuntu): /var/lib/dpkg/status
//   - apk   (Alpine Linux):  /lib/apk/db/installed
//   - rpm   (RHEL/Fedora):   skipped (binary format — only file listing used)
//   - pip   (Python):        /usr/lib/python*/dist-packages/*/METADATA or .dist-info/METADATA
//   - npm   (Node.js):       /usr/lib/node_modules/*/package.json
func analyzeLayer(rc io.Reader, digest string) LayerAnalysis {
	la := LayerAnalysis{Digest: digest}

	gr, err := gzip.NewReader(rc)
	if err != nil {
		la.Error = "gzip: " + err.Error()
		return la
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			la.Error = "tar: " + err.Error()
			break
		}

		name := filepath.ToSlash(hdr.Name)
		// Strip leading "./" if present.
		name = strings.TrimPrefix(name, "./")

		switch {
		case name == "var/lib/dpkg/status":
			pkgs := parseDpkgStatus(tr, digest)
			la.Packages = append(la.Packages, pkgs...)

		case name == "lib/apk/db/installed":
			pkgs := parseApkInstalled(tr, digest)
			la.Packages = append(la.Packages, pkgs...)

		case matchPythonMetadata(name):
			pkg := parsePythonMetadata(tr, digest)
			if pkg != nil {
				la.Packages = append(la.Packages, *pkg)
			}

		case matchNpmPackageJSON(name):
			pkg := parseNpmPackageJSON(tr, digest)
			if pkg != nil {
				la.Packages = append(la.Packages, *pkg)
			}
		}
	}
	return la
}

// ─── dpkg ─────────────────────────────────────────────────────────────────────

// parseDpkgStatus parses the Debian dpkg status file.
// Format: RFC 822-like stanzas separated by blank lines.
func parseDpkgStatus(r io.Reader, digest string) []InstalledPackage {
	var (
		out     []InstalledPackage
		current InstalledPackage
	)
	current.Ecosystem = EcosystemDpkg
	current.LayerDigest = digest

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			// End of stanza — emit if we have a name.
			if current.Name != "" {
				out = append(out, current)
			}
			current = InstalledPackage{Ecosystem: EcosystemDpkg, LayerDigest: digest}
			continue
		}

		// Skip continuation lines.
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			continue
		}

		key, val, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		switch strings.ToLower(key) {
		case "package":
			current.Name = val
		case "version":
			current.Version = val
		case "architecture":
			current.Arch = val
		case "source":
			current.Source = val
		case "installed-size":
			if n, err := strconv.ParseInt(val, 10, 64); err == nil {
				current.InstalledSize = n * 1024 // dpkg stores KB
			}
		case "description":
			current.Description = val
		case "status":
			// Only include installed packages.
			if !strings.HasPrefix(val, "install ok") {
				current.Name = "" // mark for discard
			}
		}
	}
	// Flush last stanza.
	if current.Name != "" {
		out = append(out, current)
	}
	return out
}

// ─── apk ──────────────────────────────────────────────────────────────────────

// parseApkInstalled parses the Alpine Linux apk installed database.
// Format: fields separated by newlines; records separated by blank lines.
// Key fields: P (package), V (version), A (arch), S (installed size), T (description).
func parseApkInstalled(r io.Reader, digest string) []InstalledPackage {
	var (
		out     []InstalledPackage
		current InstalledPackage
	)
	current.Ecosystem = EcosystemApk
	current.LayerDigest = digest

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			if current.Name != "" {
				out = append(out, current)
			}
			current = InstalledPackage{Ecosystem: EcosystemApk, LayerDigest: digest}
			continue
		}

		if len(line) < 2 || line[1] != ':' {
			continue
		}
		key := string(line[0])
		val := strings.TrimSpace(line[2:])

		switch key {
		case "P":
			current.Name = val
		case "V":
			current.Version = val
		case "A":
			current.Arch = val
		case "S":
			if n, err := strconv.ParseInt(val, 10, 64); err == nil {
				current.InstalledSize = n
			}
		case "T":
			current.Description = val
		}
	}
	if current.Name != "" {
		out = append(out, current)
	}
	return out
}

// ─── Python (pip / dist-packages) ─────────────────────────────────────────────

// matchPythonMetadata returns true when the tar entry looks like a
// Python package METADATA or PKG-INFO file.
func matchPythonMetadata(name string) bool {
	base := filepath.Base(name)
	if base != "METADATA" && base != "PKG-INFO" {
		return false
	}
	// Must be inside a .dist-info or .egg-info directory.
	return strings.Contains(name, ".dist-info/") || strings.Contains(name, ".egg-info/")
}

// parsePythonMetadata parses a PEP 566 METADATA file.
func parsePythonMetadata(r io.Reader, digest string) *InstalledPackage {
	pkg := &InstalledPackage{Ecosystem: EcosystemPip, LayerDigest: digest}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // headers end at first blank line
		}
		key, val, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			pkg.Name = strings.TrimSpace(val)
		case "version":
			pkg.Version = strings.TrimSpace(val)
		case "summary":
			pkg.Description = strings.TrimSpace(val)
		}
	}
	if pkg.Name == "" {
		return nil
	}
	return pkg
}

// ─── Node.js (npm / node_modules) ─────────────────────────────────────────────

// matchNpmPackageJSON returns true when the tar entry is a top-level
// node_modules package.json (not a nested dependency's package.json).
func matchNpmPackageJSON(name string) bool {
	if filepath.Base(name) != "package.json" {
		return false
	}
	// Accept paths like:
	//   usr/local/lib/node_modules/express/package.json
	//   usr/lib/node_modules/npm/package.json
	// Reject nested:
	//   usr/local/lib/node_modules/express/node_modules/qs/package.json
	if !strings.Contains(name, "node_modules/") {
		return false
	}
	// Count occurrences of "node_modules/" — nested deps have more than one.
	if strings.Count(name, "node_modules/") > 1 {
		return false
	}
	return true
}

// parseNpmPackageJSON parses relevant fields from a package.json.
func parseNpmPackageJSON(r io.Reader, digest string) *InstalledPackage {
	data, err := io.ReadAll(io.LimitReader(r, 64*1024))
	if err != nil || len(data) == 0 {
		return nil
	}

	// Minimal hand-rolled parse to avoid importing encoding/json overhead
	// for potentially thousands of small files.
	pkg := &InstalledPackage{Ecosystem: EcosystemNpm, LayerDigest: digest}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, `"name"`) {
			pkg.Name = extractJSONStringValue(line)
		} else if strings.HasPrefix(line, `"version"`) {
			pkg.Version = extractJSONStringValue(line)
		} else if strings.HasPrefix(line, `"description"`) {
			pkg.Description = extractJSONStringValue(line)
		}
	}
	if pkg.Name == "" {
		return nil
	}
	return pkg
}

// extractJSONStringValue extracts the string value from a JSON key-value line
// like `"name": "express",`.
func extractJSONStringValue(line string) string {
	colon := strings.Index(line, ":")
	if colon == -1 {
		return ""
	}
	val := strings.TrimSpace(line[colon+1:])
	val = strings.Trim(val, `",`)
	return val
}
