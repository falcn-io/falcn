package gitutil

import (
	"os/exec"
	"path/filepath"
	"strings"
)

// knownManifests is the set of dependency manifest file names across all ecosystems.
var knownManifests = map[string]bool{
	// npm / Node
	"package.json": true, "package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	// Python
	"requirements.txt": true, "pyproject.toml": true, "Pipfile": true, "Pipfile.lock": true,
	"setup.py": true, "setup.cfg": true,
	// Go
	"go.mod": true, "go.sum": true,
	// Rust
	"Cargo.toml": true, "Cargo.lock": true,
	// Ruby
	"Gemfile": true, "Gemfile.lock": true,
	// PHP
	"composer.json": true, "composer.lock": true,
	// Java
	"pom.xml": true, "build.gradle": true, "build.gradle.kts": true,
	// .NET
	"packages.lock.json": true,
}

// IsManifestFile reports whether the file name (basename only) is a known
// dependency manifest that Falcn can scan.
func IsManifestFile(name string) bool {
	return knownManifests[filepath.Base(name)]
}

// ChangedManifests returns the relative paths of dependency manifest files that
// differ between HEAD and baseRef in the git repository rooted at repoRoot.
//
// It calls `git diff --name-only <baseRef>` which lists files changed between
// baseRef and the current working tree (including staged changes).
//
// Returns nil, nil if git is unavailable or the directory is not a git repo.
func ChangedManifests(repoRoot, baseRef string) ([]string, error) {
	cmd := exec.Command("git", "diff", "--name-only", baseRef)
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		// Also try --cached to catch staged-only changes
		cmd2 := exec.Command("git", "diff", "--name-only", "--cached", baseRef)
		cmd2.Dir = repoRoot
		out2, err2 := cmd2.Output()
		if err2 != nil {
			return nil, err // return original error
		}
		out = append(out, out2...)
	}

	seen := map[string]bool{}
	var manifests []string
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if IsManifestFile(f) && !seen[f] {
			seen[f] = true
			manifests = append(manifests, f)
		}
	}
	return manifests, nil
}
