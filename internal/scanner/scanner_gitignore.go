package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

// shouldSkipPath checks if a path should be skipped during scanning
func (s *Scanner) shouldSkipPath(path string) bool {
	// If RespectGitignore is not enabled, don't skip anything
	if s.config.Scanner == nil || !s.config.Scanner.RespectGitignore {
		return false
	}

	basename := filepath.Base(path)

	// Check scanner-configured skip patterns first
	if s.config.Scanner.SkipPatterns != nil {
		for _, pattern := range s.config.Scanner.SkipPatterns {
			// Basic prefix matching for performance
			if strings.HasPrefix(basename, pattern) {
				return true
			}
			// Also check exact match
			if matches, _ := filepath.Match(pattern, basename); matches {
				return true
			}
		}
	}

	// Check .falcnignore patterns
	if s.ignorePatterns != nil {
		for _, pattern := range s.ignorePatterns {
			// Handle directory matches (pattern ends with /)
			if strings.HasSuffix(pattern, "/") {
				// Match directory name or path prefix
				dirPattern := strings.TrimSuffix(pattern, "/")
				if basename == dirPattern || strings.HasPrefix(path, dirPattern) || strings.Contains(path, string(os.PathSeparator)+dirPattern) {
					return true
				}
			} else {
				// Simple shell pattern matching for files
				if matched, _ := filepath.Match(pattern, basename); matched {
					return true
				}
				// Check relative path match
				// Note: complex gitignore logic is hard, simplified here
				if strings.Contains(path, pattern) {
					return true
				}
			}
		}
	}

	// Common patterns to always skip (even if SkipPatterns is not configured)
	commonSkipPatterns := []string{
		"node_modules", ".git", "vendor", ".venv", "__pycache__",
		".tox", ".pytest_cache", // Python test/build
		"target",        // Java/Rust build
		"dist", "build", // Common build directories
		".terraform", ".gradle", // Infrastructure/build tools
		".svn", ".hg", ".bzr", // Other VCS
	}

	for _, pattern := range commonSkipPatterns {
		if basename == pattern || strings.HasPrefix(basename, pattern) {
			return true
		}
	}

	// Windows-specific: skip real-actions-, docker-test-, custom_test_workspace
	windowsSkipPrefixes := []string{
		"real-actions-",
		"docker-test-",
		"docker-realworld-",
		"docker-e2e-",
		"custom_test_workspace",
	}

	for _, prefix := range windowsSkipPrefixes {
		if strings.HasPrefix(basename, prefix) {
			return true
		}
	}

	return false
}

// loadIgnorePatterns loads ignore patterns from .falcnignore
func (s *Scanner) loadIgnorePatterns(projectRoot string) {
	ignoreFile := filepath.Join(projectRoot, ".falcnignore")

	// Create or append to ignore list
	s.ignorePatterns = make([]string, 0)

	file, err := os.Open(ignoreFile)
	if err != nil {
		if !os.IsNotExist(err) {
			logrus.Debugf("Failed to open .falcnignore: %v", err)
		}
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s.ignorePatterns = append(s.ignorePatterns, line)
	}

	if len(s.ignorePatterns) > 0 {
		logrus.Debugf("Loaded %d patterns from .falcnignore", len(s.ignorePatterns))
	}
}
