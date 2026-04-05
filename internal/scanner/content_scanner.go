package scanner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/falcn-io/falcn/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// ─────────────────────────────────────────────────────────────────────────────
// Pre-compiled regexes (compiled once at package init, not per-file scan)
// ─────────────────────────────────────────────────────────────────────────────

// Pattern detection regexes
var (
	reBase64         = regexp.MustCompile(`[A-Za-z0-9+/]{50,}={0,2}`)
	reHexEncoding    = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	reUnicodeEscape  = regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)
	reSingleCharVar  = regexp.MustCompile(`\b[a-z]\s*=\s*`)
	reSetTimeout     = regexp.MustCompile(`setTimeout\s*\(\s*[^,]+,\s*(\d+)\s*\)`)
	reSetInterval    = regexp.MustCompile(`setInterval\s*\(\s*[^,]+,\s*(\d+)\s*\)`)
	reDateCheck      = regexp.MustCompile(`(new\s+Date\(\)|Date\.now\(\))\s*[><=]+`)
)

// Secret detection regexes
var (
	reGenericAPIKey   = regexp.MustCompile(`(?i)(api[_-]?key|apikey)["\s:=]+[a-zA-Z0-9]{20,}`)
	reAWSKey          = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reGitHubToken     = regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)
	reGenericSecret   = regexp.MustCompile(`(?i)(secret|password|passwd|pwd)["\s:=]+[^\s"']{8,}`)
	rePrivateKeyHdr   = regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`)
	reJWTToken        = regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`)
)

// Network indicator regexes
var (
	reIPAddress     = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	reURL           = regexp.MustCompile(`https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	reDomainExtract = regexp.MustCompile(`https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)
)

// Credential harvesting regex
var reCredentialPaths = regexp.MustCompile(`(?i)(\.ssh|\.aws|\.kube|\.config/gcloud|\.config/sysmon|\.npmrc|\.pypirc|\.docker/config|\.gnupg|\.netrc|\.gitconfig|\.git-credentials|\.config/gh|id_rsa|id_ed25519|credentials\.json|service_account\.json)`)

// OS persistence regexes
var (
	reSystemdCreate  = regexp.MustCompile(`(?i)(systemctl\s+(enable|start|daemon-reload)|\.config/systemd/user|ExecStart\s*=)`)
	reSystemdUnit    = regexp.MustCompile(`(?s)\[Unit\].*\[Service\].*ExecStart`)
	reCronInstall    = regexp.MustCompile(`(?i)(crontab\s+-[elr]|/etc/cron\.\w+/|sched\.scheduler\(\))`)
	reLaunchdMac     = regexp.MustCompile(`(?i)(launchctl\s+(load|submit)|LaunchAgents|LaunchDaemons|ProgramArguments)`)
	reWindowsRunKey  = regexp.MustCompile(`(?i)(CurrentVersion\\\\Run|HKCU\\\\Software\\\\Microsoft|reg\s+add\s+.*\\\\Run|schtasks\s+/create)`)
	reWindowsStartup = regexp.MustCompile(`(?i)(Startup\\\\|shell:startup|APPDATA.*\\\\Microsoft\\\\Windows\\\\Start Menu)`)
)

// Anti-forensics regexes
var (
	reJSSelfDelete     = regexp.MustCompile(`fs\.(unlink|unlinkSync|rmSync)\s*\(\s*__filename`)
	reJSFileRemoval    = regexp.MustCompile(`fs\.(unlink|unlinkSync|rmSync)\s*\(\s*(__dirname|__filename|process\.argv\[1\])`)
	rePySelfDelete     = regexp.MustCompile(`os\.(remove|unlink)\s*\(\s*__file__`)
	rePyPathlibDelete  = regexp.MustCompile(`Path\s*\(\s*__file__\s*\)\s*\.unlink`)
	reShellSelfDelete  = regexp.MustCompile(`rm\s+(-f\s+)?"?\$0"?|shred\s+-u\s+"?\$0"?`)
	rePkgJsonCleanup   = regexp.MustCompile(`(?i)(writeFileSync|writeFile)\s*\(.*package\.json`)
	reHistoryWipe      = regexp.MustCompile(`(?i)(history\s+-c|>.*\.bash_history|rm\s+.*\.log|unset\s+HISTFILE)`)
)

// Custom cipher regexes
var (
	reJSCharCodeXOR   = regexp.MustCompile(`charCodeAt\s*\([^)]*\)\s*\^`)
	reJSFromCharXOR   = regexp.MustCompile(`String\.fromCharCode\s*\([^)]*\^`)
	rePyByteXOR       = regexp.MustCompile(`(?:ord|chr)\s*\([^)]*\)\s*\^`)
	rePyBytearrayXOR  = regexp.MustCompile(`(?:bytes|bytearray)\s*\(\s*\[?[^]]*\^`)
	reNamedDeobfFunc  = regexp.MustCompile(`(?i)(?:function|def|const|var|let)\s+_?(?:trans|decode|decrypt|deobfuscate|unpack)_?\d*\s*[=(]`)
	reBufferXOR       = regexp.MustCompile(`(?:Buffer\.from|new\s+Uint8Array)\s*\([^)]*\).*\^`)
	reStringRevDecode = regexp.MustCompile(`(?:reverse|split\s*\(\s*['"]{2}\s*\)\s*\.reverse|\[::\-1\]).*(?:base64|atob|b64decode)`)
)

// ContentScanner scans package contents for malicious patterns
type ContentScanner struct {
	maxFileSize       int64
	entropyThreshold  float64
	windowSize        int
	includeGlobs      []string
	excludeGlobs      []string
	whitelistExt      []string
	maxFiles          int
	maxWorkers        int
	allowCIDRs        []string
	denyCIDRs         []string
	asnSources        []string
	asnMergeMode      string
	suspiciousIPs     []string
	suspiciousDomains []string
}

// NewContentScanner creates a new content scanner
func NewContentScanner() *ContentScanner {
	// Configurable thresholds
	maxSize := viper.GetInt64("scanner.content.max_file_size")
	if maxSize <= 0 {
		maxSize = 1 * 1024 * 1024
	}
	entropy := viper.GetFloat64("scanner.content.entropy_threshold")
	if entropy <= 0 {
		entropy = 7.0
	}
	win := viper.GetInt("scanner.content.entropy_window")
	if win <= 0 {
		win = 256
	}
	inc := viper.GetStringSlice("scanner.content.include_globs")
	exc := viper.GetStringSlice("scanner.content.exclude_globs")
	wl := viper.GetStringSlice("scanner.content.whitelist_extensions")
	mf := viper.GetInt("scanner.content.max_files")
	mw := viper.GetInt("scanner.content.max_workers")
	allow := viper.GetStringSlice("scanner.content.allowlist_cidrs")
	deny := viper.GetStringSlice("scanner.content.denylist_cidrs")
	asnSrc := viper.GetStringSlice("scanner.content.asn_sources")
	asnMode := viper.GetString("scanner.content.asn_merge_mode")

	return &ContentScanner{
		maxFileSize:      maxSize,
		entropyThreshold: entropy,
		windowSize:       win,
		includeGlobs:     inc,
		excludeGlobs:     exc,
		whitelistExt:     wl,
		maxFiles:         mf,
		maxWorkers:       mw,
		allowCIDRs:       allow,
		denyCIDRs:        deny,
		asnSources:       asnSrc,
		asnMergeMode:     strings.ToLower(asnMode),
		suspiciousIPs: []string{
			// Known malicious IPs (examples - in production, use threat intel feeds)
			"0.0.0.0",
		},
		suspiciousDomains: []string{
			// Free TLDs often used by attackers
			".tk", ".ml", ".ga", ".cf", ".gq",
			// TLDs commonly used in brand-impersonation supply chain attacks
			".zone", ".cloud", ".xyz", ".top", ".icu", ".buzz",
			".site", ".online", ".fun", ".click", ".link",
			".work", ".rest", ".live", ".sbs", ".cfd",
		},
	}
}

// ScanDirectory scans all files in a directory for malicious content
func (cs *ContentScanner) ScanDirectory(path string) ([]types.Threat, error) {
	var threats []types.Threat
	var scannedFiles int
	var suspiciousFiles []string

	// Merge ASN sources into CIDR lists
	cs.loadASNFromSources()

	var files []string
	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(path, filePath)

		if len(cs.includeGlobs) > 0 {
			matched := false
			for _, g := range cs.includeGlobs {
				if ok, _ := filepath.Match(g, rel); ok {
					matched = true
					break
				}
			}
			if !matched {
				logrus.Debugf("Skipped %s (Not in includeGlobs: %v)", rel, cs.includeGlobs)
				return nil
			}
		}
		for _, g := range cs.excludeGlobs {
			if ok, _ := filepath.Match(g, rel); ok {
				logrus.Debugf("Skipped %s (Excluded by glob: %s)", rel, g)
				return nil
			}
		}
		if cs.maxFiles > 0 && scannedFiles >= cs.maxFiles {
			logrus.Debugf("Skipped %s (Max files limit reached)", rel)
			return nil
		}
		if len(cs.whitelistExt) > 0 {
			ok := false
			ext := strings.ToLower(filepath.Ext(filePath))
			for _, e := range cs.whitelistExt {
				if strings.EqualFold(e, ext) {
					ok = true
					break
				}
			}
			if !ok {
				logrus.Debugf("Skipped %s (Extension %s not in whitelist: %v)", rel, ext, cs.whitelistExt)
				return nil
			}
		}
		if info.Size() > cs.maxFileSize {
			logrus.Debugf("Skipped %s (Size %d > %d)", rel, info.Size(), cs.maxFileSize)
			return nil
		}
		if cs.isBinaryFile(filePath) {
			logrus.Debugf("Skipped %s (Detected as binary)", rel)
			return nil
		}
		logrus.Debugf("ACCEPTED file %s", rel)
		files = append(files, filePath)
		scannedFiles++
		return nil
	})

	if err != nil {
		return threats, err
	}

	workers := cs.maxWorkers
	if workers <= 0 {
		workers = 4
	}
	ch := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range ch {
				ts := cs.scanFile(file)
				if len(ts) > 0 {
					mu.Lock()
					threats = append(threats, ts...)
					relPath, _ := filepath.Rel(path, file)
					suspiciousFiles = append(suspiciousFiles, relPath)
					mu.Unlock()
				}
			}
		}()
	}
	for _, f := range files {
		ch <- f
	}
	close(ch)
	wg.Wait()

	logrus.Debugf("Content scanner: scanned %d files, found %d threats", scannedFiles, len(threats))
	return threats, nil
}

// scanFile scans a single file for malicious content
func (cs *ContentScanner) scanFile(filePath string) []types.Threat {
	// For memory efficiency, stream large files in chunks
	info, _ := os.Stat(filePath)
	if info != nil && info.Size() > int64(256*1024) {
		return cs.scanFileStream(filePath)
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}
	contentStr := string(content)
	var threats []types.Threat

	// Check for high entropy (obfuscated/encrypted content) global and windowed
	if entropy := cs.calculateEntropy(contentStr); entropy > cs.entropyThreshold {
		threats = append(threats, cs.createEntropyThreat(filePath, entropy))
	}
	if spans := cs.detectHighEntropySpans(contentStr, cs.windowSize, cs.entropyThreshold); len(spans) > 0 {
		threats = append(threats, cs.createEntropySpanThreat(filePath, spans[0]))
	}

	// Check for suspicious patterns
	if patterns := cs.detectSuspiciousPatterns(contentStr); len(patterns) > 0 {
		t := cs.createPatternThreat(filePath, patterns)
		// Escalate to CRITICAL when suspicious patterns appear in package.json install hooks
		if filepath.Base(filePath) == "package.json" {
			if hooks := extractInstallHooks(content); len(hooks) > 0 {
				t.Severity = types.SeverityCritical
				t.Description = t.Description + " — found in install hook — executes automatically on npm install"
			}
		}
		threats = append(threats, t)
	}

	// Check for embedded secrets/credentials
	if secrets := cs.detectEmbeddedSecrets(contentStr); len(secrets) > 0 {
		t := cs.createSecretThreat(filePath, secrets)
		// Escalate: secrets in package.json install hooks are always CRITICAL (already are, but reinforce)
		if filepath.Base(filePath) == "package.json" {
			if hooks := extractInstallHooks(content); len(hooks) > 0 {
				t.Severity = types.SeverityCritical
				t.Description = t.Description + " — found in install hook — executes automatically on npm install"
			}
		}
		threats = append(threats, t)
	}

	// Check for network indicators
	if networks := cs.detectNetworkIndicators(contentStr); len(networks) > 0 {
		threats = append(threats, cs.createNetworkThreat(filePath, networks))
	}

	// Phase 4: Advanced supply chain attack detection (2026 real-world attacks)
	if t := cs.detectCredentialHarvesting(contentStr); len(t) > 0 {
		threats = append(threats, t...)
	}
	if t := cs.detectOSPersistence(contentStr); len(t) > 0 {
		threats = append(threats, t...)
	}
	if t := cs.detectAntiForensics(contentStr); len(t) > 0 {
		threats = append(threats, t...)
	}
	if t := cs.detectCompoundBehaviors(contentStr); len(t) > 0 {
		threats = append(threats, t...)
	}
	if t := cs.detectCustomCiphers(contentStr); len(t) > 0 {
		threats = append(threats, t...)
	}
	if t := cs.detectPythonAutoExec(filePath, contentStr); len(t) > 0 {
		threats = append(threats, t...)
	}

	return threats
}

// scanFileStream performs chunk-based scanning to reduce memory usage
func (cs *ContentScanner) scanFileStream(filePath string) []types.Threat {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, 64*1024)
	carry := ""
	var fullContent strings.Builder // accumulate for Phase 4 detectors that need full context
	var threats []types.Threat
	var spansAll []entropySpan
	pattSet := map[string]struct{}{}
	secSet := map[string]struct{}{}
	netSet := map[string]struct{}{}
	previewSet := map[string]struct{}{}
	for {
		n, er := f.Read(buf)
		if n > 0 {
			chunk := string(buf[:n])
			fullContent.WriteString(chunk)
			segment := carry + chunk
			if spans := cs.detectHighEntropySpans(segment, cs.windowSize, cs.entropyThreshold); len(spans) > 0 {
				spansAll = append(spansAll, spans...)
			}
			if pats := cs.detectSuspiciousPatterns(segment); len(pats) > 0 {
				for _, p := range pats {
					pattSet[p] = struct{}{}
				}
			}
			if secs := cs.detectEmbeddedSecrets(segment); len(secs) > 0 {
				for _, s := range secs {
					secSet[s] = struct{}{}
				}
			}
			if nets := cs.detectNetworkIndicators(segment); len(nets) > 0 {
				for _, v := range nets {
					netSet[v] = struct{}{}
				}
			}
			if prev := cs.detectBase64Previews(segment); len(prev) > 0 {
				for _, pv := range prev {
					previewSet[pv] = struct{}{}
				}
			}
			if len(segment) > cs.windowSize {
				carry = segment[len(segment)-cs.windowSize:]
			} else {
				carry = segment
			}
		}
		if er != nil {
			break
		}
	}
	if len(spansAll) > 0 {
		threats = append(threats, cs.createAggregatedEntropyThreat(filePath, spansAll))
	}
	if len(pattSet) > 0 {
		var patterns []string
		for p := range pattSet {
			patterns = append(patterns, p)
		}
		var previews []string
		for pv := range previewSet {
			previews = append(previews, pv)
		}
		if len(previews) > 0 {
			threats = append(threats, cs.createPatternThreatWithPreviews(filePath, patterns, previews))
		} else {
			threats = append(threats, cs.createPatternThreat(filePath, patterns))
		}
	}
	if len(secSet) > 0 {
		var secrets []string
		for s := range secSet {
			secrets = append(secrets, s)
		}
		threats = append(threats, cs.createSecretThreat(filePath, secrets))
	}
	if len(netSet) > 0 {
		var nets []string
		for v := range netSet {
			nets = append(nets, v)
		}
		threats = append(threats, cs.createNetworkThreat(filePath, nets))
	}

	// Phase 4 detectors require full file content (compound behaviors, credential harvesting, etc.)
	contentStr := fullContent.String()
	if t := cs.detectCredentialHarvesting(contentStr); len(t) > 0 {
		threats = append(threats, t...)
	}
	if t := cs.detectOSPersistence(contentStr); len(t) > 0 {
		threats = append(threats, t...)
	}
	if t := cs.detectAntiForensics(contentStr); len(t) > 0 {
		threats = append(threats, t...)
	}
	if t := cs.detectCompoundBehaviors(contentStr); len(t) > 0 {
		threats = append(threats, t...)
	}
	if t := cs.detectCustomCiphers(contentStr); len(t) > 0 {
		threats = append(threats, t...)
	}
	if t := cs.detectPythonAutoExec(filePath, contentStr); len(t) > 0 {
		threats = append(threats, t...)
	}

	return threats
}

// loadASNFromSources merges ASN source CIDRs into allow/deny lists
func (cs *ContentScanner) loadASNFromSources() {
	if len(cs.asnSources) == 0 {
		return
	}
	for _, src := range cs.asnSources {
		// Only support local files for safety; format: "ASNNUM,CIDR" per line
		if _, err := os.Stat(src); err != nil {
			continue
		}
		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, ln := range lines {
			parts := strings.Split(strings.TrimSpace(ln), ",")
			if len(parts) < 2 {
				continue
			}
			cidr := strings.TrimSpace(parts[1])
			// Merge according to mode; default deny
			if cs.asnMergeMode == "allow" {
				cs.allowCIDRs = append(cs.allowCIDRs, cidr)
			} else {
				cs.denyCIDRs = append(cs.denyCIDRs, cidr)
			}
		}
	}
}

// calculateEntropy calculates Shannon entropy of a string
func (cs *ContentScanner) calculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0.0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, char := range data {
		freq[char]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

type entropySpan struct {
	start int
	end   int
	score float64
}

func (cs *ContentScanner) detectHighEntropySpans(data string, window int, threshold float64) []entropySpan {
	var spans []entropySpan
	if window <= 0 || len(data) == 0 {
		return spans
	}
	w := window
	if w > len(data) {
		w = len(data)
	}
	step := w / 2
	if step <= 0 {
		step = w
	}
	for i := 0; i <= len(data)-w; i += step {
		seg := data[i : i+w]
		s := cs.calculateEntropy(seg)
		if s >= threshold {
			spans = append(spans, entropySpan{start: i, end: i + w, score: s})
		}
	}
	return spans
}

// detectSuspiciousPatterns detects obfuscation and suspicious code patterns
func (cs *ContentScanner) detectSuspiciousPatterns(content string) []string {
	var patterns []string

	// Eval chains
	if strings.Contains(content, "eval(") && strings.Count(content, "eval") > 3 {
		patterns = append(patterns, "Multiple eval calls (potential code injection)")
	}

	// Base64 encoded payloads — two tiers:
	// Tier 1: single large blob (>200 chars) that decodes → HIGH (catches LiteLLM-style single payload)
	// Tier 2: many blobs (>5 matches of 50+ chars) → existing behavior
	allBase64 := reBase64.FindAllString(content, -1)
	// Tier 1: single large base64 blob
	for _, match := range allBase64 {
		if len(match) < 200 {
			continue
		}
		if decoded, err := base64.StdEncoding.DecodeString(match); err == nil && len(decoded) > 50 {
			patterns = append(patterns, fmt.Sprintf("Large base64 payload detected (%d chars, decodes to %d bytes)", len(match), len(decoded)))
			// Double-base64 detection (LiteLLM v1.82.8 nested encoding)
			inner64 := reBase64.FindString(string(decoded))
			if len(inner64) > 100 {
				if _, err2 := base64.StdEncoding.DecodeString(inner64); err2 == nil {
					patterns = append(patterns, "CRITICAL: Double-base64 encoding detected (nested payload)")
				}
			}
			break
		}
	}
	// Tier 2: many base64 blobs (existing behavior)
	if len(allBase64) > 5 {
		for _, match := range allBase64[:min(5, len(allBase64))] {
			if decoded, err := base64.StdEncoding.DecodeString(match); err == nil && len(decoded) > 20 {
				patterns = append(patterns, "Large base64 encoded strings detected")
				break
			}
		}
	}

	// Hex encoded strings
	if hexMatches := reHexEncoding.FindAllString(content, -1); len(hexMatches) > 20 {
		patterns = append(patterns, "Extensive hex encoding (potential obfuscation)")
	}

	// Unicode escapes
	if unicodeMatches := reUnicodeEscape.FindAllString(content, -1); len(unicodeMatches) > 20 {
		patterns = append(patterns, "Extensive unicode escaping (potential obfuscation)")
	}

	// Suspicious function chains
	suspiciousFuncs := []string{"fromCharCode", "unescape", "escape", "atob", "btoa"}
	count := 0
	for _, fn := range suspiciousFuncs {
		if strings.Contains(content, fn) {
			count++
		}
	}
	if count >= 3 {
		patterns = append(patterns, "Multiple encoding/decoding functions")
	}

	// Minified variables (single char names in excess)
	if singleCharMatches := reSingleCharVar.FindAllString(content, -1); len(singleCharMatches) > 30 {
		patterns = append(patterns, "Excessive single-character variables (minification or obfuscation)")
	}

	// Phase 1: Dormancy Detection (SUNBURST-style time delays)
	// Detect long setTimeout/setInterval (> 7 days in milliseconds = 604800000)
	for _, match := range reSetTimeout.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			if delay := match[1]; len(delay) > 0 {
				// Simple check: if delay > 7 days (in ms)
				if len(delay) > 8 || (len(delay) == 8 && delay[0] >= '6') {
					patterns = append(patterns, fmt.Sprintf("Suspicious long setTimeout delay (potential dormancy: %s ms, >7 days)", delay))
				}
			}
		}
	}

	for _, match := range reSetInterval.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			if delay := match[1]; len(delay) > 0 {
				if len(delay) > 8 || (len(delay) == 8 && delay[0] >= '6') {
					patterns = append(patterns, fmt.Sprintf("Suspicious long setInterval delay (potential dormancy: %s ms, >7 days)", delay))
				}
			}
		}
	}

	// Detect date-based activation conditionals
	if reDateCheck.MatchString(content) {
		// Count occurrences
		if len(reDateCheck.FindAllString(content, -1)) > 2 {
			patterns = append(patterns, "Multiple date-based conditionals (potential time-delayed activation)")
		}
	}

	// Phase 2: Supply Chain Attack Vectors (XZ-like)
	// 1. Detect Payload Extraction Chains (eval + pipes + text processing)
	// Pattern used in XZ: eval $gl_path_map | tr ...
	if strings.Contains(content, "eval") && (strings.Contains(content, "|") || strings.Contains(content, "$")) {
		// Check for de-obfuscation tools commonly used in build script attacks
		if strings.Contains(content, "tr ") || strings.Contains(content, "sed ") || strings.Contains(content, "head ") || strings.Contains(content, "tail ") || strings.Contains(content, "cut ") {
			patterns = append(patterns, "Suspicious execution chain (eval + text processing)")
		}
	}

	// 2. Detect Suspicious Binary Extraction
	// Checking for indicators of trying to extract or decode binary blobs within text files
	if (strings.Contains(content, "cat") || strings.Contains(content, "dd")) &&
		(strings.Contains(content, ".xz") || strings.Contains(content, ".gz")) &&
		(strings.Contains(content, "decode") || strings.Contains(content, "-d")) {
		patterns = append(patterns, "Potential binary payload extraction")
	}

	return patterns
}

// detectEmbeddedSecrets detects embedded API keys, tokens, and credentials
func (cs *ContentScanner) detectEmbeddedSecrets(content string) []string {
	var secrets []string

	// API Key patterns (using pre-compiled regexes)
	patterns := map[string]*regexp.Regexp{
		"Generic API Key":    reGenericAPIKey,
		"AWS Key":            reAWSKey,
		"GitHub Token":       reGitHubToken,
		"Generic Secret":     reGenericSecret,
		"Private Key Header": rePrivateKeyHdr,
		"JWT Token":          reJWTToken,
	}

	for secretType, pattern := range patterns {
		if pattern.MatchString(content) {
			secrets = append(secrets, secretType)
		}
	}

	return secrets
}

// detectNetworkIndicators detects suspicious IPs and domains
func (cs *ContentScanner) detectNetworkIndicators(content string) []string {
	var indicators []string

	// IP address pattern (pre-compiled)
	ips := reIPAddress.FindAllString(content, -1)

	// Filter out common safe IPs (localhost, private RFC 1918 networks)
	safeIPPrefixes := []string{"127.", "192.168.", "10.", "0.0.0.", "169.254."}
	for _, ip := range ips {
		isSafe := false
		for _, prefix := range safeIPPrefixes {
			if strings.HasPrefix(ip, prefix) {
				isSafe = true
				break
			}
		}
		// Check 172.16.0.0/12 range (172.16.x.x - 172.31.x.x) properly
		if !isSafe && strings.HasPrefix(ip, "172.") {
			parsedIP := net.ParseIP(ip)
			_, rfc1918, _ := net.ParseCIDR("172.16.0.0/12")
			if parsedIP != nil && rfc1918 != nil && rfc1918.Contains(parsedIP) {
				isSafe = true
			}
		}
		if !isSafe {
			if cs.inCIDRs(ip, cs.denyCIDRs) && !cs.inCIDRs(ip, cs.allowCIDRs) {
				indicators = append(indicators, fmt.Sprintf("External IP: %s", ip))
			}
		}
	}

	// Check for suspicious TLDs
	for _, domain := range cs.suspiciousDomains {
		if strings.Contains(content, domain) {
			indicators = append(indicators, fmt.Sprintf("Suspicious TLD: %s", domain))
		}
	}

	// Check for HTTP/HTTPS requests to external domains (pre-compiled)
	urls := reURL.FindAllString(content, -1)
	// Whitelist known-safe domains (registries, CDNs, documentation)
	safeURLDomains := map[string]bool{
		"registry.npmjs.org": true, "www.npmjs.com": true, "npmjs.com": true,
		"pypi.org": true, "pypi.python.org": true, "files.pythonhosted.org": true,
		"cdn.jsdelivr.net": true, "unpkg.com": true, "cdnjs.cloudflare.com": true,
		"github.com": true, "raw.githubusercontent.com": true, "api.github.com": true,
		"gitlab.com": true, "bitbucket.org": true,
		"nodejs.org": true, "yarnpkg.com": true, "pnpm.io": true,
		"crates.io": true, "rubygems.org": true, "repo1.maven.org": true,
		"api.nuget.org": true, "packagist.org": true,
		"fonts.googleapis.com": true, "fonts.gstatic.com": true,
		"docs.rs": true, "docs.python.org": true,
	}
	var suspiciousURLs []string
	for _, u := range urls {
		if m := reDomainExtract.FindStringSubmatch(u); len(m) > 1 {
			if !safeURLDomains[strings.ToLower(m[1])] {
				suspiciousURLs = append(suspiciousURLs, u)
			}
		}
	}
	if len(suspiciousURLs) > 0 {
		indicators = append(indicators, fmt.Sprintf("Non-whitelisted URLs detected (%d): %s", len(suspiciousURLs), strings.Join(suspiciousURLs[:min(3, len(suspiciousURLs))], ", ")))
	}

	return indicators
}

func (cs *ContentScanner) inCIDRs(ipStr string, cidrs []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func (cs *ContentScanner) detectBase64Previews(content string) []string {
	var previews []string
	matches := reBase64.FindAllString(content, -1)
	max := min(3, len(matches))
	for i := 0; i < max; i++ {
		m := matches[i]
		if dec, err := base64.StdEncoding.DecodeString(m); err == nil {
			if len(dec) > 16 {
				previews = append(previews, string(dec[:16]))
			}
		}
	}
	return previews
}

func (cs *ContentScanner) createAggregatedEntropyThreat(filePath string, spans []entropySpan) types.Threat {
	relPath := filepath.Base(filePath)
	var ev []types.Evidence
	for i := 0; i < min(5, len(spans)); i++ {
		sp := spans[i]
		ev = append(ev, types.Evidence{Type: "entropy_span", Description: "range", Value: map[string]interface{}{"start": sp.start, "end": sp.end, "score": sp.score}})
	}
	ev = append(ev, types.Evidence{Type: "file", Description: "Suspicious file", Value: map[string]interface{}{"relative": relPath, "path": filePath}})
	return types.Threat{
		Type:            types.ThreatTypeObfuscatedCode,
		Severity:        types.SeverityHigh,
		Confidence:      0.8,
		Description:     fmt.Sprintf("File '%s' has multiple high-entropy spans", relPath),
		DetectionMethod: "entropy_window_analysis",
		Recommendation:  "Review high-entropy segments for obfuscated payloads.",
		Evidence:        ev,
		Metadata:        map[string]interface{}{"file_path": filePath, "relative_path": relPath},
		DetectedAt:      time.Now(),
	}
}

func (cs *ContentScanner) createPatternThreatWithPreviews(filePath string, patterns []string, previews []string) types.Threat {
	relPath := filepath.Base(filePath)
	ev := []types.Evidence{
		{Type: "patterns", Description: "Detected patterns", Value: strings.Join(patterns, "; ")},
		{Type: "file", Description: "Suspicious file", Value: map[string]interface{}{"relative": relPath, "path": filePath}},
	}
	if len(previews) > 0 {
		ev = append(ev, types.Evidence{Type: "preview", Description: "decoded_base64", Value: map[string]interface{}{"contentType": "base64", "previews": previews}})
	}
	return types.Threat{
		Type:            types.ThreatTypeSuspiciousPattern,
		Severity:        types.SeverityHigh,
		Confidence:      0.85,
		Description:     fmt.Sprintf("File '%s' contains suspicious code patterns", relPath),
		DetectionMethod: "pattern_analysis",
		Recommendation:  "Review detected patterns and decoded previews.",
		Evidence:        ev,
		Metadata:        map[string]interface{}{"file_path": filePath, "relative_path": relPath},
		DetectedAt:      time.Now(),
	}
}

// Threat creation helpers

func (cs *ContentScanner) createEntropyThreat(filePath string, entropy float64) types.Threat {
	relPath := filepath.Base(filePath)
	return types.Threat{
		Type:            types.ThreatTypeObfuscatedCode,
		Severity:        types.SeverityHigh,
		Confidence:      0.8,
		Description:     fmt.Sprintf("File '%s' has high entropy (%.2f), indicating potential obfuscation or encryption", relPath, entropy),
		DetectionMethod: "entropy_analysis",
		Recommendation:  "Review file contents for obfuscated or encrypted code. High entropy often indicates malicious obfuscation techniques.",
		Evidence: []types.Evidence{
			{
				Type:        "entropy",
				Description: "Shannon entropy score",
				Value:       fmt.Sprintf("%.2f", entropy),
			},
			{
				Type:        "file",
				Description: "Suspicious file",
				Value:       map[string]interface{}{"relative": relPath, "path": filePath},
			},
		},
		Metadata:   map[string]interface{}{"file_path": filePath, "relative_path": relPath},
		DetectedAt: time.Now(),
	}
}

func (cs *ContentScanner) createEntropySpanThreat(filePath string, span entropySpan) types.Threat {
	relPath := filepath.Base(filePath)
	return types.Threat{
		Type:            types.ThreatTypeObfuscatedCode,
		Severity:        types.SeverityHigh,
		Confidence:      0.8,
		Description:     fmt.Sprintf("File '%s' has high-entropy span (%.2f)", relPath, span.score),
		DetectionMethod: "entropy_window_analysis",
		Recommendation:  "Review high-entropy segments for obfuscated payloads.",
		Evidence: []types.Evidence{
			{Type: "entropy_span", Description: "range", Value: map[string]interface{}{"start": span.start, "end": span.end, "score": span.score}},
			{Type: "file", Description: "Suspicious file", Value: map[string]interface{}{"relative": relPath, "path": filePath}},
		},
		Metadata:   map[string]interface{}{"file_path": filePath, "relative_path": relPath},
		DetectedAt: time.Now(),
	}
}

func (cs *ContentScanner) createPatternThreat(filePath string, patterns []string) types.Threat {
	relPath := filepath.Base(filePath)
	return types.Threat{
		Type:            types.ThreatTypeSuspiciousPattern,
		Severity:        types.SeverityHigh,
		Confidence:      0.85,
		Description:     fmt.Sprintf("File '%s' contains suspicious code patterns: %s", relPath, strings.Join(patterns, ", ")),
		DetectionMethod: "pattern_analysis",
		Recommendation:  "Review detected patterns. Multiple obfuscation techniques often indicate malicious intent.",
		Evidence: []types.Evidence{
			{
				Type:        "patterns",
				Description: "Detected patterns",
				Value:       strings.Join(patterns, "; "),
			},
			{
				Type:        "file",
				Description: "Suspicious file",
				Value:       map[string]interface{}{"relative": relPath, "path": filePath},
			},
		},
		Metadata:   map[string]interface{}{"file_path": filePath, "relative_path": relPath},
		DetectedAt: time.Now(),
	}
}

func (cs *ContentScanner) createSecretThreat(filePath string, secrets []string) types.Threat {
	relPath := filepath.Base(filePath)
	return types.Threat{
		Type:            types.ThreatTypeEmbeddedSecret,
		Severity:        types.SeverityCritical,
		Confidence:      0.9,
		Description:     fmt.Sprintf("File '%s' contains embedded secrets or credentials: %s", relPath, strings.Join(secrets, ", ")),
		DetectionMethod: "secret_scanning",
		Recommendation:  "CRITICAL: Embedded secrets detected. This package may contain leaked credentials or be designed to steal secrets. Do not install.",
		Evidence: []types.Evidence{
			{
				Type:        "secrets",
				Description: "Types of secrets found",
				Value:       strings.Join(secrets, "; "),
			},
			{
				Type:        "file",
				Description: "File containing secrets",
				Value:       map[string]interface{}{"relative": relPath, "path": filePath},
			},
		},
		Metadata:   map[string]interface{}{"file_path": filePath, "relative_path": relPath},
		DetectedAt: time.Now(),
	}
}

func (cs *ContentScanner) createNetworkThreat(filePath string, indicators []string) types.Threat {
	relPath := filepath.Base(filePath)
	return types.Threat{
		Type:            types.ThreatTypeSuspiciousPattern,
		Severity:        types.SeverityMedium,
		Confidence:      0.7,
		Description:     fmt.Sprintf("File '%s' contains network indicators: %s", relPath, strings.Join(indicators[:min(3, len(indicators))], ", ")),
		DetectionMethod: "network_indicator_analysis",
		Recommendation:  "Review network connections. Legitimate packages rarely make external requests during installation.",
		Evidence: []types.Evidence{
			{
				Type:        "network_indicators",
				Description: "Detected network activity",
				Value:       strings.Join(indicators, "; "),
			},
			{
				Type:        "file",
				Description: "File with network code",
				Value:       map[string]interface{}{"relative": relPath, "path": filePath},
			},
		},
		Metadata:   map[string]interface{}{"file_path": filePath, "relative_path": relPath},
		DetectedAt: time.Now(),
	}
}

// Helper functions

func (cs *ContentScanner) isBinaryFile(filePath string) bool {
	// Simple heuristic: check extension
	ext := strings.ToLower(filepath.Ext(filePath))
	binaryExts := []string{".exe", ".dll", ".so", ".dylib", ".node", ".bin", ".dat", ".pyc", ".pyo"}
	for _, binExt := range binaryExts {
		if ext == binExt {
			return true
		}
	}

	// Check file header for binary indicators
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	header := make([]byte, 512)
	n, err := file.Read(header)
	if err != nil {
		return false
	}

	// Check for null bytes (common in binary files)
	for i := 0; i < n; i++ {
		if header[i] == 0 {
			return true
		}
	}

	return false
}

// extractInstallHooks extracts the content of install-time hooks from package.json.
// These hooks execute automatically on `npm install` and are high-risk if malicious.
func extractInstallHooks(content []byte) []string {
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(content, &pkg); err != nil {
		return nil
	}
	hookKeys := []string{"preinstall", "install", "postinstall", "prepare", "prepack"}
	var hooks []string
	for _, k := range hookKeys {
		if v, ok := pkg.Scripts[k]; ok && v != "" {
			hooks = append(hooks, v)
		}
	}
	return hooks
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 4: Advanced Supply Chain Attack Detection (2026 real-world attacks)
// ─────────────────────────────────────────────────────────────────────────────

// detectCredentialHarvesting detects code that reads sensitive credential files.
// Catches: LiteLLM attack (reads ~/.ssh, ~/.aws, ~/.kube, ~/.config).
func (cs *ContentScanner) detectCredentialHarvesting(content string) []types.Threat {
	readOps := []string{
		"open(", "readFile", "readFileSync", "readdir", "readdirSync",
		"os.listdir", "os.walk", "glob(", "glob.glob", "Path(",
		"io.ReadFile", "ioutil.ReadFile",
	}

	pathHits := 0
	var matchedPaths []string
	for _, m := range reCredentialPaths.FindAllString(content, -1) {
		pathHits++
		if len(matchedPaths) < 5 {
			matchedPaths = append(matchedPaths, m)
		}
	}

	hasReadOp := false
	for _, op := range readOps {
		if strings.Contains(content, op) {
			hasReadOp = true
			break
		}
	}

	if pathHits >= 2 && hasReadOp {
		return []types.Threat{{
			Type:            types.ThreatTypeCredentialHarvesting,
			Severity:        types.SeverityCritical,
			Confidence:      0.92,
			Description:     fmt.Sprintf("Code accesses %d sensitive credential paths (%s) with file read operations — matches credential harvesting pattern used in supply chain attacks (LiteLLM, SANDWORM)", pathHits, strings.Join(matchedPaths, ", ")),
			DetectionMethod: "credential_harvesting_analysis",
			Recommendation:  "CRITICAL: This code reads credential files from the system. Libraries should never access SSH keys, cloud credentials, or authentication tokens. Do NOT install this package.",
			Evidence: []types.Evidence{
				{Type: "credential_paths", Description: "Matched credential paths", Value: strings.Join(matchedPaths, "; ")},
			},
			Metadata:   map[string]interface{}{"path_hits": pathHits, "has_read_op": hasReadOp},
			DetectedAt: time.Now(),
		}}
	}
	return nil
}

// detectOSPersistence detects code that installs OS-level persistence mechanisms.
// Catches: LiteLLM attack (systemd service), Axios attack (Windows Run key, LaunchAgent).
func (cs *ContentScanner) detectOSPersistence(content string) []types.Threat {
	persistencePatterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		// systemd (pre-compiled)
		{"systemd service creation", reSystemdCreate},
		{"systemd unit file", reSystemdUnit},
		// cron
		{"cron job installation", reCronInstall},
		// launchd (macOS)
		{"macOS LaunchAgent/Daemon", reLaunchdMac},
		// Windows
		{"Windows Run key persistence", reWindowsRunKey},
		{"Windows startup folder", reWindowsStartup},
	}

	var matched []string
	for _, pp := range persistencePatterns {
		if pp.pattern.MatchString(content) {
			matched = append(matched, pp.name)
		}
	}

	if len(matched) > 0 {
		return []types.Threat{{
			Type:            types.ThreatTypeOSPersistence,
			Severity:        types.SeverityHigh,
			Confidence:      0.88,
			Description:     fmt.Sprintf("Code installs OS-level persistence: %s — library packages should never create system services, cron jobs, or startup entries", strings.Join(matched, "; ")),
			DetectionMethod: "os_persistence_analysis",
			Recommendation:  "DANGER: This package attempts to install persistent background services on your system. This is a strong indicator of malware. Do NOT install.",
			Evidence: []types.Evidence{
				{Type: "persistence_mechanisms", Description: "Detected persistence patterns", Value: strings.Join(matched, "; ")},
			},
			Metadata:   map[string]interface{}{"mechanisms": matched},
			DetectedAt: time.Now(),
		}}
	}
	return nil
}

// detectAntiForensics detects self-deleting scripts and evidence cleanup.
// Catches: Axios attack (setup.js deletes itself, restores clean package.json).
func (cs *ContentScanner) detectAntiForensics(content string) []types.Threat {
	antiForensicPatterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		// JavaScript self-deletion (pre-compiled)
		{"JS self-deleting script", reJSSelfDelete},
		{"JS file removal after run", reJSFileRemoval},
		// Python self-deletion
		{"Python self-deleting script", rePySelfDelete},
		{"Python pathlib self-deletion", rePyPathlibDelete},
		// Shell self-deletion
		{"Shell self-deleting script", reShellSelfDelete},
		// package.json manipulation (restoring clean state after attack)
		{"package.json post-attack cleanup", rePkgJsonCleanup},
		// Log/history wiping
		{"history/log wiping", reHistoryWipe},
	}

	var matched []string
	for _, pp := range antiForensicPatterns {
		if pp.pattern.MatchString(content) {
			matched = append(matched, pp.name)
		}
	}

	if len(matched) > 0 {
		return []types.Threat{{
			Type:            types.ThreatTypeAntiForensics,
			Severity:        types.SeverityCritical,
			Confidence:      0.90,
			Description:     fmt.Sprintf("Code contains anti-forensic techniques: %s — self-deleting scripts and evidence cleanup are hallmarks of supply chain malware", strings.Join(matched, "; ")),
			DetectionMethod: "anti_forensics_analysis",
			Recommendation:  "CRITICAL: This package uses anti-forensic techniques to hide its activity. Self-deleting install scripts are a strong malware indicator. Do NOT install.",
			Evidence: []types.Evidence{
				{Type: "anti_forensic_patterns", Description: "Detected anti-forensic techniques", Value: strings.Join(matched, "; ")},
			},
			Metadata:   map[string]interface{}{"patterns": matched},
			DetectedAt: time.Now(),
		}}
	}
	return nil
}

// detectCompoundBehaviors detects dangerous co-occurrence of multiple attack signals.
// Catches: LiteLLM (base64+exec), Axios (eval+fetch+self-delete), SANDWORM (env+POST).
func (cs *ContentScanner) detectCompoundBehaviors(content string) []types.Threat {
	// Classify content into signal categories
	type signal struct {
		name    string
		present bool
	}
	signals := []signal{
		{"base64_decode", strings.Contains(content, "atob(") || strings.Contains(content, "base64.b64decode") || strings.Contains(content, "Buffer.from") || strings.Contains(content, "base64.decode") || strings.Contains(content, "b64decode")},
		{"exec_eval", strings.Contains(content, "eval(") || strings.Contains(content, "exec(") || strings.Contains(content, "subprocess") || strings.Contains(content, "child_process") || strings.Contains(content, "os.system(") || strings.Contains(content, "os.popen(")},
		{"network_call", strings.Contains(content, "fetch(") || strings.Contains(content, "curl") || strings.Contains(content, "wget") || strings.Contains(content, "requests.post") || strings.Contains(content, "requests.get") || strings.Contains(content, "http.request") || strings.Contains(content, "https.request") || strings.Contains(content, "urllib") || strings.Contains(content, "XMLHttpRequest") || strings.Contains(content, "axios")},
		{"file_write", strings.Contains(content, "writeFile") || strings.Contains(content, "writeFileSync") || strings.Contains(content, "os.WriteFile") || strings.Contains(content, "open(") && (strings.Contains(content, `"w"`) || strings.Contains(content, `'w'`) || strings.Contains(content, `"w+"`) || strings.Contains(content, `"a"`))},
		{"chmod_exec", strings.Contains(content, "chmod") || strings.Contains(content, "0o755") || strings.Contains(content, "0755") || strings.Contains(content, "+x")},
		{"env_access", strings.Contains(content, "os.environ") || strings.Contains(content, "os.getenv(") || (strings.Contains(content, "process.env[") || strings.Contains(content, "process.env.") && !strings.Contains(content, "process.env.NODE_ENV"))},
		{"credential_read", strings.Contains(content, ".ssh") || strings.Contains(content, ".aws") || strings.Contains(content, ".npmrc") || strings.Contains(content, ".kube")},
	}

	// Define dangerous compound patterns
	type compound struct {
		name       string
		requires   []string // signal names that must ALL be present
		severity   types.Severity
		confidence float64
	}
	compounds := []compound{
		{"base64 decode + code execution", []string{"base64_decode", "exec_eval"}, types.SeverityCritical, 0.93},
		{"code execution + network call", []string{"exec_eval", "network_call"}, types.SeverityCritical, 0.88},
		{"file write + make executable", []string{"file_write", "chmod_exec"}, types.SeverityHigh, 0.82},
		{"credential read + network exfiltration", []string{"credential_read", "network_call"}, types.SeverityCritical, 0.95},
		{"environment access + network exfiltration", []string{"env_access", "network_call"}, types.SeverityHigh, 0.80},
		{"base64 decode + file write + network call", []string{"base64_decode", "file_write", "network_call"}, types.SeverityCritical, 0.95},
	}

	// Build signal lookup
	sigMap := make(map[string]bool)
	for _, s := range signals {
		if s.present {
			sigMap[s.name] = true
		}
	}

	var threats []types.Threat
	for _, c := range compounds {
		allPresent := true
		for _, req := range c.requires {
			if !sigMap[req] {
				allPresent = false
				break
			}
		}
		if allPresent {
			threats = append(threats, types.Threat{
				Type:            types.ThreatTypeCompoundObfuscation,
				Severity:        c.severity,
				Confidence:      c.confidence,
				Description:     fmt.Sprintf("Dangerous compound behavior detected: %s — this combination of operations is characteristic of supply chain malware", c.name),
				DetectionMethod: "compound_behavior_analysis",
				Recommendation:  "Multiple dangerous operations co-occur in a single file. Legitimate libraries rarely combine encoding, execution, and network calls. Review this package carefully before installing.",
				Evidence: []types.Evidence{
					{Type: "compound_pattern", Description: c.name, Value: strings.Join(c.requires, " + ")},
				},
				Metadata:   map[string]interface{}{"pattern": c.name, "signals": c.requires},
				DetectedAt: time.Now(),
			})
			break // report highest-severity compound match only
		}
	}
	return threats
}

// detectCustomCiphers detects XOR byte manipulation and custom encoding schemes.
// Catches: Axios attack (two-layer XOR with _trans_1, _trans_2 functions).
func (cs *ContentScanner) detectCustomCiphers(content string) []types.Threat {
	cipherPatterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		// JavaScript XOR (pre-compiled)
		{"JS charCode XOR", reJSCharCodeXOR},
		{"JS String.fromCharCode XOR", reJSFromCharXOR},
		// Python XOR
		{"Python byte XOR", rePyByteXOR},
		{"Python bytearray XOR", rePyBytearrayXOR},
		// Named decode/deobfuscation functions
		{"Named deobfuscation function", reNamedDeobfFunc},
		// Buffer-based XOR loops
		{"Buffer XOR loop", reBufferXOR},
		// Reverse string + base64 combo (Axios _trans_2 pattern)
		{"String reversal + decode", reStringRevDecode},
	}

	var matched []string
	for _, pp := range cipherPatterns {
		if pp.pattern.MatchString(content) {
			matched = append(matched, pp.name)
		}
	}

	if len(matched) >= 1 {
		sev := types.SeverityMedium
		conf := 0.70
		if len(matched) >= 2 {
			sev = types.SeverityHigh
			conf = 0.85
		}
		return []types.Threat{{
			Type:            types.ThreatTypeCustomCipher,
			Severity:        sev,
			Confidence:      conf,
			Description:     fmt.Sprintf("Custom cipher/obfuscation detected: %s — XOR byte manipulation and custom decode functions are used to evade static analysis in supply chain attacks", strings.Join(matched, "; ")),
			DetectionMethod: "custom_cipher_analysis",
			Recommendation:  "This code uses custom encoding/decryption routines. While not always malicious, XOR-based obfuscation combined with other suspicious indicators is a strong supply chain attack signal.",
			Evidence: []types.Evidence{
				{Type: "cipher_patterns", Description: "Detected cipher/obfuscation patterns", Value: strings.Join(matched, "; ")},
			},
			Metadata:   map[string]interface{}{"patterns": matched, "count": len(matched)},
			DetectedAt: time.Now(),
		}}
	}
	return nil
}

// detectPythonAutoExec detects Python-specific auto-execution vectors.
// Catches: LiteLLM attack (.pth file with import statement auto-executes on Python startup).
func (cs *ContentScanner) detectPythonAutoExec(filePath, content string) []types.Threat {
	base := filepath.Base(filePath)
	ext := strings.ToLower(filepath.Ext(filePath))

	// .pth files: auto-executed if they contain "import" statements
	if ext == ".pth" {
		hasImport := strings.Contains(content, "import ") || strings.Contains(content, "__import__")
		hasExec := strings.Contains(content, "exec(") || strings.Contains(content, "eval(") || strings.Contains(content, "subprocess")
		if hasImport || hasExec {
			return []types.Threat{{
				Type:            types.ThreatTypePythonAutoExec,
				Severity:        types.SeverityCritical,
				Confidence:      0.95,
				Description:     fmt.Sprintf("Python .pth file '%s' contains executable code (import/exec statements). .pth files in site-packages auto-execute on every Python interpreter startup — this is the exact technique used in the LiteLLM supply chain attack (March 2026)", base),
				DetectionMethod: "python_pth_analysis",
				Recommendation:  "CRITICAL: .pth files with import statements execute automatically when Python starts. This is a persistence mechanism used by supply chain malware. Remove this package immediately and audit your environment.",
				Evidence: []types.Evidence{
					{Type: "python_auto_exec", Description: ".pth file with executable code", Value: base},
				},
				Metadata:   map[string]interface{}{"file": base, "has_import": hasImport, "has_exec": hasExec},
				DetectedAt: time.Now(),
			}}
		}
	}

	// sitecustomize.py, usercustomize.py: auto-imported by Python on startup
	// NOTE: conftest.py excluded — it's a standard pytest fixture file and causes too many false positives
	autoImportFiles := map[string]bool{
		"sitecustomize.py":  true,
		"usercustomize.py":  true,
	}
	if autoImportFiles[base] {
		dangerousOps := []string{"subprocess", "os.system", "exec(", "eval(", "requests.", "urllib", "http.client", "socket."}
		var found []string
		for _, op := range dangerousOps {
			if strings.Contains(content, op) {
				found = append(found, op)
			}
		}
		if len(found) > 0 {
			return []types.Threat{{
				Type:            types.ThreatTypePythonAutoExec,
				Severity:        types.SeverityHigh,
				Confidence:      0.85,
				Description:     fmt.Sprintf("Python auto-import file '%s' contains dangerous operations: %s — this file executes automatically on Python startup", base, strings.Join(found, ", ")),
				DetectionMethod: "python_auto_import_analysis",
				Recommendation:  fmt.Sprintf("The file '%s' is auto-imported by Python and contains suspicious operations. Review carefully.", base),
				Evidence: []types.Evidence{
					{Type: "python_auto_exec", Description: "Auto-import file with dangerous ops", Value: strings.Join(found, "; ")},
				},
				Metadata:   map[string]interface{}{"file": base, "dangerous_ops": found},
				DetectedAt: time.Now(),
			}}
		}
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
