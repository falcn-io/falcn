package container

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/falcn-io/falcn/pkg/retry"
	"github.com/sirupsen/logrus"
)

// ─── Scanner ──────────────────────────────────────────────────────────────────

// Scanner performs security analysis on OCI/Docker container images.
// Use New() to obtain a configured instance.
type Scanner struct {
	vulnDB vulnChecker
}

// vulnChecker is the interface the Scanner uses to look up CVEs.
// It is satisfied by an *http.Client calling the OSV API, keeping
// the container package dependency-free from the vulnerability subtree.
type vulnChecker struct {
	client *http.Client
}

// New returns a Scanner ready to scan images.
func New() *Scanner {
	return &Scanner{
		vulnDB: vulnChecker{
			client: &http.Client{Timeout: 30 * time.Second},
		},
	}
}

// ─── Public API ───────────────────────────────────────────────────────────────

// ScanImage pulls metadata for the container image identified by imageRef,
// enumerates installed packages, checks for CVEs, and performs image-level
// security checks. Results are returned as an ImageScanResult.
func (s *Scanner) ScanImage(ctx context.Context, imageRef string, opts ScanOptions) (*ImageScanResult, error) {
	start := time.Now()

	ref, err := ParseImageRef(imageRef)
	if err != nil {
		return nil, fmt.Errorf("invalid image reference %q: %w", imageRef, err)
	}

	result := &ImageScanResult{
		Ref:       ref,
		ScannedAt: time.Now(),
	}

	// ── Step 1: Fetch manifest ──────────────────────────────────────────────
	client := newClient(ref, opts)
	manifest, digest, err := client.GetManifest(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	result.ResolvedDigest = digest
	result.LayerCount = len(manifest.Layers)

	// Compute total (compressed) image size.
	var totalBytes int64
	for _, l := range manifest.Layers {
		totalBytes += l.Size
	}
	result.ImageSizeMB = math.Round(float64(totalBytes)/1024/1024*100) / 100

	// ── Step 2: Fetch image config ─────────────────────────────────────────
	cfg, err := client.GetConfig(ctx, manifest.Config.Digest)
	if err != nil {
		result.Errors = append(result.Errors, "config: "+err.Error())
	} else {
		result.OS = cfg.OS
		result.Architecture = cfg.Architecture
		result.BaseImage = extractBaseImage(cfg)
		// Security findings derived from the image config.
		result.SecurityFindings = append(result.SecurityFindings,
			s.analyzeConfig(cfg, manifest)...)
	}

	// ── Step 3: Layer analysis (optional) ──────────────────────────────────
	if !opts.Light {
		maxBytes := opts.MaxLayerSizeMB * 1024 * 1024
		if maxBytes == 0 {
			maxBytes = 100 * 1024 * 1024 // default 100 MB
		}
		layerResults := s.analyzeLayers(ctx, client, manifest, cfg, maxBytes)
		result.Layers = layerResults

		seen := map[string]struct{}{}
		for _, la := range layerResults {
			if la.Error != "" {
				result.Errors = append(result.Errors, "layer "+la.Digest[:min(12, len(la.Digest))]+": "+la.Error)
			}
			for _, pkg := range la.Packages {
				key := pkg.Ecosystem.String() + ":" + pkg.Name + ":" + pkg.Version
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				result.Packages = append(result.Packages, pkg)
			}
		}
		result.PackageCount = len(result.Packages)
	}

	// ── Step 4: CVE lookup ─────────────────────────────────────────────────
	if len(result.Packages) > 0 {
		vulns := s.checkVulnerabilities(ctx, result.Packages)
		result.Vulnerabilities = vulns
	}

	// ── Step 5: Risk scoring ───────────────────────────────────────────────
	result.RiskScore, result.RiskLevel = computeRisk(result)
	result.ScanDurationMs = time.Since(start).Milliseconds()

	return result, nil
}

// ─── Layer analysis ───────────────────────────────────────────────────────────

func (s *Scanner) analyzeLayers(
	ctx context.Context,
	client *registryClient,
	manifest *ImageManifest,
	cfg *ImageConfig,
	maxBytes int64,
) []LayerAnalysis {
	results := make([]LayerAnalysis, len(manifest.Layers))

	// Build history commands indexed by non-empty layer position.
	histCmds := layerHistoryCommands(cfg)

	// Use a small worker pool to fetch layers in parallel.
	type job struct {
		idx   int
		layer ManifestDescr
		cmd   string
	}
	jobs := make(chan job, len(manifest.Layers))
	for i, l := range manifest.Layers {
		cmd := ""
		if i < len(histCmds) {
			cmd = histCmds[i]
		}
		jobs <- job{i, l, cmd}
	}
	close(jobs)

	var mu sync.Mutex
	var wg sync.WaitGroup
	workers := 3
	if len(manifest.Layers) < workers {
		workers = len(manifest.Layers)
	}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				la := s.analyzeOneLayer(ctx, client, j.layer, j.cmd, maxBytes)
				mu.Lock()
				results[j.idx] = la
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return results
}

func (s *Scanner) analyzeOneLayer(
	ctx context.Context,
	client *registryClient,
	layer ManifestDescr,
	cmd string,
	maxBytes int64,
) LayerAnalysis {
	la := LayerAnalysis{Digest: layer.Digest, Size: layer.Size, Command: cmd}

	rc, err := client.GetLayerStream(ctx, layer.Digest, maxBytes)
	if err != nil {
		la.Error = err.Error()
		return la
	}
	if rc == nil {
		la.Error = fmt.Sprintf("layer too large (%.1f MB, limit %.0f MB) — skipped",
			float64(layer.Size)/1024/1024, float64(maxBytes)/1024/1024)
		return la
	}
	defer rc.Close()

	return analyzeLayer(rc, layer.Digest)
}

// ─── Config-level security checks ─────────────────────────────────────────────

var privilegedPortRe = regexp.MustCompile(`^(\d+)/`)

func (s *Scanner) analyzeConfig(cfg *ImageConfig, manifest *ImageManifest) []SecurityFinding {
	var findings []SecurityFinding

	// IMG001: runs as root
	user := strings.TrimSpace(cfg.Config.User)
	if user == "" || user == "root" || user == "0" || user == "0:0" {
		findings = append(findings, SecurityFinding{
			ID:          "IMG001",
			Severity:    "high",
			Title:       "Container runs as root",
			Detail:      "The image USER is empty or 'root'.",
			Remediation: "Add a non-root USER instruction, e.g. `USER 1000:1000`.",
		})
	}

	// IMG002: secrets in env
	for _, env := range cfg.Config.Env {
		if secretEnvRe.MatchString(env) {
			findings = append(findings, SecurityFinding{
				ID:          "IMG002",
				Severity:    "high",
				Title:       "Potential secret in ENV variable",
				Detail:      "Env contains: " + maskSecret(env),
				Remediation: "Use runtime secrets injection (e.g. Docker secrets, Vault) instead of ENV.",
			})
			break
		}
	}

	// IMG008: privileged port exposed
	for port := range cfg.Config.ExposedPorts {
		if m := privilegedPortRe.FindStringSubmatch(port); m != nil {
			// ports below 1024 are privileged
			var p int
			fmt.Sscanf(m[1], "%d", &p)
			if p > 0 && p < 1024 {
				findings = append(findings, SecurityFinding{
					ID:          "IMG008",
					Severity:    "low",
					Title:       "Privileged port exposed",
					Detail:      fmt.Sprintf("Port %d is exposed and requires root on most hosts.", p),
					Remediation: "Use a port >= 1024 and configure a reverse-proxy.",
				})
				break
			}
		}
	}

	// IMG009: very large image
	var totalMB float64
	for _, l := range manifest.Layers {
		totalMB += float64(l.Size) / 1024 / 1024
	}
	if totalMB > 1024 {
		findings = append(findings, SecurityFinding{
			ID:       "IMG009",
			Severity: "low",
			Title:    "Oversized image",
			Detail:   fmt.Sprintf("Total compressed image size is %.0f MB; large images increase attack surface.", totalMB),
			Remediation: "Use multi-stage builds, distroless or alpine base images, " +
				"and remove build-time tools from the final stage.",
		})
	}

	return findings
}

// ─── CVE lookup via OSV API ───────────────────────────────────────────────────

// osvEcosystem maps our PackageEcosystem to the OSV ecosystem name.
var osvEcosystem = map[PackageEcosystem]string{
	EcosystemDpkg: "Debian",
	EcosystemApk:  "Alpine",
	EcosystemRpm:  "RHEL",
	EcosystemPip:  "PyPI",
	EcosystemNpm:  "npm",
}

func (s *Scanner) checkVulnerabilities(ctx context.Context, pkgs []InstalledPackage) []PackageVuln {
	type result struct {
		vuln *PackageVuln
		err  error
	}

	sem := make(chan struct{}, 8) // 8 concurrent OSV queries
	ch := make(chan result, len(pkgs))
	var wg sync.WaitGroup

	for _, pkg := range pkgs {
		eco, ok := osvEcosystem[pkg.Ecosystem]
		if !ok {
			continue // skip unsupported ecosystems
		}
		wg.Add(1)
		go func(p InstalledPackage, ecosystem string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			vuln, err := s.queryOSV(ctx, p, ecosystem)
			ch <- result{vuln, err}
		}(pkg, eco)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	var out []PackageVuln
	for r := range ch {
		if r.err != nil {
			logrus.WithError(r.err).Warn("OSV lookup failed; vulnerability data may be incomplete")
			continue
		}
		if r.vuln != nil {
			out = append(out, *r.vuln)
		}
	}
	return out
}

// queryOSV calls the OSV REST API for a single package and returns a PackageVuln
// if any vulnerabilities are found. Retries up to 3 times on transient errors.
func (s *Scanner) queryOSV(ctx context.Context, pkg InstalledPackage, ecosystem string) (*PackageVuln, error) {
	reqBody := fmt.Sprintf(`{"version":%q,"package":{"name":%q,"ecosystem":%q}}`,
		pkg.Version, pkg.Name, ecosystem)

	var rawBody []byte
	err := retry.Do(ctx, 3, 500*time.Millisecond, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			"https://api.osv.dev/v1/query",
			strings.NewReader(reqBody))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.vulnDB.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return retry.StatusError(resp.StatusCode, fmt.Errorf("OSV returned %d", resp.StatusCode))
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return err
		}
		rawBody = b
		return nil
	})
	if err != nil {
		// Return the error so callers can flag the result as incomplete rather
		// than silently reporting "no vulnerabilities found".
		return nil, fmt.Errorf("OSV query for %s@%s failed: %w", pkg.Name, pkg.Version, err)
	}

	var r struct {
		Vulns []struct {
			ID       string `json:"id"`
			Aliases  []string `json:"aliases"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			Affected []struct {
				Ranges []struct {
					Type   string `json:"type"`
					Events []struct {
						Introduced string `json:"introduced,omitempty"`
						Fixed      string `json:"fixed,omitempty"`
					} `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
		} `json:"vulns"`
	}
	if err := json.Unmarshal(rawBody, &r); err != nil {
		return nil, nil
	}
	if len(r.Vulns) == 0 {
		return nil, nil
	}

	pv := &PackageVuln{Package: pkg}
	maxSev := ""
	for _, v := range r.Vulns {
		pv.OSVIDs = append(pv.OSVIDs, v.ID)
		for _, alias := range v.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				pv.CVEs = append(pv.CVEs, alias)
			}
		}
		// Pick the highest severity seen.
		for _, sev := range v.Severity {
			if sev.Type == "CVSS_V3" {
				maxSev = pickHigher(maxSev, cvssScore(sev.Score))
			}
		}
		// Find fix version.
		for _, aff := range v.Affected {
			for _, rng := range aff.Ranges {
				for _, ev := range rng.Events {
					if ev.Fixed != "" && pv.FixedIn == "" {
						pv.FixedIn = ev.Fixed
					}
				}
			}
		}
	}
	if maxSev == "" {
		maxSev = "medium"
	}
	pv.Severity = maxSev
	return pv, nil
}

// ─── Risk scoring ─────────────────────────────────────────────────────────────

// computeRisk derives a 0.0–1.0 risk score and a risk level label.
func computeRisk(r *ImageScanResult) (float64, string) {
	score := 0.0

	// Critical findings
	for _, f := range r.SecurityFindings {
		switch f.Severity {
		case "critical":
			score += 0.30
		case "high":
			score += 0.15
		case "medium":
			score += 0.07
		case "low":
			score += 0.02
		}
	}

	// CVEs
	for _, v := range r.Vulnerabilities {
		switch v.Severity {
		case "critical":
			score += 0.20
		case "high":
			score += 0.10
		case "medium":
			score += 0.04
		case "low":
			score += 0.01
		}
	}

	if score > 1.0 {
		score = 1.0
	}
	score = math.Round(score*100) / 100

	var level string
	switch {
	case score >= 0.75:
		level = "critical"
	case score >= 0.50:
		level = "high"
	case score >= 0.25:
		level = "medium"
	case score >= 0.05:
		level = "low"
	default:
		level = "minimal"
	}
	return score, level
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// layerHistoryCommands maps the non-empty history entries (those that generate
// a layer) to their CreatedBy command strings, in layer order.
func layerHistoryCommands(cfg *ImageConfig) []string {
	if cfg == nil {
		return nil
	}
	var cmds []string
	for _, h := range cfg.History {
		if !h.EmptyLayer {
			cmd := h.CreatedBy
			// Strip the buildkit prefix.
			cmd = strings.TrimPrefix(cmd, "|")
			if idx := strings.Index(cmd, "/bin/sh -c "); idx != -1 {
				cmd = cmd[idx+len("/bin/sh -c "):]
			}
			if len(cmd) > 120 {
				cmd = cmd[:120] + "…"
			}
			cmds = append(cmds, cmd)
		}
	}
	return cmds
}

// extractBaseImage tries to find the FROM instruction from the image history.
func extractBaseImage(cfg *ImageConfig) string {
	if cfg == nil {
		return ""
	}
	for _, h := range cfg.History {
		if strings.Contains(strings.ToUpper(h.CreatedBy), "FROM ") {
			// Extract the image name after "FROM ".
			parts := strings.Fields(h.CreatedBy)
			for i, p := range parts {
				if strings.EqualFold(p, "FROM") && i+1 < len(parts) {
					return parts[i+1]
				}
			}
		}
	}
	return ""
}

// maskSecret replaces the value part of an env var like KEY=secret with KEY=***.
func maskSecret(env string) string {
	if idx := strings.Index(env, "="); idx != -1 {
		return env[:idx+1] + "***"
	}
	return env
}

// cvssScore parses a CVSS v3 vector string and returns a severity label using
// the official CVSS v3.1 base score formula (FIRST.org specification).
func cvssScore(vector string) string {
	score := cvssV3BaseScore(vector)
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "low" // unknown / parse failure → conservative default
	}
}

// cvssV3BaseScore computes the CVSS v3.1 base score from a vector string.
// Returns 0.0 if the vector is empty or cannot be parsed.
func cvssV3BaseScore(vector string) float64 {
	if vector == "" {
		return 0
	}
	vals := make(map[string]string, 10)
	for _, part := range strings.Split(vector, "/") {
		if idx := strings.IndexByte(part, ':'); idx >= 0 {
			vals[part[:idx]] = part[idx+1:]
		}
	}

	avM := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	acM := map[string]float64{"L": 0.77, "H": 0.44}
	uiM := map[string]float64{"N": 0.85, "R": 0.62}
	impM := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.00}

	scope := vals["S"]
	prM := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		prM = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	}

	av, ok1 := avM[vals["AV"]]
	ac, ok2 := acM[vals["AC"]]
	pr, ok3 := prM[vals["PR"]]
	ui, ok4 := uiM[vals["UI"]]
	ic, ok5 := impM[vals["C"]]
	ii, ok6 := impM[vals["I"]]
	ia, ok7 := impM[vals["A"]]
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 {
		return 0
	}

	iscBase := 1 - (1-ic)*(1-ii)*(1-ia)
	var isc float64
	if scope == "C" {
		isc = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		isc = 6.42 * iscBase
	}
	if isc <= 0 {
		return 0
	}

	exploitability := 8.22 * av * ac * pr * ui
	var raw float64
	if scope == "C" {
		raw = math.Min(1.08*(isc+exploitability), 10)
	} else {
		raw = math.Min(isc+exploitability, 10)
	}
	return math.Ceil(raw*10) / 10
}

// pickHigher returns the more severe of two severity strings.
func pickHigher(a, b string) string {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// String implements Stringer for PackageEcosystem.
func (e PackageEcosystem) String() string { return string(e) }
