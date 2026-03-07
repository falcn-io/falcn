# Falcn User Guide — v2.3.0

Falcn is a Go-based supply chain security scanner that detects malicious packages,
typosquatting attacks, embedded secrets, CI/CD vulnerabilities, and CVEs across
eight ecosystems: npm, PyPI, Maven, Go, NuGet, RubyGems, Cargo, and Composer.

---

## Table of Contents

1. [Installation](#installation)
2. [CLI Commands](#cli-commands)
3. [Interpreting Results](#interpreting-results)
4. [Output Formats](#output-formats)
5. [Configuration](#configuration)
6. [Air-gap / Offline Mode](#air-gap--offline-mode)
7. [Troubleshooting](#troubleshooting)

---

## Installation

### Binary Download

Pre-built binaries are published for every release. Download the appropriate
binary for your platform:

```
https://github.com/falcn-io/falcn/releases/latest/download/falcn-{version}-{os}-{arch}
```

| Platform       | URL suffix                        |
|----------------|-----------------------------------|
| Linux x86-64   | `falcn-v2.3.0-linux-amd64`        |
| Linux ARM64    | `falcn-v2.3.0-linux-arm64`        |
| macOS x86-64   | `falcn-v2.3.0-darwin-amd64`       |
| macOS ARM64    | `falcn-v2.3.0-darwin-arm64`       |
| Windows x86-64 | `falcn-v2.3.0-windows-amd64.exe`  |

Quick install (Linux/macOS):

```bash
VERSION=v2.3.0
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -fsSL "https://github.com/falcn-io/falcn/releases/latest/download/falcn-${VERSION}-${OS}-${ARCH}" \
  -o /usr/local/bin/falcn
chmod +x /usr/local/bin/falcn
```

### Homebrew (macOS and Linux)

```bash
brew install falcn-io/tap/falcn
```

### From Source

Go 1.25 or later is required.

```bash
git clone https://github.com/falcn-io/falcn.git
cd falcn
make build
# Binary is placed at ./build/falcn
sudo cp build/falcn /usr/local/bin/falcn
```

To build for all platforms at once:

```bash
make build-all
# Binaries are placed under ./dist/
```

### Docker

```bash
docker pull ghcr.io/falcn-io/falcn:latest

# Scan the current directory
docker run --rm -v "$(pwd):/workspace" \
  ghcr.io/falcn-io/falcn:latest \
  falcn scan /workspace

# Scan with vulnerability checking enabled
docker run --rm -v "$(pwd):/workspace" \
  ghcr.io/falcn-io/falcn:latest \
  falcn scan /workspace --check-vulnerabilities --output json
```

### Verify Installation

```bash
falcn version
```

Expected output:

```
Falcn v2.3.0
Build:   2026-03-07_12:00:00
Commit:  f1a57ee
Go:      go1.25.0
OS/Arch: darwin/arm64
```

---

## CLI Commands

Falcn exposes the following subcommands:

| Subcommand      | Purpose                                          |
|-----------------|--------------------------------------------------|
| `scan`          | Scan a project for supply chain threats          |
| `fix`           | Generate remediation commands from a scan report |
| `version`       | Display version and build information            |
| `compliance`    | Generate compliance artifacts (SBOM, SSDF, SLSA) |
| `scan-images`   | Scan OCI/Docker container images                 |
| `report`        | Generate a formatted report from last scan       |
| `update-db`     | Download or refresh the offline CVE database     |
| `update-packages` | Refresh the popular packages cache             |

Global flags available on all subcommands:

```
-c, --config string    Config file path (default: $HOME/.falcn.yaml)
-v, --verbose          Verbose output
-o, --output string    Output format: json, table, sarif, futuristic (default: futuristic)
```

---

### 1. falcn scan

Scan a project directory for supply chain threats. Falcn auto-detects project
types based on manifest files (package.json, requirements.txt, go.mod, pom.xml,
Cargo.toml, Gemfile, composer.json, *.csproj).

```
falcn scan [path] [flags]
```

**All flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--deep` | false | Deep analysis — inspect package internals, not just metadata |
| `--include-dev` | false | Include dev/test dependencies (devDependencies, extras, etc.) |
| `--threshold float` | 0.8 | Typosquatting similarity threshold (0.0–1.0) |
| `--exclude pkg1,pkg2` | — | Comma-separated list of packages to skip |
| `--file path` | — | Scan a specific manifest file instead of auto-detecting |
| `--check-vulnerabilities` | false | Enable CVE lookup against vulnerability databases |
| `--vulnerability-db osv,github` | osv,nvd | Vulnerability databases to query |
| `--recursive` | false | Scan subdirectories (monorepos, multi-project repos) |
| `--workspace-aware` | false | Understand npm/pnpm/Yarn workspaces |
| `--consolidate-report` | false | Merge results from recursive scans into a single report |
| `--package-manager npm,pypi` | auto | Limit to specific ecosystems |
| `--registry npm` | auto | Force a specific registry for lookup |
| `--sbom-format spdx\|cyclonedx` | — | Generate an SBOM in the specified format |
| `--sbom-output path` | stdout | Write SBOM to a file |
| `--supply-chain` | false | Run enhanced supply chain analysis (dependency confusion, namespace squatting) |
| `--advanced` | false | Enable all advanced analysis features |
| `--no-llm` | false | Disable AI threat explanations |
| `--max-llm-calls int` | 10 | Maximum LLM explanation calls per scan |
| `--no-sandbox` | false | Disable dynamic sandbox analysis |
| `--offline` | false | Air-gap mode: use local SQLite CVE database |
| `--local-db path` | ~/.local/share/falcn/cve.db | Path to local CVE database |
| `--output json\|table\|sarif` | futuristic | Output format |

**Examples:**

Basic scan of the current directory:

```bash
falcn scan .
```

Scan with vulnerability checking against OSV and GitHub Advisory databases:

```bash
falcn scan . --check-vulnerabilities --vulnerability-db osv,github
```

Example output (table format):

```
SEVERITY   TYPE               PACKAGE             VERSION     DESCRIPTION
────────   ────────────────   ─────────────────   ─────────   ───────────────────────────────
CRITICAL   vulnerable         lodash              4.17.15     CVE-2021-23337: command injection
HIGH       typosquatting      colosr              1.0.0       Similar to "colors" (score: 0.94)
HIGH       embedded_secret    my-auth-helper      2.1.0       AWS access key found in index.js
MEDIUM     install_script     postinstall-hook    1.0.1       Suspicious network call in postinstall
LOW        low_reputation     brand-new-pkg       0.0.1       First published 2 days ago, 0 stars

5 threats found (1 critical, 2 high, 1 medium, 1 low)
```

Scan a monorepo recursively, consolidating results:

```bash
falcn scan . --recursive --workspace-aware --consolidate-report
```

Scan only Python dependencies with deep analysis:

```bash
falcn scan ./backend --package-manager pypi --deep --include-dev
```

Generate a CycloneDX SBOM alongside the scan:

```bash
falcn scan . --check-vulnerabilities \
  --sbom-format cyclonedx \
  --sbom-output sbom.cdx.json
```

CI gate: fail on high or critical threats, output SARIF:

```bash
falcn scan . --check-vulnerabilities --output sarif > results.sarif
# Exits with code 1 if threats are found
```

Fast heuristics-only mode for pre-commit hooks (under 100 ms per package):

```bash
falcn scan . --fast --no-llm
```

Offline scan using a local CVE database:

```bash
falcn scan . --offline --local-db /opt/falcn/cve.db --check-vulnerabilities
```

JSON output for piping to `falcn fix`:

```bash
falcn scan . --check-vulnerabilities --output json | falcn fix
```

Example JSON result structure:

```json
{
  "scan_id": "a3f8c1d2-...",
  "target": "/home/user/myproject",
  "total_packages": 312,
  "threats": [
    {
      "id": "threat-9e4f...",
      "type": "vulnerable",
      "severity": "critical",
      "package": "lodash",
      "version": "4.17.15",
      "registry": "npm",
      "cves": ["CVE-2021-23337"],
      "fixed_version": "4.17.21",
      "reachable": true,
      "remediation": "npm install lodash@4.17.21",
      "description": "Prototype pollution via the merge function",
      "confidence": 1.0
    }
  ],
  "summary": {
    "total_threats": 5,
    "critical_count": 1,
    "high_count": 2,
    "medium_count": 1,
    "low_count": 1
  }
}
```

---

### 2. falcn fix

Read the JSON output of a previous `falcn scan` and produce ecosystem-specific
upgrade commands for every vulnerability that has a known fixed version.

```
falcn fix [path] [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--input path` | `-i` | stdin | Path to a saved scan JSON report |
| `--only-reachable` | `-r` | false | Only show fixes for reachable vulnerabilities |
| `--script` | `-s` | false | Emit a shell script ready to execute (bash) |
| `--min-severity level` | `-m` | low | Minimum severity: low, medium, high, critical |
| `--patch-file` | `-p` | false | Emit a machine-readable JSON patch manifest |

**Examples:**

Pipe scan output directly into fix:

```bash
falcn scan . --check-vulnerabilities --output json | falcn fix
```

Example output:

```
SEVERITY        PACKAGE         CURRENT    FIXED IN    CVEs
────────        ──────────────  ─────────  ──────────  ────────────────────
CRITICAL        lodash          4.17.15    4.17.21     CVE-2021-23337
HIGH [reachable] express        4.17.1     4.19.2      CVE-2024-29041
MEDIUM          semver          5.7.1      5.7.2       CVE-2022-25883

3 fixable package(s). Remediation commands:

  npm install lodash@4.17.21
  npm install express@4.19.2
  npm install semver@5.7.2
```

Read from a saved report file:

```bash
falcn fix --input falcn_report.json
```

Emit a bash script for automated remediation:

```bash
falcn fix --input falcn_report.json --script > fix.sh
bash fix.sh
```

Script output (`fix.sh`):

```bash
#!/usr/bin/env bash
set -euo pipefail
# Auto-generated by falcn fix

# --- npm ---
npm install lodash@4.17.21
npm install express@4.19.2

# --- pypi ---
pip install "requests==2.32.3"
```

CI gate — fail if any high or critical fixable vulnerabilities exist:

```bash
falcn scan . --output json | falcn fix --min-severity high
echo "Exit code: $?"   # non-zero when high/critical fixable CVEs are present
```

Only reachable fixes, output as JSON patch manifest:

```bash
falcn fix --input falcn_report.json --only-reachable --patch-file
```

Patch manifest format:

```json
{
  "total_fixes": 2,
  "fixes": [
    {
      "package": "lodash",
      "registry": "npm",
      "from_version": "4.17.15",
      "to_version": "4.17.21",
      "command": "npm install lodash@4.17.21",
      "cves": ["CVE-2021-23337"],
      "severity": "critical",
      "reachable": true
    }
  ]
}
```

---

### 3. falcn version

Display version and build metadata:

```bash
falcn version
```

Output:

```
Falcn v2.3.0
Build:   2026-03-07_12:00:00
Commit:  f1a57ee
Go:      go1.25.0
OS/Arch: linux/amd64
```

---

### 4. falcn compliance

Generate machine-readable compliance artifacts for supply chain regulations.

```
falcn compliance [path] [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--framework string` | all | sbom, ssdf, slsa, cra, or all |
| `--out-dir path` | `.` | Output directory for generated artifacts |
| `--project-name string` | directory name | Project name for artifact metadata |
| `--project-version string` | 1.0.0 | Project version |
| `--supplier string` | — | Organisation name (required for EU CRA) |
| `--check-vulnerabilities` | true | Include vulnerability data in SBOM |
| `--no-llm` | true | Disable AI explanations (faster) |

**Frameworks:**

| Value | Produces |
|-------|----------|
| `sbom` | SPDX 2.3 JSON + CycloneDX 1.5 JSON |
| `ssdf` | NIST SP 800-218 attestation JSON |
| `slsa` | SLSA Level 1 provenance stub JSON |
| `cra` | sbom + ssdf + slsa (EU Cyber Resilience Act bundle) |
| `all` | All of the above (default) |

**Examples:**

Full compliance pack for EU CRA submission:

```bash
falcn compliance . \
  --framework cra \
  --supplier "Acme Corp" \
  --project-name "acme-api" \
  --project-version "2.3.0" \
  --out-dir ./compliance-artifacts/
```

Produces (in `./compliance-artifacts/`):

```
acme-api-sbom.spdx.json          # SPDX 2.3 — EO 14028 / EU CRA Art.13
acme-api-sbom.cdx.json           # CycloneDX 1.5 with VEX — EU CRA Art.13
acme-api-nist-ssdf-attestation.json  # NIST SP 800-218 control mapping
acme-api-slsa-provenance.json    # SLSA Level 1 provenance
```

SBOM only (for NIST SSDF attestation workflows):

```bash
falcn compliance . --framework sbom --out-dir ./sbom/
```

Use pre-existing policy files for OPA enforcement:

```bash
# Policies are evaluated automatically when placed in ./policies/
ls policies/
# block_critical.rego  nist_ssdf.rego  cra_sbom.rego
```

The `policies/block_critical.rego` policy blocks builds with critical threats:

```rego
package falcn.policy

deny[msg] {
  threat := input.threats[_]
  threat.severity == "critical"
  msg := sprintf("Critical threat detected: %s in %s", [threat.type, threat.package])
}
```

---

### 5. falcn scan-images

Scan OCI/Docker container images for CVEs and security misconfigurations.

```
falcn scan-images [image...] [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--light` | false | Skip layer downloads; analyse manifest and config only |
| `--format table\|json\|sarif` | table | Output format |
| `--out path` | stdout | Write output to a file |
| `--username string` | — | Registry username (or FALCN_REGISTRY_USER) |
| `--password string` | — | Registry password (or FALCN_REGISTRY_PASSWORD) |
| `--token string` | — | Bearer token (or FALCN_REGISTRY_TOKEN) |
| `--insecure` | false | Allow plain-HTTP registry connections |
| `--max-layer-mb int` | 100 | Skip layers larger than this size |
| `--dockerfile path` | — | Scan a Dockerfile for anti-patterns |

**Examples:**

```bash
# Scan multiple images
falcn scan-images nginx:1.27.2 python:3.12-slim node:20-alpine

# Fast scan (no layer downloads)
falcn scan-images --light ghcr.io/myorg/myapp:v1.0

# Scan a Dockerfile for anti-patterns
falcn scan-images --dockerfile Dockerfile

# Private registry with credentials
falcn scan-images \
  --username ci-bot \
  --password "$REGISTRY_PASSWORD" \
  myregistry.corp/backend:prod

# JSON output for downstream processing
falcn scan-images nginx:latest --format json --out image-report.json
```

---

### 6. falcn report

Generate a formatted report from the most recent scan (reads `falcn_report.json`
written by the last `falcn scan` invocation).

```
falcn report [flags]
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format string` | `-f` | html | Output format: html, json, markdown |
| `--file path` | `-i` | falcn_report.json | Input scan result file |

**Examples:**

```bash
# HTML report from the most recent scan
falcn report --format html > report.html

# Markdown report for GitHub wiki
falcn report --format markdown > SECURITY_REPORT.md

# Re-process a specific saved report
falcn report --file /var/log/falcn/2026-03-01-report.json --format html
```

---

### 7. falcn update-db

Download or refresh the local offline CVE database from OSV.dev.

```
falcn update-db [flags]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--db path` | `~/.local/share/falcn/cve.db` | SQLite database path |
| `--ecosystems list` | all | Comma-separated ecosystems to update |
| `--airgap-bundle` | false | Export a gzip bundle after updating |
| `--output path` | `<db-dir>/cve-bundle.json.gz` | Bundle output path |

**Examples:**

```bash
# Update all ecosystems
falcn update-db

# Update npm and PyPI only
falcn update-db --ecosystems npm,PyPI

# Build an air-gap bundle for offline transfer
falcn update-db --airgap-bundle --output /tmp/falcn-cve-bundle.json.gz
```

Output:

```
Opening local CVE database: /home/user/.local/share/falcn/cve.db
Last updated: 2026-03-01T10:00:00Z
Current entries: 245,318

Updating ecosystems: npm, PyPI, Go, Maven, NuGet, RubyGems, crates.io, Packagist

[1/8] Downloading npm...
[2/8] Downloading PyPI...
...

Update complete in 38.2s
  Fetched  : 12,844
  Inserted : 3,201
  Updated  : 9,643
  Total    : 248,519
```

---

## Interpreting Results

### Threat Types

| Type | What it means |
|------|---------------|
| `vulnerable` | Package version has one or more known CVEs |
| `malicious_package` | Package confirmed malicious (typosquatting payload, data exfil, etc.) |
| `typosquatting` | Package name is suspiciously similar to a popular, legitimate package |
| `embedded_secret` | Source file contains an API key, token, or credential |
| `obfuscated_code` | High entropy or encoded payload detected in source |
| `install_script` | `preinstall`/`postinstall` script makes suspicious network calls or file operations |
| `supply_chain_risk` | Dependency confusion, namespace squatting, or unexpected publisher |
| `cicd_injection` | CI/CD workflow file references untrusted external actions or script injection |
| `unexpected_binary` | Compiled binary bundled inside a source package |
| `low_reputation` | Package is very new, has few downloads, or no public repository |

### Severity Levels

| Severity | CVSS equivalent | Action |
|----------|-----------------|--------|
| `critical` | 9.0–10.0 | Block immediately — do not ship |
| `high` | 7.0–8.9 | Fix before next release |
| `medium` | 4.0–6.9 | Fix within sprint |
| `low` | 0.1–3.9 | Track; fix when convenient |

### Reachability

The `reachable` field indicates whether Falcn's static call-graph analysis has
confirmed that the vulnerable code path is actually reachable from the
application's entry points.

- `reachable: true` — the vulnerability is on a reachable call path; prioritize this fix.
- `reachable: false` — the vulnerable function exists in the dependency but is
  never called by your code; lower priority, but still worth tracking.
- `reachable: null` — reachability analysis was not performed (use
  `--advanced` or `--supply-chain` to enable it).

Focusing only on reachable vulnerabilities dramatically reduces false positives.
In large projects, 60–80% of CVEs are typically in unreachable code paths.

### Fixed Version and Remediation

When `fixed_version` is populated, a safe upgrade exists. The `remediation`
field contains the exact ecosystem command to run:

```json
{
  "package": "lodash",
  "version": "4.17.15",
  "fixed_version": "4.17.21",
  "remediation": "npm install lodash@4.17.21"
}
```

Pipe to `falcn fix` to apply all remediations in one step:

```bash
falcn scan . --output json | falcn fix --script | bash
```

---

## Output Formats

### Table (default)

Human-readable columnar output. Best for interactive use:

```bash
falcn scan .
```

### JSON

Machine-readable. Use for piping to `falcn fix`, `jq` post-processing, or
storing scan history:

```bash
falcn scan . --check-vulnerabilities --output json > report.json
jq '.threats[] | select(.severity == "critical")' report.json
```

### SARIF

Static Analysis Results Interchange Format — consumed by GitHub Code Scanning,
Azure DevOps, and security dashboards:

```bash
falcn scan . --output sarif > results.sarif
```

Upload to GitHub Code Scanning in a workflow:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### CycloneDX with VEX

EU Cyber Resilience Act-compliant SBOM that includes VEX (Vulnerability
Exploitability eXchange) statements. The `analysis.state` field on each
vulnerability reflects Falcn's reachability verdict:

```bash
falcn scan . --sbom-format cyclonedx --sbom-output sbom.cdx.json
```

Key VEX states in output:

| `analysis.state` | Meaning |
|------------------|---------|
| `exploitable` | Vulnerability confirmed reachable |
| `not_affected` | Vulnerability present but not reachable |
| `in_triage` | Reachability not yet determined |

### SPDX

NIST SSDF and US Executive Order 14028-compliant SBOM format:

```bash
falcn scan . --sbom-format spdx --sbom-output sbom.spdx.json
```

### PDF / HTML Report

Generate via the REST API after running a scan:

```bash
# The API server generates a rich PDF
curl -X POST http://localhost:8080/v1/reports/generate \
  -H "X-API-Key: $FALCN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "a3f8c1d2-..."}' \
  --output report.pdf
```

Or generate an HTML report from the CLI:

```bash
falcn scan . && falcn report --format html > report.html
```

---

## Configuration

Falcn loads configuration from (in order of precedence):

1. Flags passed on the command line
2. Environment variables (`FALCN_<SECTION>_<FIELD>`)
3. `.falcn.yaml` in the project directory
4. `~/.falcn.yaml` (user-level default)

### Full Configuration Reference

Place this file at `~/.falcn.yaml` or `.falcn.yaml` in your project root:

```yaml
# ~/.falcn.yaml — Falcn v2.3.0 configuration

app:
  environment: "production"   # development | staging | production
  log_level: "info"           # trace | debug | info | warn | error
  data_dir: "~/.local/share/falcn"
  max_workers: 4              # concurrent scan workers (default: CPU count)

server:
  host: "0.0.0.0"
  port: 8080
  read_timeout: "30s"
  write_timeout: "60s"
  idle_timeout: "120s"
  shutdown_timeout: "30s"
  # TLS: set FALCN_TLS_CERT and FALCN_TLS_KEY env vars

database:
  type: "sqlite"
  database: "~/.local/share/falcn/falcn.db"

scanner:
  max_concurrency: 8
  timeout: "30s"
  retry_attempts: 3
  respect_gitignore: true
  # skip_patterns:
  #   - "vendor/"
  #   - "*.generated.go"

  content:
    entropy_threshold: 4.5    # Shannon entropy threshold for obfuscation detection
    entropy_window: 256       # sliding window size in bytes
    max_files: 5000           # max files to inspect per scan
    max_workers: 4
    include_globs:
      - "**/*.js"
      - "**/*.py"
      - "**/*.go"
    exclude_globs:
      - "**/node_modules/**"
      - "**/.git/**"
    whitelist_extensions:
      - ".min.js"             # skip minified files

policies:
  fail_on_threats: true
  min_threat_level: "medium"  # low | medium | high | critical

typo_detection:
  enabled: true
  threshold: 0.85             # Jaro-Winkler similarity score
  edit_distance_threshold: 2
  phonetic_matching: true
  check_homoglyphs: true      # detect l→1, o→0 substitutions

ml:
  enabled: true
  model_path: ""              # leave empty to use built-in heuristic engine
  threshold: 0.5              # score >= threshold → malicious
  cache_size: 10000

# LLM explanations — optional, privacy-first with local Ollama
llm:
  enabled: true
  provider: "ollama"          # ollama | openai | anthropic
  ollama_host: "http://localhost:11434"
  model: "llama3.2"
  max_calls_per_scan: 5
  timeout: "60s"
  # For cloud providers, set via env:
  #   FALCN_LLM_PROVIDER=openai
  #   FALCN_OPENAI_API_KEY=sk-...
  #   FALCN_LLM_MODEL=gpt-4o-mini

output:
  default_format: "table"
  color: true

redis:
  enabled: false
  host: "localhost"
  port: 6379

metrics:
  enabled: false
  provider: "prometheus"
  address: ":9090"

features:
  ml_scoring: true
  caching: true
  webhooks: false
  bulk_scanning: true
  experimental_apis: false
```

---

## Air-gap / Offline Mode

Falcn supports fully air-gapped operation with zero outbound network access.

### Step 1: Download the CVE Database (internet-connected machine)

```bash
falcn update-db \
  --airgap-bundle \
  --output /tmp/falcn-cve-bundle.json.gz
```

This creates a compressed bundle of vulnerability data from OSV.dev for all
eight supported ecosystems.

### Step 2: Transfer the Bundle

Copy the bundle to the air-gapped machine using whatever secure transfer
mechanism is available (USB, enterprise file share, etc.).

### Step 3: Initialize the Local Database

```bash
falcn update-db --db /var/lib/falcn/cve.db
# Or import from the bundle (if your organisation uses a custom process)
```

### Step 4: Scan Offline

Use the `--offline` flag:

```bash
falcn scan . \
  --offline \
  --local-db /var/lib/falcn/cve.db \
  --check-vulnerabilities
```

Or set the environment variable to make offline mode the default:

```bash
export FALCN_OFFLINE=true
export FALCN_LOCAL_DB=/var/lib/falcn/cve.db
falcn scan .
```

The `--offline` flag is also activated automatically when the `FALCN_OFFLINE=true`
environment variable is set.

**What works offline:**

- Typosquatting detection (popular packages list is embedded in the binary)
- CVE lookup (via local SQLite database)
- ML scoring (heuristic engine is built-in; ONNX model must be bundled separately)
- Secret detection and obfuscation analysis
- SBOM generation
- CI/CD injection detection

**What requires network access:**

- Live package metadata from npm/PyPI/etc. registries
- LLM explanations (unless using a local Ollama instance on the same network)
- CVE database updates

---

## Troubleshooting

### "path is a file, not a directory — use --file"

You passed a file path as the positional argument. Use `--file` instead:

```bash
falcn scan --file package.json
```

### "invalid --sbom-format: must be one of: spdx, cyclonedx"

Only `spdx` and `cyclonedx` are supported SBOM formats. Do not use `CycloneDX`
(capitalised) — use the lowercase form:

```bash
falcn scan . --sbom-format cyclonedx   # correct
falcn scan . --sbom-format CycloneDX   # incorrect
```

### "local CVE database does not exist (required for --offline mode)"

Run `falcn update-db` first to populate the database, or point `--local-db` at
an existing database:

```bash
falcn update-db --db /var/lib/falcn/cve.db
falcn scan . --offline --local-db /var/lib/falcn/cve.db
```

### "could not parse scan output: unrecognised JSON shape"

`falcn fix` received input that does not match any known JSON structure. Ensure
you are piping from `falcn scan --output json` or reading a file written by
Falcn:

```bash
falcn scan . --output json | falcn fix     # correct
falcn scan .               | falcn fix     # incorrect (default output is not JSON)
```

### "no input: provide --input or pipe 'falcn scan . --output json | falcn fix'"

`falcn fix` was called with no arguments, no `--input` flag, and no data on
stdin. Provide a report file or pipe from `falcn scan`:

```bash
falcn fix --input falcn_report.json
```

### Scan is slow on large monorepos

Use `--fast` for heuristics-only analysis, limit ecosystems with
`--package-manager`, and disable LLM explanations with `--no-llm`:

```bash
falcn scan . --fast --no-llm --package-manager npm,pypi
```

### LLM explanations are not appearing

1. Check that a provider is configured. For Ollama: ensure `ollama serve` is
   running and the model is pulled (`ollama pull llama3.2`).
2. For cloud providers, set the API key:
   ```bash
   export FALCN_LLM_PROVIDER=openai
   export FALCN_OPENAI_API_KEY=sk-...
   ```
3. Ensure `--no-llm` is not set and `--max-llm-calls` is greater than 0.

### False positives from typosquatting detection

Lower the threshold to reduce sensitivity, or exclude known-good packages:

```bash
falcn scan . --threshold 0.95 --exclude my-internal-pkg,another-safe-pkg
```

### "scan failed: failed to create analyzer"

Falcn could not load a valid configuration. Run with `--verbose` to see the
specific error:

```bash
falcn scan . --verbose
```

Common causes: malformed `.falcn.yaml`, missing data directory, or a database
file with incorrect permissions.
