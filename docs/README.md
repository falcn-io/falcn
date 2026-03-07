# Falcn

[![Go Version](https://img.shields.io/badge/go-1.25+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](../LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)
[![Go Report Card](https://goreportcard.com/badge/github.com/falcn-io/falcn)](https://goreportcard.com/report/github.com/falcn-io/falcn)

**The supply chain security scanner that tells you what's actually exploitable.**

Falcn is a Go-based supply chain security scanner covering 8 package ecosystems. It detects
malicious packages, typosquatting, embedded secrets, CI/CD vulnerabilities, and CVEs — then uses
reachability analysis to tell you which findings are actually exploitable from your code's entry
points, eliminating alert fatigue from unreachable vulnerabilities.

---

## Why Falcn

Most scanners give you a list of CVEs. Falcn gives you a list of CVEs **you actually need to fix**.

| Capability | Falcn | Most scanners |
|---|---|---|
| Reachability analysis (Go, Python, JS) | Yes | No |
| VEX output with `analysis.state` | Yes | Rarely |
| `falcn fix` — generates upgrade commands | Yes | No |
| ML 25-feature ensemble per package | Yes | No |
| EU CRA compliance (Art.13, Art.14) | Yes | No |
| 8 ecosystems from one binary | Yes | Partial |
| Air-gap / offline mode | Yes | Rarely |
| SSE real-time streaming API | Yes | No |

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Commands](#core-commands)
- [CI/CD Integration](#cicd-integration)
- [Output Formats](#output-formats)
- [EU CRA Compliance](#eu-cra-compliance)
- [REST API](#rest-api)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

---

## Installation

### Homebrew (macOS and Linux)

```bash
brew install falcn-io/tap/falcn
```

### Binary Download

Download the pre-built binary for your platform from
[GitHub Releases](https://github.com/falcn-io/falcn/releases/latest).

**Linux (amd64)**
```bash
curl -Lo falcn https://github.com/falcn-io/falcn/releases/latest/download/falcn-linux-amd64
chmod +x falcn
sudo mv falcn /usr/local/bin/falcn
```

**Linux (arm64)**
```bash
curl -Lo falcn https://github.com/falcn-io/falcn/releases/latest/download/falcn-linux-arm64
chmod +x falcn
sudo mv falcn /usr/local/bin/falcn
```

**macOS (amd64)**
```bash
curl -Lo falcn https://github.com/falcn-io/falcn/releases/latest/download/falcn-darwin-amd64
chmod +x falcn
sudo mv falcn /usr/local/bin/falcn
```

**macOS (arm64 / Apple Silicon)**
```bash
curl -Lo falcn https://github.com/falcn-io/falcn/releases/latest/download/falcn-darwin-arm64
chmod +x falcn
sudo mv falcn /usr/local/bin/falcn
```

**Windows (amd64)**

Download `falcn-windows-amd64.exe` from the releases page and add it to your `PATH`.

### From Source

Requires Go 1.25+.

```bash
git clone https://github.com/falcn-io/falcn
cd falcn
make build
# Binary is output to ./build/falcn
```

### Docker

```bash
docker pull ghcr.io/falcn-io/falcn:latest
docker run --rm -v $(pwd):/workspace ghcr.io/falcn-io/falcn:latest scan /workspace
```

### Verify Installation

```bash
falcn version
# falcn v2.3.0 (go1.25, darwin/arm64)
```

---

## Quick Start

Scan a project and see results in under 30 seconds:

```bash
# Scan the current directory
falcn scan .

# Example output:
# Scanning /workspace (npm, PyPI detected)
# [████████████████████] 142 packages scanned in 4.2s
#
# CRITICAL  lodash-utils@1.0.2  — MALICIOUS: exfiltrates AWS credentials via install script
#           CVE-2024-28849 (CVSS 9.1) — reachable from src/api/client.js:47
#
# HIGH      recat@0.18.2        — TYPOSQUATTING: 2-edit distance from 'react' (edit: transposition)
#
# HIGH      requests@2.28.0     — CVE-2023-32681 (CVSS 6.1) — NOT reachable (suppressed in SARIF)
#           VEX state: not_affected / code_not_reachable
#
# MEDIUM    axios@0.21.1        — CVE-2021-3749 (CVSS 6.5) — reachable from src/http/client.js:12
#
# Summary: 4 findings (1 critical, 2 high, 1 medium) — 3 require action, 1 suppressed
```

Use `--fast` for sub-100ms scans using heuristics only (ideal for pre-commit):

```bash
falcn scan --fast .
```

Scan offline in air-gapped environments:

```bash
falcn scan --offline .
```

---

## Core Commands

Falcn has 8 subcommands. The most commonly used are `scan`, `fix`, and `policy`.

### falcn scan

Scan a project directory or a specific manifest file.

```bash
# Scan a directory (auto-detects ecosystems)
falcn scan /path/to/project

# Scan a specific manifest
falcn scan --manifest package-lock.json .

# Select output format
falcn scan --format sarif --output falcn.sarif .
falcn scan --format cyclonedx --output sbom.json .
falcn scan --format spdx --output sbom.spdx .
falcn scan --format pdf --output report.pdf .

# Block the pipeline on severity threshold
falcn scan --fail-on high .

# Heuristics-only mode — results in < 100ms
falcn scan --fast .

# Air-gap mode — uses bundled SQLite CVE database, no outbound calls
falcn scan --offline .

# Write raw scan results to JSON for use by falcn fix
falcn scan --output scan.json .
```

**Supported ecosystems:** npm, PyPI, Maven, Go, NuGet, RubyGems, Cargo, Composer

### falcn fix

Reads a scan result JSON file and generates ecosystem-specific upgrade commands to remediate
findings. No guessing — it resolves the minimum safe version from the OSV and GitHub Advisory
databases.

```bash
# Print upgrade commands to stdout
falcn fix scan.json

# Example output:
# npm install lodash@4.17.21
# pip install requests==2.31.0
# go get golang.org/x/net@v0.17.0

# Output as a shell script
falcn fix --script scan.json > remediate.sh
bash remediate.sh

# Output as a JSON patch manifest for programmatic use
falcn fix --patch-file patches.json scan.json
```

### falcn policy

Evaluate a scan result against OPA (Open Policy Agent) Rego policies. Falcn ships three
compliance policy templates.

```bash
# Evaluate against a built-in policy
falcn policy eval --policy block_critical scan.json
falcn policy eval --policy nist_ssdf scan.json
falcn policy eval --policy cra_sbom scan.json

# Evaluate against a custom Rego file
falcn policy eval --policy-file ./policies/my-policy.rego scan.json

# List available built-in policies
falcn policy list

# Validate a Rego file before use
falcn policy validate --policy-file ./policies/my-policy.rego
```

Built-in policies:

| Policy file | Purpose |
|---|---|
| `block_critical.rego` | Fail on any CVSS >= 9.0 finding |
| `nist_ssdf.rego` | NIST Secure Software Development Framework checks |
| `cra_sbom.rego` | EU Cyber Resilience Act SBOM completeness requirements |

### Other subcommands

```bash
falcn version          # Print version and build metadata
falcn serve            # Start the REST API server
falcn sbom             # Generate SBOM without threat analysis
falcn completion       # Shell completion scripts (bash, zsh, fish, powershell)
```

---

## CI/CD Integration

### GitHub Actions

Use the official Falcn GitHub Action. Results are uploaded to GitHub Advanced Security as SARIF
and PR annotations are posted automatically.

```yaml
# .github/workflows/supply-chain.yml
name: Supply Chain Security

on:
  push:
    branches: [main]
  pull_request:

jobs:
  falcn:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - uses: falcn-io/falcn@v2
        with:
          path: .
          fail-on: high
          sarif-output: falcn.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: falcn.sarif
```

The action configuration file is at
[`deploy/github-action/action.yml`](../deploy/github-action/action.yml). It caches the Falcn
binary between runs for faster CI execution.

### GitLab CI

Include the Falcn GitLab CI template directly from the repository:

```yaml
# .gitlab-ci.yml
include:
  - project: falcn-io/falcn
    file: deploy/gitlab-template/.gitlab-ci.yml

variables:
  FALCN_FAIL_ON: high
  FALCN_SARIF_OUTPUT: falcn.sarif
```

The template provides two jobs: `falcn:full` (all detectors, runs on merge requests) and
`falcn:fast-gate` (heuristics-only, < 100ms, runs on every push). The template file is at
[`deploy/gitlab-template/.gitlab-ci.yml`](../deploy/gitlab-template/.gitlab-ci.yml).

### Pre-commit Hook

Block installs before they reach the repository. The hook scans dependency manifest changes
(e.g., `package.json`, `requirements.txt`, `go.mod`) on every `git commit`.

```bash
# Install the pre-commit hook
cp deploy/pre-commit-hook/falcn-pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Or integrate with the pre-commit framework:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/falcn-io/falcn
    rev: v2.3.0
    hooks:
      - id: falcn
        args: [--fast, --fail-on, high]
```

The hook script is at
[`deploy/pre-commit-hook/falcn-pre-commit`](../deploy/pre-commit-hook/falcn-pre-commit).

---

## Output Formats

### SARIF

Static Analysis Results Interchange Format — compatible with GitHub Advanced Security, VS Code,
and any SARIF-aware tool.

```bash
falcn scan --format sarif --output falcn.sarif .
```

Falcn SARIF output includes:
- `suppressions` on results for threats that are not reachable from entry points (VEX state:
  `not_affected / code_not_reachable`), keeping your Security tab clean.
- Rule metadata with CVSS scores and CWE IDs.
- Location-aware results pointing to the manifest line that introduces each dependency.

### CycloneDX with VEX

Falcn produces CycloneDX 1.5 SBOM documents with embedded Vulnerability Exploitability eXchange
(VEX) data. The `analysis.state` field is populated from reachability analysis results.

```bash
falcn scan --format cyclonedx --output sbom.cdx.json .
```

VEX `analysis.state` values used by Falcn:

| State | Meaning |
|---|---|
| `exploitable` | Vulnerability is reachable and exploitable |
| `in_triage` | Under investigation |
| `not_affected` | Code path is not reachable from entry points |
| `fixed` | Remediated version is available and specified |

### SPDX

```bash
falcn scan --format spdx --output sbom.spdx.json .
```

Produces SPDX 2.3 JSON. Suitable for EU CRA SBOM submission requirements.

### PDF

```bash
falcn scan --format pdf --output report.pdf .
```

Generates a human-readable executive report with risk summary, finding details, and remediation
guidance. Suitable for sharing with security teams or auditors.

---

## EU CRA Compliance

The EU Cyber Resilience Act mandates security requirements for products with digital elements.
**Article 13 and Article 14 obligations take effect September 11, 2026.**

Falcn covers the following CRA obligations:

| CRA Requirement | Falcn Capability |
|---|---|
| Art. 13(1) — Vulnerability identification | OSV + GitHub Advisory DB scanning |
| Art. 13(2) — SBOM generation | CycloneDX 1.5 and SPDX 2.3 output |
| Art. 13(5) — VEX / exploitability | Reachability analysis + VEX `analysis.state` |
| Art. 13(6) — Coordinated disclosure | `SECURITY.md` template generation |
| Art. 14 — Actively exploited CVE reporting | CVSS-gated alerting via policy engine |

To run a CRA-focused scan and validate SBOM completeness:

```bash
# Generate CycloneDX SBOM with VEX
falcn scan --format cyclonedx --output sbom.cdx.json .

# Validate SBOM meets CRA requirements via the built-in policy
falcn policy eval --policy cra_sbom sbom.cdx.json
```

For teams approaching the September 2026 deadline, see the
[EU CRA integration guide](INTEGRATIONS.md#eu-cra).

---

## REST API

Falcn includes a production-ready REST API server with 16 endpoints, JWT and API key
authentication, SSE real-time streaming, and tiered rate limits.

### Starting the API Server

```bash
falcn serve --config falcn.yaml
```

### Authentication

```bash
# API key
curl -H "X-API-Key: <your-key>" http://localhost:8080/v1/health

# JWT bearer token
curl -H "Authorization: Bearer <jwt>" http://localhost:8080/v1/health
```

### Rate Limit Tiers

| Tier | Requests / minute |
|---|---|
| Free | 10 |
| Viewer | 50 |
| Analyst | 200 |
| Admin | 1000 |

### Common Endpoints

```bash
# Health check
GET /v1/health

# Submit a scan
POST /v1/scan
Content-Type: application/json
{"path": "/workspace", "format": "cyclonedx"}

# Get scan results
GET /v1/scan/{scan_id}

# Real-time threat stream (Server-Sent Events)
GET /v1/stream
Accept: text/event-stream

# OpenAPI / Swagger UI
GET /docs
```

The SSE stream at `GET /v1/stream` emits `threat` events as packages are analyzed and a `done`
event on completion, allowing dashboards and IDE extensions to display results in real time.

The full OpenAPI 3.1.0 specification is served at `GET /docs` (Swagger UI) and available as
JSON at [`docs/openapi.json`](openapi.json).

For complete endpoint documentation, authentication details, request/response schemas, and
error codes, see the [API Reference](API_REFERENCE.md).

---

## Configuration

Falcn looks for `falcn.yaml` (or `.falcn.yaml`) in the working directory, `$HOME/.config/falcn/`,
or the path given by `--config`.

```yaml
# falcn.yaml

version: "2"

scan:
  ecosystems:
    - npm
    - pypi
    - go
    - maven
    - nuget
    - rubygems
    - cargo
    - composer
  workers: 4            # concurrent package analysis workers
  fast: false           # heuristics-only mode (< 100ms)
  offline: false        # air-gap mode; uses bundled SQLite CVE DB
  fail_on: high         # severity threshold: critical | high | medium | low

output:
  format: sarif         # sarif | cyclonedx | spdx | pdf | json
  file: falcn.sarif

api:
  host: "0.0.0.0"
  port: 8080
  jwt_secret: "${FALCN_JWT_SECRET}"
  cors_origins: "${FALCN_CORS_ORIGINS}"   # comma-separated allowed origins
  rate_limits:
    free: 10
    viewer: 50
    analyst: 200
    admin: 1000

ml:
  enabled: true
  model_path: "./models/falcn.onnx"       # optional ONNX model; pure-Go fallback if absent
  threshold: 0.65

policy:
  files:
    - ./policies/block_critical.rego
    - ./policies/cra_sbom.rego

vulnerability:
  databases:
    - osv
    - github_advisory
  offline_db: "./data/cve.db"             # SQLite DB used in --offline mode
```

Environment variables take precedence over file values. All string config values support
`${ENV_VAR}` interpolation.

---

## Architecture

```
                      falcn CLI / REST API
                             |
                    ┌────────┴────────┐
                    │  Core Engine    │
                    │  (orchestrator) │
                    └────────┬────────┘
           ┌─────────────────┼─────────────────┐
           |                 |                 |
    ┌──────┴──────┐  ┌───────┴──────┐  ┌──────┴──────┐
    │  Scanner    │  │  Detector    │  │  ML Engine  │
    │  Engine     │  │  Engine      │  │  (25-feat.) │
    └──────┬──────┘  └───────┬──────┘  └──────┬──────┘
           |                 |                 |
    ┌──────┴──────┐  ┌───────┴──────┐  ┌──────┴──────┐
    │  Content    │  │ Typosquatting│  │  Reachability│
    │  Scanner    │  │ + DIRT graph │  │  Analyzers  │
    │  CI/CD scan │  │ Secrets      │  │ (Go/Py/JS)  │
    └─────────────┘  └─────────────┘  └─────────────┘
           |
    ┌──────┴──────────────────────────────────────┐
    │  Vulnerability DBs: OSV + GitHub Advisory   │
    │  Policy Engine: OPA / Rego                  │
    │  Output: SARIF · CycloneDX+VEX · SPDX · PDF │
    └─────────────────────────────────────────────┘
```

**Key components:**

- `main.go` + `cmd/` — Cobra CLI entry point with 8 subcommands
- `api/main.go` — REST API server (Gorilla Mux, SSE broker, JWT middleware)
- `internal/scanner/scanner.go` — core orchestration, 4-worker bounded pool
- `internal/scanner/unified_scanner.go` — concurrent content + network + CI/CD scanning
- `internal/detector/` — typosquatting (enhanced Levenshtein/Jaro-Winkler), DIRT/GTR graph,
  reputation engine
- `internal/ml/` — 25-feature extractor, ensemble inference, feedback store, model registry
- `internal/vulnerability/` — OSV database client, GitHub Advisory client, semver range engine
- `internal/llm/` — LLM explanation layer (Ollama / OpenAI / Anthropic) with prompt injection
  guardrails
- `internal/supplychain/` — OPA policy engine, Rego evaluation, compliance report generation

**ML engine features (25 total):** install scripts, maintainer velocity, domain age, entropy,
dependency delta, stars/forks, namespace age, download anomaly, and 17 additional behavioral
and metadata signals. A pure-Go heuristic fallback is used when no ONNX model file is present.

**Reachability analysis:** Static call-graph analyzers for Go, Python, and JavaScript walk from
configured entry points and determine whether a vulnerable code path is actually callable. Results
drive the VEX `analysis.state` field and SARIF suppressions.

For a full component diagram and data flow description, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](../CONTRIBUTING.md) before opening a
pull request.

```bash
# Clone and set up
git clone https://github.com/falcn-io/falcn
cd falcn

# Build
make build

# Run tests
go test ./... -v

# Lint
golangci-lint run

# Secret scan (required before submitting a PR)
gitleaks detect --source . --config-path .gitleaks.toml
```

**Reporting security vulnerabilities:** Please follow the process described in
[SECURITY.md](../SECURITY.md). Do not open a public issue for security bugs.

---

## License

Falcn is licensed under the [Apache License 2.0](../LICENSE).

Copyright 2024-2026 falcn-io contributors.

---

*Built for teams that need to know what's actually exploitable, not just what's theoretically
vulnerable.*
