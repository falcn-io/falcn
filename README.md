<div align="center">
  <img src="docs/assets/logo.png" alt="Falcn" width="200">
  <h1>Falcn</h1>
  <p><strong>AI-Native Supply Chain Security Platform</strong></p>
  <p>
    <a href="https://falcn.io">Website</a> •
    <a href="docs/USER_GUIDE.md">Docs</a> •
    <a href="docs/PRODUCTION_GUIDE.md">Deploy</a> •
    <a href="https://github.com/falcn-io/falcn/releases">Releases</a>
  </p>
  <p>
    <img src="https://img.shields.io/badge/go-1.24+-blue?logo=go" alt="Go Version">
    <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
    <img src="https://img.shields.io/badge/release-v3.0.0-blue" alt="Release">
    <img src="https://img.shields.io/badge/build-passing-brightgreen" alt="Build">
  </p>
</div>

---

**Falcn** is an enterprise-grade, privacy-first supply chain security scanner. It combines production ML scoring, behavioral heuristics, real vulnerability databases, and local LLM explanations — all running on your infrastructure with no data leaving your environment.

---

## ⚡ Quick Install

**Docker Compose (full stack — API + Web dashboard)**
```bash
cp .env.example .env          # fill in API_KEYS and FALCN_CORS_ORIGINS
docker compose up -d
# Web dashboard → http://localhost:3000
# API           → http://localhost:8082
```

**CLI only**
```bash
go install github.com/falcn-io/falcn@latest
falcn scan .
```

**Binary**
```bash
# Linux
curl -sSL https://github.com/falcn-io/falcn/releases/latest/download/falcn-linux-amd64 \
  -o falcn && chmod +x falcn && sudo mv falcn /usr/local/bin/
```

---

## 🚀 What's in v3

### 🔍 Detection (real implementations, no stubs)
| Detector | Technique | Status |
|---|---|---|
| Typosquatting | Levenshtein + Jaro-Winkler + homoglyphs | ✅ |
| Malicious code | Entropy analysis + AST pattern matching | ✅ |
| Behavioral signals | Network calls, FS access, data collection | ✅ |
| CVE / vulnerability | Semver range matching vs. OSV + NVD | ✅ |
| Dependency confusion | Namespace gap + popularity analysis | ✅ |
| Secret leaks | Regex + entropy for 40+ credential types | ✅ |
| CI/CD injection | Pipeline file static analysis | ✅ |

### 🧠 ML Pipeline
- **25-feature classifier**: install scripts, maintainer velocity, domain age, entropy histogram, dependency delta, star/fork anomaly
- **Ensemble model**: RandomForest + GradientBoosting + LightGBM (exported to ONNX)
- **Feedback loop**: false-positive store, nightly retraining trigger, A/B model versioning
- **Graceful fallback**: heuristic scoring when no model file present

### 🤖 AI Explanations
Every detected threat gets a structured AI explanation rendered live in the web dashboard:
- **What** — one-sentence threat summary
- **Why** — technical evidence
- **Impact** — blast radius assessment
- **Fix** — specific remediation with version or alternative package
- Explanations are **cached in SQLite** (7-day TTL) and streamed via SSE — no reload needed
- Works with **Ollama** (local/air-gapped), **OpenAI**, or **Anthropic**

### ⚡ Speed
| Mode | Typical time |
|---|---|
| `--fast` (heuristics only, no network) | < 100 ms |
| Full scan (deep analysis + AI) | 2–5 s |
| Batch (100 packages) | < 10 s |

### 🌐 Web Dashboard
A React 19 + Vite 7 dashboard with:
- Live threat feed via Server-Sent Events (SSE)
- Expandable AI explanation panels per threat
- Severity filtering, search, pagination
- Scan history and metrics charts
- Served via nginx in Docker; configurable API proxy

### 🔒 CI/CD Native
```yaml
# GitHub Actions (one-liner)
uses: falcn-io/falcn-action@v1
with:
  fail-on: high
  output-format: sarif

# GitLab CI (include template)
include:
  - project: 'falcn-io/falcn'
    file: 'deploy/gitlab-template/.gitlab-ci.yml'
```

Also ships a **pre-commit hook** that blocks installs on dependency file changes.

---

## 💻 CLI Quick Start

```bash
# Scan current project
falcn scan .

# Fast mode for CI gates (< 100ms)
falcn scan . --fast --fail-on high

# With AI explanations (requires LLM provider)
export FALCN_OLLAMA_HOST=http://localhost:11434
falcn scan . --llm-provider ollama

# Output SARIF for GitHub Security tab
falcn scan . --output-format sarif --output falcn.sarif

# Batch scan from lock file
falcn scan package-lock.json --check-vulnerabilities
```

### Key flags
| Flag | Description |
|---|---|
| `--fast` | Heuristics only, no network — sub-100ms |
| `--fail-on <sev>` | Exit 1 if threats ≥ severity (critical\|high\|medium\|low) |
| `--no-llm` | Skip AI explanations |
| `--max-llm-calls <n>` | Limit LLM calls (default: 10) |
| `--output-format` | json \| sarif \| spdx \| cyclonedx |
| `--check-vulnerabilities` | Include OSV/NVD CVE checks |
| `--threshold <0-1>` | Minimum risk score to report (default: 0.7) |

---

## 🏗️ Architecture

```
CLI  ──────────────────────────────────────────────────────┐
                                                            │
REST API  ─────────────────────────────────────────────┐   │
Web Dashboard (React + SSE)  ──────────────────────┐   │   │
                                                    ▼   ▼   ▼
                                           ┌─── Falcn Core ───┐
                                           │                   │
                                 ┌─────────┴────────┐         │
                                 │  Scanner Engine   │         │
                                 │  ┌─────────────┐  │         │
                                 │  │ Heuristics  │  │         │
                                 │  │ ML (ONNX)   │  │         │
                                 │  │ Behavioral  │  │         │
                                 │  │ CVE/OSV/NVD │  │         │
                                 │  └─────────────┘  │         │
                                 └─────────┬────────┘         │
                                           │ Threats           │
                                           ▼                   │
                                 ┌─────────────────┐          │
                                 │  LLM Explainer  │          │
                                 │  (cached, async) │          │
                                 └─────────────────┘          │
                                           │                   │
                                           ▼                   │
                                 ┌─────────────────┐          │
                                 │  SQLite Store   │          │
                                 │  + SSE Broker   │          │
                                 └─────────────────┘          │
                                                    └──────────┘
```

For the full architecture reference see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 🔐 Security & Privacy

- **No telemetry** — zero data leaves your network
- **Air-gap ready** — embedded popular-packages DB, offline CVE bundle via `make airgap-bundle`
- **Auth** — RS256 JWT + API key; auto-dev-mode disabled in production
- **CORS** — specific header allowlist; required origins enforced in production
- **Metrics endpoint** — restricted to internal/RFC-1918 networks by default
- **File permissions** — all output files written `0600`

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Quick start:
```bash
make test          # run unit + integration tests
make quality       # lint + vet + staticcheck + gosec
make pre-commit    # full pre-commit gate
```

## 📄 License

Falcn is open-source software licensed under the [MIT License](LICENSE).

---
<div align="center">
  <sub>Built with ❤️ by the Falcn Community</sub>
</div>
