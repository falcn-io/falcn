# Falcn v2.3.0 — Feature Status Audit

This document is the authoritative, honest record of what is actually implemented in Falcn
v2.3.0 versus what is scaffolded, partial, or not yet built. It is updated whenever the
implementation status of a feature changes.

Status icons:
- Implemented — feature is fully coded, wired end-to-end, and exercised by at least one test
- Partial — core logic exists but coverage, edge-cases, or wiring is incomplete
- Scaffolded/Stub — package and types exist; production logic is not yet present
- Not implemented — no code exists for this feature

---

## CLI Commands

| Command | Status | Notes |
|---|---|---|
| `falcn scan [path]` | Implemented | Full project scan with auto-detected ecosystem; SBOM output via `--sbom-format`; parallel 4-worker package loop; `--fast` heuristics mode |
| `falcn fix` | Implemented | Reads JSON scan output; emits remediation commands, shell script (`-s`), or patch manifest (`-p`); `--only-reachable` filter |
| `falcn version` | Implemented | Prints version, build timestamp, and commit hash |
| `falcn compliance [path]` | Implemented | Generates SPDX 2.3, CycloneDX 1.5, NIST SSDF attestation, SLSA Level 1 stub, and compliance-gap report; supports `--framework cra|sbom|ssdf|slsa|all` |
| `falcn report` | Implemented | Reads `falcn_report.json`; emits HTML, JSON, or Markdown report |
| `falcn scan image` | Implemented | Container image and Dockerfile scanning via `internal/container`; flags for credentials, insecure registries, and layer size limits |
| `falcn db update` | Implemented | Downloads OSV and NVD advisory data; `--airgap` flag creates an offline bundle |
| `falcn serve` | Not implemented | No `serve` subcommand exists in `cmd/`. The REST API server is started via `api/main.go` directly (e.g. `go run ./api`), not through a CLI subcommand. |

---

## Detection Methods

| Method | Status | Notes |
|---|---|---|
| Typosquatting (edit distance, Jaro-Winkler, visual similarity, homoglyphs) | Implemented | `internal/detector/enhanced_typosquatting.go`; production-grade with homoglyph map and visual confusable detection |
| Malicious package detection (behavioral patterns, install scripts, post-install hooks) | Implemented | `internal/scanner/scanner.go` runs 13 behavioral pattern matchers against real file content; `internal/scanner/content_scanner.go` |
| Embedded secrets scanning (regex + entropy) | Implemented | `internal/secrets/`; high-entropy string detection combined with secret-pattern regexes |
| CI/CD vulnerability scanning (injection, misconfigured workflows) | Implemented | `internal/scanner/cicd_scanner.go` |
| CVE/vulnerability scanning (OSV, GitHub Advisory) | Implemented | `internal/vulnerability/osv_database.go` and `github_database.go`; real semver range checking with CVSS vector parsing |
| ML-based threat scoring (25-feature ensemble + heuristic fallback) | Implemented | `internal/ml/features.go` extracts 25 features; `internal/ml/inference.go` computes calibrated score; graceful ONNX model fallback to heuristic |
| Reachability analysis (Go, Python, JS) | Implemented | `internal/reachability/` with per-language analyzers (`go_analyzer.go`, `python_analyzer.go`, `js_analyzer.go`) and entry-point detection |
| Dynamic sandbox analysis | Partial | `internal/sandbox/docker_sandbox.go` uses a Docker-based sandbox; requires Docker daemon with privileged mode — not available in all CI environments |
| DIRT/GTR graph risk scoring | Implemented | `internal/edge/dirt.go`; business-aware risk scoring over the dependency graph |
| Reputation engine (npm, PyPI metadata) | Implemented | `internal/detector/` reputation engine fetches npm and PyPI registry metadata; live API calls (flagged in existing test failures) |

---

## Package Ecosystems

| Ecosystem | Status | Notes |
|---|---|---|
| npm | Implemented | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| PyPI | Implemented | `requirements.txt`, `Pipfile`, `Pipfile.lock`, `pyproject.toml`, `poetry.lock` |
| Go | Implemented | `go.mod`, `go.sum` |
| Maven | Implemented | `pom.xml` |
| Gradle | Implemented | `build.gradle`, `build.gradle.kts` |
| NuGet | Implemented | Detected by scanner; manifest parsing |
| RubyGems | Implemented | `Gemfile`, `Gemfile.lock` |
| Cargo (Rust) | Implemented | `Cargo.toml`, `Cargo.lock` |
| Composer (PHP) | Implemented | `composer.json`, `composer.lock` |
| Container images (OS packages) | Implemented | `internal/container/`; layer-by-layer scanning via `falcn scan image` |

---

## Output Formats

| Format | Status | Notes |
|---|---|---|
| SARIF 2.1.0 | Implemented | Includes `suppression` objects for unreachable findings |
| CycloneDX 1.5 | Implemented | Includes `vulnerabilities` array and VEX `analysis` field; EU CRA compliant |
| SPDX 2.3 | Implemented | JSON serialisation; generated via `compliance` command and `--sbom-format spdx` |
| PDF | Implemented | `internal/output/` PDF renderer |
| JSON | Implemented | Default machine-readable format; used by `fix`, `report`, and CI integrations |
| Table | Implemented | Default human-readable terminal output |
| HTML | Implemented | `falcn report --format html` |
| Markdown | Implemented | `falcn report --format markdown` |

---

## API Endpoints

All endpoints are registered in `api/main.go`. Authentication uses JWT bearer tokens or API
keys; RBAC roles are `viewer`, `analyst`, `admin`, `owner`.

| Endpoint | Method | Min Role | Status | Notes |
|---|---|---|---|---|
| `GET /health` | GET | Public | Implemented | Liveness probe; no auth required |
| `GET /ready` | GET | Public | Implemented | Readiness probe; no auth required |
| `GET /v1/status` | GET | Public | Implemented | Extended status; used by load balancers and uptime monitors |
| `POST /v1/auth/token` | POST | Public | Implemented | Exchanges API key for signed JWT |
| `POST /v1/analyze` | POST | Analyst | Implemented | Single-package threat analysis; rate-limited; Redis distributed limiter when `RATE_LIMIT_REDIS_URL` is set |
| `POST /v1/analyze/batch` | POST | Analyst | Implemented | Batch analysis; maximum 100 packages per request |
| `POST /v1/analyze/image` | POST | Analyst | Implemented | Container image and Dockerfile scanning |
| `GET /v1/stats` | GET | Viewer | Implemented | Aggregate scan statistics |
| `GET /v1/vulnerabilities` | GET | Viewer | Implemented | Paginated vulnerability list |
| `GET /v1/scans` | GET | Viewer | Implemented | Scan history (last 500 records in memory) |
| `GET /v1/threats` | GET | Viewer | Implemented | Paginated threat list with filters |
| `GET /v1/dashboard/metrics` | GET | Viewer | Implemented | Dashboard aggregate metrics |
| `GET /v1/dashboard/performance` | GET | Viewer | Implemented | Scanner performance metrics |
| `POST /v1/reports/generate` | POST | Analyst | Implemented | On-demand report generation (JSON, SARIF, CycloneDX, SPDX) |
| `GET /v1/stream` | GET | Analyst | Implemented | SSE real-time stream; publishes `connected`, `scan_started`, `threat`, `explanation`, `done`, `ping` events; 15 s keepalive heartbeat |
| `GET /metrics` | GET | Internal | Implemented | Prometheus metrics; restricted to `METRICS_ALLOWED_CIDRS` (default: loopback) |
| `GET /metrics.json` | GET | Internal | Implemented | JSON metrics mirror of `/metrics`; same CIDR restriction |
| `GET /openapi.json` | GET | Public | Implemented | OpenAPI 3.0 spec served from `docs/openapi.json` |
| `GET /docs` | GET | Public | Implemented | Swagger UI served from `docs/swagger.html` |

---

## Compliance Frameworks

| Framework | Status | Notes |
|---|---|---|
| EU CRA (Art. 13, Art. 14, Rec. 58) | Implemented | CycloneDX VEX output; `cra_sbom.rego` OPA policy; `falcn compliance --framework cra`; critical CVE disclosure flag |
| NIST SSDF (SP 800-218) | Implemented | SSDF attestation report mapping scan results to SSDF controls |
| SLSA Level 1–2 | Partial | Level 1 provenance stub generated by `compliance` command; Level 2 requires signed provenance via a separate build system (not automated by Falcn) |
| SOC 2 | Scaffolded/Stub | Audit log fields exist; no automated SOC 2 report or control mapping |
| FedRAMP | Not implemented | No FedRAMP control mapping or OSCAL output |

---

## Integrations

| Integration | Status | Notes |
|---|---|---|
| GitHub Action | Implemented | `deploy/github-action/action.yml`; binary caching, PR annotation, severity gate, SARIF upload |
| GitLab CI | Implemented | `deploy/gitlab-template/.gitlab-ci.yml`; full scan + fast-gate jobs; binary caching |
| Pre-commit hook | Implemented | `deploy/pre-commit-hook/falcn-pre-commit`; triggers only when dependency files are staged |
| Slack webhook | Implemented | `internal/integrations/connectors/slack.go` |
| Splunk HEC | Implemented | `internal/integrations/connectors/splunk.go` |
| Generic webhook | Implemented | `internal/integrations/connectors/webhook.go`; custom headers, bearer auth, retry |
| Email SMTP | Implemented | `internal/integrations/connectors/email.go`; TLS support |
| Jira | Implemented | `internal/integrations/connectors/jira.go`; creates issues on threat detection |
| Microsoft Teams | Implemented | `internal/integrations/connectors/teams.go`; webhook-based card messages |
| Elasticsearch | Implemented | `internal/integrations/connectors/elasticsearch.go` |
| QRadar | Implemented | `internal/integrations/connectors/qradar.go` |
| VS Code extension | Scaffolded/Stub | Code exists; not yet published to VS Code Marketplace |
| JetBrains plugin | Scaffolded/Stub | Code exists; not yet published to JetBrains Marketplace |
| PagerDuty | Partial | Supported via the generic webhook connector; no native PagerDuty connector with incident lifecycle management |
| Bitbucket Pipelines | Partial | Shell-script example provided in documentation; no first-party Bitbucket Pipe published |
| Azure DevOps | Partial | Shell-script example provided in documentation; no first-party Azure DevOps extension published |

---

## Infrastructure and Platform Features

| Feature | Status | Notes |
|---|---|---|
| SSE real-time streaming | Implemented | `/v1/stream` with `SSEBroker` pub/sub; 15 s heartbeat; nginx buffering disabled via `X-Accel-Buffering: no` |
| In-process rate limiting | Implemented | `golang.org/x/time/rate` token-bucket limiter per IP; default 10 req/min |
| Redis distributed rate limiting | Implemented | `internal/api/middleware/`; activated when `RATE_LIMIT_REDIS_URL` env var is set; falls back to in-process limiter |
| JWT authentication | Implemented | `POST /v1/auth/token` issues signed JWTs; `authMiddleware` validates on all protected routes |
| API key authentication | Implemented | `X-API-Key` header; validated in `authMiddleware` |
| RBAC (viewer/analyst/admin/owner) | Implemented | `internal/security/rbac.go`; enforced per route in `api/main.go` |
| Prometheus metrics | Implemented | `pkg/metrics/`; `internal/api/metrics/`; middleware wraps all routes |
| Structured audit logging | Implemented | Request/response logging via `pkg/logger/`; structured fields include scan ID, package, severity |
| Air-gap / offline mode | Implemented | `falcn db update --airgap` creates a self-contained CVE bundle; scanner reads from local DB when offline |
| LLM threat explanations (Ollama / OpenAI / Anthropic) | Implemented | `internal/llm/`; `What`, `Why`, `Impact`, `Remediation` schema; prompt injection guardrails (Unicode stripping, XML tag removal) |
| LLM explanation caching | Implemented | Explanation results are cached; `cache_hit` field in `ThreatExplanation` response |
| A/B model testing | Implemented | `internal/ml/feedback.go` — `ModelRegistry` with versioning and A/B routing |
| ML feedback store | Implemented | `internal/ml/feedback.go` — SQLite-backed `FeedbackStore`; `ExportTrainingCSV()` for retraining pipeline |
| FIPS build target | Implemented | `internal/security/fips.go`; HMAC-SHA-256 for approved MAC operations; build tag `fips` |
| CORS configuration | Implemented | Configurable via `FALCN_CORS_ORIGINS` env var; fails at startup if unset in production |
| Graceful shutdown | Implemented | 30 s shutdown window; catches SIGINT/SIGTERM |
| OAuth2 / LDAP SSO | Not implemented | Only JWT + API key auth is present; OAuth2 and LDAP integrations are not implemented |

---

## Known Limitations

The following are accurate, known constraints in v2.3.0:

1. **Dynamic sandbox requires Docker privileged mode.** `internal/sandbox/docker_sandbox.go`
   launches containers with elevated privileges. This mode is not available in most hosted CI
   environments (GitHub Actions, GitLab SaaS). The sandbox step is skipped automatically when
   Docker is not present.

2. **Offline CVE database requires manual refresh.** The local advisory database used in air-gap
   mode does not self-update. Run `falcn db update --airgap` and distribute the resulting bundle
   to air-gapped environments.

3. **IDE extensions are not yet marketplace-published.** The VS Code extension and JetBrains
   plugin code exists but neither has been submitted to or approved by the respective marketplace.
   Install from VSIX / ZIP during the preview period.

4. **OAuth2 and LDAP SSO are not implemented.** Authentication is limited to API keys and JWTs
   issued by `POST /v1/auth/token`. Enterprise SSO integration (OAuth2 PKCE, LDAP bind) is not
   present in any form.

5. **Maximum 100 packages per batch API call.** `maxBatchSize = 100` is enforced in `api/main.go`.
   Larger dependency trees must be scanned via `falcn scan [path]` rather than the batch API.

6. **`falcn serve` subcommand does not exist.** The API server is started by running
   `go run ./api` or the compiled `falcn-api` binary directly. There is no `serve` subcommand
   registered in the Cobra CLI.

7. **Reputation engine makes live registry API calls.** `TestReputationEngine_fetchNPMData`
   is excluded from unit test runs that block network access. In fully offline environments,
   reputation scoring falls back to cached or zero scores.

8. **SLSA Level 2 is not automated.** Falcn generates a Level 1 provenance stub. Achieving
   Level 2 requires signed provenance from the build system (e.g. SLSA GitHub Generator), which
   is outside Falcn's scope.

9. **SOC 2 report generation is not implemented.** Audit log fields are present but no SOC 2
   control mapping or automated report exists.

10. **FedRAMP is not implemented.** No OSCAL output or FedRAMP control mapping is present.
