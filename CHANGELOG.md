# Changelog

All notable changes to Falcn are documented here.

---

## [3.0.0] — 2026-03-06

### 🚀 v3 — AI-Native Supply Chain Security Platform

This is a major release completing the Falcn v3 roadmap across six phases.

#### Phase 1 — Critical Bug Fixes
- **ML inference** (`internal/ml/inference.go`): `Predict()` now computes a real heuristic score from the full feature vector; no longer always returns `0.1`
- **Behavioral stubs** (`internal/scanner/scanner.go`): all 13 hardcoded stubs replaced with real file pattern matching (`countNetworkCalls`, `countFileSystemAccess`, `hasDataCollection`, etc.)
- **`ScanPackageParallel()`** (`internal/scanner/optimized_scanner.go`): now calls the real `analyzePackageThreats()` instead of returning hardcoded low risk
- **Vulnerability semver** (`internal/vulnerability/osv_database.go`, `github_database.go`): proper CVSS score parsing and real semver range matching (`<`, `>=`, `~`, `^`) — replaces string containment
- **Threat IDs** (`internal/detector/engine.go`): `uuid.New().String()` replaces `time.Now().UnixNano()`
- **Nil-check** (`internal/scanner/scanner.go:1153`): guard before `pkg.Metadata.Author` access
- **Report permissions** (`cmd/scan.go`): `0644` → `0600`
- **LLM prompt injection** (`internal/llm/guardrails.go`): Unicode control character stripping and XML tag removal
- **Debug log flood** (`internal/scanner/content_scanner.go`): removed per-file `DEBUG: Checking file:` log

#### Phase 2 — Real ML Pipeline
- **Feature extraction** (`internal/ml/features.go`): expanded from 7 to 25 features (install scripts, maintainer velocity, domain age, entropy histogram, dependency delta, star/fork anomaly, namespace age, download anomaly) with z-score normalization
- **Ensemble training** (`scripts/train_ml_model.py`): RandomForest + GradientBoosting + LightGBM, real labeled taxonomy, k-fold CV, SHAP values, ONNX export
- **Inference** (`internal/ml/inference.go`): batch support, feature normalization, graceful fallback to heuristics if model absent
- **Feedback loop** (`internal/ml/feedback.go`): SQLite false-positive store, model versioning, A/B testing flag, `ExportTrainingCSV()` for retraining
- **Evaluation** (`scripts/evaluate_model.py`): precision/recall/F1 dashboard, permutation importance, heuristic baseline comparison

#### Phase 3 — Speed & CI/CD Integration
- **Unified scanner** (`internal/scanner/unified_scanner.go`): single `filepath.WalkDir()` pass replacing triple independent walks; concurrent per-file dispatch with worker pool; `--fast` mode (< 100ms, zero network)
- **Parallel threat loop** (`internal/scanner/scanner.go`): sequential → bounded 4-worker pool
- **GitHub Action** (`deploy/github-action/action.yml`): binary caching, PR annotations, fail-on severity gate
- **GitLab CI template** (`deploy/gitlab-template/.gitlab-ci.yml`): include template, SARIF artifact, fast + full modes
- **Pre-commit hook** (`deploy/pre-commit-hook/falcn-pre-commit`): blocks installs on dependency file changes
- **SSE streaming** (`api/main.go`): replaced 3-ping-and-close stub with real `SSEBroker` pub/sub; emits `threat`, `explanation`, `done`, `ping` events

#### Phase 4 — AI Explainability
- **Structured explanation schema**: `ThreatExplanation` (What / Why / Impact / Remediation / Confidence) in types, API, and database
- **LLM integration**: Ollama, OpenAI, Anthropic providers wired to threat pipeline; `--no-llm` and `--max-llm-calls` flags enforced
- **Explanation caching**: 7-day SQLite TTL; cache key `explain:{package}:{version}:{type}`; version normalization (`"unknown"` → `""`)
- **Goroutine safety**: semaphore (capacity 8) + panic recovery on all explanation goroutines
- **Web dashboard**: expandable AI panels per threat row (What/Why/Impact/Fix + confidence bar + provider badge + cache indicator); live SSE merge by `threat_id`

#### Phase 5 — Enterprise Platform
- **Authentication**: RS256 JWT + API key; ephemeral dev key; explicit `API_AUTH_ENABLED` flag; production startup check
- **Auth on data endpoints**: `/v1/threats`, `/v1/scans`, `/v1/dashboard/*`, `/v1/vulnerabilities` now require authentication
- **CORS**: specific header allowlist (`Content-Type`, `Authorization`, `X-API-Key`, `Accept`, `X-Requested-With`); required in production
- **`/metrics` security**: IP allowlist middleware — RFC-1918 + loopback only by default; configurable via `METRICS_ALLOWED_CIDRS`
- **Dashboard endpoints**: all `/v1/dashboard/*` endpoints return real data from SQLite store
- **Database migrations**: scan_threats, explanations tables with LEFT JOIN in threat list queries

#### Phase 6 — Deployment & Air-Gap
- **`web/Dockerfile`**: multi-stage nginx build (node:20-alpine builder → nginx:1.27-alpine); non-root `nginx` user
- **`web/nginx.conf`**: production nginx config with `/api/` proxy, SSE support, SPA routing, security headers, gzip
- **`api/Dockerfile`**: updated Go 1.21 → 1.24; non-root `appuser`; pinned alpine:3.21
- **`.env.example`**: comprehensive variable reference with security guidance
- **`docker-compose.yml`**: `DISABLE_AUTH` default `false`; hardcoded passwords removed; `?:` required-var syntax for DB password and Grafana password
- **`make airgap-bundle`**: embeds popular_packages.json + CVE DB + ML model into single offline binary

#### Fixes
- `update_packages.go` file permissions: `0644` → `0600`
- `Settings.tsx` default API URL: `http://localhost:8080` → `""` (relative)
- `StubRepo.Generate()` removed from `NewStub()` — prevents synthetic threats in production
- CORS `AllowedHeaders: ["*"]` → explicit allowlist

---

## [2.0.0] — 2025-12-18

- feat: SBOM generation (SPDX / CycloneDX) and `falcn report` command
- feat: enhanced typosquatting detection with Jaro-Winkler and Sørensen-Dice
- feat: Shai-Hulud attack detection (self-hosted runners, injection, C2 channels)
- feat: CICD scanner with pipeline file static analysis
- fix: incomplete_metadata false positives in MetadataEnricher Author field
- output: SARIF physical locations, byte-range regions, structured evidence
- scanner: entropy position ranges, preview content type, file path metadata
- docker: stable multi-stage build, cache mounts, non-root user

---

## [1.x] — 2025-12-03

- docs: ecosystem help sections (npm, Ruby, Python obfuscation)
- scanner: entropy analysis, content detection patterns
- output: SARIF triage improvements
- Initial public release
