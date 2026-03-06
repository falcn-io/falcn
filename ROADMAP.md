# 🗺️ Falcn Roadmap

## v3.0 — Completed ✅ (March 2026)

All six phases of the v3 plan are shipped.

| Phase | Focus | Status |
|---|---|---|
| 1 | Critical bug fixes (ML stubs, semver, permissions, UUID IDs) | ✅ Done |
| 2 | Real ML pipeline (25 features, ensemble, SHAP, feedback loop) | ✅ Done |
| 3 | Speed & CI/CD (single-pass scanner, GitHub Action, GitLab template, pre-commit) | ✅ Done |
| 4 | AI explainability (structured schema, SSE streaming, cached panels) | ✅ Done |
| 5 | Enterprise platform (JWT/API key auth, RBAC middleware, dashboard endpoints) | ✅ Done |
| 6 | Air-gap & deployment (web Dockerfile, nginx, .env.example, docker-compose hardening) | ✅ Done |

---

## v3.1 — Near Term (Q2 2026)

**Goal:** Harden for production adoption and widen ecosystem coverage.

### Detection
- [ ] **ONNX runtime integration** — load and run the trained model for true ML inference (currently uses calibrated heuristics as fallback)
- [ ] **Cargo / crates.io** — expand package metadata fetching (downloads, author history)
- [ ] **NuGet dependency confusion** — namespace gap detection for .NET internal registries
- [ ] **Download count analysis** — `AnalyzeDownloadCount()` is currently a no-op; wire to registry metadata

### Platform
- [ ] **Kubernetes Helm chart** — `deploy/helm/` with values.yaml, HPA, network policies
- [ ] **GitHub Actions workflow** — `.github/workflows/ci.yml` in-repo (not just the reusable Action)
- [ ] **Container registry push** — `make push-docker` target for automated release publishing
- [ ] **RBAC** — `viewer` / `analyst` / `admin` roles enforced on API routes
- [ ] **OAuth2** — GitHub + Google device flow for CLI login

### Integrations
- [ ] **Jira** — auto-create issues for critical/high findings
- [ ] **Microsoft Teams** — threat alert cards
- [ ] **SMTP** — email digests for scan summaries

### Performance
- [ ] **Frontend code splitting** — reduce 787KB JS bundle with dynamic `import()` per route
- [ ] **Redis distributed rate limiting** — replace in-memory per-pod limiter
- [ ] **ASN cache** — move ASN lookups from disk-per-scan to in-memory (content_scanner.go)

---

## v4.0 — Vision (H2 2026)

**Goal:** Falcn as a Private Security Hub — active blocking, not just detection.

### Firewall Mode
- Package proxy that intercepts `npm install` / `pip install` at the network layer
- Real-time allow/block decisions based on Falcn risk score
- Policy-as-code: OPA Rego rules for org-specific block lists

### Continuous Monitoring
- Scheduled re-scans of installed dependency trees
- Delta alerts: "Package X just received a new version — re-scan triggered"
- Webhook push for any new threat above threshold

### Private Intelligence
- Organisation-private threat intelligence DB (custom IOCs, block lists)
- Federated threat sharing across org instances (opt-in, E2E encrypted)
- MITRE ATLAS mapping for supply-chain attack patterns

### FIPS 140-2 / FedRAMP
- FIPS build tag swapping crypto primitives (no MD5/SHA1)
- Compliance matrix documentation
- FedRAMP impact-level assessment guide
