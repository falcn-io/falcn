# Falcn Production Deployment Guide

Complete guide for deploying Falcn v3 in a production environment.

---

## 1. Prerequisites

| Requirement | Minimum |
|---|---|
| Docker | 24+ |
| Docker Compose | v2.20+ |
| RAM | 512 MB (API) + 256 MB (web) |
| Disk | 1 GB (SQLite) / 10 GB (PostgreSQL) |

---

## 2. Quick Start — Docker Compose (Recommended)

```bash
# 1. Clone repo
git clone https://github.com/falcn-io/falcn.git && cd falcn

# 2. Create environment file
cp .env.example .env
$EDITOR .env    # fill in all REQUIRED values (see section 3)

# 3. Start (SQLite single-node)
docker compose --profile sqlite up -d

# 4. Verify health
curl http://localhost:8080/health
# → {"status":"ok","version":"3.0.0"}

# 5. Open dashboard
open http://localhost:3000
```

For PostgreSQL HA:
```bash
docker compose --profile postgres up -d
```

For monitoring (Prometheus + Grafana):
```bash
docker compose --profile monitoring up -d
# Grafana → http://localhost:3001  (admin / $GRAFANA_PASSWORD)
```

---

## 3. Environment Variables

Copy `.env.example` to `.env` and fill in the required values. All variables can also be set directly in the environment.

### 3.1 Security (REQUIRED in production)

| Variable | Description | Generate |
|---|---|---|
| `API_AUTH_ENABLED` | Must be `true` (default) in production | — |
| `API_KEYS` | Comma-separated API keys (≥32 chars each) | `openssl rand -hex 32` |
| `FALCN_JWT_PRIVATE_KEY_FILE` | Path to RSA private key PEM | See §3.2 |
| `FALCN_SECURITY_ENCRYPTION_KEY` | 32-byte AES key (hex) | `openssl rand -hex 16` |

> **CRITICAL:** If both `API_KEYS` and `FALCN_JWT_PRIVATE_KEY_FILE` are empty the server enters **auto dev-mode** (no auth). Set `API_AUTH_ENABLED=true` to prevent this even when credentials are not yet configured.

### 3.2 Generating JWT Keys

```bash
# RSA-4096 (recommended for production)
openssl genpkey -algorithm RSA -out falcn-private.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout -in falcn-private.pem -out falcn-public.pem
chmod 600 falcn-private.pem

# Set in .env
echo "FALCN_JWT_PRIVATE_KEY_FILE=/run/secrets/falcn-private.pem" >> .env
```

### 3.3 Required in Production

| Variable | Description | Example |
|---|---|---|
| `FALCN_APP_ENVIRONMENT` | Enables strict checks | `production` |
| `FALCN_CORS_ORIGINS` | Comma-separated frontend origins | `https://security.acme.com` |

> The server calls `log.Fatalf` on startup if `FALCN_CORS_ORIGINS` is empty and `FALCN_APP_ENVIRONMENT=production`.

### 3.4 TLS (recommended)

Run TLS directly on the API process, or (preferred) terminate TLS at a reverse proxy (nginx, Caddy, AWS ALB).

```bash
# Direct TLS
FALCN_TLS_CERT=/run/secrets/falcn.crt
FALCN_TLS_KEY=/run/secrets/falcn.key
```

### 3.5 Database

| Variable | Default | Notes |
|---|---|---|
| `Falcn_DB_TYPE` | `sqlite` | `sqlite` or `postgres` |
| `Falcn_DB_NAME` | `/app/data/falcn.db` | SQLite path |
| `Falcn_DB_HOST` | `postgres` | PostgreSQL host |
| `Falcn_DB_PASSWORD` | — | Required for postgres profile |
| `Falcn_DB_SSLMODE` | `require` (postgres) | Use `require` or `verify-full` in prod |

### 3.6 LLM Explanations (optional)

| Variable | Provider |
|---|---|
| `FALCN_OLLAMA_HOST` | Ollama (local/air-gapped) — e.g. `http://ollama:11434` |
| `FALCN_OPENAI_API_KEY` | OpenAI GPT-4o |
| `FALCN_ANTHROPIC_API_KEY` | Anthropic Claude |

Auto-detection order: explicit `FALCN_LLM_PROVIDER` env → Anthropic key → OpenAI key → Ollama.

### 3.7 Metrics endpoint security

`/metrics` (Prometheus) is automatically restricted to loopback and RFC-1918 addresses. To widen the allowlist:

```bash
METRICS_ALLOWED_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8
```

To restrict further (e.g., allow only your Prometheus server):
```bash
METRICS_ALLOWED_CIDRS=10.10.5.20/32
```

### 3.8 Alerting (optional)

| Variable | Description |
|---|---|
| `SLACK_WEBHOOK_URL` | Slack incoming webhook for high-risk alerts |
| `FALCN_SMTP_HOST` | SMTP hostname for email digests |
| `FALCN_SMTP_PORT` | SMTP port (default: 587) |
| `FALCN_SMTP_USER` / `FALCN_SMTP_PASS` | SMTP credentials |

---

## 4. Production Checklist

```bash
# ── Step 1: Secrets ──────────────────────────────────────────────────────────
export API_KEY=$(openssl rand -hex 32)
export AES_KEY=$(openssl rand -hex 16)
openssl genpkey -algorithm RSA -out falcn-private.pem -pkeyopt rsa_keygen_bits:4096
chmod 600 falcn-private.pem

# ── Step 2: Environment ──────────────────────────────────────────────────────
cat > .env <<EOF
API_AUTH_ENABLED=true
API_KEYS=$API_KEY
FALCN_JWT_PRIVATE_KEY_FILE=$(pwd)/falcn-private.pem
FALCN_APP_ENVIRONMENT=production
FALCN_CORS_ORIGINS=https://your-dashboard.example.com
FALCN_SECURITY_ENCRYPTION_KEY=$AES_KEY
Falcn_DB_TYPE=sqlite
Falcn_DB_NAME=/app/data/falcn.db
Falcn_LOG_LEVEL=info
EOF

# ── Step 3: Start ────────────────────────────────────────────────────────────
docker compose --profile sqlite up -d

# ── Step 4: Verify ───────────────────────────────────────────────────────────
# Health
curl http://localhost:8080/health
# → 200 {"status":"ok"}

# Auth works
curl -H "X-API-Key: $API_KEY" http://localhost:8080/v1/status
# → 200

# Unauthenticated request is rejected
curl http://localhost:8080/v1/threats
# → 401

# Threat detection
curl -s -X POST http://localhost:8080/v1/analyze \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"package_name":"crossenv","registry":"npm"}' | jq .risk_score
# → 0.9+ (high risk — typosquatting of cross-env)

# False-positive check
curl -s -X POST http://localhost:8080/v1/analyze \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"package_name":"lodash","registry":"npm"}' | jq .risk_score
# → 0.0-0.2 (low risk — well-known package)

# Metrics restricted to internal network
curl http://localhost:8080/metrics
# → 403 Forbidden (unless you're on loopback/RFC-1918)
```

---

## 5. Docker Compose Architecture

```
                    ┌─────────────────────────────┐
Browser ──HTTPS──▶ │  nginx (falcn-web :80)       │
                    │  Serves React SPA             │
                    │  Proxies /api/* → API         │
                    └──────────────┬──────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │  falcn-api (:8080)            │
                    │  Go API server                │
                    │  ├─ Auth middleware            │
                    │  ├─ Rate limiter               │
                    │  ├─ SSE broker                 │
                    │  └─ LLM explainer (async)      │
                    └──────────────┬──────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │  SQLite / PostgreSQL           │
                    │  scan_threats + explanations   │
                    └─────────────────────────────┘
```

---

## 6. Security Hardening

### Auth mode summary

| Condition | Auth mode |
|---|---|
| `API_AUTH_ENABLED=true` | Always require credentials |
| `API_KEYS` or `FALCN_JWT_PRIVATE_KEY_FILE` set | Require credentials |
| Neither key set AND `API_AUTH_ENABLED` unset | **Auto dev-mode** (all requests allowed) |
| `API_AUTH_ENABLED=false` | Disable auth (developer only) |

> Set `API_AUTH_ENABLED=true` in production. It prevents accidental open-access if credentials are accidentally unset.

### CORS headers

The server sends an explicit header allowlist:
```
Content-Type, Authorization, X-API-Key, Accept, X-Requested-With
```
`AllowedHeaders: *` was removed in v3.

### JWT key rotation

```bash
# Generate new key pair
openssl genpkey -algorithm RSA -out new-private.pem -pkeyopt rsa_keygen_bits:4096
chmod 600 new-private.pem

# Update secret / env var and restart
FALCN_JWT_PRIVATE_KEY_FILE=/path/to/new-private.pem
docker compose restart falcn-api
# Existing tokens signed with the old key are invalidated — re-login required.
```

### File permissions

All output files (reports, SBOM, DB exports) are written `0600` (owner read/write only).

---

## 7. Air-Gap Deployment

```bash
# ── On internet-connected machine ────────────────────────────────────────────
# Build the air-gap bundle (embeds popular_packages + CVE DB + ML model)
make airgap-bundle
# Produces: dist/falcn-airgap-linux-amd64.tar.gz

# Transfer
scp dist/falcn-airgap-linux-amd64.tar.gz airgap:/opt/falcn/

# ── On air-gapped machine ─────────────────────────────────────────────────────
tar -xzf /opt/falcn/falcn-airgap-linux-amd64.tar.gz -C /opt/falcn/
/opt/falcn/falcn scan /project --offline --no-llm
```

For scheduled CVE DB refreshes:
```bash
# Weekly cron on relay machine
0 2 * * 0 falcn update-db --airgap-bundle --output /transfer/falcn-$(date +\%Y\%m\%d).tar.gz
```

---

## 8. CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Supply Chain Security
on: [push, pull_request]
jobs:
  falcn:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: falcn-io/falcn-action@v1
        with:
          fail-on: high
          output-format: sarif
          upload-sarif: true
```

### GitLab CI

```yaml
include:
  - project: 'falcn-io/falcn'
    file: 'deploy/gitlab-template/.gitlab-ci.yml'

variables:
  FALCN_FAIL_ON: "critical"
  FALCN_THRESHOLD: "0.8"
```

### Pre-commit hook

```bash
cp deploy/pre-commit-hook/falcn-pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

---

## 9. Monitoring

### Key endpoints

| Endpoint | Description | Auth |
|---|---|---|
| `GET /health` | Liveness probe | None |
| `GET /ready` | Readiness probe | None |
| `GET /metrics` | Prometheus metrics | Internal network only |
| `GET /v1/status` | API feature flags | None |

### Key Prometheus metrics

| Metric | Alert condition |
|---|---|
| `falcn_scan_duration_seconds{quantile="0.99"}` | > 10s |
| `falcn_threats_total` | Spike > 10× baseline |
| `http_requests_total{status="401"}` | > 100/min |
| `http_requests_total{status="429"}` | > 50/min |

---

## 10. Troubleshooting

### Server exits on startup

```
FATAL: FALCN_CORS_ORIGINS must be set in production
```
→ Set `FALCN_CORS_ORIGINS=https://your-frontend.com`

```
FATAL: FALCN_JWT_PRIVATE_KEY_FILE must be set in production
```
→ Generate RSA key pair and set `FALCN_JWT_PRIVATE_KEY_FILE`

### 403 on `/metrics`

The endpoint is restricted to RFC-1918 + loopback. Your Prometheus scraper IP is not in the allowed CIDR. Set `METRICS_ALLOWED_CIDRS` to include the Prometheus server IP.

### High false-positive rate

1. Check `data/popular_packages.json` — package may be missing from curated list
2. Raise `typo_detection.threshold` (0.8 → 0.9 for fewer, more precise alerts)
3. Add to `.falcnignore`

### Scan too slow

1. Use `--fast` for CI gates (heuristics only, < 100ms)
2. Use `--no-llm` to skip AI explanation generation
3. Enable Redis rate-limit caching (`RATE_LIMIT_REDIS_URL`)
4. Increase `FALCN_SCANNER_MAX_CONCURRENCY` (default: 8)

### SQLite WAL files accumulating

```bash
sqlite3 /app/data/falcn.db "PRAGMA wal_checkpoint(TRUNCATE);"
sqlite3 /app/data/falcn.db "VACUUM;"
```
