# Falcn Production Deployment Guide — v2.3.0

This guide covers everything needed to deploy the Falcn supply chain security
scanner in a production environment: Docker Compose, Kubernetes, environment
variable reference, security hardening, CI/CD integration, monitoring, and
tiered rate limiting.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start with Docker Compose](#quick-start-with-docker-compose)
3. [Environment Variables](#environment-variables)
4. [Security Hardening Checklist](#security-hardening-checklist)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [GitHub Actions CI/CD Integration](#github-actions-cicd-integration)
7. [GitLab CI Integration](#gitlab-ci-integration)
8. [Pre-commit Hook](#pre-commit-hook)
9. [Monitoring](#monitoring)
10. [Tiered Rate Limits](#tiered-rate-limits)
11. [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Component | Version | Required? | Purpose |
|-----------|---------|-----------|---------|
| Go | 1.25+ | Only for source builds | Compile Falcn from source |
| Docker | 24+ | For containerised deployment | Run Falcn API server |
| Docker Compose | 2.20+ | For local / small-scale production | Orchestrate services |
| Redis | 7+ | Optional | Distributed rate limiting across replicas |
| PostgreSQL | 15+ | Optional | Persistent scan history (default: SQLite) |
| Prometheus | 2.45+ | Optional | Metrics collection |
| Grafana | 10+ | Optional | Metrics visualisation |
| Ollama | 0.3+ | Optional | Local LLM for air-gapped AI explanations |

---

## Quick Start with Docker Compose

The following `docker-compose.yml` brings up the Falcn API server with Redis
for distributed rate limiting, plus an optional Prometheus/Grafana monitoring
stack. It matches the service and volume names in the existing
`docker-compose.yml` at the repository root.

Save the file below as `docker-compose.prod.yml` (or adapt the existing one)
and set the required environment variables before starting:

```bash
export API_KEYS="$(openssl rand -hex 32),$(openssl rand -hex 32)"
export FALCN_JWT_PRIVATE_KEY_FILE=/run/secrets/falcn-jwt-private.pem
export FALCN_CORS_ORIGINS="https://dashboard.yourcompany.com"
export GRAFANA_PASSWORD="$(openssl rand -hex 16)"
```

```yaml
# docker-compose.prod.yml
version: "3.8"

services:
  # ── Falcn API server ───────────────────────────────────────────────────
  falcn-api:
    image: ghcr.io/falcn-io/falcn:latest
    container_name: falcn-api
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      PORT: "8080"
      FALCN_APP_ENVIRONMENT: "production"
      # Auth — REQUIRED in production
      API_KEYS: "${API_KEYS}"
      FALCN_JWT_PRIVATE_KEY_FILE: "/run/secrets/falcn-jwt-private.pem"
      # CORS — REQUIRED in production (comma-separated)
      FALCN_CORS_ORIGINS: "${FALCN_CORS_ORIGINS}"
      # Distributed rate limiting via Redis
      RATE_LIMIT_REDIS_URL: "redis://redis:6379"
      # Persistence
      FALCN_DB_PATH: "/app/data/falcn.db"
      # Logging
      FALCN_LOG_LEVEL: "info"
      # Metrics CIDR allowlist (Prometheus scraper IP range)
      METRICS_ALLOWED_CIDRS: "10.0.0.0/8,172.16.0.0/12"
      # LLM (optional — remove if not using AI explanations)
      FALCN_LLM_PROVIDER: "ollama"
      FALCN_LLM_MODEL: "llama3.2"
    secrets:
      - falcn-jwt-private.pem
    volumes:
      - falcn_data:/app/data
      - falcn_logs:/app/logs
    networks:
      - falcn-network
    depends_on:
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # ── Redis (distributed rate limiting + caching) ────────────────────────
  redis:
    image: redis:7-alpine
    container_name: falcn-redis
    restart: unless-stopped
    command: >
      redis-server
      --maxmemory 256mb
      --maxmemory-policy allkeys-lru
      --requirepass "${REDIS_PASSWORD}"
      --loglevel warning
    volumes:
      - redis_data:/data
    networks:
      - falcn-network
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "${REDIS_PASSWORD}", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  # ── Prometheus (optional monitoring) ──────────────────────────────────
  prometheus:
    image: prom/prometheus:latest
    container_name: falcn-prometheus
    restart: unless-stopped
    profiles:
      - monitoring
    ports:
      - "9090:9090"
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.path=/prometheus"
      - "--storage.tsdb.retention.time=30d"
      - "--web.enable-lifecycle"
    volumes:
      - ./config/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    networks:
      - falcn-network

  # ── Grafana (optional dashboards) ─────────────────────────────────────
  grafana:
    image: grafana/grafana:latest
    container_name: falcn-grafana
    restart: unless-stopped
    profiles:
      - monitoring
    ports:
      - "3001:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: "${GRAFANA_PASSWORD}"
      GF_USERS_ALLOW_SIGN_UP: "false"
      GF_SERVER_ROOT_URL: "https://grafana.yourcompany.com"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/provisioning:/etc/grafana/provisioning:ro
    networks:
      - falcn-network

volumes:
  falcn_data:
  falcn_logs:
  redis_data:
  prometheus_data:
  grafana_data:

networks:
  falcn-network:
    driver: bridge

secrets:
  falcn-jwt-private.pem:
    file: ./secrets/falcn-jwt-private.pem
```

Start the core stack:

```bash
docker compose -f docker-compose.prod.yml up -d
```

Start with the monitoring profile:

```bash
docker compose -f docker-compose.prod.yml --profile monitoring up -d
```

Verify health:

```bash
curl http://localhost:8080/health
# {"status":"ok","timestamp":"2026-03-07T12:00:00Z","version":"v2.3.0"}

curl http://localhost:8080/ready
# {"ready":true,"timestamp":"2026-03-07T12:00:00Z"}
```

---

## Environment Variables

Complete reference for all environment variables recognised by the Falcn API
server. Variables marked **REQUIRED** must be set in production; the server
will refuse to start or will log a prominent warning without them.

### Authentication

| Variable | Required | Description |
|----------|----------|-------------|
| `API_KEYS` | REQUIRED | Comma-separated list of API keys. Each key should be a minimum of 32 random hex characters. Generate with `openssl rand -hex 32`. |
| `FALCN_JWT_PRIVATE_KEY_FILE` | REQUIRED (for JWT) | Path to an RSA-2048 private key PEM file. Used for RS256 JWT signing. Generate with `openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048`. |
| `FALCN_JWT_PRIVATE_KEY` | Alternative | Base64-encoded RSA private key (use `FALCN_JWT_PRIVATE_KEY_FILE` in production). |
| `API_AUTH_ENABLED` | — | Set to `true` to enforce authentication even when `API_KEYS` is set. Defaults to `true` when `API_KEYS` is non-empty. |

In development with no keys configured, the server starts in **dev mode**:
all `/v1` endpoints are open. A warning is logged at startup:

```
WARNING: DEV MODE: no API_KEYS or JWT secret configured — all /v1 endpoints are open.
```

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | TCP port the HTTP server listens on. |
| `FALCN_APP_ENVIRONMENT` | `development` | Set to `production` to enable additional validation (CORS enforcement, JWT key requirement). |
| `FALCN_CORS_ORIGINS` | — | REQUIRED in production. Comma-separated list of allowed CORS origins (e.g. `https://app.yourcompany.com`). The server will refuse to start in production mode without this. |
| `FALCN_TLS_CERT` | — | Path to TLS certificate PEM file. When set with `FALCN_TLS_KEY`, the server runs HTTPS automatically. |
| `FALCN_TLS_KEY` | — | Path to TLS private key PEM file. |
| `FALCN_LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error`. |

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `FALCN_DB_PATH` | `./data/falcn.db` | Path to the SQLite database for scan history and feedback. Use an absolute path in production (e.g. `/var/lib/falcn/falcn.db`). |

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_REDIS_URL` | — | Redis connection DSN (e.g. `redis://:password@redis:6379`). When set, rate limiting state is shared across all Falcn API replicas. When absent, in-memory per-process rate limiting is used. |

### Offline / Air-gap

| Variable | Default | Description |
|----------|---------|-------------|
| `FALCN_OFFLINE` | `false` | Set to `true` to disable all outbound network calls. All vulnerability lookups use the local SQLite CVE database. |
| `FALCN_LOCAL_DB` | `~/.local/share/falcn/cve.db` | Path to the local SQLite CVE database used in offline mode. Populate with `falcn update-db`. |

### LLM / AI Explanations

| Variable | Description |
|----------|-------------|
| `FALCN_LLM_PROVIDER` | LLM provider: `ollama`, `openai`, or `anthropic`. |
| `FALCN_LLM_MODEL` | Model name (e.g. `llama3.2`, `gpt-4o-mini`, `claude-3-haiku-20240307`). |
| `FALCN_LLM_API_KEY` | API key for cloud providers. Alternatively use `FALCN_OPENAI_API_KEY` or `FALCN_ANTHROPIC_API_KEY`. |
| `FALCN_OPENAI_API_KEY` | OpenAI API key. Takes precedence when `FALCN_LLM_PROVIDER=openai`. |
| `FALCN_ANTHROPIC_API_KEY` | Anthropic API key. Takes precedence when `FALCN_LLM_PROVIDER=anthropic`. |

When no API key or Ollama host is configured, LLM explanations are silently
skipped. Scans continue without AI descriptions.

### Metrics

| Variable | Default | Description |
|----------|---------|-------------|
| `METRICS_ALLOWED_CIDRS` | `127.0.0.1/32` | Comma-separated CIDR blocks allowed to scrape the `/metrics` Prometheus endpoint. The endpoint returns 403 for requests from IPs outside this list. Example: `10.0.0.0/8,172.16.0.0/12`. |

### Alerting (Webhooks / Email)

| Variable | Description |
|----------|-------------|
| `FALCN_WEBHOOK_URL` | HTTP endpoint to receive threat event POST requests. |
| `FALCN_SMTP_HOST` | SMTP server hostname for email alerts. |
| `FALCN_SMTP_PORT` | SMTP server port (default: `587`). |
| `FALCN_SMTP_USER` | SMTP username. |
| `FALCN_SMTP_PASS` | SMTP password (set via env, never in config file). |
| `FALCN_SMTP_FROM` | Sender address for alert emails. |
| `FALCN_SMTP_TO` | Recipient address for alert emails. |

---

## Security Hardening Checklist

### JWT Secret Rotation

Generate a fresh RSA key pair and rotate regularly (recommend 90-day cycle):

```bash
# Generate key pair
openssl genpkey -algorithm RSA -out falcn-jwt-private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in falcn-jwt-private.pem -out falcn-jwt-public.pem
chmod 600 falcn-jwt-private.pem

# Store as a Docker secret or Kubernetes secret (not in a config file)
kubectl create secret generic falcn-jwt \
  --from-file=private.pem=falcn-jwt-private.pem \
  --namespace falcn-system

# Set in environment
export FALCN_JWT_PRIVATE_KEY_FILE=/run/secrets/falcn-jwt-private.pem
```

All existing JWTs are invalidated on rotation. Clients must re-exchange their
API key for a new JWT via `POST /v1/auth/token`.

### API Key Management

- Generate API keys with at least 32 bytes of entropy:
  ```bash
  openssl rand -hex 32
  # b3f8a9c2d1e4f6789012345678901234567890abcdef1234567890abcdef1234
  ```
- Rotate keys by updating `API_KEYS` and restarting the service. Old keys are
  immediately invalidated.
- Use separate keys per team, service, or environment. Never share keys between
  production and staging.
- Store keys in a secrets manager (HashiCorp Vault, AWS Secrets Manager, etc.),
  never in version control or `.env` files checked in.

### TLS Termination

For a production deployment, terminate TLS in front of the Falcn API server.

**Nginx reverse proxy:**

```nginx
server {
    listen 443 ssl http2;
    server_name falcn.yourcompany.com;

    ssl_certificate     /etc/ssl/certs/falcn.crt;
    ssl_certificate_key /etc/ssl/private/falcn.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    location / {
        proxy_pass         http://falcn-api:8080;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 90s;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name falcn.yourcompany.com;
    return 301 https://$host$request_uri;
}
```

**Caddy (automatic HTTPS):**

```caddyfile
falcn.yourcompany.com {
    reverse_proxy falcn-api:8080
}
```

Alternatively, enable native TLS in the Falcn server itself:

```bash
export FALCN_TLS_CERT=/etc/ssl/certs/falcn.crt
export FALCN_TLS_KEY=/etc/ssl/private/falcn.key
```

### Metrics Endpoint Protection

The Prometheus `/metrics` endpoint is CIDR-gated and returns HTTP 403 for
requests from outside the allowlist. Default allowlist is `127.0.0.1/32`:

```bash
# Allow Prometheus scraper running on 10.0.1.50
export METRICS_ALLOWED_CIDRS="10.0.0.0/8,172.16.0.0/12"
```

Never expose `/metrics` on a public-facing interface. Use a separate internal
ingress or a Prometheus `scrape_config` on an internal network.

### File Permissions

Falcn writes scan reports with mode `0600` (owner-read/write only). Ensure the
data directory has appropriate ownership:

```bash
# Docker: map a host directory with correct ownership
mkdir -p /var/lib/falcn
chown 1000:1000 /var/lib/falcn
chmod 750 /var/lib/falcn
```

### Audit Logging

Enable JSON structured logging and ship logs to your SIEM:

```bash
export FALCN_LOG_LEVEL=info
# Logs are written to stdout in JSON format when FALCN_APP_ENVIRONMENT=production
```

Example log entry:

```json
{
  "level": "info",
  "time": "2026-03-07T12:01:00Z",
  "msg": "scan completed",
  "scan_id": "a3f8c1d2-...",
  "target": "/workspace",
  "packages": 312,
  "threats": 3,
  "duration_ms": 4210,
  "user_id": "ci-pipeline-prod"
}
```

### CORS Configuration

In production mode (`FALCN_APP_ENVIRONMENT=production`), the server refuses to
start unless `FALCN_CORS_ORIGINS` is set. Use the most restrictive list of
origins needed:

```bash
export FALCN_CORS_ORIGINS="https://dashboard.yourcompany.com,https://ci.yourcompany.com"
```

Wildcard origins (`*`) are not accepted in production mode.

---

## Kubernetes Deployment

The following manifests deploy Falcn API in a dedicated namespace with a
Deployment, Service, Secret, and ConfigMap. Adjust resource limits and replica
counts for your cluster size.

### secret.yaml

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: falcn-secrets
  namespace: falcn-system
type: Opaque
stringData:
  # Generate: openssl rand -hex 32
  api-key-1: "REPLACE_WITH_64_CHAR_HEX_KEY"
  api-key-2: "REPLACE_WITH_SECOND_64_CHAR_HEX_KEY"
  # Generate: openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64
  jwt-private-key: |
    -----BEGIN PRIVATE KEY-----
    REPLACE_WITH_RSA_PRIVATE_KEY_PEM
    -----END PRIVATE KEY-----
  redis-password: "REPLACE_WITH_REDIS_PASSWORD"
```

### configmap.yaml

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: falcn-config
  namespace: falcn-system
data:
  FALCN_APP_ENVIRONMENT: "production"
  PORT: "8080"
  FALCN_LOG_LEVEL: "info"
  FALCN_CORS_ORIGINS: "https://dashboard.yourcompany.com"
  RATE_LIMIT_REDIS_URL: "redis://:$(REDIS_PASSWORD)@falcn-redis:6379"
  METRICS_ALLOWED_CIDRS: "10.0.0.0/8"
  FALCN_DB_PATH: "/data/falcn.db"
  FALCN_LLM_PROVIDER: "openai"
  FALCN_LLM_MODEL: "gpt-4o-mini"
```

### deployment.yaml

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: falcn-api
  namespace: falcn-system
  labels:
    app: falcn-api
    version: v2.3.0
spec:
  replicas: 3
  selector:
    matchLabels:
      app: falcn-api
  template:
    metadata:
      labels:
        app: falcn-api
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: falcn-api
          image: ghcr.io/falcn-io/falcn:latest
          imagePullPolicy: Always
          ports:
            - containerPort: 8080
              name: http
          envFrom:
            - configMapRef:
                name: falcn-config
          env:
            - name: API_KEYS
              valueFrom:
                secretKeyRef:
                  name: falcn-secrets
                  key: api-key-1
            - name: FALCN_JWT_PRIVATE_KEY
              valueFrom:
                secretKeyRef:
                  name: falcn-secrets
                  key: jwt-private-key
            - name: REDIS_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: falcn-secrets
                  key: redis-password
            - name: FALCN_LLM_API_KEY
              valueFrom:
                secretKeyRef:
                  name: falcn-secrets
                  key: openai-api-key
                  optional: true
          volumeMounts:
            - name: falcn-data
              mountPath: /data
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 15
            periodSeconds: 30
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 10
          resources:
            requests:
              cpu: "250m"
              memory: "256Mi"
            limits:
              cpu: "2"
              memory: "2Gi"
      volumes:
        - name: falcn-data
          persistentVolumeClaim:
            claimName: falcn-data-pvc
```

### service.yaml

```yaml
apiVersion: v1
kind: Service
metadata:
  name: falcn-api
  namespace: falcn-system
  labels:
    app: falcn-api
spec:
  selector:
    app: falcn-api
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 8080
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: falcn-api
  namespace: falcn-system
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - falcn.yourcompany.com
      secretName: falcn-tls
  rules:
    - host: falcn.yourcompany.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: falcn-api
                port:
                  number: 80
```

Apply all manifests:

```bash
kubectl create namespace falcn-system
kubectl apply -f secret.yaml
kubectl apply -f configmap.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

# Verify
kubectl rollout status deployment/falcn-api -n falcn-system
kubectl get pods -n falcn-system
```

---

## GitHub Actions CI/CD Integration

Use the `falcn-io/falcn` GitHub Action to integrate supply chain scanning into
pull request workflows.

### Full Workflow Example

```yaml
# .github/workflows/supply-chain.yml
name: Supply Chain Security

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    # Daily scan at 02:00 UTC
    - cron: "0 2 * * *"

permissions:
  contents: read
  security-events: write   # required to upload SARIF to Code Scanning
  pull-requests: write      # required for PR annotations

jobs:
  falcn-scan:
    name: Falcn Supply Chain Scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Falcn scan
        id: falcn
        uses: falcn-io/falcn@v2
        with:
          # Directory to scan (default: repository root)
          path: "."
          # Fail the job on high or critical threats
          fail-on: "high"
          # Typosquatting similarity threshold
          threshold: "0.8"
          # Output format for downstream steps
          output-format: "sarif"
          output-file: "falcn-results.sarif"
          # Disable LLM in CI (faster)
          no-llm: "true"
          # fast-mode: "true"   # uncomment for <100ms heuristics-only

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: falcn-results.sarif
          category: "falcn-supply-chain"

      - name: Generate CycloneDX SBOM
        run: |
          falcn scan . \
            --check-vulnerabilities \
            --sbom-format cyclonedx \
            --sbom-output sbom.cdx.json \
            --no-llm

      - name: Upload SBOM as artifact
        uses: actions/upload-artifact@v4
        with:
          name: cyclonedx-sbom
          path: sbom.cdx.json
          retention-days: 90

      - name: Print threat summary
        if: always()
        run: |
          echo "Threats found: ${{ steps.falcn.outputs.threat-count }}"
          echo "Critical:      ${{ steps.falcn.outputs.critical-count }}"
          echo "High:          ${{ steps.falcn.outputs.high-count }}"
```

### Action Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Path to scan |
| `threshold` | `0.7` | Risk score threshold (0.0–1.0) |
| `fail-on` | `high` | Severity that triggers failure: `critical`, `high`, `medium`, `low` |
| `output-format` | `table` | `json`, `sarif`, or `table` |
| `output-file` | — | Write report to this path |
| `no-llm` | `true` | Disable LLM explanations |
| `fast-mode` | `false` | Enable heuristics-only mode |
| `version` | latest | Falcn binary version (e.g. `v2.3.0`) |

### Action Outputs

| Output | Description |
|--------|-------------|
| `threat-count` | Total number of threats found |
| `critical-count` | Number of critical-severity threats |
| `high-count` | Number of high-severity threats |
| `report-path` | Path to the generated report file |

---

## GitLab CI Integration

Include the Falcn GitLab CI template in your pipeline.

```yaml
# .gitlab-ci.yml
include:
  - project: "falcn-io/falcn"
    file: "deploy/gitlab-template/.gitlab-ci.yml"
    ref: main

variables:
  FALCN_THRESHOLD: "0.8"
  FALCN_FAIL_ON: "high"
  FALCN_OUTPUT_FORMAT: "json"
  FALCN_REPORT_FILE: "falcn-report.json"
  FALCN_NO_LLM: "true"

stages:
  - security

# Use the provided template job
falcn-supply-chain:
  stage: security
  extends: .falcn-scan-template
  artifacts:
    reports:
      # Upload SARIF to GitLab Security Dashboard when format is sarif
      sast: falcn-report.json
    paths:
      - falcn-report.json
    expire_in: 30 days
```

Available template variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `FALCN_VERSION` | latest | Falcn binary version |
| `FALCN_THRESHOLD` | `0.7` | Risk score threshold |
| `FALCN_FAIL_ON` | `high` | Failure severity gate |
| `FALCN_OUTPUT_FORMAT` | `json` | Output format |
| `FALCN_REPORT_FILE` | `falcn-report.json` | Report file path |
| `FALCN_SCAN_PATH` | `.` | Directory to scan |
| `FALCN_NO_LLM` | `true` | Disable LLM explanations |
| `FALCN_FAST_MODE` | `false` | Heuristics-only mode |

---

## Pre-commit Hook

The pre-commit hook blocks commits that add or modify dependency manifest files
until a Falcn scan passes. It detects changes to `package.json`, `go.mod`,
`requirements.txt`, `Cargo.toml`, `pom.xml`, `Gemfile`, `composer.json`, and
other manifest files.

### Installation (direct)

```bash
cp deploy/pre-commit-hook/falcn-pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### Installation (pre-commit framework)

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: falcn
        name: Falcn supply chain scan
        entry: deploy/pre-commit-hook/falcn-pre-commit
        language: script
        pass_filenames: false
        stages: [commit]
```

Install:

```bash
pip install pre-commit
pre-commit install
```

### Configuration

Override hook behaviour with environment variables:

```bash
# In ~/.bashrc or ~/.zshrc, or in a .env file loaded by your shell
export FALCN_THRESHOLD="0.9"     # stricter threshold for commits
export FALCN_FAIL_ON="critical"  # only block on critical threats
export FALCN_FAST_MODE="true"    # use heuristics only (< 100ms per package)
export FALCN_NO_LLM="true"       # skip AI explanations in hook
```

### Behaviour

When a commit touches a dependency file:

1. Falcn scans the repository.
2. If threats at or above `FALCN_FAIL_ON` severity are found, the commit is
   rejected and the scan report is printed.
3. The developer must fix the threat (upgrade, exclude, or get an explicit
   approval) before the commit is accepted.

If Falcn is not installed, the hook exits with code 0 (skips silently) and
prints an installation hint.

---

## Monitoring

### Prometheus Metrics

The `/metrics` endpoint is available at `http://falcn-api:8080/metrics` and is
gated by `METRICS_ALLOWED_CIDRS`. It exposes standard Go runtime metrics plus
the following Falcn-specific metrics:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `falcn_scans_total` | Counter | `status` (ok/error) | Total scans completed |
| `falcn_scan_duration_ms` | Histogram | `ecosystem` | Scan duration per ecosystem in milliseconds |
| `falcn_threats_total` | Counter | `type`, `severity` | Threats detected by type and severity |
| `falcn_packages_scanned_total` | Counter | `registry` | Packages scanned per registry |
| `falcn_ml_inference_duration_ms` | Histogram | — | ML scoring inference time |
| `falcn_llm_calls_total` | Counter | `provider`, `status` | LLM explanation API calls |
| `falcn_rate_limit_hits_total` | Counter | `tier` | Rate limit rejections by tier |
| `falcn_api_requests_total` | Counter | `method`, `path`, `status` | HTTP request totals |
| `falcn_api_request_duration_ms` | Histogram | `method`, `path` | HTTP request latency |

### Prometheus Scrape Configuration

```yaml
# config/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: "falcn"
    static_configs:
      - targets: ["falcn-api:8080"]
    metrics_path: /metrics
    scheme: http
    # In production, restrict access via METRICS_ALLOWED_CIDRS env var
    # and use a Prometheus scraper IP in the allowlist

alerting:
  alertmanagers:
    - static_configs:
        - targets: ["alertmanager:9093"]

rule_files:
  - "falcn-alerts.yml"
```

### Key Alerts

```yaml
# falcn-alerts.yml
groups:
  - name: falcn
    rules:
      - alert: FalcnCriticalThreatDetected
        expr: increase(falcn_threats_total{severity="critical"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Critical supply chain threat detected"
          description: "{{ $value }} critical threat(s) found in the last 5 minutes."

      - alert: FalcnScanErrorRate
        expr: |
          rate(falcn_scans_total{status="error"}[5m])
          / rate(falcn_scans_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Falcn scan error rate above 5%"
          description: "{{ $value | humanizePercentage }} of scans are failing."

      - alert: FalcnHighScanLatency
        expr: histogram_quantile(0.95, rate(falcn_scan_duration_ms_bucket[5m])) > 30000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Falcn p95 scan latency > 30 seconds"
          description: "p95 scan latency is {{ $value | humanizeDuration }}."

      - alert: FalcnRateLimitSpike
        expr: rate(falcn_rate_limit_hits_total[1m]) > 10
        for: 2m
        labels:
          severity: info
        annotations:
          summary: "Elevated rate limit rejections"
          description: "{{ $value }} rate limit hits per second."

      - alert: FalcnAPIDown
        expr: up{job="falcn"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Falcn API is unreachable"
          description: "The Falcn API server has not been scraped for 1 minute."
```

### Grafana Dashboard

A minimal Grafana dashboard JSON provisioning file. Place at
`monitoring/grafana/provisioning/dashboards/falcn.json`:

```json
{
  "title": "Falcn Supply Chain Security",
  "uid": "falcn-overview",
  "version": 1,
  "panels": [
    {
      "title": "Threats by Severity (24h)",
      "type": "stat",
      "targets": [
        {
          "expr": "sum by (severity) (increase(falcn_threats_total[24h]))",
          "legendFormat": "{{severity}}"
        }
      ]
    },
    {
      "title": "Scan Duration p95 (ms)",
      "type": "graph",
      "targets": [
        {
          "expr": "histogram_quantile(0.95, rate(falcn_scan_duration_ms_bucket[5m]))",
          "legendFormat": "p95"
        }
      ]
    },
    {
      "title": "API Request Rate",
      "type": "graph",
      "targets": [
        {
          "expr": "rate(falcn_api_requests_total[1m])",
          "legendFormat": "{{method}} {{path}} {{status}}"
        }
      ]
    },
    {
      "title": "Rate Limit Rejections",
      "type": "graph",
      "targets": [
        {
          "expr": "rate(falcn_rate_limit_hits_total[1m])",
          "legendFormat": "{{tier}}"
        }
      ]
    },
    {
      "title": "ML Inference p99 (ms)",
      "type": "stat",
      "targets": [
        {
          "expr": "histogram_quantile(0.99, rate(falcn_ml_inference_duration_ms_bucket[5m]))"
        }
      ]
    }
  ]
}
```

---

## Tiered Rate Limits

Falcn implements a token-bucket rate limiter with four tiers. The tier is
determined from the JWT `role` claim (or falls back to the IP address for
unauthenticated requests).

| Tier | Requests / minute | Key |
|------|------------------|-----|
| Unauthenticated | 10 | IP address |
| Viewer | 50 | User ID from JWT |
| Analyst | 200 | User ID from JWT |
| Admin / Owner | 1000 | User ID from JWT |

When a request is rate-limited, the server returns:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 6
Content-Type: application/json

{"error": "rate limit exceeded", "retry_after_seconds": 6}
```

### Obtaining a JWT

Exchange an API key for a JWT at `POST /v1/auth/token`:

```bash
curl -X POST https://falcn.yourcompany.com/v1/auth/token \
  -H "X-API-Key: $FALCN_API_KEY" \
  -H "Content-Type: application/json"
```

Response:

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 86400
}
```

Use the token in subsequent requests:

```bash
curl https://falcn.yourcompany.com/v1/analyze \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"package_name": "requests", "registry": "pypi"}'
```

### Distributed Rate Limiting with Redis

When `RATE_LIMIT_REDIS_URL` is set, rate limit counters are stored in Redis and
shared across all Falcn API replicas. This ensures that a client cannot bypass
the limit by load-balancing across multiple pods.

```bash
export RATE_LIMIT_REDIS_URL="redis://:$REDIS_PASSWORD@redis:6379"
```

Without Redis, each replica maintains its own in-memory counter. For single-
replica deployments this is sufficient; for multi-replica deployments, use Redis.

---

## Troubleshooting

### API server refuses to start in production mode

**Symptom:** The server exits with a fatal error referencing CORS or JWT.

**Cause:** `FALCN_APP_ENVIRONMENT=production` requires `FALCN_CORS_ORIGINS` to
be set and `API_KEYS` or `FALCN_JWT_PRIVATE_KEY_FILE` to be configured.

**Fix:**

```bash
export FALCN_CORS_ORIGINS="https://your-dashboard.com"
export API_KEYS="$(openssl rand -hex 32)"
```

### JWT errors: "JWT service initialization failed"

**Symptom:** Log line: `WARNING: JWT service initialization failed — JWT auth disabled`.

**Cause:** `FALCN_JWT_PRIVATE_KEY_FILE` points to a file that does not exist,
or the key is not a valid RSA private key.

**Fix:**

```bash
openssl genpkey -algorithm RSA -out /run/secrets/falcn-jwt-private.pem \
  -pkeyopt rsa_keygen_bits:2048
export FALCN_JWT_PRIVATE_KEY_FILE=/run/secrets/falcn-jwt-private.pem
```

JWT authentication will be unavailable but API key authentication still works.

### Rate limit issues: legitimate traffic being throttled

**Symptom:** CI pipelines or integration services receive HTTP 429.

**Cause:** The caller is using unauthenticated requests (10 req/min limit) or a
low-privilege JWT role.

**Fix:** Issue API keys to CI pipelines and include the JWT in all requests.
Ensure the JWT has the `analyst` or `admin` role. If using Redis-backed rate
limiting, verify the connection:

```bash
redis-cli -u "$RATE_LIMIT_REDIS_URL" ping
```

### ML model not loading

**Symptom:** Log line: `ml: ONNX model not found, falling back to heuristic engine`.

**Cause:** `ml.model_path` in the config points to a file that does not exist,
or the ONNX runtime is not available.

**Fix:** Either leave `model_path` empty to use the built-in heuristic engine
(equivalent accuracy for most use cases), or generate and supply an ONNX model:

```bash
python3 scripts/train_ml_model.py
# Produces: models/falcn_ensemble.onnx
```

Then set in the config:

```yaml
ml:
  model_path: "/models/falcn_ensemble.onnx"
```

### Air-gap CVE database errors

**Symptom:** `open /var/lib/falcn/cve.db: no such file or directory`

**Cause:** The local CVE database has not been populated.

**Fix:** On an internet-connected machine, run:

```bash
falcn update-db --db /var/lib/falcn/cve.db
```

Then transfer `cve.db` to the air-gapped host and set:

```bash
export FALCN_OFFLINE=true
export FALCN_LOCAL_DB=/var/lib/falcn/cve.db
```

### API health check fails in Docker

**Symptom:** Container is stuck in `unhealthy` state. `docker logs falcn-api`
shows the server started but healthcheck fails.

**Cause:** The `curl` binary is not present in the image, or the server is
listening on a different port than expected.

**Fix:** Verify the `PORT` environment variable matches the healthcheck target:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
```

If `curl` is absent, use `wget`:

```yaml
healthcheck:
  test: ["CMD", "wget", "-qO-", "http://localhost:8080/health"]
```

### Scan results not persisting across restarts

**Symptom:** Scan history is empty after restarting the container.

**Cause:** The SQLite database is stored inside the container filesystem.

**Fix:** Mount a persistent volume and set `FALCN_DB_PATH`:

```yaml
volumes:
  - falcn_data:/app/data
environment:
  FALCN_DB_PATH: "/app/data/falcn.db"
```
