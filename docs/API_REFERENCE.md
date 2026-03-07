# Falcn REST API Reference

This document covers every route exposed by the Falcn API server (`api/main.go`).

---

## Contents

- [Base URL and versioning](#base-url-and-versioning)
- [Authentication](#authentication)
- [Rate limiting](#rate-limiting)
- [Environment variables](#environment-variables)
- [Error response format](#error-response-format)
- [Routes](#routes)
  - [GET /health](#get-health)
  - [GET /ready](#get-ready)
  - [GET /v1/status](#get-v1status)
  - [POST /v1/auth/token](#post-v1authtoken)
  - [POST /v1/analyze](#post-v1analyze)
  - [POST /v1/analyze/batch](#post-v1analyzebatch)
  - [POST /v1/analyze/image](#post-v1analyzeimage)
  - [GET /v1/scans](#get-v1scans)
  - [GET /v1/threats](#get-v1threats)
  - [GET /v1/vulnerabilities](#get-v1vulnerabilities)
  - [GET /v1/stats](#get-v1stats)
  - [GET /v1/dashboard/metrics](#get-v1dashboardmetrics)
  - [GET /v1/dashboard/performance](#get-v1dashboardperformance)
  - [POST /v1/reports/generate](#post-v1reportsgenerate)
  - [GET /v1/stream](#get-v1stream)
  - [GET /docs](#get-docs)
  - [GET /openapi.json](#get-openapijson)
  - [GET /metrics](#get-metrics)
- [Webhook payloads](#webhook-payloads)

---

## Base URL and versioning

```
http(s)://<host>:<PORT>
```

Default port is `8080`. All protected routes are under `/v1/`.

---

## Authentication

Two credential forms are accepted. Send one of the following on every request to a protected endpoint.

**Bearer JWT** (recommended for web clients and long-running sessions):

```
Authorization: Bearer <jwt>
```

Obtain a JWT from `POST /v1/auth/token`. JWTs are RS256-signed and expire after 24 hours. Claims include `user_id`, `org_id`, and `role`.

**Raw API key** (suitable for scripts and CI pipelines):

```
X-API-Key: <key>
```

or

```
Authorization: Bearer <key>
```

API keys are configured via the `API_KEYS` environment variable (comma-separated list). When a key is used directly without exchanging it for a JWT, the request receives the `analyst` role.

**Dev mode**: when neither `API_KEYS` nor a JWT key file is configured (`FALCN_JWT_PRIVATE_KEY_FILE` and `FALCN_JWT_PRIVATE_KEY` are both absent), every request is allowed through and a warning banner is printed at startup. Set `API_KEYS` or `API_AUTH_ENABLED=true` to lock down the API.

The following endpoints are **always public** (no credentials required):

- `GET /health`
- `GET /ready`
- `GET /v1/status`
- `POST /v1/auth/token`
- `GET /docs`
- `GET /openapi.json`

---

## Rate limiting

Rate limits are keyed by user ID (from JWT claims) when authenticated, or by client IP for unauthenticated requests. Limits are applied per minute using a token-bucket algorithm. Authenticated users share one bucket across all their IPs, so VPN or mobile IP changes do not reset their quota.

| Role | Requests per minute |
|------|---------------------|
| Unauthenticated | 10 |
| viewer | 50 |
| analyst | 200 |
| admin / owner | 1 000 |

When the limit is exceeded the server returns `429 Too Many Requests` with the following headers:

```
X-RateLimit-Limit: <quota>
Retry-After: 60
```

Redis-backed distributed rate limiting is activated when `RATE_LIMIT_REDIS_URL` is set.

### Role capabilities

| Role | scan:read | scan:create | policy:write | user:write | billing:write |
|------|-----------|-------------|--------------|------------|---------------|
| viewer | yes | no | no | no | no |
| analyst | yes | yes | no | no | no |
| admin | yes | yes | yes | yes | no |
| owner | yes | yes | yes | yes | yes |

---

## Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | TCP port to listen on | `8080` |
| `API_KEYS` | Comma-separated list of valid raw API keys | _(none — dev mode)_ |
| `FALCN_JWT_SECRET` | Symmetric JWT secret (development only; prefer key files in production) | _(none)_ |
| `FALCN_JWT_PRIVATE_KEY_FILE` | Path to RSA private key file for JWT signing | _(none)_ |
| `FALCN_JWT_PRIVATE_KEY` | PEM-encoded RSA private key for JWT signing (alternative to file) | _(none)_ |
| `FALCN_CORS_ORIGINS` | Comma-separated allowed CORS origins. **Required in production** (`APP_ENV=production`). | `http://localhost:3000,http://localhost:5173,http://localhost:8080` |
| `API_AUTH_ENABLED` | Force auth on (`true`/`1`) or off (`false`/`0`). Omit to use auto-detection. | _(auto)_ |
| `RATE_LIMIT_REDIS_URL` | Redis DSN for distributed rate limiting, e.g. `redis://localhost:6379/0` | _(in-process limiter)_ |
| `FALCN_DB_PATH` | Path to the SQLite scan history database | `falcn.db` |
| `METRICS_ALLOWED_CIDRS` | Comma-separated CIDRs allowed to access `/metrics` | `127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` |
| `FALCN_TLS_CERT` | TLS certificate file path. When set together with `FALCN_TLS_KEY`, TLS is enabled. | _(none)_ |
| `FALCN_TLS_KEY` | TLS private key file path | _(none)_ |
| `ANTHROPIC_API_KEY` | Enables Anthropic Claude (claude-haiku-4-5) for LLM threat explanations | _(none)_ |
| `OPENAI_API_KEY` | Enables OpenAI (gpt-4o-mini) for LLM threat explanations | _(none)_ |
| `FALCN_LLM_PROVIDER` | Force LLM provider: `anthropic`, `openai`, or `ollama` | _(auto-detect)_ |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL for high-risk threat alerts | _(none)_ |
| `SMTP_HOST` / `SMTP_USER` / `SMTP_PASS` / `EMAIL_TO` / `EMAIL_FROM` | SMTP credentials for email threat alerts | _(none)_ |

---

## Error response format

All error responses use `Content-Type: application/json` and follow this shape:

```json
{
  "error": "human-readable error message"
}
```

Common HTTP status codes:

| Code | Meaning |
|------|---------|
| `400` | Bad request — missing or malformed fields |
| `401` | Unauthorized — missing or invalid credentials |
| `403` | Forbidden — authenticated but insufficient role |
| `429` | Too many requests — rate limit exceeded |
| `500` | Internal server error |

**400 example — missing package name:**

```json
{
  "error": "Package name is required"
}
```

**401 example:**

```json
{
  "error": "Missing Authorization header"
}
```

**429 example:**

```json
{
  "error": "Rate limit exceeded",
  "message": "Too many requests. Your tier allows 50 requests/minute.",
  "retry_after": "60 seconds",
  "tier": "viewer"
}
```

---

## Routes

### GET /health

Liveness probe. Always returns `200 OK`. No authentication required.

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2026-03-07T12:00:00Z",
  "version": "1.0.0"
}
```

**curl:**

```bash
curl http://localhost:8080/health
```

---

### GET /ready

Readiness probe. Checks Redis connectivity (if configured) and webhook provider configuration. Returns `200` when ready to serve traffic. No authentication required.

When Redis is configured but unreachable, `ready` is `false`.

**Response:**

```json
{
  "ready": true,
  "timestamp": "2026-03-07T12:00:00Z",
  "redis": {
    "configured": true,
    "connected": true
  },
  "webhooks": {
    "slack": { "configured": true },
    "teams": { "configured": false }
  }
}
```

**curl:**

```bash
curl http://localhost:8080/ready
```

---

### GET /v1/status

Returns API status, feature flags, ML model info, and request limits. Public endpoint.

**Response:**

```json
{
  "service": "Falcn API",
  "version": "1.0.0",
  "status": "operational",
  "timestamp": "2026-03-07T12:00:00Z",
  "features": {
    "typosquatting_detection": true,
    "malware_scanning": true,
    "reputation_analysis": true,
    "homoglyph_detection": true,
    "dependency_confusion": true,
    "batch_analysis": true,
    "rate_limiting": true
  },
  "limits": {
    "requests_per_minute": 10,
    "batch_size_limit": 100
  }
}
```

**curl:**

```bash
curl http://localhost:8080/v1/status
```

---

### POST /v1/auth/token

Exchange a valid API key for a 24-hour JWT. Public endpoint. The returned token should be used as a `Bearer` credential on subsequent requests.

The JWT is RS256-signed. The `user_id` claim is a SHA-256 prefix of the submitted API key (never stored in plaintext). The `role` claim is set to `analyst` for all keys exchanged via this endpoint.

**Request body:**

```json
{
  "api_key": "falcn-your-api-key-here"
}
```

**Response `200`:**

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 86400,
  "token_type": "Bearer"
}
```

**Response `401`:**

```json
{
  "error": "Invalid API key"
}
```

**curl:**

```bash
curl -X POST http://localhost:8080/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "falcn-your-api-key-here"}'
```

Store the returned token:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "falcn-your-api-key-here"}' | jq -r .token)
```

---

### POST /v1/analyze

Analyze a single package for supply chain threats. Requires `analyst` role or higher.

Supported registries: `npm`, `pypi`, `go`, `maven`, `nuget`, `rubygems`, `crates.io`, `packagist`. Registry defaults to `npm` when omitted.

The detector engine runs typosquatting checks (Levenshtein, homoglyph, phonetic, keyboard-proximity), DIRT/GTR graph scoring, reputation analysis, dependency confusion detection, embedded-secret scanning, and OSV / GitHub Advisory CVE lookups. If an LLM provider is configured, AI-generated threat explanations are produced asynchronously (up to 8 concurrent goroutines) and broadcast as `explanation` SSE events.

`risk_level` values: `0` = no threats, `1` = low (confidence > 0), `2` = medium (>= 0.5), `3` = high (>= 0.8).

**Request body:**

```json
{
  "package_name": "reqests",
  "registry": "npm"
}
```

**Response `200`:**

```json
{
  "package_name": "reqests",
  "registry": "npm",
  "threats": [
    {
      "id": "a3f1b2c4-d5e6-7890-abcd-ef1234567890",
      "type": "typosquatting",
      "severity": "high",
      "title": "Typosquatting",
      "description": "Package 'reqests' closely resembles popular package 'requests'",
      "package": "reqests",
      "registry": "npm",
      "confidence": 0.94,
      "similar_to": "requests",
      "cve_id": "",
      "cvss_score": 0,
      "detected_at": "2026-03-07T12:00:01Z",
      "explanation": null
    }
  ],
  "warnings": [],
  "risk_level": 3,
  "risk_score": 0.94,
  "analyzed_at": "2026-03-07T12:00:01Z"
}
```

When an LLM explanation is cached and available, the `explanation` field is populated inline:

```json
"explanation": {
  "what": "This package name is a one-character deviation from the widely-used 'requests' library.",
  "why": "Attackers publish packages with near-identical names to intercept installs from developers who mistype.",
  "impact": "Installing this package may execute malicious code at install time or exfiltrate credentials.",
  "remediation": "Remove the package immediately and audit your dependency tree.",
  "confidence": 0.94,
  "generated_by": "anthropic",
  "generated_at": "2026-03-07T11:50:00Z",
  "cache_hit": true
}
```

**curl:**

```bash
curl -X POST http://localhost:8080/v1/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"package_name": "reqests", "registry": "npm"}'
```

---

### POST /v1/analyze/batch

Analyze up to 100 packages in a single request. Requires `analyst` role or higher.

Packages without an explicit `registry` field default to `npm`. Each package is analyzed independently using the same pipeline as `POST /v1/analyze`.

**Request body:**

```json
{
  "packages": [
    { "package_name": "lodash", "registry": "npm" },
    { "package_name": "reqests", "registry": "npm" },
    { "package_name": "requests", "registry": "pypi" }
  ]
}
```

**Response `200`:**

```json
{
  "results": [
    {
      "package_name": "lodash",
      "registry": "npm",
      "threats": [],
      "warnings": [],
      "risk_level": 0,
      "risk_score": 0.0,
      "analyzed_at": "2026-03-07T12:00:01Z"
    },
    {
      "package_name": "reqests",
      "registry": "npm",
      "threats": [
        {
          "id": "a3f1b2c4-d5e6-7890-abcd-ef1234567890",
          "type": "typosquatting",
          "severity": "high",
          "title": "Typosquatting",
          "description": "Package 'reqests' closely resembles popular package 'requests'",
          "package": "reqests",
          "registry": "npm",
          "confidence": 0.94,
          "similar_to": "requests",
          "detected_at": "2026-03-07T12:00:01Z"
        }
      ],
      "warnings": [],
      "risk_level": 3,
      "risk_score": 0.94,
      "analyzed_at": "2026-03-07T12:00:01Z"
    },
    {
      "package_name": "requests",
      "registry": "pypi",
      "threats": [],
      "warnings": [],
      "risk_level": 0,
      "risk_score": 0.0,
      "analyzed_at": "2026-03-07T12:00:01Z"
    }
  ],
  "summary": {
    "total": 3,
    "high_risk": 1,
    "medium_risk": 0,
    "low_risk": 0,
    "no_threats": 2
  },
  "analyzed_at": "2026-03-07T12:00:01Z"
}
```

**curl:**

```bash
curl -X POST http://localhost:8080/v1/analyze/batch \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "packages": [
      {"package_name": "lodash", "registry": "npm"},
      {"package_name": "reqests", "registry": "npm"},
      {"package_name": "requests", "registry": "pypi"}
    ]
  }'
```

---

### POST /v1/analyze/image

Scan a container image for vulnerabilities and misconfigurations. Requires `analyst` role or higher.

The scanner pulls image layers from the registry (unless `light: true`), checks each layer against the OSV vulnerability database, and inspects Dockerfile instructions for misconfigurations. Layer downloads larger than `max_layer_mb` are skipped.

**Request body:**

```json
{
  "image": "nginx:1.27",
  "light": false,
  "username": "",
  "password": "",
  "token": "",
  "max_layer_mb": 100
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `image` | string | yes | Image reference, e.g. `nginx:1.27` or `ghcr.io/org/app:sha-abc123` |
| `light` | boolean | no | Skip layer downloads; run metadata-only checks |
| `username` | string | no | Registry username for private images |
| `password` | string | no | Registry password for private images |
| `token` | string | no | Bearer token for private registries |
| `max_layer_mb` | integer | no | Skip individual layers larger than this size in MB |

**Response `200`:** `ImageScanResult` JSON (structure depends on the container scanner output for the given image).

**curl:**

```bash
curl -X POST http://localhost:8080/v1/analyze/image \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"image": "nginx:1.27", "light": false, "max_layer_mb": 100}'
```

---

### GET /v1/scans

List recent scans in reverse chronological order. Requires `viewer` role or higher. Results are served from SQLite when available, falling back to the in-memory ring buffer (capped at 500 entries) when not.

**Query parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | `50` | Maximum records to return (capped at `200`) |
| `offset` | integer | `0` | Pagination offset |

**Response `200`:**

```json
{
  "scans": [
    {
      "id": "reqests@npm",
      "target": "reqests",
      "status": "threats_found",
      "threat_count": 1,
      "warning_count": 0,
      "duration_ms": "142ms",
      "duration_ms_raw": 142,
      "created_at": "2026-03-07T12:00:01Z"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

`status` values: `clean` or `threats_found`.

**curl:**

```bash
curl "http://localhost:8080/v1/scans?limit=20&offset=0" \
  -H "Authorization: Bearer $TOKEN"
```

---

### GET /v1/threats

Paginated list of all recorded threats across all scans, sourced from SQLite. Requires `viewer` role or higher.

**Query parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | `50` | Maximum records to return (capped at `200`) |
| `offset` | integer | `0` | Pagination offset |

**Response `200`:**

```json
{
  "threats": [
    {
      "scan_id": "reqests@npm",
      "package": "reqests",
      "registry": "npm",
      "threat_type": "typosquatting",
      "severity": "high",
      "description": "Package 'reqests' closely resembles popular package 'requests'",
      "confidence": 0.94,
      "created_at": "2026-03-07T12:00:01Z"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

**curl:**

```bash
curl "http://localhost:8080/v1/threats?limit=20&offset=0" \
  -H "Authorization: Bearer $TOKEN"
```

---

### GET /v1/vulnerabilities

Aggregated CVE data from OSV and GitHub Advisory databases across all recorded scans. Requires `viewer` role or higher.

**Response `200`:**

```json
{
  "total_scans": 47,
  "total_threats": 12,
  "ecosystems": ["npm", "pypi", "go", "maven", "nuget", "rubygems", "crates.io", "packagist"],
  "last_updated": "2026-03-07T12:00:00Z",
  "data_note": "Aggregated from SQLite scan history."
}
```

When SQLite is unavailable, `data_note` indicates in-memory fallback.

**curl:**

```bash
curl http://localhost:8080/v1/vulnerabilities \
  -H "Authorization: Bearer $TOKEN"
```

---

### GET /v1/stats

Aggregated scan statistics. Requires `viewer` role or higher.

**Response `200`:**

```json
{
  "total_requests": 47,
  "packages_analyzed": 47,
  "threats_detected": 12,
  "warnings_detected": 3,
  "popular_ecosystems": ["npm", "pypi", "go", "maven", "nuget", "rubygems", "crates.io", "packagist"]
}
```

**curl:**

```bash
curl http://localhost:8080/v1/stats \
  -H "Authorization: Bearer $TOKEN"
```

---

### GET /v1/dashboard/metrics

Comprehensive time-series and summary data for the security dashboard. Requires `viewer` role or higher.

The JSON shape matches the frontend `DashboardMetrics` TypeScript interface exactly. The 14-day threat trend and ecosystem distribution are sourced from SQLite. When SQLite is unavailable, the endpoint falls back to the in-memory ring buffer for basic counts, and array fields (`top_ecosystems`, `threat_trend`, `recent_threats`) are empty arrays rather than `null`.

**Response `200`:**

```json
{
  "total_scans": 47,
  "total_packages": 47,
  "total_threats": 12,
  "critical_threats": 1,
  "high_threats": 5,
  "medium_threats": 4,
  "low_threats": 2,
  "avg_risk_score": 0.712,
  "scans_today": 8,
  "threats_today": 3,
  "top_ecosystems": [
    { "ecosystem": "npm", "count": 30 },
    { "ecosystem": "pypi", "count": 12 }
  ],
  "threat_trend": [
    { "date": "2026-02-22", "count": 1 },
    { "date": "2026-02-23", "count": 0 },
    { "date": "2026-03-07", "count": 3 }
  ],
  "recent_threats": [
    {
      "package": "reqests",
      "registry": "npm",
      "threat_type": "typosquatting",
      "severity": "high",
      "confidence": 0.94,
      "created_at": "2026-03-07T12:00:01Z"
    }
  ]
}
```

**curl:**

```bash
curl http://localhost:8080/v1/dashboard/metrics \
  -H "Authorization: Bearer $TOKEN"
```

---

### GET /v1/dashboard/performance

p50 / p95 / p99 latency data and Prometheus-sourced performance metrics for the dashboard. Requires `viewer` role or higher.

**Response `200`:**

```json
{
  "p50_ms": 38,
  "p95_ms": 210,
  "p99_ms": 487,
  "requests_per_second": 4.2,
  "error_rate": 0.002,
  "uptime_seconds": 86412
}
```

**curl:**

```bash
curl http://localhost:8080/v1/dashboard/performance \
  -H "Authorization: Bearer $TOKEN"
```

---

### POST /v1/reports/generate

Generate and download a security report. Requires `analyst` role or higher.

The report is built from the last 500 recorded threats in SQLite and returned as a file attachment via `Content-Disposition: attachment`. The four supported formats map onto four SBOM and security-report standards.

**Request body:**

```json
{
  "type": "technical",
  "format": "sarif"
}
```

| Field | Allowed values | Default |
|-------|---------------|---------|
| `type` | `technical`, `executive`, `compliance` | `technical` |
| `format` | `sarif`, `cyclonedx`, `spdx`, `json` | `json` |

**Response `200` headers:**

| Format | Content-Type | Example filename |
|--------|-------------|-----------------|
| `sarif` | `application/sarif+json` | `falcn-technical-2026-03-07.sarif` |
| `cyclonedx` | `application/vnd.cyclonedx+json` | `falcn-compliance-2026-03-07.cdx.json` |
| `spdx` | `application/spdx+json` | `falcn-technical-2026-03-07.spdx.json` |
| `json` | `application/json` | `falcn-executive-2026-03-07.json` |

**curl (download SARIF):**

```bash
curl -X POST http://localhost:8080/v1/reports/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type": "technical", "format": "sarif"}' \
  -O -J
```

**curl (download CycloneDX 1.5):**

```bash
curl -X POST http://localhost:8080/v1/reports/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type": "compliance", "format": "cyclonedx"}' \
  -O -J
```

**curl (download SPDX):**

```bash
curl -X POST http://localhost:8080/v1/reports/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type": "technical", "format": "spdx"}' \
  -O -J
```

---

### GET /v1/stream

Server-Sent Events (SSE) stream for real-time threat and explanation events. Requires authentication (Bearer JWT or `X-API-Key`). Open in dev mode.

Connect once and receive events from all concurrent scans on this server instance. The connection stays open indefinitely. The server sends a heartbeat `ping` every 15 seconds to prevent idle-connection timeouts in HTTP proxies. The `X-Accel-Buffering: no` header disables nginx proxy buffering.

The connection remains open after receiving `done` because `explanation` events arrive asynchronously as the LLM finishes generating or loading from cache.

**SSE event types:**

| Event | Trigger | Data payload |
|-------|---------|--------------|
| `connected` | Immediately on connect | `{"status": "connected", "timestamp": "..."}` |
| `scan_started` | When `POST /v1/analyze` begins | `{"package": "...", "registry": "...", "timestamp": "..."}` |
| `threat` | Each threat discovered during a scan | Full `Threat` JSON object (same shape as `/v1/analyze` response) |
| `explanation` | LLM explanation generated or served from SQLite cache | `{"threat_id": "...", "package": "...", "registry": "...", "type": "...", "explanation": {...}}` |
| `done` | All threats for a scan have been discovered | `{"package": "...", "registry": "...", "threat_count": N, "warning_count": N, "timestamp": "..."}` |
| `ping` | Every 15 seconds | `{"timestamp": "...", "clients": N}` |
| `scan_error` | Detector engine error | `{"package": "...", "registry": "...", "error": "..."}` |

**EventSource example (browser):**

```javascript
const es = new EventSource('/v1/stream', {
  headers: { 'Authorization': `Bearer ${token}` }
});

es.addEventListener('threat', e => {
  const threat = JSON.parse(e.data);
  console.log('Threat detected:', threat.type, threat.severity, threat.package);
});

es.addEventListener('explanation', e => {
  const { threat_id, explanation } = JSON.parse(e.data);
  console.log('AI explanation for', threat_id, ':', explanation.what);
});

es.addEventListener('done', e => {
  const summary = JSON.parse(e.data);
  console.log('Scan complete. Threats found:', summary.threat_count);
});

es.addEventListener('ping', () => { /* keepalive — no action needed */ });
es.addEventListener('error', () => { setTimeout(() => es.close(), 1000); });
```

**curl example:**

```bash
curl -N -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/v1/stream
```

**Example wire output:**

```
event: connected
data: {"status":"connected","timestamp":"2026-03-07T12:00:00Z"}

event: scan_started
data: {"package":"reqests","registry":"npm","timestamp":"2026-03-07T12:00:01Z"}

event: threat
data: {"id":"a3f1b2c4-d5e6-7890-abcd-ef1234567890","type":"typosquatting","severity":"high","title":"Typosquatting","description":"Package 'reqests' closely resembles popular package 'requests'","package":"reqests","registry":"npm","confidence":0.94,"similar_to":"requests","detected_at":"2026-03-07T12:00:01Z"}

event: done
data: {"package":"reqests","registry":"npm","threat_count":1,"warning_count":0,"timestamp":"2026-03-07T12:00:01Z"}

event: explanation
data: {"threat_id":"a3f1b2c4-d5e6-7890-abcd-ef1234567890","package":"reqests","registry":"npm","type":"typosquatting","explanation":{"what":"This package name is a one-character deviation from the widely-used 'requests' library.","why":"Attackers publish packages with near-identical names to intercept installs from developers who mistype the dependency name.","impact":"Installing this package may execute malicious code at install time or exfiltrate credentials from the runtime environment.","remediation":"Remove the package immediately and audit your full dependency tree for similar deviations.","confidence":0.94,"generated_by":"anthropic","generated_at":"2026-03-07T12:00:02Z","cache_hit":false}}

event: ping
data: {"timestamp":"2026-03-07T12:00:16Z","clients":3}
```

---

### GET /docs

Swagger UI for interactive API exploration. Public endpoint. Served from `docs/swagger.html`.

```bash
open http://localhost:8080/docs
```

---

### GET /openapi.json

OpenAPI 3.1.0 specification in JSON format. Public endpoint. Served from `docs/openapi.json`.

```bash
curl http://localhost:8080/openapi.json | jq .info
```

---

### GET /metrics

Prometheus metrics in text exposition format. Restricted to requests originating from loopback or RFC-1918 private addresses (configurable via `METRICS_ALLOWED_CIDRS`). Requests from public IPs receive `403 Forbidden`.

```bash
curl http://localhost:8080/metrics
```

---

## Webhook payloads

The API fires outbound webhooks when a scan returns `risk_level >= 3` (confidence >= 0.8). Both delivery mechanisms use exponential backoff with up to 3 retry attempts (1 s, 2 s, 4 s).

### Slack webhook

Configured via `SLACK_WEBHOOK_URL`. Uses the Slack incoming webhook format:

```json
{
  "text": "High risk detected: reqests (npm) risk=3"
}
```

### SMTP email alert

Configured via `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`, `EMAIL_TO`, `EMAIL_FROM`. Sends a plain-text email on port 587 (STARTTLS) with subject `Falcn Alert` and body:

```
High risk detected: reqests (npm) risk=3
```

### Integration hub events (Jira, Microsoft Teams, email templates)

When `cfg.Integrations.Enabled` is `true` in the Falcn config file, each detected threat is published to the integration hub as a structured `SecurityEvent`. The hub dispatches to all configured providers (Jira ticket creation, Microsoft Teams adaptive card, email template). The event payload:

```json
{
  "id": "api_event_<uuid>",
  "timestamp": "2026-03-07T12:00:01Z",
  "type": "threat_detected",
  "severity": "high",
  "package": {
    "name": "reqests",
    "version": "unknown",
    "registry": "npm"
  },
  "threat": {
    "type": "typosquatting",
    "description": "Package 'reqests' closely resembles popular package 'requests'",
    "risk_score": 0.94,
    "confidence": 0.94,
    "mitigations": ["Remove the package and audit your dependency tree"]
  },
  "metadata": {
    "detection_method": "enhanced_typosquatting",
    "tags": ["api", "automated"]
  }
}
```
