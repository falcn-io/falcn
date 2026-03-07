# Falcn v2.3.0 — Integrations Guide

This guide covers every integration point Falcn supports: CI/CD pipelines, security event
forwarding, IDE tooling, SBOM and compliance platforms, and the real-time SSE streaming API.

---

## Table of Contents

- [CI/CD Integrations](#cicd-integrations)
  - [GitHub Action](#github-action)
  - [GitLab CI](#gitlab-ci)
  - [Pre-commit Hook](#pre-commit-hook)
  - [Bitbucket Pipelines](#bitbucket-pipelines)
  - [Azure DevOps](#azure-devops)
  - [Jenkins](#jenkins)
- [Security Event Forwarding](#security-event-forwarding)
  - [Splunk HEC](#splunk-hec)
  - [Slack](#slack)
  - [Generic Webhook](#generic-webhook)
  - [Email (SMTP)](#email-smtp)
  - [PagerDuty](#pagerduty)
- [IDE Integrations](#ide-integrations)
- [SBOM and Compliance Integrations](#sbom-and-compliance-integrations)
  - [Dependency-Track](#dependency-track)
  - [GUAC](#guac)
  - [ENISA / EU CRA](#enisa--eu-cra)
- [SSE Streaming Integration](#sse-streaming-integration)
- [Configuration Reference](#configuration-reference)

---

## CI/CD Integrations

### GitHub Action

The Falcn GitHub Action (`deploy/github-action/action.yml`) downloads a pinned or latest binary,
runs a scan, posts a PR comment summarising threats, and optionally uploads a SARIF report to
GitHub Advanced Security.

#### Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory to scan |
| `threshold` | `0.7` | Minimum risk score to flag (0.0–1.0) |
| `fail-on` | `high` | Severity level that causes a non-zero exit: `critical`, `high`, `medium`, `low` |
| `output-format` | `table` | Report format: `json`, `sarif`, `table` |
| `output-file` | `` | Write report to this path (required for PR annotation and SARIF upload) |
| `no-llm` | `true` | Disable LLM-powered threat explanations (recommended for CI speed) |
| `fast-mode` | `false` | Heuristics-only scan targeting <100 ms per package |
| `version` | `` | Pin a specific Falcn release, e.g. `v2.3.0`. Empty uses latest. |
| `token` | `${{ github.token }}` | GitHub token used to post PR comments |

#### Outputs

| Output | Description |
|---|---|
| `threat-count` | Total threats found |
| `critical-count` | Critical-severity threat count |
| `high-count` | High-severity threat count |
| `report-path` | Path to the generated report file |

#### Basic usage

```yaml
name: Supply Chain Security

on:
  pull_request:
  push:
    branches: [main]

jobs:
  falcn:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required for SARIF upload
      pull-requests: write     # required for PR comments

    steps:
      - uses: actions/checkout@v4

      - uses: falcn-io/falcn@v2
        with:
          path: '.'
          fail-on: 'high'
          output-format: 'sarif'
          output-file: 'falcn.sarif'
          no-llm: 'true'
          fast-mode: 'false'

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: falcn.sarif
```

#### Full example with caching and PR annotation

The action caches the Falcn binary automatically using `actions/cache`. The PR annotation step
runs only when the event is a pull request and threats were found. No extra configuration is
needed — the action handles both automatically when `output-file` is set.

```yaml
name: Falcn Supply Chain Security

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'   # Weekly Monday scan

jobs:
  falcn-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - uses: actions/checkout@v4

      # Binary is cached automatically by the action.
      # Cache key: falcn-<version>-<runner.os>-<runner.arch>
      - name: Falcn scan
        id: falcn
        uses: falcn-io/falcn@v2
        with:
          path: '.'
          fail-on: 'high'
          output-format: 'sarif'
          output-file: 'falcn.sarif'
          no-llm: 'true'
          # Use fast-mode on PRs, full scan on main
          fast-mode: ${{ github.event_name == 'pull_request' && 'true' || 'false' }}

      - name: Upload SARIF to GitHub Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: falcn.sarif

      - name: Upload JSON report as artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: falcn-report
          path: falcn.sarif
          retention-days: 30

      - name: Print threat summary
        if: always()
        run: |
          echo "Threats: ${{ steps.falcn.outputs.threat-count }}"
          echo "Critical: ${{ steps.falcn.outputs.critical-count }}"
          echo "High: ${{ steps.falcn.outputs.high-count }}"
```

#### Monorepo matrix strategy

```yaml
jobs:
  falcn-matrix:
    strategy:
      fail-fast: false
      matrix:
        service:
          - path: services/api
            name: api
          - path: services/frontend
            name: frontend
          - path: services/worker
            name: worker

    name: Falcn — ${{ matrix.service.name }}
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - uses: actions/checkout@v4

      - uses: falcn-io/falcn@v2
        with:
          path: ${{ matrix.service.path }}
          fail-on: 'high'
          output-format: 'sarif'
          output-file: falcn-${{ matrix.service.name }}.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: falcn-${{ matrix.service.name }}.sarif
          category: falcn-${{ matrix.service.name }}
```

---

### GitLab CI

Include the Falcn GitLab CI template to get two pre-built jobs: a full scan on merge requests
and default branch pushes, and a fast heuristics-only gate for MR pipelines.

#### Minimal include

```yaml
# .gitlab-ci.yml
include:
  - remote: 'https://raw.githubusercontent.com/falcn-io/falcn/main/deploy/gitlab-template/.gitlab-ci.yml'

variables:
  FALCN_FAIL_ON: high
  FALCN_SBOM_FORMAT: cyclonedx
```

#### Available variables

| Variable | Default | Description |
|---|---|---|
| `FALCN_VERSION` | `` | Pin a release, e.g. `v2.3.0`. Empty uses latest. |
| `FALCN_THRESHOLD` | `0.7` | Risk score threshold (0.0–1.0) |
| `FALCN_FAIL_ON` | `high` | Fail pipeline at: `critical`, `high`, `medium`, `low` |
| `FALCN_OUTPUT_FORMAT` | `json` | `json`, `sarif`, or `table` |
| `FALCN_REPORT_FILE` | `falcn-report.json` | Artifact file path |
| `FALCN_SCAN_PATH` | `.` | Directory to scan |
| `FALCN_NO_LLM` | `true` | Disable LLM explanations |
| `FALCN_FAST_MODE` | `false` | Enable <100 ms heuristics-only mode |
| `FALCN_CACHE_DIR` | `$CI_PROJECT_DIR/.falcn-cache` | Binary cache location |

#### Pre-built jobs included by the template

- `falcn-dependency-scan` — full scan; runs on MR events and default branch pushes; fails on
  `high` severity by default.
- `falcn-fast-gate` — heuristics-only scan; runs on MR events only; fails on `critical` severity.

The binary is cached between jobs using the GitLab CI cache keyed on `FALCN_VERSION`. Reports are
uploaded as artifacts and exposed as GitLab SAST dashboard entries when the output format is SARIF.

#### Override specific jobs

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/falcn-io/falcn/main/deploy/gitlab-template/.gitlab-ci.yml'

falcn-dependency-scan:
  variables:
    FALCN_FAIL_ON: critical
    FALCN_FAST_MODE: 'true'
  stage: security
```

---

### Pre-commit Hook

The pre-commit hook (`deploy/pre-commit-hook/falcn-pre-commit`) watches for changes to dependency
manifest files and blocks the commit when threats above the configured severity threshold are found.
It only runs when a dependency file is actually staged, so it adds no overhead to ordinary commits.

Supported manifest files: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`,
`requirements.txt`, `Pipfile`, `Pipfile.lock`, `pyproject.toml`, `poetry.lock`, `go.mod`,
`go.sum`, `pom.xml`, `build.gradle`, `build.gradle.kts`, `Gemfile`, `Gemfile.lock`,
`Cargo.toml`, `Cargo.lock`, `composer.json`, `composer.lock`.

#### Installation — pre-commit framework

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: falcn
        name: Falcn supply chain scan
        entry: deploy/pre-commit-hook/falcn-pre-commit
        language: script
        pass_filenames: false
```

```bash
pre-commit install
```

#### Installation — direct Git hook

```bash
cp deploy/pre-commit-hook/falcn-pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

#### Configuration via environment variables

| Variable | Default | Description |
|---|---|---|
| `FALCN_THRESHOLD` | `0.7` | Minimum risk score to flag |
| `FALCN_FAIL_ON` | `high` | Block commit at: `critical`, `high`, `medium`, `low` |
| `FALCN_FAST_MODE` | `true` | Use heuristics-only mode (recommended for local commits) |
| `FALCN_NO_LLM` | `true` | Disable LLM explanations |

The hook automatically locates the `falcn` binary in `~/.falcn/bin/falcn`,
`~/.local/bin/falcn`, `/usr/local/bin/falcn`, and `.falcn/bin/falcn` inside the repository root.
If none is found, the hook exits cleanly with a warning rather than blocking the commit.

To bypass the hook in an emergency:

```bash
git commit --no-verify
```

---

### Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
image: ubuntu:22.04

pipelines:
  pull-requests:
    '**':
      - step:
          name: Falcn Supply Chain Scan
          script:
            - apt-get update -qq && apt-get install -y -qq curl jq tar ca-certificates
            - |
              VERSION=$(curl -fsSL https://api.github.com/repos/falcn-io/falcn/releases/latest \
                | jq -r '.tag_name')
              curl -fsSL "https://github.com/falcn-io/falcn/releases/download/${VERSION}/falcn_${VERSION}_linux_amd64.tar.gz" \
                | tar -xz -C /usr/local/bin
              chmod +x /usr/local/bin/falcn
            - falcn scan . --output json --report falcn-report.json --no-llm --threshold 0.7
            - |
              CRITICAL=$(jq -r '.summary.critical_count // 0' falcn-report.json)
              HIGH=$(jq -r '.summary.high_count // 0' falcn-report.json)
              echo "Critical: ${CRITICAL}, High: ${HIGH}"
              [ "${CRITICAL}" -eq 0 ] && [ "${HIGH}" -eq 0 ] || exit 1
          artifacts:
            - falcn-report.json
```

---

### Azure DevOps

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main
      - develop

pr:
  branches:
    include:
      - main

pool:
  vmImage: ubuntu-latest

variables:
  FALCN_VERSION: ''        # leave empty for latest
  FALCN_FAIL_ON: high

steps:
  - script: |
      VERSION="${FALCN_VERSION}"
      if [ -z "${VERSION}" ]; then
        VERSION=$(curl -fsSL https://api.github.com/repos/falcn-io/falcn/releases/latest \
          | jq -r '.tag_name')
      fi
      curl -fsSL \
        "https://github.com/falcn-io/falcn/releases/download/${VERSION}/falcn_${VERSION}_linux_amd64.tar.gz" \
        | tar -xz -C /usr/local/bin
      chmod +x /usr/local/bin/falcn
      falcn version
    displayName: Install Falcn

  - script: |
      falcn scan . \
        --output json \
        --report $(Build.ArtifactStagingDirectory)/falcn-report.json \
        --no-llm \
        --threshold 0.7

      CRITICAL=$(jq -r '.summary.critical_count // 0' $(Build.ArtifactStagingDirectory)/falcn-report.json)
      HIGH=$(jq -r '.summary.high_count // 0' $(Build.ArtifactStagingDirectory)/falcn-report.json)
      echo "Threats — Critical: ${CRITICAL}, High: ${HIGH}"

      if [ "${FALCN_FAIL_ON}" = "high" ]; then
        [ "${CRITICAL}" -eq 0 ] && [ "${HIGH}" -eq 0 ] || exit 1
      elif [ "${FALCN_FAIL_ON}" = "critical" ]; then
        [ "${CRITICAL}" -eq 0 ] || exit 1
      fi
    displayName: Run Falcn Scan

  - task: PublishBuildArtifacts@1
    condition: always()
    inputs:
      PathtoPublish: $(Build.ArtifactStagingDirectory)
      ArtifactName: falcn-report
```

---

### Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent { label 'linux' }

    environment {
        FALCN_FAIL_ON = 'high'
        FALCN_THRESHOLD = '0.7'
    }

    stages {
        stage('Install Falcn') {
            steps {
                sh '''
                    set -euo pipefail
                    VERSION=$(curl -fsSL https://api.github.com/repos/falcn-io/falcn/releases/latest \
                      | jq -r '.tag_name')
                    INSTALL_DIR="${HOME}/.falcn/bin"
                    mkdir -p "${INSTALL_DIR}"
                    if [ ! -x "${INSTALL_DIR}/falcn" ]; then
                      curl -fsSL \
                        "https://github.com/falcn-io/falcn/releases/download/${VERSION}/falcn_${VERSION}_linux_amd64.tar.gz" \
                        | tar -xz -C "${INSTALL_DIR}"
                      chmod +x "${INSTALL_DIR}/falcn"
                    fi
                    echo "${INSTALL_DIR}" >> "${JENKINS_HOME}/.profile" || true
                '''
            }
        }

        stage('Supply Chain Scan') {
            steps {
                sh '''
                    set -euo pipefail
                    export PATH="${HOME}/.falcn/bin:${PATH}"

                    falcn scan . \
                      --output json \
                      --report falcn-report.json \
                      --no-llm \
                      --threshold "${FALCN_THRESHOLD}"

                    CRITICAL=$(jq -r '.summary.critical_count // 0' falcn-report.json)
                    HIGH=$(jq -r '.summary.high_count // 0' falcn-report.json)
                    echo "Critical: ${CRITICAL}, High: ${HIGH}"

                    case "${FALCN_FAIL_ON}" in
                      critical) [ "${CRITICAL}" -eq 0 ] || exit 1 ;;
                      high)     [ "${CRITICAL}" -eq 0 ] && [ "${HIGH}" -eq 0 ] || exit 1 ;;
                    esac
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'falcn-report.json', allowEmptyArchive: true
            publishHTML([
                reportDir: '.',
                reportFiles: 'falcn-report.json',
                reportName: 'Falcn Security Report'
            ])
        }
    }
}
```

---

## Security Event Forwarding

All event-forwarding connectors are configured under the `integrations` key in `.falcn.yaml`.
The integration hub routes internal `SecurityEvent` objects to all enabled connectors matching
the event's type and severity filters.

### Splunk HEC

The Splunk connector (`internal/integrations/connectors/splunk.go`) forwards events to a Splunk
HTTP Event Collector endpoint.

#### Configuration

```yaml
integrations:
  enabled: true
  connectors:
    splunk_siem:
      type: splunk
      enabled: true
      settings:
        hec_url: "https://splunk.corp.example.com:8088/services/collector/event"
        token: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        index: "falcn"
        source: "falcn_scanner"
        sourcetype: "falcn:threat"
        host: "falcn-api-prod"
        timeout: 30
      retry:
        enabled: true
        max_attempts: 3
        initial_delay: 1s
        max_delay: 30s
        backoff_factor: 2.0
```

#### Splunk event envelope

Each event is wrapped in the standard Splunk HEC envelope:

```json
{
  "time": 1741305600,
  "host": "falcn-api-prod",
  "source": "falcn_scanner",
  "sourcetype": "falcn:threat",
  "index": "falcn",
  "event": {
    "id": "3a7c1f22-...",
    "timestamp": "2026-03-07T10:00:00Z",
    "type": "threat_detected",
    "severity": "high",
    "source": "Falcn",
    "package": {
      "name": "req",
      "version": "0.1.0",
      "registry": "pypi"
    },
    "threat": {
      "type": "typosquatting",
      "confidence": 0.94,
      "risk_score": 0.87,
      "description": "Package name closely resembles popular 'requests' package",
      "mitigations": ["Remove req, install requests==2.31.0"]
    },
    "metadata": {
      "detection_method": "enhanced_typosquatting",
      "correlation_id": "scan-20260307-abc123"
    }
  }
}
```

#### Example SPL search

```
index=falcn sourcetype="falcn:threat"
| spath "event.severity" OUTPUT severity
| spath "event.package.name" OUTPUT package
| spath "event.threat.type" OUTPUT threat_type
| where severity IN ("critical", "high")
| stats count BY threat_type, package
| sort -count
```

---

### Slack

The Slack connector (`internal/integrations/connectors/slack.go`) delivers rich message
attachments to any Slack channel via an incoming webhook URL.

#### Configuration

```yaml
integrations:
  enabled: true
  connectors:
    security_slack:
      type: slack
      enabled: true
      settings:
        webhook_url: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
        channel: "#security-alerts"
        username: "Falcn"
        icon_emoji: ":shield:"
        timeout: 10
      retry:
        enabled: true
        max_attempts: 2
        initial_delay: 2s
        max_delay: 10s
        backoff_factor: 2.0
      filters:
        - high_severity_only
```

#### Slack message format

```json
{
  "channel": "#security-alerts",
  "username": "Falcn",
  "icon_emoji": ":shield:",
  "text": "Supply chain threat detected",
  "attachments": [
    {
      "color": "#FF0000",
      "title": "[HIGH] typosquatting — req (pypi)",
      "text": "Package name closely resembles popular 'requests' package",
      "fields": [
        { "title": "Package",    "value": "req@0.1.0",       "short": true },
        { "title": "Registry",   "value": "pypi",             "short": true },
        { "title": "Risk Score", "value": "0.87",             "short": true },
        { "title": "Confidence", "value": "94%",              "short": true },
        { "title": "Remediation","value": "Remove req, install requests==2.31.0", "short": false }
      ],
      "ts": 1741305600
    }
  ]
}
```

#### Routing by severity

Use connector-level filters to send only critical threats to a high-priority channel while
routing all threats to a general channel:

```yaml
integrations:
  connectors:
    slack_critical:
      type: slack
      settings:
        webhook_url: "https://hooks.slack.com/..."
        channel: "#soc-critical"
      filters: [critical_only]

    slack_all:
      type: slack
      settings:
        webhook_url: "https://hooks.slack.com/..."
        channel: "#security-alerts"

  filters:
    - name: critical_only
      type: severity
      condition: equals
      value: critical
```

---

### Generic Webhook

The webhook connector (`internal/integrations/connectors/webhook.go`) delivers a JSON payload to
any HTTP/HTTPS endpoint. It supports custom headers, bearer token auth, configurable retry, and
content-type negotiation.

#### Configuration

```yaml
integrations:
  enabled: true
  connectors:
    custom_endpoint:
      type: webhook
      enabled: true
      settings:
        url: "https://api.corp.example.com/security/falcn-events"
        method: POST
        headers:
          X-Source: "falcn"
          Accept: "application/json"
        auth_header: "Authorization"
        auth_token: "Bearer eyJhbGci..."
        content_type: "application/json"
        timeout: 15
        retry_count: 3
      retry:
        enabled: true
        max_attempts: 3
        initial_delay: 500ms
        max_delay: 4s
        backoff_factor: 2.0
```

#### POST payload structure

```json
{
  "source": "Falcn",
  "timestamp": "2026-03-07T10:00:00Z",
  "event": {
    "id": "3a7c1f22-9b4d-4e01-a8f3-c7d2e5b1f890",
    "timestamp": "2026-03-07T10:00:00Z",
    "type": "threat_detected",
    "severity": "high",
    "source": "Falcn",
    "package": {
      "name": "req",
      "version": "0.1.0",
      "registry": "pypi",
      "hash": "sha256:abc123...",
      "path": "requirements.txt"
    },
    "threat": {
      "type": "typosquatting",
      "confidence": 0.94,
      "risk_score": 0.87,
      "description": "Package name closely resembles popular 'requests' package",
      "evidence": {
        "similar_package": "requests",
        "edit_distance": "2"
      },
      "mitigations": ["Remove req, install requests==2.31.0"]
    },
    "metadata": {
      "detection_method": "enhanced_typosquatting",
      "tags": ["supply-chain", "typosquatting"],
      "correlation_id": "scan-20260307-abc123"
    }
  },
  "metadata": {
    "scan_id": "scan-20260307-abc123",
    "reachable": true
  }
}
```

#### Retry logic

The connector retries failed deliveries up to `retry_count` times (default: 3) with exponential
backoff. The default `initial_delay` is 500 ms and `backoff_factor` is 2.0, giving delays of
500 ms, 1 s, and 2 s for three attempts.

#### HMAC signature verification

When the incoming webhook handler receives scan-trigger payloads from external systems (e.g.
GitHub), it verifies the request using HMAC-SHA256. The signature is carried in the header
configured via `signature_header` (typically `X-Hub-Signature-256` for GitHub or
`X-Falcn-Signature` for custom senders). The secret is set in `WebhookConfig.Secret`.

Verification is implemented in `internal/api/webhook/handlers.go` using `crypto/hmac` and
`crypto/sha256` from the Go standard library.

---

### Email (SMTP)

The email connector (`internal/integrations/connectors/email.go`) sends formatted alert emails
over SMTP with optional TLS.

#### Configuration

```yaml
integrations:
  enabled: true
  connectors:
    email_alerts:
      type: email
      enabled: true
      settings:
        smtp_host: "smtp.corp.example.com"
        smtp_port: 587
        username: "falcn-alerts@corp.example.com"
        password: "${SMTP_PASSWORD}"
        from_email: "falcn-alerts@corp.example.com"
        from_name: "Falcn Security Scanner"
        to_emails:
          - "security-team@corp.example.com"
          - "devops@corp.example.com"
        cc_emails:
          - "ciso@corp.example.com"
        subject_prefix: "[FALCN ALERT]"
        use_tls: true
        timeout: 30
      retry:
        enabled: true
        max_attempts: 2
        initial_delay: 5s
        max_delay: 30s
        backoff_factor: 2.0
      filters:
        - high_severity_only
```

#### Alert email format

```
Subject: [FALCN ALERT] HIGH — typosquatting detected in req (pypi)

Falcn Supply Chain Security Alert
==================================
Severity:         HIGH
Threat Type:      typosquatting
Package:          req@0.1.0
Registry:         pypi
Risk Score:       0.87
Confidence:       94%
Detected At:      2026-03-07 10:00:00 UTC
Scan ID:          scan-20260307-abc123

Description:
  Package name closely resembles popular 'requests' package

Remediation:
  Remove req and install requests==2.31.0

---
Falcn v2.3.0 — https://github.com/falcn-io/falcn
```

---

### PagerDuty

PagerDuty integration is achieved via the generic webhook connector by pointing it at the
PagerDuty Events API v2 endpoint. Use a filter to restrict delivery to critical events only.

```yaml
integrations:
  connectors:
    pagerduty:
      type: webhook
      enabled: true
      settings:
        url: "https://events.pagerduty.com/v2/enqueue"
        method: POST
        headers:
          Content-Type: "application/json"
        auth_header: "Authorization"
        auth_token: "Token token=your-pagerduty-routing-key"
        timeout: 10
        retry_count: 3
      filters:
        - critical_only
```

Map the Falcn payload to PagerDuty's `trigger` action in a thin adapter service, or use a
PagerDuty webhook transformation rule to extract `event.threat.description`,
`event.package.name`, and `event.severity` into a PagerDuty incident.

---

## IDE Integrations

### VS Code

Install the Falcn VS Code extension to get inline vulnerability highlighting directly in your
editor:

```bash
code --install-extension falcn-io.falcn-vscode
```

Once installed, the extension scans your `package.json`, `requirements.txt`, `go.mod`, and other
manifest files on save. Flagged packages are underlined with severity-coloured squiggles and a
hover tooltip shows the threat type, risk score, and remediation suggestion.

The extension reads `.falcn.yaml` from the workspace root for threshold and registry settings,
and invokes the local `falcn` binary (must be on `PATH` or configured via
`falcn.binaryPath` in VS Code settings).

Note: the extension is not yet published to the VS Code Marketplace. Install from VSIX during
the current preview period. See Known Limitations below.

---

### JetBrains

Install the Falcn JetBrains plugin from **Settings > Plugins > Marketplace** (search "Falcn"):

```
Settings > Plugins > Marketplace > search "Falcn Supply Chain Security"
```

The plugin provides the same inline manifest-file highlighting as the VS Code extension. It
supports IntelliJ IDEA, GoLand, PyCharm, and WebStorm.

Note: the plugin is not yet published to the JetBrains Marketplace. Install from disk using the
`.zip` distribution from GitHub Releases. See Known Limitations below.

---

## SBOM and Compliance Integrations

### Dependency-Track

Dependency-Track consumes CycloneDX SBOMs. Generate one and upload it via the Dependency-Track
API:

```bash
# 1. Generate CycloneDX SBOM
falcn scan . --sbom-format cyclonedx --sbom-output sbom.cdx.json

# 2. Upload to Dependency-Track
DT_URL="https://dependencytrack.corp.example.com"
DT_API_KEY="odt_..."
PROJECT_UUID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

curl -s -X PUT \
  "${DT_URL}/api/v1/bom" \
  -H "X-Api-Key: ${DT_API_KEY}" \
  -H "Content-Type: multipart/form-data" \
  -F "project=${PROJECT_UUID}" \
  -F "bom=@sbom.cdx.json"
```

Falcn's CycloneDX 1.5 output includes the `vulnerabilities` array and `analysis` (VEX) fields
populated by the OSV and GitHub Advisory databases, so Dependency-Track will automatically
import known CVEs alongside the component inventory.

---

### GUAC

GUAC (Google's supply chain metadata aggregator) ingests SARIF files produced by Falcn. Feed
Falcn output into GUAC's collector directly:

```bash
# 1. Generate SARIF
falcn scan . --output sarif --report falcn.sarif

# 2. Publish to GUAC file collector
cp falcn.sarif /path/to/guac/blob-store/

# Or push via the GUAC REST ingestor
curl -X POST https://guac.corp.example.com/api/v1/publish \
  -H "Content-Type: application/json" \
  -d @falcn.sarif
```

Falcn SARIF output follows the SARIF 2.1.0 schema and includes `suppression` objects for
unreachable findings, which GUAC surfaces in its metadata graph to reduce noise in downstream
policy queries.

---

### ENISA / EU CRA

Falcn supports Article 13 (vulnerability handling) and Article 14 (active vulnerability
disclosure) of the EU Cyber Resilience Act via its `compliance` command and CycloneDX VEX output.

#### Generate CRA-compliant artifacts

```bash
falcn compliance . \
  --framework cra \
  --project-name "MyProduct" \
  --project-version "1.4.2" \
  --supplier "Acme Corp" \
  --out-dir ./cra-artifacts
```

This produces:

- `sbom.spdx.json` — SPDX 2.3 SBOM (EO 14028 / EU CRA Art. 13(1))
- `sbom.cdx.json` — CycloneDX 1.5 SBOM with VEX analysis field (EU CRA Art. 13(5))
- `ssdf-attestation.json` — NIST SP 800-218 SSDF control mapping
- `compliance-gap.json` — Remediation guidance for open gaps

#### OPA / Rego policy enforcement

Apply the bundled CRA Rego policy to block builds that violate CRA requirements:

```bash
# Evaluate the CRA policy against a scan report
opa eval \
  --data policies/cra_sbom.rego \
  --input falcn-report.json \
  "data.falcn.cra.violations"
```

The `cra_sbom.rego` policy enforces:

- Art. 13 Rec. 58: SBOM must be present and contain all direct dependencies
- Art. 14: Critical vulnerabilities with CVSS >= 9.0 must be disclosed within 24 hours
- All components must have a declared license

---

## SSE Streaming Integration

The `/v1/stream` endpoint is a Server-Sent Events stream that pushes real-time scan events to
connected clients. The connection stays open and delivers events for all scans triggered by any
client connected to the same API server instance.

### SSE event types

| Event | Data | Description |
|---|---|---|
| `connected` | `{"status":"connected","timestamp":"..."}` | Handshake on connection |
| `scan_started` | `{"package":"...","registry":"...","timestamp":"..."}` | A scan began |
| `threat` | Threat JSON object | A threat was found |
| `explanation` | `{"threat_id":"...","package":"...","type":"...","explanation":{...}}` | LLM explanation ready |
| `done` | `{"timestamp":"...","total_threats":N}` | Scan complete |
| `ping` | `{}` | Keepalive heartbeat (every 15 s) |

### Authentication

In development mode (no credentials configured) the stream is open. In production, pass either
an API key header or a JWT bearer token:

```
GET /v1/stream
X-API-Key: falcn_live_...
```

or

```
GET /v1/stream
Authorization: Bearer eyJhbGci...
```

### JavaScript (EventSource)

```javascript
const key = 'falcn_live_your_api_key';

const sse = new EventSource('/v1/stream', {
  headers: { 'X-API-Key': key }
});

sse.addEventListener('connected', e => {
  console.log('Stream connected', JSON.parse(e.data));
});

sse.addEventListener('threat', e => {
  const threat = JSON.parse(e.data);
  console.log(`[${threat.severity.toUpperCase()}] ${threat.type} — ${threat.package}`);
});

sse.addEventListener('explanation', e => {
  const { threat_id, explanation } = JSON.parse(e.data);
  console.log(`Explanation for ${threat_id}:`, explanation.remediation);
});

sse.addEventListener('done', e => {
  const summary = JSON.parse(e.data);
  console.log('Scan complete. Total threats:', summary.total_threats);
  sse.close();
});

sse.onerror = err => {
  console.error('SSE error', err);
};
```

### Go

```go
package main

import (
    "bufio"
    "fmt"
    "net/http"
    "strings"
)

func main() {
    req, _ := http.NewRequest("GET", "https://falcn.corp.example.com/v1/stream", nil)
    req.Header.Set("X-API-Key", "falcn_live_your_api_key")
    req.Header.Set("Accept", "text/event-stream")

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    scanner := bufio.NewScanner(resp.Body)
    var eventType, data string

    for scanner.Scan() {
        line := scanner.Text()
        if strings.HasPrefix(line, "event:") {
            eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
        } else if strings.HasPrefix(line, "data:") {
            data = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
        } else if line == "" && eventType != "" {
            fmt.Printf("[%s] %s\n", eventType, data)
            eventType, data = "", ""
        }
    }
}
```

### Python

```python
import sseclient
import requests

url = "https://falcn.corp.example.com/v1/stream"
headers = {
    "X-API-Key": "falcn_live_your_api_key",
    "Accept": "text/event-stream",
}

response = requests.get(url, headers=headers, stream=True)
client = sseclient.SSEClient(response)

for event in client.events():
    if event.event == "threat":
        import json
        threat = json.loads(event.data)
        print(f"[{threat['severity'].upper()}] {threat['type']} — {threat['package']}")
    elif event.event == "done":
        print("Scan complete:", event.data)
        break
```

Install the SSE client: `pip install sseclient-py requests`

### curl

```bash
curl -N \
  -H "X-API-Key: falcn_live_your_api_key" \
  -H "Accept: text/event-stream" \
  https://falcn.corp.example.com/v1/stream
```

The `-N` flag disables curl's output buffering so events appear in real time.

---

## Configuration Reference

Complete `.falcn.yaml` structure for the integrations section:

```yaml
integrations:
  enabled: true

  # Event routing: maps event types to connector names.
  # Event types: threat_detected, package_blocked, policy_violation, system_alert
  event_routing:
    threat_detected:
      - splunk_siem
      - security_slack
      - custom_endpoint
    policy_violation:
      - email_alerts
    system_alert:
      - security_slack

  # Global filters applied before routing.
  filters:
    - name: high_severity_only
      type: severity        # severity | package_name | threat_type
      condition: equals     # equals | contains | regex
      value: high

    - name: exclude_dev_packages
      type: package_name
      condition: contains
      value: "-dev"
      metadata:
        exclude: true

    - name: critical_only
      type: severity
      condition: equals
      value: critical

  connectors:
    # ── Splunk ────────────────────────────────────────────────────────────────
    splunk_siem:
      type: splunk
      enabled: true
      settings:
        hec_url: "https://splunk.corp.example.com:8088/services/collector/event"
        token: "${SPLUNK_HEC_TOKEN}"
        index: falcn
        source: falcn_scanner
        sourcetype: "falcn:threat"
        host: "falcn-api-prod"
        timeout: 30
      retry:
        enabled: true
        max_attempts: 3
        initial_delay: 1s
        max_delay: 30s
        backoff_factor: 2.0

    # ── Slack ─────────────────────────────────────────────────────────────────
    security_slack:
      type: slack
      enabled: true
      settings:
        webhook_url: "${SLACK_WEBHOOK_URL}"
        channel: "#security-alerts"
        username: Falcn
        icon_emoji: ":shield:"
        timeout: 10
      retry:
        enabled: true
        max_attempts: 2
        initial_delay: 2s
        max_delay: 10s
        backoff_factor: 2.0
      filters:
        - high_severity_only

    # ── Generic webhook ───────────────────────────────────────────────────────
    custom_endpoint:
      type: webhook
      enabled: true
      settings:
        url: "https://api.corp.example.com/security/falcn-events"
        method: POST
        headers:
          X-Source: falcn
        auth_header: Authorization
        auth_token: "${WEBHOOK_TOKEN}"
        content_type: application/json
        timeout: 15
        retry_count: 3
      retry:
        enabled: true
        max_attempts: 3
        initial_delay: 500ms
        max_delay: 4s
        backoff_factor: 2.0

    # ── Email ─────────────────────────────────────────────────────────────────
    email_alerts:
      type: email
      enabled: true
      settings:
        smtp_host: smtp.corp.example.com
        smtp_port: 587
        username: falcn-alerts@corp.example.com
        password: "${SMTP_PASSWORD}"
        from_email: falcn-alerts@corp.example.com
        from_name: Falcn Security Scanner
        to_emails:
          - security-team@corp.example.com
        cc_emails:
          - ciso@corp.example.com
        subject_prefix: "[FALCN ALERT]"
        use_tls: true
        timeout: 30
      retry:
        enabled: true
        max_attempts: 2
        initial_delay: 5s
        max_delay: 30s
        backoff_factor: 2.0
      filters:
        - high_severity_only
```

### Connector type reference

| Type | Package | Required settings |
|---|---|---|
| `splunk` | `internal/integrations/connectors/splunk.go` | `hec_url`, `token` |
| `slack` | `internal/integrations/connectors/slack.go` | `webhook_url` |
| `webhook` | `internal/integrations/connectors/webhook.go` | `url` |
| `email` | `internal/integrations/connectors/email.go` | `smtp_host`, `smtp_port`, `from_email`, `to_emails` |

### Environment variable substitution

All string values in `settings` support `${ENV_VAR}` substitution through Viper's environment
binding. Sensitive credentials should always be passed via environment variables rather than
being written directly to `.falcn.yaml`.
