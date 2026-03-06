# Falcn Supply Chain Security — VS Code Extension

Real-time supply chain security scanning for your dependency manifest files. Detects malicious packages, typosquatting, embedded secrets, and known CVEs across 8 package ecosystems directly inside VS Code.

---

## Features

### Inline Diagnostics
Risky packages are flagged inline in your manifest files (`package.json`, `go.mod`, `requirements.txt`, `Cargo.toml`, `composer.json`, `Gemfile`) with color-coded severity levels:

- **Error (red)** — Critical or High risk (malicious, typosquatting, known CVE)
- **Warning (yellow)** — Medium risk
- **Information (blue)** — Low risk
- **Hint** — Informational findings

### Hover Cards
Hover over any package name in a manifest to see:
- Risk score with a visual bar
- Detected threat types (typosquatting, dependency confusion, hijacked account, etc.)
- LLM-generated explanation of why the package is suspicious
- Recommended safe version to upgrade to
- Link to the Falcn dashboard

### Quick Fix — Update to Safe Version
When a safer version is available, a quick fix (lightbulb) appears. Click it to:
- **Update to safe version** — automatically rewrites the version in your manifest
- **View on Falcn Dashboard** — open the package details in your browser
- **Add falcn-ignore comment** — suppress the warning for this package

### Command Palette
| Command | Description |
|---|---|
| `Falcn: Scan Project` | Scan all manifest files in the workspace |
| `Falcn: Scan Current File` | Scan only the active manifest file |
| `Falcn: Clear Diagnostics` | Remove all Falcn diagnostics |
| `Falcn: Show Output Log` | Open the Falcn output channel |
| `Falcn: Open Settings` | Jump to Falcn settings |

### Status Bar
The status bar item (bottom-left) shows:
- `$(shield) Falcn` — idle, no issues
- `$(sync~spin) Falcn: scanning 3/12 files` — scan in progress
- `$(shield-check) Falcn: clean` — no threats found
- `$(shield-x) Falcn: 5 threats` — threats detected (click to re-scan)

---

## Supported Ecosystems

| File | Registry |
|---|---|
| `package.json` | npm |
| `go.mod` | Go Modules |
| `requirements.txt` | PyPI |
| `Cargo.toml` | Cargo (Rust) |
| `composer.json` | Composer (PHP) |
| `Gemfile` | RubyGems |

---

## Requirements

### Option A: Falcn API (recommended)
Start the Falcn API server:

```bash
# Docker
docker run -p 8082:8082 ghcr.io/falcn-io/falcn:latest api

# Or from binary
falcn-api --port 8082
```

The extension defaults to `http://localhost:8082`. Configure `falcn.apiEndpoint` in settings.

### Option B: Falcn CLI (fallback)
Install the Falcn CLI:

```bash
# macOS / Linux
curl -fsSL https://falcn.io/install.sh | sh

# Go install
go install github.com/falcn-io/falcn@latest
```

If the API is unreachable, the extension automatically falls back to running `falcn scan --output json` as a subprocess.

---

## Settings

| Setting | Default | Description |
|---|---|---|
| `falcn.apiEndpoint` | `http://localhost:8082` | Falcn REST API base URL |
| `falcn.apiKey` | `""` | API authentication key |
| `falcn.cliPath` | `falcn` | Path to the falcn CLI binary |
| `falcn.autoScanOnSave` | `true` | Scan manifest files on save |
| `falcn.autoScanOnOpen` | `true` | Scan manifest files on open |
| `falcn.riskThreshold` | `0.5` | Risk score (0–1) above which to flag a package |
| `falcn.severityLevel` | `warning` | VS Code diagnostic severity level |
| `falcn.debounceMs` | `1500` | Delay before scanning after document changes |
| `falcn.maxConcurrentRequests` | `5` | Max parallel API requests per scan |
| `falcn.enableHoverProvider` | `true` | Show hover cards |
| `falcn.enableQuickFix` | `true` | Show quick-fix suggestions |

---

## Ignoring Packages

### In `go.mod`, `requirements.txt`, `Cargo.toml`, `Gemfile`:
Append a `falcn-ignore` comment to the dependency line:

```
# requirements.txt
requests==2.28.0  # falcn-ignore
```

```
# go.mod
require github.com/foo/bar v1.2.3 // falcn-ignore
```

### In `package.json` / `composer.json`:
Create a `.falcnignore` file in your project root:

```
# .falcnignore
lodash
some-package
```

---

## API Reference

The extension calls:

```
POST {apiEndpoint}/v1/analyze
Content-Type: application/json

{
  "package_name": "lodash",
  "version": "4.17.15",
  "registry": "npm"
}
```

Response:

```json
{
  "package_name": "lodash",
  "version": "4.17.15",
  "registry": "npm",
  "risk_score": 0.12,
  "is_malicious": false,
  "threats": [],
  "safe_version": null,
  "explanation": null,
  "cached": true,
  "scan_duration_ms": 42
}
```

---

## Privacy

- Package names and versions are sent to your configured Falcn API endpoint only.
- No source code is ever transmitted.
- If using the local API at `localhost:8082`, all data stays on your machine.

---

## License

MIT — See the [Falcn repository](https://github.com/falcn-io/falcn) for details.
