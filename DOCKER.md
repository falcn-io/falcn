# Docker Usage Guide

This guide covers building and running Falcn via Docker for both the CLI and API server.

## Prebuilt Image

- Pull: `docker pull vanali/Falcn:latest`
- CLI scan: `docker run --rm vanali/Falcn:latest scan /workspace --output json`
- API server: `docker run --rm -p 8080:8080 vanali/Falcn:latest server`

## Build Locally

```bash
docker build -t Falcn:latest .
```

Run CLI with a mounted project directory:

```bash
docker run --rm -v "$PWD:/workspace" Falcn:latest scan /workspace --output json
```

Run API server:

```bash
docker run --rm -p 8080:8080 Falcn:latest server
```

## Windows Path Conversion (Git Bash)

Git Bash rewrites volume paths. Disable path conversion when mounting:

```bash
MSYS_NO_PATHCONV=1 docker run --rm \
  --mount type=bind,source="$PWD",target=/workspace \
  vanali/Falcn:latest scan /workspace --output json
```

## SBOM and SARIF Outputs

```bash
docker run --rm -v "$PWD:/workspace" vanali/Falcn:latest scan /workspace --output sarif > scan.sarif.json
docker run --rm -v "$PWD:/workspace" vanali/Falcn:latest scan /workspace --output cyclonedx > sbom.cyclonedx.json
docker run --rm -v "$PWD:/workspace" vanali/Falcn:latest scan /workspace --output spdx > sbom.spdx.json
```

## Dependency Graph (DOT)

```bash
docker run --rm -v "$PWD:/workspace" vanali/Falcn:latest \
  graph export /workspace --format dot --graph-style modern --rankdir LR > graph.dot
```

## Edge Algorithm (DIRT)

```bash
docker run --rm vanali/Falcn:latest edge dirt lodash --max-depth 8 --risk-threshold 0.6 --include-graph > edge_dirt.txt
```

## Authentication for API

```bash
docker run --rm -p 8080:8080 \
  -e API_AUTH_ENABLED=true \
  -e API_KEYS=key1,key2 \
  vanali/Falcn:latest server
```

## Compose (API + Database)

```bash
docker compose up -d
```

## Notes

- `CGO_ENABLED=1` is set in the Dockerfile for maximum compatibility.
- Use persistent volumes for data (e.g., `-v Falcn-data:/data`).

## Content Scanning Configuration

- `Falcn_SCANNER_CONTENT_MAX_FILE_SIZE=1048576`
- `Falcn_SCANNER_CONTENT_ENTROPY_THRESHOLD=6.8`
- `Falcn_SCANNER_CONTENT_ENTROPY_WINDOW=512`
- `Falcn_SCANNER_CONTENT_INCLUDE_GLOBS=**/*.js,**/*.py`
- `Falcn_SCANNER_CONTENT_EXCLUDE_GLOBS=**/node_modules/**,**/vendor/**`
- `Falcn_SCANNER_CONTENT_WHITELIST_EXTENSIONS=.js,.py,.ts,.rb,.sh,.json`
- `Falcn_SCANNER_CONTENT_MAX_FILES=500`

Example:

```bash
docker run --rm -v "$PWD:/workspace" \
  -e Falcn_SCANNER_CONTENT_ENTROPY_THRESHOLD=6.8 \
  -e Falcn_SCANNER_CONTENT_INCLUDE_GLOBS=**/*.js,**/*.py \
  vanali/Falcn:latest scan /workspace --output json
```

## Policy Authoring

- Place `.rego` policies in the directory specified by `Falcn_POLICIES_PATH` (default `policies/`).
- Enable hot-reload with `Falcn_POLICIES_HOT_RELOAD=true`.
- Example policies:
  - `default.rego`: flags embedded secrets and install scripts
  - `suspicious.rego`: flags suspicious patterns
  - `binary.rego`: suggests severity downgrade for binaries in legitimate paths

Example:

```bash
docker run --rm -v "$PWD:/workspace" \
  -v "$PWD/policies:/policies" \
  -e Falcn_POLICIES_PATH=/policies \
  -e Falcn_POLICIES_HOT_RELOAD=true \
  vanali/Falcn:latest scan /workspace --output json
```



