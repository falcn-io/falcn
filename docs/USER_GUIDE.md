# Falcn User Guide

## Installation

### Binary
- Download platform binary from GitHub Releases and place on PATH

### From Source
```bash
git clone https://github.com/falcn-io/falcn.git
cd falcn
go build -o falcn .
```

### Docker
You can pull the official image or build it yourself:

```bash
# Pull official image
docker pull vanali/falcn:latest
docker run --rm -v $(pwd):/scan vanali/falcn scan /scan

# Or build from source
docker build -t falcn . && docker run --rm -v $(pwd):/scan falcn scan /scan
```

## CLI Usage
```bash
./falcn version
./falcn scan . --output json --supply-chain --advanced
```

### CLI Flags
- `--output {json|sarif|table}`: output format
- `--supply-chain`: enable supply chain analysis
- `--advanced`: enhanced detection algorithms
- `--threshold <0..1>`: similarity threshold
- `--registry <npm|pypi|go|maven>`: force registry when needed

## Configuration
- Environment variables for API auth
- CLI flags for output, supply chain analysis, and detection options

## CI/CD Integration
- Use reusable workflow `.github/workflows/supply-chain-firewall.yml`
- Or build and run CLI in your pipelines to enforce policies

## Troubleshooting
- `401 Unauthorized`: ensure `API_KEYS` set and header included
- `429 Too Many Requests`: reduce request rate
- Docker: map port `-p 8080:8080`; set env vars with `-e`


