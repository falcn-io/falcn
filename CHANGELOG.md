[2025-12-03 00:00] - docs: add ecosystem help sections (npm install script dos/don’ts, Ruby eval-chain remediation, Python obfuscation examples)
[2025-12-03 00:00] - output: improve SARIF triage with physical locations, byte-range regions, and structured evidence
[2025-12-03 00:00] - scanner: enrich evidence with entropy position ranges, preview content type, and file path metadata
[2025-12-04 00:00] - docker: update Dockerfile to stable multi-stage build, cache mounts, non-root user, labels; remove references to missing resources
[2025-12-17 14:00] - feat: implemented SBOM generation (SPDX/CycloneDX) and falcn report command
[2025-12-17 14:30] - feat: enhanced typosquatting detection with Jaro-Winkler and Sorensen-Dice algorithms
[2025-12-17 15:00] - demo: added enterprise demo scenarios (Sunburst, Dependency Confusion, Brandjacking)
[2025-12-17 15:30] - feat: implemented Shai-Hulud attack detection (Self-hosted runners, Injection, C2 channels) in CICDScanner
[2025-12-17 16:00] - fix: resolved CICD scanner root path issue and variable shadowing in scanner.go
[2025-12-18 11:45] - fix: resolved incomplete_metadata false positives by correctly populating Author field in MetadataEnricher
