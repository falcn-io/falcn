<div align="center">
  <img src="docs/assets/logo.png" alt="Falcn" width="200">
  <h1>Falcn</h1>
  <p><strong>Precision Supply Chain Security</strong></p>
  <p>
    <a href="https://falcn.io">Website</a> •
    <a href="https://docs.falcn.io">Docs</a> •
    <a href="https://github.com/falcn-io/falcn/releases">Releases</a>
  </p>
  <p>
    <img src="https://img.shields.io/badge/go-1.24+-blue?logo=go" alt="Go Version">
    <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
    <img src="https://img.shields.io/github/v/release/falcn-io/falcn" alt="Release">
    <img src="https://img.shields.io/badge/threats_detected-0-success" alt="Status">
  </p>
</div>

---

> **"See threats before they strike."**

**Falcn** is an open-source supply chain security platform that protects software teams from dependency-based attacks. Like a falcon with exceptional vision, it provides comprehensive visibility into your software supply chain, detecting threats specifically in `npm`, `PyPI`, `Go`, and `Maven` ecosystems with sub-60ms scan times.

## 🚀 Key Features

- **⚡ Speed**: Single-pass analysis architecture (<60ms response time).
- **🎯 Precision**: Low false positives using advanced typosquatting detection algorithms (edit distance, homoglyphs, brand impersonation).
- **👁️ Vision**: Comprehensive visibility across multiple ecosystems.
- **🛡️ Protection**: Proactive blocking of malicious packages before installation.
- **🔌 Integration**: Seamless CI/CD integration (GitHub Actions, GitLab CI, etc.).
- **📊 Reporting**: SBOM generation (SPDX, CycloneDX) and multiple output formats (JSON, SARIF, Table).

## 📥 Installation

### Homebrew
```bash
brew tap falcn-io/tap
brew install falcn
```

### Go Install
```bash
go install github.com/falcn-io/falcn@latest
```

### Docker
```bash
docker pull falcn-io/falcn:latest
```

## 💻 Usage

```bash
# Scan the current directory
falcn scan .

# Scan a specific directory
falcn scan /path/to/project

# Analyze a specific package for typosquatting
falcn analyze lodash

# Continuous monitoring mode
falcn watch --ci
```

## 🎨 Visual Identity

Falcn embodies speed and precision.

- **Primary Color**: Falcon Navy `#0A1628`
- **Accent**: Sky Gold `#F5A623`

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---
<div align="center">
  <sub>Built with ❤️ by the Falcn Community</sub>
</div>


