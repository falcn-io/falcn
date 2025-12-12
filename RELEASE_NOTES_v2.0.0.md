# Falcn v2.0.0 - The Next-Gen AI Security Platform

We are proud to announce the release of **Falcn v2.0.0**, transforming our static analysis tool into a comprehensive, AI-native security platform.

## 🌟 Major Features

### 🧠 Advanced Heuristics Engine (Detection)
- **Deterministic Scoring**: New multi-variable scoring system based on Damerau-Levenshtein distance, keyboard layout analysis, and namespace confusion patterns.
- **Why Heuristics?**: Provides deterministic, explainable results without the false positives inherent in black-box ML models.
- **Performance**: Sub-millisecond analysis times per package.

### 📦 Behavioral Analysis (Sandboxing)
- **Docker Integration**: Safely detonates suspicious packages in ephemeral containers.
- **Trace Analysis**: Monitors syscalls and logs for indicators of compromise (IOCs) like `curl`, `wget`, `subshells`, and file system modifications.
- **Dynamic Installation**: Captures threats that only manifest during `npm install` (lifecycle scripts).

### 🤖 LLM Explainability
- **Human-Readable Reports**: "Why is this package dangerous?" - Falcn now tells you in plain English.
- **Multi-Provider Support**:
  - **Ollama**: First-class support for airgapped/local models (Llama 3, Mistral).
  - **OpenAI / Anthropic**: **[Roadmap]** Planned support for cloud APIs in v2.1.

### 📡 Real-Time Intelligence
- **Live Data Fetching**: Removed simulation logic. Falcn now queries NPM and PyPI registries in real-time for authentic download counts, maintainer history, and release dates.

## 🛠️ Improvements
- **Refactored Architecture**: Clear separation of Scanner, Detector, ML, and Behavioral engines.
- **Enhanced Polling**: HTTP Client optimizations for registry communication.
- **Configuration**: Unified `config.yaml` for all new subsystems.

## 🚀 Upgrade Guide
Run `go install github.com/falcn-io/falcn@v2.0.0` or pull the latest Docker image.
Existing users should update their `config.yaml` to include the new `ml` and `llm` sections (see README).
