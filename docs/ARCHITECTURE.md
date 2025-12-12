# Falcn Architecture & Reference

This document provides a comprehensive overview of the Falcn architecture, command-line interface, and feature set.

## 1. High-Level System Architecture

```mermaid
flowchart TB
    subgraph Users["👥 Users & Integrations"]
        CLI["🖥️ CLI"]
        API["🌐 REST API"]
        CICD["⚙️ CI/CD Pipelines"]
        Webhooks["🔗 Webhooks"]
    end

    subgraph Core["🔷 Falcn Core"]
        Analyzer["🧠 Analyzer Engine"]
        Scanner["📦 Scanner Engine"]
        Detector["🔍 Threat Detector"]
        ML["🧠 ML Engine"]
        Behavioral["📦 Behavioral Engine (Sandbox)"]
        LLM["🤖 LLM Explainer"]
        Policy["📋 Policy Engine"]
    end

    subgraph Registries["📚 Package Registries"]
        NPM["npm"]
        PyPI["PyPI"]
        Go["Go Modules"]
        Maven["Maven"]
        NuGet["NuGet"]
        More["..."]
    end

    subgraph Storage["💾 Storage & Cache"]
        Redis["Redis Cache"]
        DB["Vulnerability DB"]
        Config["Configuration"]
    end

    subgraph Output["📊 Output & Reporting"]
        JSON["JSON"]
        SARIF["SARIF"]
        SBOM["SBOM"]
        Dashboard["Dashboard"]
    end

    CLI --> Analyzer
    API --> Analyzer
    CICD --> API
    Webhooks --> API

    Analyzer --> Scanner
    Analyzer --> Policy
    
    Scanner --> Detector
    Scanner --> ML
    Scanner --> Behavioral
    
    Behavioral --> Detector
    
    Detector --> Registries
    ML --> Registries
    
    Scanner --> Storage
    Detector --> Storage
    
    Analyzer --> LLM
    Analyzer --> Output
    Policy --> Output

    style Core fill:#e1f5fe
    style Users fill:#f3e5f5
    style Registries fill:#e8f5e9
    style Storage fill:#fff3e0
    style Output fill:#fce4ec
```

## 2. Detection Methods Architecture

```mermaid
flowchart TB
    Package["📦 Package Name"] --> Detection["🔍 Detection Engine"]
    
    subgraph StringMethods["String Similarity Methods"]
        Levenshtein["Levenshtein Distance"]
        JaroWinkler["Jaro-Winkler"]
        LCS["Longest Common\nSubsequence"]
        Cosine["Cosine Similarity"]
        NGram["N-Gram Analysis"]
    end
    
    subgraph VisualMethods["Visual Similarity Methods"]
        Homoglyph["Homoglyph Detection\n(а vs a, 0 vs O)"]
        ScriptMix["Script Mixing\n(Latin + Cyrillic)"]
        Confusables["Confusable\nCharacters"]
    end
    
    subgraph BehavioralMethods["Behavioral Analysis (Sandbox)"]
        Sandbox["Docker Container"]
        Tracing["Process/Net Tracing"]
        Install["Dynamic Install"]
    end
    
    subgraph MLMethods["ML Inference"]
        MLP["MLP Neural Network"]
        Features["Feature Extraction"]
        ONNX["ONNX Runtime"]
    end
    
    subgraph ReputationMethods["Reputation Analysis"]
        Downloads["Download\nStatistics"]
        Age["Package Age"]
        Maintainers["Maintainer\nVerification"]
        Community["Community\nFeedback"]
    end
    
    Detection --> StringMethods
    Detection --> VisualMethods
    Detection --> BehavioralMethods
    Detection --> MLMethods
    Detection --> ReputationMethods
    
    StringMethods --> Scoring["🎯 Risk Scoring Engine"]
    VisualMethods --> Scoring
    BehavioralMethods --> Scoring
    MLMethods --> Scoring
    ReputationMethods --> Scoring
    
    Scoring --> Result["📊 Threat Assessment\n(Critical/High/Medium/Low)"]
    Result --> LLM["🤖 LLM Explainer\n(Why is this risky?)"]

    style StringMethods fill:#e3f2fd
    style VisualMethods fill:#f3e5f5
    style BehavioralMethods fill:#e8f5e9
    style MLMethods fill:#fff3e0
    style ReputationMethods fill:#ffebee
```

## 3. Architecture Clarification: Scanner vs Analyzer

| Component | Package | Role | Responsibilities |
|-----------|---------|------|------------------|
| **Analyzer** | `internal/analyzer` | **The Brain (Orchestrator)** | • Integration point for CLI/API.<br>• Orchestrates the entire flow.<br>• Resolves dependency graphs (Resolution).<br>• Aggregates results from Detectors and Scanner.<br>• Invokes LLM for explanation.<br>• Determines final Risk Scores. |
| **Scanner** | `internal/scanner` | **The Eyes (Discovery)** | • Crawls the file system.<br>• Detects project types (e.g., NPM, PyPI).<br>• Parses manifest files (Extraction).<br>• Runs file-level scans (Content, CI/CD).<br>• Returns raw `Package` objects. |

**Flow:** `CLI/API` -> `Analyzer.Scan()` -> `Scanner.ScanProject()`

## 4. API Request Flow

```mermaid
sequenceDiagram
    participant Client as 🖥️ Client
    participant API as 🌐 API Server
    participant Analyzer as 🧠 Analyzer
    participant Scanner as 📦 Scanner
    participant ML as 🧠 ML Engine
    participant Behavioral as 📦 Behavioral
    participant LLM as 🤖 LLM

    Client->>API: POST /v1/analyze
    
    API->>Analyzer: Analyze Package
    Analyzer->>Scanner: Scan Project
    
    Scanner->>ML: ML Inference (Static)
    ML-->>Scanner: Score (0.9)
    
    Scanner->>Behavioral: Sandbox Analysis (Dynamic)
    Behavioral-->>Scanner: Threat Indicators (Network, Files)
        
    Scanner-->>Analyzer: Scan Results
    
    Analyzer->>LLM: Generate Explanation(Threats)
    LLM-->>Analyzer: "This package communicates with a known C2 server."
    
    Analyzer-->>API: Analysis Result + Explanation
    API-->>Client: 200 OK + JSON Response
```
