# Technical Decisions Log

## ML Feature Decision
Date: 2025-11-27
Decision: A (Remove ML claims)
Rationale: Existing ML references are not implemented; removing ML claims ensures honest documentation and accelerates a stable release.
Action Items:
- Replace ML references with multi‑algorithm heuristic detection in documentation
- Keep enhanced detection via heuristics (edit distance, keyboard, visual, phonetic)
- Plan ML exploration post‑release if needed

## Rebranding to Falcn
Date: 2025-12-01
Decision: Rename project identity from "Typosentinel" to "Falcn".
Rationale: The scope has expanded beyond simple typosquatting detection to a broader "Supply Chain Firewall". The new name reflects speed, precision, and active monitoring capabilities.
Action Items:
- Update CLI root command to `falcn`
- Update Docker repository to `vanali/falcn`
- Standardize environment variables to `FALCN_` prefix

## Heuristic-Based Detection Engine
Date: 2025-12-05
Decision: Implement deterministic heuristics (Levenshtein, Jaro-Winkler, Namespace Confusion) as the core detection mechanism for V2.
Rationale: ML models require significant training data and maintenance. Deterministic heuristics provide explainable, fast, and immediate value for the most common supply chain attacks without the overhead of maintaining models.
Action Items:
- Implement `internal/detector` with `enhanced_typosquatting.go`
- Add specific tests for variation attacks (insertion, deletion, substitution)

## LLM Integration & Guardrails
Date: 2025-12-10
Decision: Integrate Local LLMs (via Ollama) for threat explanation, wrapped in a strict Guardrails layer.
Rationale: Users need context for *why* a package is flagged. Local LLMs ensure privacy (no code sent to cloud) and zero cost. Guardrails are strictly required to prevent prompt injection and ensure output reliability.
Action Items:
- Implement `internal/llm` provider abstraction
- Add `SafeProvider` decorator for input sanitization
- Trigger LLM explanations only for High/Critical threats

## Containerized Build Workflow
Date: 2025-12-12
Decision: Standardize build and distribution on Docker multi-stage builds.
Rationale: Ensures consistent build environments across Windows/Linux/Mac dev machines and CI/CD pipelines.
Action Items:
- Create optimized `Dockerfile` with build and runtime stages
- Publish to Docker Hub as primary distribution method
