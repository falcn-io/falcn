# LLM Setup Guide

Falcn uses large language models (LLMs) to generate human-readable threat explanations —
converting raw detection signals into actionable security advice. Three providers are supported:
**Ollama** (local, air-gap friendly), **OpenAI**, and **Anthropic**. This guide covers all three.

---

## Provider Comparison

| Feature | Ollama (local) | OpenAI | Anthropic |
|---------|---------------|--------|-----------|
| Data privacy | ✅ Fully local | ❌ Data sent to API | ❌ Data sent to API |
| Air-gap compatible | ✅ Yes | ❌ No | ❌ No |
| Cost | Free (hardware only) | Per-token | Per-token |
| Quality (security tasks) | Good (Llama 3.1+) | Best | Excellent |
| Setup complexity | Medium | Low | Low |

---

## Ollama (Recommended for Enterprise / Air-gap)

### Prerequisites

| Tier | RAM | CPU | GPU |
|------|-----|-----|-----|
| Minimum | 8 GB | 4 cores | None (slow) |
| Recommended | 16 GB | 8 cores | NVIDIA 8GB VRAM |
| Optimal | 32 GB+ | 16 cores | NVIDIA 24GB VRAM |

### Installation

**Linux / macOS:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Docker (recommended for consistent enterprise deployment):**
```bash
# CPU only
docker run -d \
  -v ollama:/root/.ollama \
  -p 11434:11434 \
  -e OLLAMA_HOST=0.0.0.0 \
  --name ollama \
  ollama/ollama

# With NVIDIA GPU (requires nvidia-container-toolkit)
docker run -d \
  --gpus=all \
  -v ollama:/root/.ollama \
  -p 11434:11434 \
  -e OLLAMA_HOST=0.0.0.0 \
  --name ollama \
  ollama/ollama
```

### Model Selection

| Model | Pull Command | VRAM | Best For |
|-------|-------------|------|----------|
| **Llama 3.1 8B** (recommended) | `ollama pull llama3.1` | 6 GB | Best balance of quality and speed |
| **Llama 3.2 3B** | `ollama pull llama3.2` | 3 GB | Fast, low-resource environments |
| **Mistral Nemo** | `ollama pull mistral-nemo` | 8 GB | Strong code and security reasoning |
| **Gemma 2 9B** | `ollama pull gemma2` | 8 GB | Google's model, excellent at summaries |
| **Phi-3 Mini** | `ollama pull phi3:mini` | 3 GB | Edge / very constrained environments |

> **License check**: Always verify that the model license permits your use case
> (commercial, government, etc.) before deploying in production.

### Configuration with Falcn

**Environment variables:**
```bash
export FALCN_LLM_ENABLED=true
export FALCN_LLM_PROVIDER=ollama
export FALCN_LLM_MODEL=llama3.1
export FALCN_LLM_ENDPOINT=http://localhost:11434   # Change for remote Ollama
```

**YAML config (`~/.falcn.yaml` or `.falcn.yaml`):**
```yaml
llm:
  enabled: true
  provider: ollama
  model: llama3.1
  endpoint: http://localhost:11434
  timeout: 30s
  max_tokens: 4096          # Falcn hard-caps responses at 4096 chars
  max_calls_per_scan: 10    # Override with --max-llm-calls flag
```

**CLI override:**
```bash
falcn scan . --no-llm                    # Disable LLM for this scan
falcn scan . --max-llm-calls 5          # Limit to 5 explanations
```

### Air-gap / Offline Model Distribution

For environments with no outbound internet access:

```bash
# On an internet-connected machine, export the model
ollama pull llama3.1
ollama save llama3.1 -o llama3.1.tar

# Transfer llama3.1.tar to air-gapped server (USB, internal artifact store, etc.)

# On the air-gapped server
ollama load llama3.1.tar

# Verify
ollama list
```

### Verification

```bash
# Test Ollama is reachable
curl http://localhost:11434/api/tags

# Run Falcn with LLM explanation
falcn scan . --max-llm-calls 1

# Expected output includes an "Explanation" section below each threat
```

---

## OpenAI

```bash
export FALCN_LLM_ENABLED=true
export FALCN_LLM_PROVIDER=openai
export FALCN_LLM_MODEL=gpt-4o-mini        # gpt-4o for highest quality
export FALCN_LLM_API_KEY=sk-...
```

YAML:
```yaml
llm:
  enabled: true
  provider: openai
  model: gpt-4o-mini
  api_key: ${FALCN_LLM_API_KEY}
  max_tokens: 4096
```

> Cost control: `--max-llm-calls 10` limits API calls per scan. Each explanation
> averages ~800 input tokens + ~300 output tokens on gpt-4o-mini.

---

## Anthropic

```bash
export FALCN_LLM_ENABLED=true
export FALCN_LLM_PROVIDER=anthropic
export FALCN_LLM_MODEL=claude-haiku-4-5   # claude-sonnet-4-5 for highest quality
export FALCN_LLM_API_KEY=sk-ant-...
```

YAML:
```yaml
llm:
  enabled: true
  provider: anthropic
  model: claude-haiku-4-5
  api_key: ${FALCN_LLM_API_KEY}
  max_tokens: 4096
```

---

## Security Guardrails

Falcn applies automatic sanitization to all LLM outputs before displaying them:

- **Unicode control character stripping** — prevents terminal escape injection
- **XML/HTML tag removal** — prevents markup injection in reports
- **Response length cap** — hard limit of 4096 characters per explanation
- **Input sanitization** — package names and threat data are escaped before being sent to the LLM

These guardrails run regardless of which provider is configured and cannot be disabled.

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `connection refused :11434` | Ollama not listening on all interfaces | Add `-e OLLAMA_HOST=0.0.0.0` to Docker run |
| `model not found` | Model not pulled | Run `ollama pull <model-name>` |
| Slow responses (>30s) | No GPU / model too large | Use a smaller quantized model or enable GPU |
| `401 Unauthorized` | Wrong API key | Check `FALCN_LLM_API_KEY` value |
| Garbled output | Model producing control chars | Guardrails strip these automatically |
| LLM not called | `--no-llm` set or `max_calls` reached | Check flags and `max_calls_per_scan` config |
