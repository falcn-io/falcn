# Enterprise Ollama Setup Guide

This guide describes how to deploy and configure [Ollama](https://ollama.ai) for use with Falcn's AI capabilities in an airgapped or enterprise environment.

## Prerequisites

- **Hardware**:
  - Minimum: 8GB RAM, 4 CPU Cores (for 7B models)
  - Recommended: 16GB+ RAM, NVIDIA GPU (6GB+ VRAM)
- **OS**: Linux, macOS, or Windows (WSL2 recommended)

## 1. Installation

### Linux
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### Docker (Recommended for Enterprise)
For consistent deployment, use the official Docker image.

```bash
docker run -d -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama
```

To use GPU acceleration (requires NVIDIA Container Toolkit):
```bash
docker run -d --gpus=all -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama
```

## 2. Model Selection

We recommend the following models for security analysis:

- **Llama 3 (8B)**: Best balance of speed and reasoning.
  - Command: `ollama pull llama3`
- **Mistral (7B)**: Very fast, good for concise summaries.
  - Command: `ollama pull mistral`
- **Gemma (7B)**: Google's open model, strong on code tasks.
  - Command: `ollama pull gemma`

**Note**: Verify the model license complies with your organization's policy.

## 3. Configuration with Falcn

Falcn connects to Ollama via HTTP. Configure the connection using environment variables:

```powershell
# Enable LLM
$env:FALCN_LLM_ENABLED="true"

# Select Provider
$env:FALCN_LLM_PROVIDER="ollama"

# Set Model (must match what you pulled)
$env:FALCN_LLM_MODEL="llama3"

# Endpoint (default is localhost:11434)
# If Ollama is on a remote server, specify the IP
$env:FALCN_LLM_ENDPOINT="http://localhost:11434"
```

## 4. Verification

Run a test scan to verify the connection:

```bash
# Verify connection logic directly
go run scripts/verify_llm.go

# Run Falcn
falcn scan /path/to/project
```

## 5. Security & Privacy

- **Data Privacy**: Local Ollama runs entirely on your infrastructure. No data is sent to cloud providers.
- **Airgap**: You can save/load models as files if the server has no internet access.
  - Save: `ollama save llama3 > llama3.tar`
  - Load: `ollama load < llama3.tar` (conceptually - see Ollama docs for `modelfile` offline loading)

## 6. Troubleshooting

- **Connection Refused**: Ensure Ollama is listening on all interfaces if running in Docker (`OLLAMA_HOST=0.0.0.0`).
- **Slow Performance**: Enable GPU support or switch to a smaller quantized model (e.g., `q4_0`).
