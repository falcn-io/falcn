package llm

import (
	"context"
	"fmt"

	"github.com/falcn-io/falcn/internal/config"
)

// Provider defines the interface for LLM providers
type Provider interface {
	// GenerateExplanation generates a human-readable explanation for a threat
	GenerateExplanation(ctx context.Context, prompt string) (string, error)
	// ID returns the provider identifier
	ID() string
}

// NewProvider creates a new LLM provider based on configuration
func NewProvider(cfg config.LLMConfig) (Provider, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("llm is disabled")
	}

	switch cfg.Provider {
	case "ollama":
		return NewOllamaProvider(cfg), nil
	case "openai":
		return NewOpenAIProvider(cfg), nil
	case "anthropic":
		return NewAnthropicProvider(cfg), nil
	default:
		return nil, fmt.Errorf("unsupported llm provider: %s", cfg.Provider)
	}
}
