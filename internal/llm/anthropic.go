package llm

import (
	"context"
	"fmt"

	"github.com/falcn-io/falcn/internal/config"
)

type AnthropicProvider struct {
	apiKey string
	model  string
}

func NewAnthropicProvider(cfg config.LLMConfig) *AnthropicProvider {
	return &AnthropicProvider{
		apiKey: cfg.APIKey,
		model:  cfg.Model,
	}
}

func (p *AnthropicProvider) ID() string {
	return "anthropic"
}

// GenerateExplanation returns a placeholder or error for Anthropic until fully implemented
func (p *AnthropicProvider) GenerateExplanation(ctx context.Context, prompt string) (string, error) {
	return "", fmt.Errorf("provider 'anthropic' is currently in roadmap for v2.1. Please use 'ollama' for now")
}
