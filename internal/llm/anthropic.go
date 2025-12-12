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

func (p *AnthropicProvider) GenerateExplanation(ctx context.Context, prompt string) (string, error) {
	// TODO: Implement Anthropic API call
	if p.apiKey == "" {
		return "", fmt.Errorf("anthropic api key not configured")
	}
	return "Anthropic explanation not implemented yet (requires API key)", nil
}
