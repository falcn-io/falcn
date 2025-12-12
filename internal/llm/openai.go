package llm

import (
	"context"
	"fmt"

	"github.com/falcn-io/falcn/internal/config"
)

type OpenAIProvider struct {
	apiKey string
	model  string
}

func NewOpenAIProvider(cfg config.LLMConfig) *OpenAIProvider {
	return &OpenAIProvider{
		apiKey: cfg.APIKey,
		model:  cfg.Model,
	}
}

func (p *OpenAIProvider) ID() string {
	return "openai"
}

// GenerateExplanation returns a placeholder or error for OpenAI until fully implemented
func (p *OpenAIProvider) GenerateExplanation(ctx context.Context, prompt string) (string, error) {
	return "", fmt.Errorf("provider 'openai' is currently in roadmap for v2.1. Please use 'ollama' for now")
}
