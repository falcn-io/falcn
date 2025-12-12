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

func (p *OpenAIProvider) GenerateExplanation(ctx context.Context, prompt string) (string, error) {
	// TODO: Implement actual OpenAI API call using github.com/sashabaranov/go-openai or direct HTTP
	if p.apiKey == "" {
		return "", fmt.Errorf("openai api key not configured")
	}
	return "OpenAI explanation not implemented yet (requires API key)", nil
}
