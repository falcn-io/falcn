package llm

import (
	"context"
	"testing"

	"github.com/falcn-io/falcn/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestNewProvider_Factory(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config.LLMConfig
		wantErr bool
		wantID  string
	}{
		{
			name: "Ollama Provider",
			cfg: config.LLMConfig{
				Enabled:  true,
				Provider: "ollama",
				Model:    "llama3",
				Endpoint: "http://localhost:11434",
			},
			wantErr: false,
			wantID:  "ollama",
		},
		{
			name: "OpenAI Provider",
			cfg: config.LLMConfig{
				Enabled:  true,
				Provider: "openai",
				Model:    "gpt-4",
				APIKey:   "sk-test",
			},
			wantErr: false,
			wantID:  "openai",
		},
		{
			name: "Anthropic Provider",
			cfg: config.LLMConfig{
				Enabled:  true,
				Provider: "anthropic",
				Model:    "claude-3",
				APIKey:   "sk-ant-test",
			},
			wantErr: false,
			wantID:  "anthropic",
		},
		{
			name: "Disabled",
			cfg: config.LLMConfig{
				Enabled: false,
			},
			wantErr: true,
		},
		{
			name: "Unknown Provider",
			cfg: config.LLMConfig{
				Enabled:  true,
				Provider: "deepmind", // Not supported yet :)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewProvider(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, got)
			assert.Equal(t, tt.wantID, got.ID())
		})
	}
}

func TestOpenAIProvider_GenerateExplanation_Stub(t *testing.T) {
	cfg := config.LLMConfig{
		Enabled:  true,
		Provider: "openai",
		Model:    "gpt-4",
		APIKey:   "sk-test",
	}
	p := NewOpenAIProvider(cfg)

	resp, err := p.GenerateExplanation(context.Background(), "test prompt")
	assert.NoError(t, err)
	assert.Contains(t, resp, "not implemented yet")
}

func TestAnthropicProvider_GenerateExplanation_Stub(t *testing.T) {
	cfg := config.LLMConfig{
		Enabled:  true,
		Provider: "anthropic",
		Model:    "claude-3",
		APIKey:   "sk-test",
	}
	p := NewAnthropicProvider(cfg)

	resp, err := p.GenerateExplanation(context.Background(), "test prompt")
	assert.NoError(t, err)
	assert.Contains(t, resp, "not implemented yet")
}
