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
				Provider: "deepmind", // Not supported
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

// TestOpenAIProvider_NoAPIKey verifies that an empty API key is rejected before
// any network call, preventing accidental usage without credentials.
func TestOpenAIProvider_NoAPIKey(t *testing.T) {
	cfg := config.LLMConfig{
		Enabled:  true,
		Provider: "openai",
		Model:    "gpt-4o-mini",
		APIKey:   "", // empty — should fail fast
	}
	p := NewOpenAIProvider(cfg)

	_, err := p.GenerateExplanation(context.Background(), "test prompt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OPENAI_API_KEY")
}

// TestOpenAIProvider_ID verifies the provider returns the correct identifier.
func TestOpenAIProvider_ID(t *testing.T) {
	p := NewOpenAIProvider(config.LLMConfig{})
	assert.Equal(t, "openai", p.ID())
}

// TestOpenAIProvider_DefaultModel verifies that a default model is set when
// the config leaves the model field empty.
func TestOpenAIProvider_DefaultModel(t *testing.T) {
	p := NewOpenAIProvider(config.LLMConfig{})
	assert.Equal(t, "gpt-4o-mini", p.model)
}

// TestAnthropicProvider_NoAPIKey verifies that an empty API key is rejected
// before any network call.
func TestAnthropicProvider_NoAPIKey(t *testing.T) {
	cfg := config.LLMConfig{
		Enabled:  true,
		Provider: "anthropic",
		Model:    "claude-haiku-4-5",
		APIKey:   "", // empty — should fail fast
	}
	p := NewAnthropicProvider(cfg)

	_, err := p.GenerateExplanation(context.Background(), "test prompt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ANTHROPIC_API_KEY")
}

// TestAnthropicProvider_ID verifies the provider returns the correct identifier.
func TestAnthropicProvider_ID(t *testing.T) {
	p := NewAnthropicProvider(config.LLMConfig{})
	assert.Equal(t, "anthropic", p.ID())
}

// TestAnthropicProvider_DefaultModel verifies that a default model is used
// when the config is empty.
func TestAnthropicProvider_DefaultModel(t *testing.T) {
	p := NewAnthropicProvider(config.LLMConfig{})
	assert.Equal(t, "claude-haiku-4-5", p.model)
}
