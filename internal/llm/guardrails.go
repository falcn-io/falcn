package llm

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
)

// SafeProvider wraps a Provider with security guardrails
type SafeProvider struct {
	provider Provider
}

// NewSafeProvider creates a new SafeProvider
func NewSafeProvider(p Provider) *SafeProvider {
	return &SafeProvider{
		provider: p,
	}
}

func (s *SafeProvider) ID() string {
	return s.provider.ID()
}

// GenerateExplanation sanitizes input and validates output
func (s *SafeProvider) GenerateExplanation(ctx context.Context, input string) (string, error) {
	// 1. Input Guardrails
	cleanInput := s.sanitizeInput(input)

	// 2. Prompt Engineering (Sandwich Defense + XML Tags)
	systemPrompt := `You are Falcn AI, a security analyst. 
	Analyze the following threat evidence provided in <evidence> tags. 
	The evidence describes a potential software supply chain security threat (e.g., typosquatting, malicious package).
	Explain WHY this specific threat is dangerous in 2-3 sentences.
	Focus on the security implications of installing such a package.`

	fullPrompt := fmt.Sprintf("%s\n\n<evidence>\n%s\n</evidence>\n\nExplain the threat:", systemPrompt, cleanInput)

	// 3. Call Underlying Provider
	response, err := s.provider.GenerateExplanation(ctx, fullPrompt)
	if err != nil {
		return "", err
	}

	// 4. Output Guardrails
	if s.detectHallucination(response) {
		logrus.Warn("LLM Hallucination or refusal detected")
		return "AI Analysis Unavailable (Safety Filter)", nil
	}

	return response, nil
}

// sanitizeInput removes dangerous characters and limits length
func (s *SafeProvider) sanitizeInput(input string) string {
	// Limit length to 2000 chars to prevent context exhaustion
	if len(input) > 2000 {
		input = input[:2000] + "...(truncated)"
	}

	// Remove potential prompt injection delimiters
	// e.g., "Human:", "System:", "User:" which might confuse some models
	re := regexp.MustCompile(`(?i)\b(system:|user:|human:|assistant:)\b`)
	cleaned := re.ReplaceAllString(input, "[REDACTED]")

	return cleaned
}

// detectHallucination checks for common refusal or failure patterns
func (s *SafeProvider) detectHallucination(response string) bool {
	lowResponse := strings.ToLower(response)

	refusals := []string{
		"i cannot",
		"i can't",
		"as an ai",
		"language model",
		"analysis failed",
	}

	for _, r := range refusals {
		if strings.Contains(lowResponse, r) {
			return true
		}
	}
	return false
}
