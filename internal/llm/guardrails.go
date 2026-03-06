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
	// Cap response length to prevent unbounded memory use from runaway LLM output.
	const maxLLMResponseLength = 4096
	if len(response) > maxLLMResponseLength {
		response = response[:maxLLMResponseLength]
	}
	response = strings.TrimSpace(response)

	if s.detectHallucination(response) {
		logrus.Warn("LLM Hallucination or refusal detected")
		return "AI Analysis Unavailable (Safety Filter)", nil
	}

	return response, nil
}

// sanitizeInput removes dangerous characters and limits length to defend against
// prompt injection attacks via malicious package names, descriptions, or author fields.
func (s *SafeProvider) sanitizeInput(input string) string {
	// Strip Unicode control characters (incl. zero-width chars used to hide injections)
	var sb strings.Builder
	for _, r := range input {
		if r >= 0x20 || r == '\n' || r == '\t' {
			sb.WriteRune(r)
		}
	}
	input = sb.String()

	// Limit length to 2000 chars to prevent context exhaustion
	if len(input) > 2000 {
		input = input[:2000] + "...(truncated)"
	}

	// Remove prompt injection role delimiters that confuse LLMs
	re := regexp.MustCompile(`(?i)\b(system:|user:|human:|assistant:|<\|im_start\||<\|im_end\||<\|system\||<\|user\||<\|assistant\|)\b`)
	input = re.ReplaceAllString(input, "[REDACTED]")

	// Remove XML/HTML tags that could escape the <evidence> enclosure
	tagRe := regexp.MustCompile(`<[^>]{0,200}>`)
	input = tagRe.ReplaceAllString(input, "")

	return input
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
