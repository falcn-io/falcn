package llm

import (
	"fmt"
	"strings"

	"github.com/falcn-io/falcn/pkg/types"
)

// ExplanationRequest carries everything the prompt builder needs.
type ExplanationRequest struct {
	Threat          types.Threat
	SHAPImportances []SHAPFeature // top features from ML model (optional)
	DIRTScore       float64       // business impact score (0–1)
	PackageAge      int           // age in days
	DownloadCount   int64
}

// SHAPFeature is one entry from the SHAP importance vector.
type SHAPFeature struct {
	Name      string
	Importance float64
}

// structuredSystemPrompt is shared across all threat types.
const structuredSystemPrompt = `You are Falcn AI, a supply chain security analyst.
Your task is to explain a detected threat in a structured JSON format.

Rules:
- Be concise and technical. Developers read these explanations.
- Cite the specific evidence provided. Do not hallucinate.
- "what" must be one sentence (≤20 words).
- "why" must reference at least one piece of evidence.
- "impact" must mention a realistic attack scenario.
- "remediation" must give a specific action (version pin, removal command, or alternative package).
- Output ONLY valid JSON matching the schema below — no markdown, no prose.

Schema:
{
  "what": "<one-sentence summary>",
  "why": "<technical evidence>",
  "impact": "<attack scenario and blast radius>",
  "remediation": "<specific fix>"
}`

// BuildExplanationPrompt constructs a threat-type-specific prompt with evidence injection.
func BuildExplanationPrompt(req ExplanationRequest) string {
	t := req.Threat

	// Base evidence block
	var evidenceParts []string
	for _, e := range t.Evidence {
		evidenceParts = append(evidenceParts, fmt.Sprintf("  - [%s] %s: %v", e.Type, e.Description, e.Value))
	}
	evidenceBlock := strings.Join(evidenceParts, "\n")
	if evidenceBlock == "" {
		evidenceBlock = "  (no structured evidence available)"
	}

	// SHAP features block (top 5)
	shapBlock := ""
	if len(req.SHAPImportances) > 0 {
		var sb strings.Builder
		sb.WriteString("ML Feature Importances (top signals):\n")
		max := 5
		if len(req.SHAPImportances) < max {
			max = len(req.SHAPImportances)
		}
		for _, f := range req.SHAPImportances[:max] {
			sb.WriteString(fmt.Sprintf("  - %s: %.4f\n", f.Name, f.Importance))
		}
		shapBlock = sb.String()
	}

	// Package context
	contextBlock := fmt.Sprintf("Package context:\n  - Downloads: %d\n  - Age: %d days\n  - DIRT business impact score: %.2f",
		req.DownloadCount, req.PackageAge, req.DIRTScore)

	// Threat-type specific guidance
	guidance := threatTypeGuidance(t.Type)

	return fmt.Sprintf(`%s

---
Threat Details:
  Package:   %s@%s (%s)
  Type:      %s
  Severity:  %s
  Confidence: %.0f%%
  Description: %s

Evidence:
%s

%s

%s

%s

Output the JSON explanation now:`,
		structuredSystemPrompt,
		t.Package, t.Version, t.Registry,
		string(t.Type),
		t.Severity.String(),
		t.Confidence*100,
		t.Description,
		evidenceBlock,
		contextBlock,
		shapBlock,
		guidance,
	)
}

// threatTypeGuidance returns threat-specific instructions injected into the prompt.
func threatTypeGuidance(tt types.ThreatType) string {
	switch tt {
	case types.ThreatTypeTyposquatting, types.ThreatTypeHomoglyph:
		return `Guidance: Focus on the visual/phonetic similarity to a legitimate package. Explain how developers are deceived. Remediation should specify the correct package name.`

	case types.ThreatTypeDependencyConfusion:
		return `Guidance: Explain the internal vs public namespace collision. Remediation must include scoping the dependency to the private registry (e.g. .npmrc, pip.conf settings).`

	case types.ThreatTypeEmbeddedSecret, types.ThreatTypeObfuscatedCode:
		return `Guidance: Specify which secret type or obfuscation technique was detected. Impact should mention credential theft or data exfiltration. Remediation should include rotation of any exposed credentials.`

	case types.ThreatTypeInstallScript, types.ThreatTypeCICDInjection:
		return `Guidance: Explain what the install/postinstall script does at a technical level. Remediation should include how to audit the script and whether to use --ignore-scripts.`

	case types.ThreatTypeSelfHostedRunner:
		return `Guidance: Explain the supply chain risk of self-hosted CI runners (persistence, lateral movement). Remediation should recommend ephemeral runners or GitHub-hosted runners.`

	case types.ThreatTypeVulnerable:
		return `Guidance: Reference the specific CVE(s). Impact must include CVSS score context. Remediation must specify the patched version or workaround.`

	case types.ThreatTypeMaliciousPackage, types.ThreatTypeMalicious:
		return `Guidance: This is a confirmed malicious package. Impact is severe — assume full system compromise on install. Remediation is immediate removal and system audit.`

	case types.ThreatTypeEnvironmentAware, types.ThreatTypeBeaconActivity, types.ThreatTypeRuntimeExfiltration:
		return `Guidance: Explain the data exfiltration or C2 communication pattern. Impact includes credential and environment variable theft. Remediation should include immediate network isolation.`

	default:
		return `Guidance: Explain why this package poses a supply chain risk based on the evidence. Be specific about what an attacker could achieve.`
	}
}

// ParseStructuredExplanation extracts a ThreatExplanation from the LLM JSON response.
// Falls back gracefully if the response is not valid JSON or is missing fields.
func ParseStructuredExplanation(response, providerID string, confidence float64) *types.ThreatExplanation {
	// Strip markdown code fences if the model wrapped the JSON
	response = strings.TrimSpace(response)
	response = strings.TrimPrefix(response, "```json")
	response = strings.TrimPrefix(response, "```")
	response = strings.TrimSuffix(response, "```")
	response = strings.TrimSpace(response)

	// Find JSON object boundaries
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start == -1 || end == -1 || end <= start {
		// Not JSON — treat entire response as the "what" field
		return &types.ThreatExplanation{
			What:        truncate(response, 200),
			Confidence:  confidence,
			GeneratedBy: providerID,
		}
	}
	jsonStr := response[start : end+1]

	// Manual field extraction (avoids importing encoding/json into this package)
	expl := &types.ThreatExplanation{
		Confidence:  confidence,
		GeneratedBy: providerID,
	}
	expl.What = extractJSONString(jsonStr, "what")
	expl.Why = extractJSONString(jsonStr, "why")
	expl.Impact = extractJSONString(jsonStr, "impact")
	expl.Remediation = extractJSONString(jsonStr, "remediation")

	// If all fields empty, fall back to raw text
	if expl.What == "" && expl.Why == "" {
		expl.What = truncate(response, 200)
	}
	return expl
}

// extractJSONString extracts the value of a simple string field from a JSON object.
// Only handles flat string fields (no nesting needed here).
func extractJSONString(json, field string) string {
	key := `"` + field + `"`
	idx := strings.Index(json, key)
	if idx == -1 {
		return ""
	}
	rest := json[idx+len(key):]
	colon := strings.Index(rest, ":")
	if colon == -1 {
		return ""
	}
	rest = strings.TrimSpace(rest[colon+1:])
	if !strings.HasPrefix(rest, `"`) {
		return ""
	}
	// Find closing quote (handling escaped quotes)
	var sb strings.Builder
	for i := 1; i < len(rest); i++ {
		if rest[i] == '\\' && i+1 < len(rest) {
			switch rest[i+1] {
			case '"':
				sb.WriteByte('"')
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			default:
				sb.WriteByte(rest[i+1])
			}
			i++
			continue
		}
		if rest[i] == '"' {
			break
		}
		sb.WriteByte(rest[i])
	}
	return sb.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
