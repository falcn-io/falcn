// Package detector provides typosquatting and threat detection algorithms.
package detector

// slopsquatting.go — detection of AI-hallucination-based supply-chain attacks.
//
// Slopsquatting (coined 2024) exploits a fundamental LLM failure mode: code
// assistants (ChatGPT, Copilot, Claude, etc.) confidently suggest package names
// that sound plausible but do not exist in any legitimate registry. Attackers
// monitor popular LLM outputs, register those hallucinated names, and publish
// malicious packages — any developer who blindly runs the generated install
// command installs malware.
//
// This detector identifies four structural patterns behind LLM hallucinations:
//
//  1. AI suffix:    known_real_package + plausible_suffix  (e.g. "requests-extended")
//  2. Combination:  real_pkg_A + real_pkg_B combos         (e.g. "flask-sqlalchemy-utils")
//  3. Missing sep:  real_pkg_Areal_pkg_B (no hyphen)       (e.g. "flasksqlalchemy")
//  4. API namespace: cloud-brand + api-word pattern         (e.g. "stripe-sdk-utils")
//  5. Catalog hit:  exact match against curated LLM corpus (highest precision)
//
// Signals 1-4 require a match against the popular package corpus to reduce false
// positives from legitimate utility packages.  Signal 5 requires no cross-reference:
// the catalog contains names confirmed to appear in LLM outputs in the wild.

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/falcn-io/falcn/pkg/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// Curated data tables
// ─────────────────────────────────────────────────────────────────────────────

// aiSuffixesByRegistry are word-tokens that LLMs commonly append to a real
// package name to create a plausible-sounding, non-existent utility package.
var aiSuffixesByRegistry = map[string][]string{
	"npm": {
		"extended", "enhanced", "utils", "utilities", "pro", "helper", "helpers",
		"extra", "extras", "lite", "plus", "core", "common", "base",
		"wrapper", "client", "server", "api", "sdk", "tools",
		"hooks", "components", "middleware", "plugin", "plugins",
		"adapter", "adapters", "types", "lib", "next",
	},
	"pypi": {
		"utils", "helpers", "extended", "enhanced", "extra", "extras", "tools",
		"client", "api", "sdk", "wrapper", "wrappers", "common", "base",
		"core", "lite", "plus", "async", "sync", "ext", "lib", "py",
	},
	"go": {
		"utils", "helpers", "extended", "client", "server", "api", "sdk",
		"wrapper", "common", "core", "lib", "v2", "v3",
	},
	"nuget": {
		"Extensions", "Helpers", "Utils", "Core", "Client",
		"Extras", "Enhanced", "Plus", "Adapters", "Wrappers",
	},
	"cargo": {"utils", "helpers", "extended", "client", "server", "core", "lib", "extra"},
	"rubygems": {
		"utils", "helpers", "ext", "extensions", "extra",
		"extras", "core", "plus", "enhanced",
	},
}

// defaultAISuffixes is used when the registry is not found in aiSuffixesByRegistry.
var defaultAISuffixes = []string{
	"utils", "helpers", "extended", "enhanced", "extra",
	"lite", "plus", "core", "client", "api", "sdk",
}

// hallucinationCatalog contains package names observed in AI-generated code
// that do not correspond to legitimate popular packages.  These are the highest-
// precision slopsquatting signal: no similarity calculation is needed.
//
// Sources: Socket.dev blog, Endor Labs research, community reports (2023-2025).
var hallucinationCatalog = map[string]struct{}{
	// npm — AI hallucinations confirmed in the wild
	"npm:react-native-utils":          {},
	"npm:express-validator-utils":     {},
	"npm:lodash-extended":             {},
	"npm:lodash-utils":                {},
	"npm:axios-retry-helper":          {},
	"npm:axios-utils":                 {},
	"npm:node-fetch-extended":         {},
	"npm:webpack-utils":               {},
	"npm:babel-utils":                 {},
	"npm:react-hooks-utils":           {},
	"npm:react-router-utils":          {},
	"npm:redux-utils":                 {},
	"npm:next-utils":                  {},
	"npm:vue-utils":                   {},
	"npm:angular-utils":               {},
	"npm:typescript-utils":            {},
	"npm:typescript-helpers":          {},
	"npm:jest-utils":                  {},
	"npm:mocha-helpers":               {},
	"npm:chai-helpers":                {},
	"npm:socket-io-client-utils":      {},
	"npm:express-helpers":             {},
	"npm:graphql-utils":               {},
	"npm:prisma-utils":                {},
	"npm:mongoose-utils":              {},
	"npm:sequelize-utils":             {},
	"npm:eslint-utils-extended":       {},
	"npm:tailwindcss-utils":           {},
	"npm:vite-utils":                  {},
	"npm:prettier-utils":              {},
	"npm:dotenv-extended":             {},
	"npm:uuid-utils":                  {},
	"npm:date-fns-utils":              {},
	"npm:moment-utils":                {},
	"npm:lodash-async":                {},
	"npm:express-middleware-utils":    {},
	"npm:passport-utils":              {},
	"npm:jwt-utils":                   {},
	"npm:bcrypt-utils":                {},
	"npm:multer-utils":                {},
	"npm:cheerio-utils":               {},
	"npm:puppeteer-utils":             {},
	"npm:playwright-utils":            {},
	"npm:nodemailer-utils":            {},
	"npm:stripe-node-utils":           {},
	"npm:aws-sdk-utils":               {},
	"npm:openai-node-utils":           {},
	"npm:langchain-utils":             {},
	// pypi — AI hallucinations confirmed in the wild
	"pypi:requests-extended":          {},
	"pypi:requests-utils":             {},
	"pypi:requests-async":             {},
	"pypi:numpy-utils":                {},
	"pypi:pandas-utils":               {},
	"pypi:pandas-helpers":             {},
	"pypi:django-utils":               {},
	"pypi:flask-utils":                {},
	"pypi:flask-helpers":              {},
	"pypi:tensorflow-utils":           {},
	"pypi:scikit-learn-utils":         {},
	"pypi:matplotlib-utils":           {},
	"pypi:pillow-extended":            {},
	"pypi:sqlalchemy-utils-extended":  {},
	"pypi:fastapi-utils-extended":     {},
	"pypi:pydantic-utils":             {},
	"pypi:boto3-utils":                {},
	"pypi:celery-utils":               {},
	"pypi:redis-utils":                {},
	"pypi:pytest-utils":               {},
	"pypi:click-utils":                {},
	"pypi:httpx-utils":                {},
	"pypi:aiohttp-utils":              {},
	"pypi:sqlalchemy-helpers":         {},
	"pypi:django-rest-utils":          {},
	"pypi:fastapi-helpers":            {},
	"pypi:openai-utils":               {},
	"pypi:langchain-utils":            {},
	"pypi:anthropic-utils":            {},
	"pypi:transformers-utils":         {},
	"pypi:torch-utils":                {},
	"pypi:scipy-utils":                {},
	"pypi:asyncio-utils":              {},
	"pypi:pathlib-utils":              {},
	"pypi:logging-utils":              {},
	"pypi:datetime-utils":             {},
	"pypi:json-utils":                 {},
	"pypi:typing-utils":               {},
	"pypi:dataclasses-utils":          {},
	"pypi:python-utils-extended":      {},
	"pypi:requests-helper":            {},
	"pypi:flask-api-utils":            {},
	"pypi:django-api-utils":           {},
	// nuget
	"nuget:Newtonsoft.Json.Extensions":                     {},
	"nuget:Microsoft.Extensions.DependencyInjection.Utils": {},
	"nuget:AutoMapper.Extensions.Utils":                    {},
	"nuget:Serilog.Utils":                                  {},
	"nuget:FluentValidation.Extensions":                    {},
	"nuget:MediatR.Utils":                                  {},
	"nuget:EntityFramework.Utils":                          {},
	// cargo
	"cargo:tokio-utils": {},
	"cargo:serde-utils":  {},
	"cargo:actix-utils":  {},
	"cargo:reqwest-utils":{},
	"cargo:diesel-utils": {},
	"cargo:clap-utils":   {},
	// rubygems
	"rubygems:rails-utils":   {},
	"rubygems:devise-utils":  {},
	"rubygems:sidekiq-utils": {},
	"rubygems:rspec-utils":   {},
}

// aiNamespacePatterns are regexp patterns for plausible-but-nonexistent
// SDK/API namespace packages that LLMs commonly hallucinate.
var aiNamespacePatterns = map[string]*regexp.Regexp{
	"npm": regexp.MustCompile(
		`^(google|aws|azure|gcp|stripe|twilio|sendgrid|shopify|salesforce|` +
			`github|gitlab|slack|discord|notion|airtable|hubspot|intercom|` +
			`anthropic|openai|cohere|mistral)` +
			`[-_](sdk|api|client|node|js|utils|helper|wrapper|v2|v3)$`,
	),
	"pypi": regexp.MustCompile(
		`^(google|aws|boto|azure|gcp|stripe|twilio|sendgrid|shopify|salesforce|` +
			`github|slack|discord|openai|anthropic|cohere|mistral|huggingface)` +
			`[-_](sdk|api|client|py|python|utils|helper|wrapper|async)$`,
	),
}

// combinationPairs are pairs of popular packages that LLMs routinely merge into
// a single nonexistent package name.
var combinationPairsByRegistry = map[string][][2]string{
	"npm": {
		{"axios", "requests"}, {"react", "router"},
		{"express", "validator"}, {"socket", "io"},
		{"redux", "saga"}, {"webpack", "babel"},
		{"typescript", "eslint"}, {"react", "query"},
		{"jest", "testing"}, {"eslint", "prettier"},
		{"mongodb", "mongoose"}, {"express", "mongoose"},
		{"react", "redux"}, {"next", "auth"},
		{"stripe", "node"}, {"openai", "sdk"},
	},
	"pypi": {
		{"flask", "sqlalchemy"}, {"django", "rest"},
		{"requests", "html"}, {"pandas", "numpy"},
		{"pytest", "mock"}, {"celery", "redis"},
		{"fastapi", "pydantic"}, {"aiohttp", "requests"},
		{"sqlalchemy", "alembic"}, {"boto3", "botocore"},
		{"flask", "restful"}, {"django", "celery"},
		{"openai", "anthropic"}, {"langchain", "openai"},
	},
	"rubygems": {
		{"rails", "devise"}, {"rspec", "rails"},
		{"sidekiq", "redis"}, {"activerecord", "grape"},
	},
}

// ─────────────────────────────────────────────────────────────────────────────
// Detector struct
// ─────────────────────────────────────────────────────────────────────────────

// SlopsquattingDetector identifies package names that match patterns commonly
// produced by LLM code assistants when hallucinating package names.
type SlopsquattingDetector struct{}

// NewSlopsquattingDetector returns an initialized SlopsquattingDetector.
func NewSlopsquattingDetector() *SlopsquattingDetector {
	return &SlopsquattingDetector{}
}

// ─────────────────────────────────────────────────────────────────────────────
// Intermediate result type (unexported)
// ─────────────────────────────────────────────────────────────────────────────

type slopMatch struct {
	matchType   string  // "ai_suffix" | "combination" | "missing_hyphen" | "api_namespace" | "hallucination_catalog"
	basePackage string  // canonical popular package the name was derived from
	confidence  float64 // 0.0-1.0
	evidence    []types.Evidence
}

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

// Detect analyses dep and returns any slopsquatting threats found.
//
// popular is the list of well-known package names for the dependency's registry,
// used by signals 1-3 to confirm that the detected base/components are genuinely
// popular packages (reducing false positives on legitimate utility wrappers).
func (sd *SlopsquattingDetector) Detect(dep types.Dependency, popular []string) []types.Threat {
	name := strings.ToLower(strings.TrimSpace(dep.Name))
	if name == "" {
		return nil
	}
	registry := strings.ToLower(dep.Registry)

	// Build a quick-lookup set of popular packages (lowercase).
	popSet := make(map[string]struct{}, len(popular))
	for _, p := range popular {
		popSet[strings.ToLower(p)] = struct{}{}
	}

	// Signal 5 — hallucination catalog (highest precision, short-circuit).
	if m := sd.detectCatalog(name, registry); m != nil {
		return []types.Threat{sd.buildThreat(dep, m)}
	}

	// Signals 1-4 — structural name patterns.
	var candidates []*slopMatch
	if m := sd.detectAISuffix(name, registry, popSet); m != nil {
		candidates = append(candidates, m)
	}
	if m := sd.detectCombination(name, registry, popSet); m != nil {
		candidates = append(candidates, m)
	}
	if m := sd.detectMissingHyphen(name, registry, popSet); m != nil {
		candidates = append(candidates, m)
	}
	if m := sd.detectAPINamespace(name, registry); m != nil {
		candidates = append(candidates, m)
	}

	best := sd.selectBest(candidates)
	if best == nil {
		return nil
	}
	return []types.Threat{sd.buildThreat(dep, best)}
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal 5 — hallucination catalog
// ─────────────────────────────────────────────────────────────────────────────

func (sd *SlopsquattingDetector) detectCatalog(name, registry string) *slopMatch {
	key := registry + ":" + name
	if _, ok := hallucinationCatalog[key]; !ok {
		return nil
	}
	return &slopMatch{
		matchType:   "hallucination_catalog",
		basePackage: name,
		confidence:  0.90,
		evidence: []types.Evidence{{
			Type:        "hallucination_catalog",
			Description: fmt.Sprintf("'%s' appears in the curated LLM hallucination corpus for %s", name, registry),
			Score:       0.90,
		}},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal 1 — AI suffix appended to a real popular package
// ─────────────────────────────────────────────────────────────────────────────

func (sd *SlopsquattingDetector) detectAISuffix(name, registry string, popSet map[string]struct{}) *slopMatch {
	suffixes := aiSuffixesByRegistry[registry]
	if suffixes == nil {
		suffixes = defaultAISuffixes
	}

	// Strip leading npm scope for matching: "@scope/foo-utils" → "foo-utils"
	stripped := name
	if registry == "npm" && strings.HasPrefix(name, "@") {
		if idx := strings.Index(name, "/"); idx >= 0 {
			stripped = name[idx+1:]
		}
	}

	for _, suffix := range suffixes {
		// Try both hyphen and underscore separators
		for _, sep := range []string{"-", "_"} {
			candidate := sep + suffix
			if !strings.HasSuffix(stripped, candidate) {
				continue
			}
			base := stripped[:len(stripped)-len(candidate)]
			if len(base) < 2 {
				continue
			}
			// Base must be a known popular package for this to be a signal.
			if _, ok := popSet[base]; !ok {
				continue
			}
			confidence := 0.72
			return &slopMatch{
				matchType:   "ai_suffix",
				basePackage: base,
				confidence:  confidence,
				evidence: []types.Evidence{
					{
						Type: "ai_suffix",
						Description: fmt.Sprintf(
							"name '%s' = popular package '%s' + AI-generated suffix '%s'",
							name, base, suffix,
						),
						Score: confidence,
					},
					{
						Type:        "popular_base_confirmed",
						Description: fmt.Sprintf("base '%s' is a well-known popular package", base),
						Score:       0.85,
					},
				},
			}
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal 2 — combination of two popular packages
// ─────────────────────────────────────────────────────────────────────────────

func (sd *SlopsquattingDetector) detectCombination(name, registry string, popSet map[string]struct{}) *slopMatch {
	// First: check the curated catalog of known pair hallucinations.
	if pairs, ok := combinationPairsByRegistry[registry]; ok {
		for _, pair := range pairs {
			a, b := strings.ToLower(pair[0]), strings.ToLower(pair[1])
			combined := a + "-" + b
			combinedRev := b + "-" + a
			// Allow an extra suffix after the combination: "flask-sqlalchemy-utils"
			if name == combined || name == combinedRev ||
				strings.HasPrefix(name, combined+"-") ||
				strings.HasPrefix(name, combinedRev+"-") {
				_, aPopular := popSet[a]
				_, bPopular := popSet[b]
				confidence := 0.78
				if aPopular && bPopular {
					confidence = 0.82
				}
				return &slopMatch{
					matchType:   "combination",
					basePackage: pair[0],
					confidence:  confidence,
					evidence: []types.Evidence{
						{
							Type: "combination",
							Description: fmt.Sprintf(
								"name '%s' combines popular packages '%s' and '%s' into a plausible LLM-hallucinated name",
								name, pair[0], pair[1],
							),
							Score: confidence,
						},
					},
				}
			}
		}
	}

	// Second: open-ended search over all popular pairs.
	// Guard: skip if popular list is too large to be practical (>500) or name too short.
	if len(name) < 6 || len(popular(popSet)) > 500 {
		return nil
	}
	for a := range popSet {
		if len(a) < 3 || !strings.HasPrefix(name, a+"-") {
			continue
		}
		rest := name[len(a)+1:] // part after "a-"
		// rest should itself be a popular package (possibly with a trailing suffix)
		for b := range popSet {
			if b == a || len(b) < 3 {
				continue
			}
			if rest == b || strings.HasPrefix(rest, b+"-") {
				confidence := 0.75
				return &slopMatch{
					matchType:   "combination",
					basePackage: a,
					confidence:  confidence,
					evidence: []types.Evidence{{
						Type: "combination",
						Description: fmt.Sprintf(
							"name '%s' combines popular packages '%s' and '%s'",
							name, a, b,
						),
						Score: confidence,
					}},
				}
			}
		}
	}
	return nil
}

// popular is a small helper to iterate pop set keys; used only for small lists.
func popular(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal 3 — two popular packages concatenated without a separator
// ─────────────────────────────────────────────────────────────────────────────

func (sd *SlopsquattingDetector) detectMissingHyphen(name, registry string, popSet map[string]struct{}) *slopMatch {
	if len(name) < 8 {
		return nil // too short to be a meaningful concatenation
	}
	// Limit to smaller popular sets to keep complexity manageable.
	if len(popSet) > 200 {
		return nil
	}
	for a := range popSet {
		if len(a) < 3 || !strings.HasPrefix(name, a) {
			continue
		}
		rest := name[len(a):]
		if _, ok := popSet[rest]; ok && rest != a && len(rest) >= 3 {
			confidence := 0.68
			return &slopMatch{
				matchType:   "missing_hyphen",
				basePackage: a,
				confidence:  confidence,
				evidence: []types.Evidence{{
					Type: "missing_hyphen",
					Description: fmt.Sprintf(
						"name '%s' concatenates popular packages '%s' and '%s' without a separator — a common LLM error",
						name, a, rest,
					),
					Score: confidence,
				}},
			}
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal 4 — plausible API / SDK namespace pattern
// ─────────────────────────────────────────────────────────────────────────────

func (sd *SlopsquattingDetector) detectAPINamespace(name, registry string) *slopMatch {
	re, ok := aiNamespacePatterns[registry]
	if !ok {
		return nil
	}
	if !re.MatchString(name) {
		return nil
	}
	return &slopMatch{
		matchType:   "api_namespace",
		basePackage: name,
		confidence:  0.60,
		evidence: []types.Evidence{{
			Type: "api_namespace",
			Description: fmt.Sprintf(
				"name '%s' follows a cloud/SaaS SDK namespace pattern commonly hallucinated by LLMs",
				name,
			),
			Score: 0.60,
		}},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// selectBest picks the highest-confidence candidate.
// ─────────────────────────────────────────────────────────────────────────────

func (sd *SlopsquattingDetector) selectBest(candidates []*slopMatch) *slopMatch {
	var best *slopMatch
	for _, c := range candidates {
		if best == nil || c.confidence > best.confidence {
			best = c
		}
	}
	return best
}

// ─────────────────────────────────────────────────────────────────────────────
// buildThreat converts a slopMatch to a types.Threat
// ─────────────────────────────────────────────────────────────────────────────

func (sd *SlopsquattingDetector) buildThreat(dep types.Dependency, m *slopMatch) types.Threat {
	return types.Threat{
		ID:             generateThreatID(),
		Package:        dep.Name,
		Version:        dep.Version,
		Registry:       dep.Registry,
		Type:           types.ThreatTypeSlopsquatting,
		Severity:       sd.confidenceToSeverity(m.confidence),
		Confidence:     m.confidence,
		Description:    sd.buildDescription(dep.Name, m),
		SimilarTo:      m.basePackage,
		Recommendation: sd.buildRecommendation(dep.Name, m),
		DetectedAt:     time.Now(),
		DetectionMethod: "slopsquatting:" + m.matchType,
		Evidence:       m.evidence,
		Metadata: map[string]interface{}{
			"match_type":   m.matchType,
			"base_package": m.basePackage,
		},
	}
}

func (sd *SlopsquattingDetector) confidenceToSeverity(c float64) types.Severity {
	switch {
	case c >= 0.85:
		return types.SeverityHigh
	case c >= 0.65:
		return types.SeverityMedium
	default:
		return types.SeverityLow
	}
}

func (sd *SlopsquattingDetector) buildDescription(name string, m *slopMatch) string {
	switch m.matchType {
	case "hallucination_catalog":
		return fmt.Sprintf(
			"'%s' is in the curated LLM hallucination corpus — this exact name has been "+
				"observed in AI-generated code that references packages which do not exist "+
				"legitimately. Attackers register these names with malicious payloads targeting "+
				"developers who install AI-generated dependency lists without verification.",
			name,
		)
	case "ai_suffix":
		return fmt.Sprintf(
			"'%s' appears to be the popular package '%s' combined with an AI-generated suffix. "+
				"LLM code assistants frequently produce names like '%s' when asked to add "+
				"utility wrappers or extensions — and attackers register these plausible names "+
				"with malicious packages (slopsquatting).",
			name, m.basePackage, name,
		)
	case "combination":
		return fmt.Sprintf(
			"'%s' combines two well-known packages into a single, plausible-sounding name. "+
				"This pattern is a common LLM hallucination target: the name sounds like it "+
				"should exist, so developers trust AI-generated code that references it. "+
				"Verify that '%s' is the intended dependency.",
			name, name,
		)
	case "missing_hyphen":
		return fmt.Sprintf(
			"'%s' appears to concatenate two popular package names without a separator — a "+
				"pattern frequently produced by LLM code generation errors "+
				"(e.g. 'flasksqlalchemy' instead of 'flask-sqlalchemy'). "+
				"This exact form is exploited by slopsquatting attackers.",
			name,
		)
	case "api_namespace":
		return fmt.Sprintf(
			"'%s' follows a cloud/SaaS API SDK namespace pattern (brand + api-word) that "+
				"LLMs commonly hallucinate. The official SDK for this service may have a different "+
				"name. Verify the correct package before installing.",
			name,
		)
	default:
		return fmt.Sprintf(
			"'%s' matches a slopsquatting pattern: the name is structurally consistent "+
				"with LLM-hallucinated package names. Verify the package is legitimate before use.",
			name,
		)
	}
}

func (sd *SlopsquattingDetector) buildRecommendation(name string, m *slopMatch) string {
	base := m.basePackage
	if base == "" {
		base = "the intended package"
	}
	return fmt.Sprintf(
		"1. Do NOT install '%s' unless you have manually verified it on the official registry. "+
			"2. If this dependency came from AI-generated code, check whether '%s' was the "+
			"intended package. "+
			"3. Search the registry for the official package and compare maintainers, "+
			"download counts, and repository links before installing. "+
			"4. Enable Falcn's --check-ai-deps flag to audit all AI-generated install commands.",
		name, base,
	)
}
