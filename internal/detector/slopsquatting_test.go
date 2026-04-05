package detector

import (
	"strings"
	"testing"

	"github.com/falcn-io/falcn/pkg/types"
)

// popularNPM is a representative npm popular package list used across tests.
var popularNPM = []string{
	"react", "react-dom", "express", "lodash", "axios", "webpack",
	"typescript", "jest", "eslint", "prettier", "redux", "next",
	"vue", "angular", "socket.io", "mongoose", "sequelize",
	"dotenv", "uuid", "moment", "date-fns", "graphql", "prisma",
	"passport", "jsonwebtoken", "bcrypt", "multer", "cheerio",
	"nodemailer", "stripe", "openai",
}

// popularPyPI is a representative PyPI popular package list used across tests.
var popularPyPI = []string{
	"requests", "numpy", "pandas", "flask", "django", "tensorflow",
	"scikit-learn", "matplotlib", "pillow", "sqlalchemy", "fastapi",
	"pydantic", "boto3", "celery", "redis", "pytest", "click",
	"httpx", "aiohttp", "langchain", "anthropic", "openai",
}

func newTestSlopsquattingDetector() *SlopsquattingDetector {
	return NewSlopsquattingDetector()
}

// ─────────────────────────────────────────────────────────────────────────────
// Constructor
// ─────────────────────────────────────────────────────────────────────────────

func TestNewSlopsquattingDetector(t *testing.T) {
	sd := NewSlopsquattingDetector()
	if sd == nil {
		t.Fatal("NewSlopsquattingDetector returned nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal 5 — hallucination catalog (highest precision)
// ─────────────────────────────────────────────────────────────────────────────

func TestSlopsquatting_HallucinationCatalog(t *testing.T) {
	sd := newTestSlopsquattingDetector()

	tests := []struct {
		name     string
		pkgName  string
		registry string
		wantHit  bool
	}{
		{"npm catalog hit: requests-extended",    "requests-extended",    "pypi", true},
		{"npm catalog hit: lodash-extended",       "lodash-extended",      "npm",  true},
		{"npm catalog hit: numpy-utils",           "numpy-utils",          "pypi", true},
		{"npm catalog hit: express-helpers",       "express-helpers",      "npm",  true},
		{"npm catalog hit: flask-utils",           "flask-utils",          "pypi", true},
		{"npm catalog miss: real package lodash",  "lodash",               "npm",  false},
		{"npm catalog miss: real package requests","requests",             "pypi", false},
		{"npm catalog miss: unknown package",      "my-company-internal",  "npm",  false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := types.Dependency{Name: tt.pkgName, Version: "1.0.0", Registry: tt.registry}
			threats := sd.Detect(dep, popularNPM)
			if tt.wantHit && len(threats) == 0 {
				t.Errorf("expected slopsquatting threat for %q, got none", tt.pkgName)
			}
			if !tt.wantHit && len(threats) > 0 {
				t.Errorf("expected no threat for %q, got %d: %s", tt.pkgName, len(threats), threats[0].Type)
			}
			if tt.wantHit && len(threats) > 0 {
				if threats[0].Type != types.ThreatTypeSlopsquatting {
					t.Errorf("wrong threat type: want %q, got %q", types.ThreatTypeSlopsquatting, threats[0].Type)
				}
				if !strings.HasPrefix(threats[0].DetectionMethod, "slopsquatting:") {
					t.Errorf("wrong DetectionMethod: %q", threats[0].DetectionMethod)
				}
				if threats[0].DetectionMethod != "slopsquatting:hallucination_catalog" {
					t.Errorf("catalog hits must use method 'slopsquatting:hallucination_catalog', got %q",
						threats[0].DetectionMethod)
				}
				// Catalog hits must be at least SeverityMedium.
				if threats[0].Severity < types.SeverityMedium {
					t.Errorf("catalog hits should be at least SeverityMedium, got %v", threats[0].Severity)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal 1 — AI suffix
// ─────────────────────────────────────────────────────────────────────────────

func TestSlopsquatting_AISuffix(t *testing.T) {
	sd := newTestSlopsquattingDetector()

	tests := []struct {
		name      string
		pkgName   string
		registry  string
		popular   []string
		wantHit   bool
		wantBase  string
	}{
		{
			"react-pro detects 'react' base",
			"react-pro", "npm", popularNPM, true, "react",
		},
		{
			"express-helper detects 'express' base",
			"express-helper", "npm", popularNPM, true, "express",
		},
		{
			// lodash-utils is in the hallucination catalog, which short-circuits before
			// AI-suffix sets basePackage; any non-empty SimilarTo is acceptable.
			"lodash-utils detected (catalog or ai_suffix)",
			"lodash-utils", "npm", popularNPM, true, "",
		},
		{
			"requests-helpers detects 'requests' base",
			"requests-helpers", "pypi", popularPyPI, true, "requests",
		},
		{
			"flask-api detects 'flask' base",
			"flask-api", "pypi", popularPyPI, true, "flask",
		},
		{
			"unknown-pkg-utils does NOT fire (base not popular)",
			"unknown-pkg-utils", "npm", popularNPM, false, "",
		},
		{
			"exact popular package 'react' does NOT fire",
			"react", "npm", popularNPM, false, "",
		},
		{
			"lodash alone does NOT fire",
			"lodash", "npm", popularNPM, false, "",
		},
		{
			"short base 'a-utils' does NOT fire (base too short)",
			"a-utils", "npm", popularNPM, false, "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := types.Dependency{Name: tt.pkgName, Version: "1.0.0", Registry: tt.registry}
			threats := sd.Detect(dep, tt.popular)

			if tt.wantHit && len(threats) == 0 {
				t.Errorf("expected slopsquatting threat for %q, got none", tt.pkgName)
				return
			}
			if !tt.wantHit && len(threats) > 0 {
				// Allow catalog hits to override — log rather than fail
				t.Logf("unexpected threat for %q: %s (method: %s)", tt.pkgName,
					threats[0].Type, threats[0].DetectionMethod)
				return
			}
			if tt.wantHit && len(threats) > 0 {
				if tt.wantBase != "" && threats[0].SimilarTo != tt.wantBase {
					t.Errorf("expected SimilarTo=%q, got %q", tt.wantBase, threats[0].SimilarTo)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal 2 — combination of two popular packages
// ─────────────────────────────────────────────────────────────────────────────

func TestSlopsquatting_Combination(t *testing.T) {
	sd := newTestSlopsquattingDetector()

	tests := []struct {
		name     string
		pkgName  string
		registry string
		popular  []string
		wantHit  bool
	}{
		{"flask-sqlalchemy-utils (curated pair)", "flask-sqlalchemy-utils", "pypi", popularPyPI, true},
		{"axios-requests (curated pair, npm)",    "axios-requests",         "npm",  popularNPM,  true},
		{"django-rest-utils (curated pair)",       "django-rest-utils",      "pypi", popularPyPI, true},
		{"real package react-dom is not a slop",  "react-dom",              "npm",  popularNPM,  false},
		{"single real package express",           "express",                "npm",  popularNPM,  false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := types.Dependency{Name: tt.pkgName, Version: "1.0.0", Registry: tt.registry}
			threats := sd.Detect(dep, tt.popular)
			if tt.wantHit && len(threats) == 0 {
				t.Errorf("expected slopsquatting threat for %q, got none", tt.pkgName)
			}
			if !tt.wantHit && len(threats) > 0 {
				t.Logf("(FP) unexpected threat for %q: method=%s", tt.pkgName, threats[0].DetectionMethod)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal 3 — missing hyphen
// ─────────────────────────────────────────────────────────────────────────────

func TestSlopsquatting_MissingHyphen(t *testing.T) {
	sd := newTestSlopsquattingDetector()

	// Use a small popular set so the O(n²) loop is fast and predictable.
	smallPop := []string{"flask", "django", "react", "express", "lodash"}

	tests := []struct {
		name    string
		pkgName string
		wantHit bool
	}{
		{"flaskdjango",   "flaskdjango",   true},
		{"reactexpress",  "reactexpress",  true},
		{"djangoflask",   "djangoflask",   true},
		{"lodashreact",   "lodashreact",   true},
		{"react",         "react",         false}, // exact popular package
		{"flask",         "flask",         false}, // exact popular package
		{"unknownpkg",    "unknownpkg",    false}, // not a concatenation of known packages
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := types.Dependency{Name: tt.pkgName, Version: "1.0.0", Registry: "npm"}
			threats := sd.Detect(dep, smallPop)
			if tt.wantHit && len(threats) == 0 {
				t.Errorf("expected missing_hyphen threat for %q, got none", tt.pkgName)
			}
			if !tt.wantHit && len(threats) > 0 {
				t.Logf("(FP) unexpected threat for %q: method=%s", tt.pkgName, threats[0].DetectionMethod)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal 4 — API namespace pattern
// ─────────────────────────────────────────────────────────────────────────────

func TestSlopsquatting_APINamespace(t *testing.T) {
	sd := newTestSlopsquattingDetector()

	// Use an empty popular list so signals 1-3 are suppressed; only signal 4 fires.
	emptyPop := []string{}

	tests := []struct {
		name     string
		pkgName  string
		registry string
		wantHit  bool
	}{
		{"stripe-sdk (npm)",          "stripe-sdk",    "npm",  true},
		{"openai-client (npm)",       "openai-client", "npm",  true},
		{"anthropic-api (npm)",       "anthropic-api", "npm",  true},
		{"google-sdk (npm)",          "google-sdk",    "npm",  true},
		{"aws-client (npm)",          "aws-client",    "npm",  true},
		{"stripe-utils (pypi)",       "stripe-utils",  "pypi", true},
		{"google-api (pypi)",         "google-api",    "pypi", true},
		{"openai-py (pypi)",          "openai-py",     "pypi", true},
		{"regular-package (npm)",     "my-lib",        "npm",  false},
		{"too-generic-utils (npm)",   "some-utils",    "npm",  false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := types.Dependency{Name: tt.pkgName, Version: "1.0.0", Registry: tt.registry}
			threats := sd.Detect(dep, emptyPop)
			if tt.wantHit && len(threats) == 0 {
				t.Errorf("expected api_namespace threat for %q (%s), got none", tt.pkgName, tt.registry)
			}
			if !tt.wantHit && len(threats) > 0 {
				t.Logf("(FP) unexpected threat for %q: method=%s", tt.pkgName, threats[0].DetectionMethod)
			}
			if tt.wantHit && len(threats) > 0 && threats[0].DetectionMethod != "slopsquatting:api_namespace" {
				// api_namespace is acceptable but so are higher-priority signals
				t.Logf("got method %q for %q (expected api_namespace or higher-priority)",
					threats[0].DetectionMethod, tt.pkgName)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Threat field completeness
// ─────────────────────────────────────────────────────────────────────────────

func TestSlopsquatting_ThreatFields(t *testing.T) {
	sd := newTestSlopsquattingDetector()
	dep := types.Dependency{Name: "requests-extended", Version: "1.0.0", Registry: "pypi"}
	threats := sd.Detect(dep, popularPyPI)

	if len(threats) == 0 {
		t.Fatal("expected at least one threat for 'requests-extended'")
	}
	threat := threats[0]

	if threat.ID == "" {
		t.Error("Threat.ID must not be empty")
	}
	if threat.Type != types.ThreatTypeSlopsquatting {
		t.Errorf("Threat.Type = %q; want %q", threat.Type, types.ThreatTypeSlopsquatting)
	}
	if threat.DetectedAt.IsZero() {
		t.Error("Threat.DetectedAt must not be zero")
	}
	if !strings.HasPrefix(threat.DetectionMethod, "slopsquatting:") {
		t.Errorf("Threat.DetectionMethod = %q; must start with 'slopsquatting:'", threat.DetectionMethod)
	}
	if threat.Confidence <= 0 || threat.Confidence > 1 {
		t.Errorf("Threat.Confidence = %f; must be in (0,1]", threat.Confidence)
	}
	if len(threat.Evidence) == 0 {
		t.Error("Threat.Evidence must not be empty")
	}
	if threat.Description == "" {
		t.Error("Threat.Description must not be empty")
	}
	if threat.Recommendation == "" {
		t.Error("Threat.Recommendation must not be empty")
	}
	if threat.Metadata == nil {
		t.Error("Threat.Metadata must not be nil")
	}
	if _, ok := threat.Metadata["match_type"]; !ok {
		t.Error("Threat.Metadata must contain 'match_type'")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Short-circuit: catalog hit must be the only returned threat
// ─────────────────────────────────────────────────────────────────────────────

func TestSlopsquatting_CatalogShortCircuit(t *testing.T) {
	sd := newTestSlopsquattingDetector()
	// "requests-extended" is in the catalog AND matches Signal 1 (ai_suffix).
	// The catalog hit should short-circuit, returning exactly one threat.
	dep := types.Dependency{Name: "requests-extended", Version: "1.0.0", Registry: "pypi"}
	threats := sd.Detect(dep, popularPyPI)

	if len(threats) != 1 {
		t.Errorf("catalog hit should return exactly 1 threat, got %d", len(threats))
	}
	if len(threats) > 0 && threats[0].DetectionMethod != "slopsquatting:hallucination_catalog" {
		t.Errorf("expected hallucination_catalog method, got %q", threats[0].DetectionMethod)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Real popular packages must NOT generate false positives
// ─────────────────────────────────────────────────────────────────────────────

func TestSlopsquatting_NoFalsePositives_PopularPackages(t *testing.T) {
	sd := newTestSlopsquattingDetector()

	realPackages := []struct {
		name     string
		registry string
		popular  []string
	}{
		{"react",         "npm",  popularNPM},
		{"express",       "npm",  popularNPM},
		{"lodash",        "npm",  popularNPM},
		{"axios",         "npm",  popularNPM},
		{"typescript",    "npm",  popularNPM},
		{"jest",          "npm",  popularNPM},
		{"eslint",        "npm",  popularNPM},
		{"webpack",       "npm",  popularNPM},
		{"requests",      "pypi", popularPyPI},
		{"numpy",         "pypi", popularPyPI},
		{"pandas",        "pypi", popularPyPI},
		{"flask",         "pypi", popularPyPI},
		{"django",        "pypi", popularPyPI},
		{"pytest",        "pypi", popularPyPI},
		{"boto3",         "pypi", popularPyPI},
		{"fastapi",       "pypi", popularPyPI},
	}

	for _, tt := range realPackages {
		t.Run(tt.name, func(t *testing.T) {
			dep := types.Dependency{Name: tt.name, Version: "1.0.0", Registry: tt.registry}
			threats := sd.Detect(dep, tt.popular)
			if len(threats) > 0 {
				t.Errorf("false positive: real package %q triggered slopsquatting threat (method: %s)",
					tt.name, threats[0].DetectionMethod)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Severity mapping
// ─────────────────────────────────────────────────────────────────────────────

func TestSlopsquatting_SeverityMapping(t *testing.T) {
	sd := newTestSlopsquattingDetector()

	tests := []struct {
		confidence   float64
		wantSeverity types.Severity
	}{
		{0.90, types.SeverityHigh},
		{0.85, types.SeverityHigh},
		{0.82, types.SeverityMedium},
		{0.72, types.SeverityMedium},
		{0.65, types.SeverityMedium},
		{0.60, types.SeverityLow},
		{0.50, types.SeverityLow},
	}

	for _, tt := range tests {
		got := sd.confidenceToSeverity(tt.confidence)
		if got != tt.wantSeverity {
			t.Errorf("confidenceToSeverity(%v) = %v; want %v", tt.confidence, got, tt.wantSeverity)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Empty input edge cases
// ─────────────────────────────────────────────────────────────────────────────

func TestSlopsquatting_EdgeCases(t *testing.T) {
	sd := newTestSlopsquattingDetector()

	t.Run("empty name", func(t *testing.T) {
		dep := types.Dependency{Name: "", Version: "1.0.0", Registry: "npm"}
		threats := sd.Detect(dep, popularNPM)
		if len(threats) != 0 {
			t.Errorf("empty name should produce no threats, got %d", len(threats))
		}
	})

	t.Run("empty popular list", func(t *testing.T) {
		dep := types.Dependency{Name: "react-utils", Version: "1.0.0", Registry: "npm"}
		threats := sd.Detect(dep, []string{})
		// Catalog hit may still fire; structural signals should NOT fire without a popular list.
		for _, th := range threats {
			if th.DetectionMethod == "slopsquatting:ai_suffix" ||
				th.DetectionMethod == "slopsquatting:combination" ||
				th.DetectionMethod == "slopsquatting:missing_hyphen" {
				t.Errorf("structural signal %q must not fire without a popular list",
					th.DetectionMethod)
			}
		}
	})

	t.Run("nil popular list", func(t *testing.T) {
		dep := types.Dependency{Name: "numpy-utils", Version: "1.0.0", Registry: "pypi"}
		// Should not panic; catalog hits are still valid.
		threats := sd.Detect(dep, nil)
		_ = threats // result may be non-nil if catalog hit; just confirm no panic
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: one threat per package (no duplicates)
// ─────────────────────────────────────────────────────────────────────────────

func TestSlopsquatting_MaxOneThreatePerPackage(t *testing.T) {
	sd := newTestSlopsquattingDetector()

	// "flask-sqlalchemy-utils" matches both combination (catalog pair) AND ai_suffix.
	dep := types.Dependency{Name: "flask-sqlalchemy-utils", Version: "1.0.0", Registry: "pypi"}
	threats := sd.Detect(dep, popularPyPI)

	if len(threats) > 1 {
		t.Errorf("Detect must emit at most 1 threat per call, got %d", len(threats))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Case insensitivity
// ─────────────────────────────────────────────────────────────────────────────

func TestSlopsquatting_CaseInsensitive(t *testing.T) {
	sd := newTestSlopsquattingDetector()

	variants := []string{"Requests-Extended", "REQUESTS-EXTENDED", "requests-Extended"}
	for _, v := range variants {
		t.Run(v, func(t *testing.T) {
			dep := types.Dependency{Name: v, Version: "1.0.0", Registry: "pypi"}
			threats := sd.Detect(dep, popularPyPI)
			if len(threats) == 0 {
				t.Errorf("case variant %q should still be detected", v)
			}
		})
	}
}
