package analyzer

import (
	"github.com/falcn-io/falcn/internal/config"
	"github.com/falcn-io/falcn/internal/detector"
	"github.com/falcn-io/falcn/internal/registry"
)

// NewStub creates a minimal Analyzer wired to a real detector engine, suitable
// for use in unit tests and lightweight integrations. It does NOT generate fake
// stub threats — all detection is performed by the real detector engine.
func NewStub() *Analyzer {
	cfg := &config.Config{
		TypoDetection: &config.TypoDetectionConfig{Enabled: true, Threshold: 0.8, MaxDistance: 2, CheckSimilarNames: true, CheckHomoglyphs: true},
		Scanner:       &config.ScannerConfig{MaxConcurrency: 4, IncludeDevDeps: true},
	}
	return &Analyzer{
		config:     cfg,
		detector:   detector.New(cfg),
		registries: make(map[string]registry.Connector),
		// stubRepo intentionally omitted — leave nil so no synthetic threats are injected.
	}
}
