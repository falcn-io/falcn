package benchmark

import (
	"path/filepath"
	"testing"

	"github.com/falcn-io/falcn/internal/analyzer"
	"github.com/falcn-io/falcn/internal/config"
)

func BenchmarkScan(b *testing.B) {
	// Setup - use a known test project
	// Ideally this should be a project with some dependencies but not too huge to be slow
	// We'll use the npm-vulnerable test project if available, or current dir
	projectPath, _ := filepath.Abs("../../tests/e2e/test-projects/npm-vulnerable")

	cfg := &config.Config{
		App: config.AppConfig{
			Name:     "Falcn-Benchmark",
			LogLevel: "error", // Reduce log noise
		},
		Logging: config.LoggingConfig{
			Level:  "error",
			Output: "stdout",
		},
		// Disable other external calls for stability if needed
	}

	// Create analyzer
	analyzerInstance, err := analyzer.New(cfg)
	if err != nil {
		b.Fatalf("Failed to create analyzer: %v", err)
	}

	b.Run("FastMode", func(b *testing.B) {
		options := &analyzer.ScanOptions{
			DisableLLM:     true,
			DisableSandbox: true,
			DeepAnalysis:   false,
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := analyzerInstance.Scan(projectPath, options)
			if err != nil {
				b.Fatalf("Scan failed: %v", err)
			}
		}
	})

	b.Run("FullMode", func(b *testing.B) {
		// Note: Full mode with LLM/Sandbox might be very slow or fail without API keys/Docker
		// benchmarking it might be tricky in CI. Using mild settings.
		options := &analyzer.ScanOptions{
			DisableLLM:     false,
			DisableSandbox: false, // This might timeout if docker is not ready or slow
			DeepAnalysis:   true,
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := analyzerInstance.Scan(projectPath, options)
			if err != nil {
				// Don't fail benchmark on runtime errors (e.g. no docker), just log
				b.Logf("Scan failed (expected if dependencies missing): %v", err)
			}
		}
	})
}
