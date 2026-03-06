package ml

import (
	"math"
	"testing"
	"time"
)

// ─── ExtractFeatures ──────────────────────────────────────────────────────────

func TestExtractFeatures_VectorLength(t *testing.T) {
	data := InputData{
		DownloadCount:   10000,
		MaintainerCount: 3,
		CreatedAt:       time.Now().Add(-365 * 24 * time.Hour),
		LastUpdated:     time.Now().Add(-30 * 24 * time.Hour),
	}
	features := ExtractFeatures(data)
	if len(features) != FeatureVectorSize {
		t.Fatalf("expected %d features, got %d", FeatureVectorSize, len(features))
	}
}

func TestExtractFeatures_ZeroInput(t *testing.T) {
	data := InputData{}
	features := ExtractFeatures(data)
	if len(features) != FeatureVectorSize {
		t.Fatalf("expected %d features, got %d", FeatureVectorSize, len(features))
	}
	// All values should be finite (not NaN or Inf).
	for i, f := range features {
		if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
			t.Fatalf("feature[%d] is not finite: %v", i, f)
		}
	}
}

func TestExtractFeatures_DownloadCountLog(t *testing.T) {
	data := InputData{DownloadCount: 1000}
	features := ExtractFeatures(data)
	// feature[0] = Log1p(1000) ≈ 6.908
	expected := float32(math.Log1p(1000))
	if math.Abs(float64(features[0]-expected)) > 0.001 {
		t.Fatalf("feature[0] expected ~%f, got %f", expected, features[0])
	}
}

func TestExtractFeatures_InstallScriptFlag(t *testing.T) {
	dataWith := InputData{HasInstallScript: true}
	dataWithout := InputData{HasInstallScript: false}

	with := ExtractFeatures(dataWith)
	without := ExtractFeatures(dataWithout)

	if with[7] != 1.0 {
		t.Fatalf("expected feature[7]=1.0 when HasInstallScript=true, got %f", with[7])
	}
	if without[7] != 0.0 {
		t.Fatalf("expected feature[7]=0.0 when HasInstallScript=false, got %f", without[7])
	}
}

func TestExtractFeatures_MalwareReportCount(t *testing.T) {
	data := InputData{MalwareReportCount: 5}
	features := ExtractFeatures(data)
	if features[5] != 5.0 {
		t.Fatalf("expected feature[5]=5.0, got %f", features[5])
	}
}

// ─── NormalizeFeatures ────────────────────────────────────────────────────────

func TestNormalizeFeatures_SameLength(t *testing.T) {
	data := InputData{DownloadCount: 5000, MaintainerCount: 2}
	features := ExtractFeatures(data)
	normalized := NormalizeFeatures(features)
	if len(normalized) != len(features) {
		t.Fatalf("NormalizeFeatures changed length: %d → %d", len(features), len(normalized))
	}
}

func TestNormalizeFeatures_FiniteValues(t *testing.T) {
	data := InputData{DownloadCount: 0, VulnerabilityCount: 100}
	features := ExtractFeatures(data)
	normalized := NormalizeFeatures(features)
	for i, f := range normalized {
		if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
			t.Fatalf("normalized feature[%d] is not finite: %v", i, f)
		}
	}
}

// ─── InferenceEngine ─────────────────────────────────────────────────────────

func newLoadedEngine(t *testing.T) *InferenceEngine {
	t.Helper()
	ie := NewInferenceEngine()
	// LoadModel with a nonexistent path → graceful fallback to heuristics.
	if err := ie.LoadModel("/nonexistent/model.onnx"); err != nil {
		t.Fatalf("LoadModel returned unexpected error: %v", err)
	}
	return ie
}

func TestInferenceEngine_LoadModelFallback(t *testing.T) {
	ie := newLoadedEngine(t)
	if !ie.loaded {
		t.Fatal("engine should report loaded=true after fallback")
	}
}

func TestInferenceEngine_PredictRequiresLoad(t *testing.T) {
	ie := NewInferenceEngine() // not loaded yet
	features := make([]float32, FeatureVectorSize)
	_, err := ie.Predict(features)
	if err == nil {
		t.Fatal("expected error when Predict called before LoadModel")
	}
}

func TestInferenceEngine_PredictFeatureLengthCheck(t *testing.T) {
	ie := newLoadedEngine(t)
	shortFeatures := make([]float32, 5)
	_, err := ie.Predict(shortFeatures)
	if err == nil {
		t.Fatal("expected error for short feature vector")
	}
}

func TestInferenceEngine_PredictRangeClean(t *testing.T) {
	ie := newLoadedEngine(t)
	// Clean package profile: many downloads, many maintainers, old, no malware.
	data := InputData{
		DownloadCount:   5_000_000,
		MaintainerCount: 10,
		CreatedAt:       time.Now().Add(-3 * 365 * 24 * time.Hour),
		LastUpdated:     time.Now().Add(-30 * 24 * time.Hour),
		VerifiedFlagCount: 5,
		StarCount:       50000,
		ForkCount:       10000,
	}
	features := ExtractFeatures(data)
	score, err := ie.Predict(features)
	if err != nil {
		t.Fatalf("Predict error: %v", err)
	}
	if score < 0 || score > 1 {
		t.Fatalf("score out of range [0,1]: %f", score)
	}
	if score > 0.5 {
		t.Fatalf("expected low risk for popular, old, verified package; got score=%.3f", score)
	}
}

func TestInferenceEngine_PredictRangeSuspicious(t *testing.T) {
	ie := newLoadedEngine(t)
	// Suspicious profile: 0 downloads, 1 maintainer, brand new, has malware reports.
	data := InputData{
		DownloadCount:      0,
		MaintainerCount:    1,
		CreatedAt:          time.Now().Add(-24 * time.Hour),
		LastUpdated:        time.Now().Add(-1 * time.Hour),
		MalwareReportCount: 2,
		HasInstallScript:   true,
		InstallScriptSize:  50000,
	}
	features := ExtractFeatures(data)
	score, err := ie.Predict(features)
	if err != nil {
		t.Fatalf("Predict error: %v", err)
	}
	if score < 0 || score > 1 {
		t.Fatalf("score out of range [0,1]: %f", score)
	}
	if score < 0.5 {
		t.Fatalf("expected high risk for new package with malware reports; got score=%.3f", score)
	}
}

func TestInferenceEngine_PredictBatch(t *testing.T) {
	ie := newLoadedEngine(t)

	batch := [][]float32{
		make([]float32, FeatureVectorSize),
		make([]float32, FeatureVectorSize),
		make([]float32, FeatureVectorSize),
	}

	scores, err := ie.PredictBatch(batch)
	if err != nil {
		t.Fatalf("PredictBatch error: %v", err)
	}
	if len(scores) != len(batch) {
		t.Fatalf("expected %d scores, got %d", len(batch), len(scores))
	}
	for i, s := range scores {
		if s < 0 || s > 1 {
			t.Fatalf("score[%d] out of range [0,1]: %f", i, s)
		}
	}
}
