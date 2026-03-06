package ml

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newLoadedEngineT is a test helper that returns a fully-initialised
// InferenceEngine using the heuristic fallback (no ONNX file needed).
func newLoadedEngineT(t *testing.T) *InferenceEngine {
	t.Helper()
	ie := NewInferenceEngine()
	require.NoError(t, ie.LoadModel("/nonexistent/model.onnx"))
	return ie
}

// ─── NewInferenceEngine ───────────────────────────────────────────────────────

func TestNewInferenceEngine_NotNil(t *testing.T) {
	ie := NewInferenceEngine()
	require.NotNil(t, ie, "NewInferenceEngine must return a non-nil engine")
}

// ─── Predict — zero input ─────────────────────────────────────────────────────

func TestInferenceEngine_Predict_ZeroInput(t *testing.T) {
	ie := newLoadedEngineT(t)
	features := make([]float32, FeatureVectorSize)

	score, err := ie.Predict(features)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, score, 0.0, "score must be >= 0")
	assert.LessOrEqual(t, score, 1.0, "score must be <= 1")
}

// ─── Predict — high risk features ────────────────────────────────────────────

func TestInferenceEngine_Predict_HighRiskFeatures(t *testing.T) {
	ie := newLoadedEngineT(t)

	// Brand-new package: created 1 day ago, 1 maintainer, no downloads,
	// has install script, 2 malware reports.
	highRisk := InputData{
		DownloadCount:      10,
		MaintainerCount:    1,
		CreatedAt:          time.Now().Add(-24 * time.Hour),
		LastUpdated:        time.Now().Add(-1 * time.Hour),
		MalwareReportCount: 2,
		HasInstallScript:   true,
		InstallScriptSize:  50_000,
		PreviousVersionCount: 1,
	}
	features := ExtractFeatures(highRisk)
	score, err := ie.Predict(features)
	require.NoError(t, err)
	assert.Greater(t, score, 0.5,
		"high-risk profile must produce score > 0.5, got %.3f", score)
}

// ─── Predict — low risk features ─────────────────────────────────────────────

func TestInferenceEngine_Predict_LowRiskFeatures(t *testing.T) {
	ie := newLoadedEngineT(t)

	// Well-established package: 5 years old, many downloads, many maintainers,
	// verified, popular on GitHub.
	lowRisk := InputData{
		DownloadCount:      10_000_000,
		MaintainerCount:    15,
		CreatedAt:          time.Now().Add(-5 * 365 * 24 * time.Hour),
		LastUpdated:        time.Now().Add(-30 * 24 * time.Hour),
		VulnerabilityCount: 0,
		MalwareReportCount: 0,
		VerifiedFlagCount:  5,
		HasInstallScript:   false,
		PreviousVersionCount: 200,
		StarCount:          50_000,
		ForkCount:          10_000,
		NamespaceAgeDays:   1825,
	}
	features := ExtractFeatures(lowRisk)
	score, err := ie.Predict(features)
	require.NoError(t, err)
	assert.Less(t, score, 0.5,
		"low-risk profile must produce score < 0.5, got %.3f", score)
}

// ─── Predict — score always in [0, 1] ─────────────────────────────────────────

func TestInferenceEngine_Predict_ScoreRange(t *testing.T) {
	ie := newLoadedEngineT(t)

	cases := [][]float32{
		// All zeros
		make([]float32, FeatureVectorSize),
		// All maxed out (worst case)
		func() []float32 {
			f := make([]float32, FeatureVectorSize)
			for i := range f {
				f[i] = 1000.0
			}
			return f
		}(),
		// Mixed
		{0, 1, 7, 1, 3, 2, 0, 1, 30, 1, 1, 5, 0.5, 100, 2, 8, 4, 7.8, 20, 0.5, 0.5, 6, 3, 20, 0.8},
	}

	for i, features := range cases {
		score, err := ie.Predict(features)
		require.NoError(t, err, "case %d: unexpected error", i)
		assert.GreaterOrEqual(t, score, 0.0, "case %d: score must be >= 0", i)
		assert.LessOrEqual(t, score, 1.0, "case %d: score must be <= 1", i)
	}
}

// ─── Predict — determinism ────────────────────────────────────────────────────

func TestInferenceEngine_Predict_Consistency(t *testing.T) {
	ie := newLoadedEngineT(t)

	data := InputData{
		DownloadCount:      500_000,
		MaintainerCount:    3,
		CreatedAt:          time.Now().Add(-200 * 24 * time.Hour),
		LastUpdated:        time.Now().Add(-10 * 24 * time.Hour),
		VulnerabilityCount: 1,
		HasInstallScript:   true,
		InstallScriptSize:  2048,
		PreviousVersionCount: 12,
		StarCount:          300,
		ForkCount:          40,
	}
	features := ExtractFeatures(data)

	score1, err := ie.Predict(features)
	require.NoError(t, err)
	score2, err := ie.Predict(features)
	require.NoError(t, err)

	assert.Equal(t, score1, score2, "Predict must be deterministic for the same input")
}

// ─── PredictBatch — empty input ───────────────────────────────────────────────

func TestInferenceEngine_PredictBatch_EmptyInput(t *testing.T) {
	ie := newLoadedEngineT(t)

	scores, err := ie.PredictBatch([][]float32{})
	require.NoError(t, err)
	assert.Empty(t, scores, "empty batch must return empty result")
}

// ─── PredictBatch — multiple packages ────────────────────────────────────────

func TestInferenceEngine_PredictBatch_MultiplePackages(t *testing.T) {
	ie := newLoadedEngineT(t)

	batch := make([][]float32, 5)
	for i := range batch {
		batch[i] = make([]float32, FeatureVectorSize)
		// Vary features slightly so scores are not all identical.
		batch[i][0] = float32(i) * 2.0
		batch[i][1] = float32(i + 1)
	}

	scores, err := ie.PredictBatch(batch)
	require.NoError(t, err)
	require.Len(t, scores, 5, "must return one score per input")

	for i, s := range scores {
		assert.GreaterOrEqual(t, s, 0.0, "score[%d] must be >= 0", i)
		assert.LessOrEqual(t, s, 1.0, "score[%d] must be <= 1", i)
	}
}

// ─── ExtractFeatures — additional tests ──────────────────────────────────────

func TestExtractFeatures_BasicPackage(t *testing.T) {
	data := InputData{
		DownloadCount:   1000,
		MaintainerCount: 2,
	}
	features := ExtractFeatures(data)
	require.NotNil(t, features)
	assert.Len(t, features, FeatureVectorSize)
}

func TestExtractFeatures_FeatureCount(t *testing.T) {
	data := InputData{
		DownloadCount:        5_000_000,
		MaintainerCount:      10,
		CreatedAt:            time.Now().Add(-3 * 365 * 24 * time.Hour),
		LastUpdated:          time.Now().Add(-30 * 24 * time.Hour),
		HasInstallScript:     true,
		HasPreinstallScript:  true,
		HasPostinstallScript: true,
		MaintainerChangeCount: 5,
		MaintainerVelocity:   0.1,
		DomainAgeOfAuthorEmail: 500,
		ExecutableBinaryCount: 1,
		NetworkCodeFileCount:  3,
		TotalFileCount:       100,
		EntropyMaxFile:       5.5,
		DependencyDelta:      3,
		PreviousVersionCount: 50,
		DaysBetweenVersions:  30.0,
		StarCount:            2000,
		ForkCount:            400,
		NamespaceAgeDays:     730,
	}
	features := ExtractFeatures(data)
	assert.Len(t, features, FeatureVectorSize,
		"ExtractFeatures must always return exactly %d features", FeatureVectorSize)
}

// ─── NormalizeFeatures — additional tests ────────────────────────────────────

func TestNormalizeFeatures_ZeroVector(t *testing.T) {
	zeros := make([]float32, FeatureVectorSize)
	normalized := NormalizeFeatures(zeros)
	require.Len(t, normalized, FeatureVectorSize)

	for i, v := range normalized {
		assert.False(t, math.IsNaN(float64(v)), "normalized[%d] must not be NaN", i)
		assert.False(t, math.IsInf(float64(v), 0), "normalized[%d] must not be Inf", i)
	}
}

func TestNormalizeFeatures_ValidVector(t *testing.T) {
	data := InputData{
		DownloadCount:   100_000,
		MaintainerCount: 4,
		CreatedAt:       time.Now().Add(-365 * 24 * time.Hour),
		LastUpdated:     time.Now().Add(-14 * 24 * time.Hour),
		StarCount:       1500,
		ForkCount:       300,
	}
	features := ExtractFeatures(data)
	normalized := NormalizeFeatures(features)
	require.Len(t, normalized, FeatureVectorSize)

	for i, v := range normalized {
		assert.False(t, math.IsNaN(float64(v)), "normalized[%d] must not be NaN", i)
		assert.False(t, math.IsInf(float64(v), 0), "normalized[%d] must not be Inf", i)
		// z-score is clamped to [-3, 3] by NormalizeFeatures.
		assert.GreaterOrEqual(t, float64(v), -3.0, "normalized[%d] must be >= -3", i)
		assert.LessOrEqual(t, float64(v), 3.0, "normalized[%d] must be <= 3", i)
	}
}

// ─── FeedbackStore tests ──────────────────────────────────────────────────────

func newTestFeedbackStore(t *testing.T) *FeedbackStore {
	t.Helper()
	dir := t.TempDir()
	store, err := NewFeedbackStore(filepath.Join(dir, "feedback.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func makeFeedback(pkg string, ft FeedbackType, score float64) FeedbackRecord {
	features := make([]float32, FeatureVectorSize)
	features[0] = 5.0
	features[1] = 2.0
	return FeedbackRecord{
		PackageName: pkg,
		Registry:    "npm",
		Version:     "1.0.0",
		Type:        ft,
		ModelScore:  score,
		Features:    features,
		Comment:     "test comment",
	}
}

func TestFeedbackStore_New_NotNil(t *testing.T) {
	store := newTestFeedbackStore(t)
	require.NotNil(t, store)
}

func TestFeedbackStore_Record_ReturnsID(t *testing.T) {
	store := newTestFeedbackStore(t)

	id, err := store.Record(makeFeedback("lodash", FeedbackFalsePositive, 0.85))
	require.NoError(t, err)
	assert.Greater(t, id, int64(0), "inserted ID must be > 0")
}

func TestFeedbackStore_Stats_EmptyStore(t *testing.T) {
	store := newTestFeedbackStore(t)

	stats, err := store.Stats()
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.TotalRecords)
	assert.Equal(t, int64(0), stats.FalsePositives)
	assert.Equal(t, int64(0), stats.FalseNegatives)
	assert.Equal(t, int64(0), stats.Confirmed)
	assert.False(t, stats.NeedsRetrain)
}

func TestFeedbackStore_Stats_CountsCorrect(t *testing.T) {
	store := newTestFeedbackStore(t)

	feedbackCases := []FeedbackRecord{
		makeFeedback("pkg-a", FeedbackFalsePositive, 0.9),
		makeFeedback("pkg-b", FeedbackFalsePositive, 0.8),
		makeFeedback("pkg-c", FeedbackFalseNegative, 0.2),
		makeFeedback("pkg-d", FeedbackConfirmed, 0.95),
	}
	for _, f := range feedbackCases {
		_, err := store.Record(f)
		require.NoError(t, err)
	}

	stats, err := store.Stats()
	require.NoError(t, err)
	assert.Equal(t, int64(4), stats.TotalRecords)
	assert.Equal(t, int64(2), stats.FalsePositives)
	assert.Equal(t, int64(1), stats.FalseNegatives)
	assert.Equal(t, int64(1), stats.Confirmed)
}

func TestFeedbackStore_NeedsRetrain_Threshold(t *testing.T) {
	store := newTestFeedbackStore(t)

	// Insert 50 false-positives: total FP+FN = 50 → NeedsRetrain must flip.
	for i := 0; i < 50; i++ {
		_, err := store.Record(makeFeedback(
			fmt.Sprintf("pkg-%d", i), FeedbackFalsePositive, 0.9))
		require.NoError(t, err)
	}

	stats, err := store.Stats()
	require.NoError(t, err)
	assert.True(t, stats.NeedsRetrain,
		"NeedsRetrain should be true when FP+FN >= 50")
}

func TestFeedbackStore_ExportTrainingCSV(t *testing.T) {
	store := newTestFeedbackStore(t)
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "training.csv")

	// Insert 3 records.
	for i := 0; i < 3; i++ {
		_, err := store.Record(makeFeedback(
			fmt.Sprintf("pkg-%d", i), FeedbackConfirmed, 0.75))
		require.NoError(t, err)
	}

	count, err := store.ExportTrainingCSV(csvPath)
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

// ─── ModelRegistry ────────────────────────────────────────────────────────────

func TestModelRegistry_NewRegistry_Empty(t *testing.T) {
	dir := t.TempDir()
	mr := NewModelRegistry(filepath.Join(dir, "registry.json"))
	require.NotNil(t, mr)
	assert.Empty(t, mr.Versions(), "new registry must start empty")
}

func TestModelRegistry_Register_And_Versions(t *testing.T) {
	dir := t.TempDir()
	mr := NewModelRegistry(filepath.Join(dir, "registry.json"))

	v := ModelVersion{
		Version: "v1.0",
		Path:    "/models/v1.onnx",
	}
	require.NoError(t, mr.Register(v))

	versions := mr.Versions()
	require.Len(t, versions, 1)
	assert.Equal(t, "v1.0", versions[0].Version)
}

func TestModelRegistry_Promote_NotFound(t *testing.T) {
	dir := t.TempDir()
	mr := NewModelRegistry(filepath.Join(dir, "registry.json"))

	err := mr.Promote("nonexistent-version")
	require.Error(t, err, "Promote on unknown version must return an error")
}

func TestModelRegistry_Promote_SetsActive(t *testing.T) {
	dir := t.TempDir()
	mr := NewModelRegistry(filepath.Join(dir, "registry.json"))

	require.NoError(t, mr.Register(ModelVersion{Version: "v1.0", Path: "/a"}))
	require.NoError(t, mr.Register(ModelVersion{Version: "v2.0", Path: "/b"}))
	require.NoError(t, mr.Promote("v2.0"))

	path, ok := mr.ActiveModel()
	require.True(t, ok)
	assert.Equal(t, "/b", path)
}

func TestModelRegistry_ActiveModel_EmptyRegistry(t *testing.T) {
	dir := t.TempDir()
	mr := NewModelRegistry(filepath.Join(dir, "registry.json"))

	_, ok := mr.ActiveModel()
	assert.False(t, ok, "empty registry must report no active model")
}

// ─── Real tree ensemble (requires tree_params.json) ──────────────────────────

// TestLoadTreeParams_RealFile verifies that the exported tree_params.json loads
// cleanly and that the resulting TreeParams produces valid probabilities.
// The test is skipped if the file is absent (e.g. in CI without the model).
func TestLoadTreeParams_RealFile(t *testing.T) {
	modelDir := filepath.Join("..", "..", "resources", "models")
	tp, err := LoadTreeParams(modelDir)
	if tp == nil && err == nil {
		t.Skip("tree_params.json not found; skipping real-model test")
	}
	require.NoError(t, err, "LoadTreeParams must not return an error")
	require.NotNil(t, tp, "TreeParams must be non-nil when file exists")

	// Run a benign-looking feature vector through the ensemble.
	benign := make([]float32, FeatureVectorSize)
	benign[0] = 16.0 // log(~9M downloads)
	benign[1] = 10.0 // 10 maintainers
	benign[2] = 1825 // 5 years old
	benign[3] = 30   // last updated 30 days ago
	benign[21] = 10  // log stars
	benign[22] = 7   // log forks

	score := tp.Predict(benign)
	assert.GreaterOrEqual(t, score, 0.0, "score must be >= 0")
	assert.LessOrEqual(t, score, 1.0, "score must be <= 1")

	// Run a suspicious vector.
	suspicious := make([]float32, FeatureVectorSize)
	suspicious[5] = 3   // malware reports
	suspicious[7] = 1   // install script
	suspicious[14] = 2  // embedded binaries

	score2 := tp.Predict(suspicious)
	assert.GreaterOrEqual(t, score2, 0.0, "score must be >= 0")
	assert.LessOrEqual(t, score2, 1.0, "score must be <= 1")
}

// TestInferenceEngine_RealModel verifies end-to-end: LoadModel picks up both
// the ONNX file and tree_params.json, setting UsingHeuristic=false.
func TestInferenceEngine_RealModel(t *testing.T) {
	onnxPath := filepath.Join("..", "..", "resources", "models", "reputation_model.onnx")
	if _, err := os.Stat(onnxPath); os.IsNotExist(err) {
		t.Skip("reputation_model.onnx not found; skipping real-model test")
	}

	ie := NewInferenceEngine()
	require.NoError(t, ie.LoadModel(onnxPath))

	info := ie.Info()
	assert.False(t, info.UsingHeuristic,
		"UsingHeuristic must be false when tree_params.json is loaded alongside the ONNX")
	assert.False(t, ie.IsUsingHeuristic(),
		"IsUsingHeuristic() must return false with real tree params loaded")

	// Predict with a representative feature vector.
	features := make([]float32, FeatureVectorSize)
	features[0] = 12.0 // moderate downloads
	features[1] = 3    // 3 maintainers
	features[2] = 400  // ~1 year old

	score, err := ie.Predict(features)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, score, 0.0)
	assert.LessOrEqual(t, score, 1.0)
	t.Logf("Real ensemble score for moderate-risk profile: %.4f", score)
}
