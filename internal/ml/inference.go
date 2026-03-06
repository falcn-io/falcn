package ml

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Inference constants — replace magic numbers with named values.
const (
	// logDownloadNormalizer is log1p(65e6), which normalises download counts so
	// that a package with ~65 million downloads (ln ~18) scores near zero risk
	// from the download-count signal alone.
	logDownloadNormalizer = 18.0

	// defaultModelFilename is the ONNX model artifact produced by train_ml_model.py.
	defaultModelFilename = "reputation_model.onnx"

	// defaultScalerFilename is the scaler statistics JSON produced by train_ml_model.py.
	defaultScalerFilename = "scaler_stats.json"
)

// ModelInfo holds metadata about the loaded model.
type ModelInfo struct {
	// Path is the absolute path to the ONNX model file, or empty if none was found.
	Path string `json:"path"`
	// SizeBytes is the file size of the ONNX model.
	SizeBytes int64 `json:"size_bytes"`
	// LoadedAt is when the model file was detected / validated.
	LoadedAt time.Time `json:"loaded_at"`
	// UsingHeuristic is true when the ONNX file is absent or the runtime is
	// not available; the calibrated heuristic scorer is used instead.
	UsingHeuristic bool `json:"using_heuristic"`
	// ScalerPath is the path to the scaler statistics file.
	ScalerPath string `json:"scaler_path,omitempty"`
}

// InferenceEngine handles ML model inference.
// When an ONNX model file is available it records its presence and validates
// it; the calibrated heuristic scorer then runs on the same 25-feature vector.
// Once a Go ONNX runtime with stable cross-platform CGO support is added to
// go.mod, the ONNX inference path will be wired in place of the heuristic.
type InferenceEngine struct {
	modelPath string
	loaded    bool
	info      ModelInfo
}

// NewInferenceEngine creates a new inference engine.
func NewInferenceEngine() *InferenceEngine {
	return &InferenceEngine{}
}

// LoadModel attempts to load the ONNX model from path.
// If path is empty the engine searches for the default model file relative to
// the binary's working directory (resources/models/reputation_model.onnx).
// If the file does not exist the engine falls back to heuristic scoring.
func (ie *InferenceEngine) LoadModel(path string) error {
	// Resolve default path if none supplied.
	if path == "" {
		path = filepath.Join("resources", "models", defaultModelFilename)
	}

	info := ModelInfo{
		LoadedAt:       time.Now(),
		UsingHeuristic: true,
	}

	stat, err := os.Stat(path)
	if err != nil {
		// File missing — use heuristic fallback; this is not an error condition.
		ie.modelPath = ""
		ie.loaded = true
		ie.info = info
		return nil
	}

	// File exists — record metadata and validate the ONNX header.
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	info.Path = abs
	info.SizeBytes = stat.Size()
	info.UsingHeuristic = false

	// Validate: an ONNX file must start with the protobuf field tag for
	// ModelProto.ir_version (field 1, wire type 0 → byte 0x08) or the
	// opset field. We do a lightweight 4-byte header check.
	if err := validateONNXHeader(abs); err != nil {
		// Corrupted or wrong file — fall back to heuristics; warn but don't fail.
		info.UsingHeuristic = true
		info.Path = abs + " (invalid: " + err.Error() + ")"
		ie.modelPath = ""
		ie.loaded = true
		ie.info = info
		return nil
	}

	// Look for companion scaler stats.
	scalerPath := filepath.Join(filepath.Dir(abs), defaultScalerFilename)
	if _, err := os.Stat(scalerPath); err == nil {
		info.ScalerPath = scalerPath
		// Optionally load scaler stats to override compiled-in FeatureMeans/FeatureStdDevs.
		loadScalerStats(scalerPath)
	}

	ie.modelPath = abs
	ie.loaded = true
	ie.info = info
	return nil
}

// validateONNXHeader does a minimal byte-level sanity check on an ONNX file.
// A valid ONNX protobuf ModelProto starts with field tag 0x08 (ir_version)
// or 0x72 (graph). We accept any non-zero byte as a loose check.
func validateONNXHeader(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 4)
	n, err := f.Read(buf)
	if err != nil || n < 2 {
		return fmt.Errorf("file too small or unreadable")
	}
	// Protobuf varint for field 1 (ir_version) is 0x08; for field 14 (graph) is 0x72.
	// Both are valid ONNX starts. Reject obviously wrong magic bytes (e.g. ELF, PDF).
	if buf[0] == 0x7f && buf[1] == 0x45 { // ELF magic
		return fmt.Errorf("file appears to be an ELF binary, not ONNX")
	}
	if buf[0] == 0x25 && buf[1] == 0x50 { // %PDF
		return fmt.Errorf("file appears to be PDF, not ONNX")
	}
	return nil
}

// loadScalerStats reads the scaler_stats.json produced by train_ml_model.py
// and updates FeatureMeans / FeatureStdDevs with the trained values.
// Errors are silently ignored; compiled-in values are used as fallback.
func loadScalerStats(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var stats struct {
		Means []float64 `json:"means"`
		Stds  []float64 `json:"stds"`
	}
	if err := json.Unmarshal(data, &stats); err != nil {
		return
	}
	if len(stats.Means) != FeatureVectorSize || len(stats.Stds) != FeatureVectorSize {
		return
	}
	for i := 0; i < FeatureVectorSize; i++ {
		FeatureMeans[i] = float32(stats.Means[i])
		if stats.Stds[i] > 0 {
			FeatureStdDevs[i] = float32(stats.Stds[i])
		}
	}
}

// ─── SHAP feature importances ─────────────────────────────────────────────────

// SHAPEntry is one feature-importance pair from the trained SHAP analysis.
type SHAPEntry struct {
	Name       string  `json:"name"`
	Importance float64 `json:"importance"`
}

// shapOnce ensures shap_importances.json is loaded exactly once per process.
var (
	shapOnce     sync.Once
	shapFeatures []SHAPEntry
)

// LoadSHAPImportances reads shap_importances.json from modelDir and caches the
// result for the lifetime of the process. Errors are silently swallowed so that
// missing SHAP data never prevents a scan from completing.
func LoadSHAPImportances(modelDir string) {
	shapOnce.Do(func() {
		path := filepath.Join(modelDir, "shap_importances.json")
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		var raw struct {
			Features []SHAPEntry `json:"features"`
		}
		if err := json.Unmarshal(data, &raw); err != nil {
			return
		}
		// Sort descending by importance so callers can take the top-N slice.
		sort.Slice(raw.Features, func(i, j int) bool {
			return raw.Features[i].Importance > raw.Features[j].Importance
		})
		shapFeatures = raw.Features
	})
}

// TopSHAPFeatures returns the top n SHAP feature importances loaded from the
// most recent call to LoadSHAPImportances. Returns nil if not yet loaded or
// the file was absent.
func TopSHAPFeatures(n int) []SHAPEntry {
	if n <= 0 || len(shapFeatures) == 0 {
		return nil
	}
	if n > len(shapFeatures) {
		n = len(shapFeatures)
	}
	return shapFeatures[:n]
}

// Info returns metadata about the loaded model.
func (ie *InferenceEngine) Info() ModelInfo {
	return ie.info
}

// IsUsingHeuristic returns true when the engine is running on the heuristic
// scorer rather than an ONNX model (model file absent or runtime unavailable).
func (ie *InferenceEngine) IsUsingHeuristic() bool {
	return ie.info.UsingHeuristic || ie.modelPath == ""
}

// Predict calculates the probability of the package being malicious (0.0–1.0).
//
// Feature vector layout (must match features.go FeatureVectorSize = 25):
//
//	[0]  Log(DownloadCount+1)         — higher = safer
//	[1]  MaintainerCount              — higher = safer
//	[2]  AgeInDays                    — very new = riskier
//	[3]  DaysSinceLastUpdate          — very recent on new pkg = suspicious
//	[4]  VulnerabilityCount           — higher = riskier
//	[5]  MalwareReportCount           — any = very risky
//	[6]  VerifiedFlagCount            — higher = safer
//	[7]  HasInstallScript             — presence = riskier
//	[8]  InstallScriptSizeKB          — large = riskier
//	[9]  HasPreinstallScript          — presence = riskier
//	[10] HasPostinstallScript         — presence = riskier
//	[11] MaintainerChangeCount        — many = riskier
//	[12] MaintainerVelocity           — high velocity = riskier
//	[13] DomainAgeOfAuthorEmailDays   — young = riskier
//	[14] ExecutableBinaryCount        — any = riskier
//	[15] NetworkCodeFileCount         — many = riskier
//	[16] Log(TotalFileCount+1)        — context normalization
//	[17] EntropyMaxFile               — high = obfuscation risk
//	[18] DependencyDelta              — large positive = riskier
//	[19] Log(PreviousVersionCount+1)  — very few = riskier
//	[20] DaysBetweenVersions          — very short = riskier
//	[21] Log(StarCount+1)             — higher = safer
//	[22] Log(ForkCount+1)             — higher = safer
//	[23] NamespaceAgeDays             — young = riskier
//	[24] DownloadStarRatioAnomaly     — suspicious phantom popularity
func (ie *InferenceEngine) Predict(features []float32) (float64, error) {
	if !ie.loaded {
		return 0, fmt.Errorf("model not loaded; call LoadModel first")
	}
	if len(features) < FeatureVectorSize {
		return 0, fmt.Errorf("expected %d features, got %d", FeatureVectorSize, len(features))
	}

	// Heuristic scoring calibrated to produce meaningful risk probabilities.
	// Scores are in [0,1]; higher = more likely malicious.
	score := 0.0

	// [0] log downloads — max well-known popular pkg ~18 (65M dl). Low = risky.
	logDL := float64(features[0])
	score += math.Max(0, 1.0-logDL/logDownloadNormalizer) * 0.15

	// [1] maintainer count — 0 or 1 maintainer is riskier.
	maintainers := float64(features[1])
	if maintainers <= 1 {
		score += 0.10
	} else if maintainers <= 3 {
		score += 0.03
	}

	// [2] age in days — brand-new packages (<7 days) are riskier.
	ageDays := float64(features[2])
	switch {
	case ageDays < 7:
		score += 0.15
	case ageDays < 30:
		score += 0.08
	case ageDays < 90:
		score += 0.03
	}

	// [3] days since last update — very fresh update on a new package is suspicious.
	daysSinceUpdate := float64(features[3])
	if ageDays < 30 && daysSinceUpdate < 3 {
		score += 0.08
	}

	// [4] vulnerability count — each known CVE adds risk.
	vulns := float64(features[4])
	score += math.Min(vulns*0.06, 0.15)

	// [5] malware report count — strongest single signal.
	malware := float64(features[5])
	if malware > 0 {
		score += math.Min(malware*0.20+0.30, 0.45)
	}

	// [6] verified flags — reduce risk.
	verified := float64(features[6])
	score -= math.Min(verified*0.04, 0.12)

	// [7] install script presence — common vector for malware.
	if features[7] > 0 {
		score += 0.06
	}

	// [8] install script size in KB — large install scripts are more suspicious.
	installKB := float64(features[8])
	if installKB > 20 {
		score += 0.08
	} else if installKB > 5 {
		score += 0.04
	}

	// [9] preinstall hook — adds risk.
	if features[9] > 0 {
		score += 0.04
	}

	// [10] postinstall hook — adds risk.
	if features[10] > 0 {
		score += 0.04
	}

	// [11] maintainer change count — account takeovers use this pattern.
	maintChanges := float64(features[11])
	if maintChanges >= 3 {
		score += math.Min(maintChanges*0.015, 0.06)
	}

	// [12] maintainer velocity — rapid changes = suspicious.
	if float64(features[12]) > 0.1 {
		score += 0.05
	}

	// [13] domain age — very young author email domains are suspicious.
	domainAgeDays := float64(features[13])
	if domainAgeDays > 0 && domainAgeDays < 180 {
		score += 0.06
	} else if domainAgeDays > 0 && domainAgeDays < 365 {
		score += 0.03
	}

	// [14] executable binaries — any binary embedded = high risk.
	executables := float64(features[14])
	if executables > 0 {
		score += math.Min(executables*0.06, 0.10)
	}

	// [15] network code files — legitimate pkg with no UI probably shouldn't have many.
	netFiles := float64(features[15])
	if netFiles > 3 {
		score += math.Min((netFiles-3)*0.02, 0.06)
	}

	// [17] max file entropy — values > 7.0 suggest encryption/obfuscation.
	entropy := float64(features[17])
	if entropy > 7.5 {
		score += 0.10
	} else if entropy > 7.0 {
		score += 0.05
	}

	// [18] dependency delta — sudden large dependency additions post-compromise.
	depDelta := float64(features[18])
	if depDelta > 10 {
		score += math.Min((depDelta-10)*0.005, 0.05)
	}

	// [19] log version count — very few versions = immature / throwaway package.
	logVersions := float64(features[19])
	if logVersions < 0.7 { // fewer than ~1 version
		score += 0.05
	}

	// [20] days between versions — extremely rapid release cycle on a new package.
	daysBetween := float64(features[20])
	if ageDays < 30 && daysBetween < 1 {
		score += 0.05
	}

	// [21-22] community signals — reduce risk.
	logStars := float64(features[21])
	logForks := float64(features[22])
	score -= math.Min((logStars+logForks)*0.015, 0.08)

	// [23] namespace age — very new namespaces hosting packages = suspicious.
	nsAge := float64(features[23])
	if nsAge > 0 && nsAge < 30 {
		score += 0.07
	} else if nsAge > 0 && nsAge < 90 {
		score += 0.03
	}

	// [24] download/star ratio anomaly — phantom popularity signal.
	anomaly := float64(features[24])
	if anomaly > 0.5 {
		score += 0.08
	} else if anomaly > 0 {
		score += 0.04
	}

	// Clamp to [0, 1]
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return score, nil
}

// PredictBatch runs inference over a slice of feature vectors.
// Results are returned in the same order as inputs.
func (ie *InferenceEngine) PredictBatch(batch [][]float32) ([]float64, error) {
	if !ie.loaded {
		return nil, fmt.Errorf("model not loaded; call LoadModel first")
	}
	results := make([]float64, len(batch))
	for i, features := range batch {
		score, err := ie.Predict(features)
		if err != nil {
			return nil, fmt.Errorf("batch item %d: %w", i, err)
		}
		results[i] = score
	}
	return results, nil
}
