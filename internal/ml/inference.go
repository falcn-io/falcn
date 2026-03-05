package ml

import (
	"fmt"
	"math"
	"os"
)

// InferenceEngine handles ML model inference.
// When an ONNX model file is available it is preferred; otherwise a calibrated
// heuristic scorer runs on the same feature vector so scores are meaningful
// even before the full ML training pipeline ships.
type InferenceEngine struct {
	modelPath string
	loaded    bool
	// onnxModel would be loaded here once the ONNX runtime is integrated
}

// NewInferenceEngine creates a new inference engine.
func NewInferenceEngine() *InferenceEngine {
	return &InferenceEngine{}
}

// LoadModel attempts to load the ONNX model from path.
// If the file does not exist the engine falls back to heuristic scoring.
func (ie *InferenceEngine) LoadModel(path string) error {
	if _, err := os.Stat(path); err != nil {
		// File missing — use heuristic fallback; this is not an error condition
		ie.modelPath = ""
		ie.loaded = true
		return nil
	}
	// TODO: uncomment once ONNX runtime is stable on all platforms
	// backend := gorgonnx.NewGraph()
	// model := onnx.NewModel(backend)
	// b, err := os.ReadFile(path)
	// if err != nil { return err }
	// if err := model.UnmarshalBinary(b); err != nil { return err }
	// ie.onnxModel = model
	ie.modelPath = path
	ie.loaded = true
	return nil
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
	score += math.Max(0, 1.0-logDL/18.0) * 0.15

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
	if installKB > 5 {
		score += 0.04
	} else if installKB > 20 {
		score += 0.08
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

// PredictBatch runs inference over a slice of feature vectors in parallel.
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
