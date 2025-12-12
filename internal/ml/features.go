package ml

import (
	"math"
	"time"
)

// FeatureVectorSize is the number of features used by the model
const FeatureVectorSize = 7

// InputData represents the raw data required for ML feature extraction
type InputData struct {
	DownloadCount      int64
	MaintainerCount    int
	CreatedAt          time.Time
	LastUpdated        time.Time
	VulnerabilityCount int
	MalwareReportCount int
	VerifiedFlagCount  int
}

// ExtractFeatures converts InputData into a feature vector for the ML model
// Features:
// 0: Log(DownloadCount + 1)
// 1: MaintainerCount
// 2: AgeInDays
// 3: DaysSinceLastUpdate
// 4: VulnerabilityCount
// 5: MalwareCount
// 6: VerifiedFlagCount
func ExtractFeatures(data InputData) []float32 {
	features := make([]float32, FeatureVectorSize)

	// 0: Log(DownloadCount + 1)
	features[0] = float32(math.Log1p(float64(data.DownloadCount)))

	// 1: MaintainerCount
	features[1] = float32(data.MaintainerCount)

	// 2: AgeInDays
	age := time.Since(data.CreatedAt)
	features[2] = float32(age.Hours() / 24.0)

	// 3: DaysSinceLastUpdate
	sinceUpdate := time.Since(data.LastUpdated)
	features[3] = float32(sinceUpdate.Hours() / 24.0)

	// 4: VulnerabilityCount
	features[4] = float32(data.VulnerabilityCount)

	// 5: MalwareCount
	features[5] = float32(data.MalwareReportCount)

	// 6: VerifiedFlagCount
	features[6] = float32(data.VerifiedFlagCount)

	return features
}
