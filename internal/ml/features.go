package ml

import (
	"math"
	"time"
)

// FeatureVectorSize is the number of features used by the model.
// Extended from 7 to 25 to cover behavioral, ecosystem, and metadata signals.
const FeatureVectorSize = 25

// InputData represents the raw data required for ML feature extraction.
type InputData struct {
	// Core metadata (original 7)
	DownloadCount      int64
	MaintainerCount    int
	CreatedAt          time.Time
	LastUpdated        time.Time
	VulnerabilityCount int
	MalwareReportCount int
	VerifiedFlagCount  int

	// Install-time behavior (features 7-10)
	HasInstallScript    bool
	InstallScriptSize   int // bytes
	HasPreinstallScript bool
	HasPostinstallScript bool

	// Maintainer dynamics (features 11-13)
	MaintainerChangeCount int // number of maintainer additions/removals in last 90d
	MaintainerVelocity    float64 // changes per day over last 90d
	DomainAgeOfAuthorEmail int // age of email domain in days (-1 = unknown)

	// File composition (features 14-17)
	ExecutableBinaryCount int
	NetworkCodeFileCount  int
	TotalFileCount        int
	EntropyMaxFile        float64 // max Shannon entropy across all files (0-8)

	// Version / dependency delta (features 18-20)
	DependencyDelta       int // # deps added vs previous version (can be negative)
	PreviousVersionCount  int // total number of published versions
	DaysBetweenVersions   float64 // avg days between the last 3 version releases

	// Ecosystem popularity signals (features 21-23)
	StarCount             int
	ForkCount             int
	NamespaceAgeDays      int // age of the owning org/user namespace in days
}

// ExtractFeatures converts InputData into a normalized feature vector.
//
// Feature index layout:
//
//	[0]  Log(DownloadCount+1)           — higher = safer
//	[1]  MaintainerCount                — higher = safer
//	[2]  AgeInDays                      — very new = riskier
//	[3]  DaysSinceLastUpdate            — very fresh on new pkg = suspicious
//	[4]  VulnerabilityCount             — higher = riskier
//	[5]  MalwareReportCount             — any = very risky
//	[6]  VerifiedFlagCount              — higher = safer
//	[7]  HasInstallScript               — presence = riskier
//	[8]  InstallScriptSizeKB            — large = riskier
//	[9]  HasPreinstallScript            — presence = riskier
//	[10] HasPostinstallScript           — presence = riskier
//	[11] MaintainerChangeCount          — many changes = riskier
//	[12] MaintainerVelocity             — high velocity = riskier
//	[13] DomainAgeOfAuthorEmailDays     — young domain = riskier
//	[14] ExecutableBinaryCount          — any = riskier
//	[15] NetworkCodeFileCount           — many = riskier
//	[16] Log(TotalFileCount+1)          — context normalization
//	[17] EntropyMaxFile                 — very high entropy = riskier (obfuscation)
//	[18] DependencyDelta                — large positive = riskier
//	[19] Log(PreviousVersionCount+1)    — very few versions = riskier
//	[20] DaysBetweenVersions            — very short = riskier (rushed releases)
//	[21] Log(StarCount+1)               — higher = safer
//	[22] Log(ForkCount+1)               — higher = safer
//	[23] NamespaceAgeDays               — young namespace = riskier
//	[24] DownloadStarRatioAnomaly       — very high downloads but zero stars = suspicious
func ExtractFeatures(data InputData) []float32 {
	features := make([]float32, FeatureVectorSize)
	now := time.Now()

	// [0] Log(DownloadCount + 1)
	features[0] = float32(math.Log1p(float64(data.DownloadCount)))

	// [1] MaintainerCount
	features[1] = float32(data.MaintainerCount)

	// [2] AgeInDays
	ageDays := 0.0
	if !data.CreatedAt.IsZero() {
		ageDays = now.Sub(data.CreatedAt).Hours() / 24.0
	}
	features[2] = float32(ageDays)

	// [3] DaysSinceLastUpdate
	sinceUpdate := 0.0
	if !data.LastUpdated.IsZero() {
		sinceUpdate = now.Sub(data.LastUpdated).Hours() / 24.0
	}
	features[3] = float32(sinceUpdate)

	// [4] VulnerabilityCount
	features[4] = float32(data.VulnerabilityCount)

	// [5] MalwareReportCount
	features[5] = float32(data.MalwareReportCount)

	// [6] VerifiedFlagCount
	features[6] = float32(data.VerifiedFlagCount)

	// [7] HasInstallScript (0/1)
	if data.HasInstallScript {
		features[7] = 1.0
	}

	// [8] InstallScriptSize in KB
	features[8] = float32(data.InstallScriptSize) / 1024.0

	// [9] HasPreinstallScript (0/1)
	if data.HasPreinstallScript {
		features[9] = 1.0
	}

	// [10] HasPostinstallScript (0/1)
	if data.HasPostinstallScript {
		features[10] = 1.0
	}

	// [11] MaintainerChangeCount (capped at 20 to reduce outlier influence)
	mc := data.MaintainerChangeCount
	if mc > 20 {
		mc = 20
	}
	features[11] = float32(mc)

	// [12] MaintainerVelocity (changes/day, capped at 1.0)
	mv := data.MaintainerVelocity
	if mv > 1.0 {
		mv = 1.0
	}
	features[12] = float32(mv)

	// [13] DomainAgeOfAuthorEmail (days; unknown → 0 which is neutral/unknown)
	domainAge := data.DomainAgeOfAuthorEmail
	if domainAge < 0 {
		domainAge = 0
	}
	features[13] = float32(domainAge)

	// [14] ExecutableBinaryCount (capped at 10)
	eb := data.ExecutableBinaryCount
	if eb > 10 {
		eb = 10
	}
	features[14] = float32(eb)

	// [15] NetworkCodeFileCount (capped at 20)
	nc := data.NetworkCodeFileCount
	if nc > 20 {
		nc = 20
	}
	features[15] = float32(nc)

	// [16] Log(TotalFileCount + 1)
	features[16] = float32(math.Log1p(float64(data.TotalFileCount)))

	// [17] EntropyMaxFile (0-8; higher = more obfuscated)
	ent := data.EntropyMaxFile
	if ent > 8.0 {
		ent = 8.0
	}
	if ent < 0 {
		ent = 0
	}
	features[17] = float32(ent)

	// [18] DependencyDelta (capped ±50)
	dd := data.DependencyDelta
	if dd > 50 {
		dd = 50
	} else if dd < -50 {
		dd = -50
	}
	features[18] = float32(dd)

	// [19] Log(PreviousVersionCount + 1)
	features[19] = float32(math.Log1p(float64(data.PreviousVersionCount)))

	// [20] DaysBetweenVersions (capped at 365; 0 for unknown)
	dbv := data.DaysBetweenVersions
	if dbv > 365 {
		dbv = 365
	}
	if dbv < 0 {
		dbv = 0
	}
	features[20] = float32(dbv)

	// [21] Log(StarCount + 1)
	features[21] = float32(math.Log1p(float64(data.StarCount)))

	// [22] Log(ForkCount + 1)
	features[22] = float32(math.Log1p(float64(data.ForkCount)))

	// [23] NamespaceAgeDays (capped at 3650 = 10 years)
	na := data.NamespaceAgeDays
	if na > 3650 {
		na = 3650
	}
	if na < 0 {
		na = 0
	}
	features[23] = float32(na)

	// [24] DownloadStarRatioAnomaly — high downloads with zero community signals = suspicious
	// Ratio = log(downloads+1) / (log(stars+1) + log(forks+1) + 1)
	// Anomaly when ratio > 10 and stars == 0.
	anomaly := 0.0
	if data.StarCount == 0 && data.ForkCount == 0 && data.DownloadCount > 10000 {
		anomaly = math.Log1p(float64(data.DownloadCount)) / 10.0
		if anomaly > 1.0 {
			anomaly = 1.0
		}
	}
	features[24] = float32(anomaly)

	return features
}

// FeatureMeans and FeatureStdDevs are pre-computed training statistics for z-score normalization.
// These must be updated whenever the ML model is retrained.
// Values for features with near-zero std are set to 1.0 to avoid division by zero.
var FeatureMeans = [FeatureVectorSize]float32{
	8.5,   // [0]  log downloads (ln(5000) ≈ 8.5 typical pkg)
	1.8,   // [1]  maintainer count
	730.0, // [2]  age days (~2 years)
	90.0,  // [3]  days since update
	0.3,   // [4]  vuln count
	0.02,  // [5]  malware reports
	0.5,   // [6]  verified flags
	0.3,   // [7]  has install script
	2.0,   // [8]  install script KB
	0.1,   // [9]  has preinstall
	0.15,  // [10] has postinstall
	0.4,   // [11] maintainer change count
	0.005, // [12] maintainer velocity
	1200.0, // [13] domain age days
	0.1,   // [14] executable binary count
	1.2,   // [15] network code files
	2.3,   // [16] log total files
	4.5,   // [17] max entropy
	0.8,   // [18] dependency delta
	1.6,   // [19] log version count
	45.0,  // [20] days between versions
	3.5,   // [21] log stars
	2.0,   // [22] log forks
	900.0, // [23] namespace age days
	0.05,  // [24] download/star anomaly
}

var FeatureStdDevs = [FeatureVectorSize]float32{
	4.0,   // [0]
	2.5,   // [1]
	600.0, // [2]
	120.0, // [3]
	1.2,   // [4]
	0.15,  // [5]
	1.0,   // [6]
	0.46,  // [7]  binary 0/1
	8.0,   // [8]
	0.30,  // [9]
	0.36,  // [10]
	1.5,   // [11]
	0.05,  // [12]
	800.0, // [13]
	0.5,   // [14]
	3.0,   // [15]
	1.5,   // [16]
	1.5,   // [17]
	5.0,   // [18]
	1.2,   // [19]
	60.0,  // [20]
	3.0,   // [21]
	2.0,   // [22]
	700.0, // [23]
	0.2,   // [24]
}

// NormalizeFeatures applies z-score normalization in-place using training statistics.
// Normalized = (value - mean) / stddev, clamped to [-3, 3].
// Call this before passing features to the ML model (not needed for heuristic fallback).
func NormalizeFeatures(features []float32) []float32 {
	if len(features) < FeatureVectorSize {
		return features
	}
	normalized := make([]float32, len(features))
	for i := 0; i < FeatureVectorSize; i++ {
		std := FeatureStdDevs[i]
		if std == 0 {
			std = 1.0
		}
		z := (features[i] - FeatureMeans[i]) / std
		// Clamp to [-3, 3] to reduce outlier impact
		if z > 3.0 {
			z = 3.0
		} else if z < -3.0 {
			z = -3.0
		}
		normalized[i] = z
	}
	return normalized
}
