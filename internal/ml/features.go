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
	HasInstallScript     bool
	InstallScriptSize    int // bytes
	HasPreinstallScript  bool
	HasPostinstallScript bool

	// Maintainer dynamics (features 11-13)
	MaintainerChangeCount  int     // number of maintainer additions/removals in last 90d
	MaintainerVelocity     float64 // changes per day over last 90d
	DomainAgeOfAuthorEmail int     // age of email domain in days (-1 = unknown)

	// File composition (features 14-17)
	ExecutableBinaryCount int
	NetworkCodeFileCount  int
	TotalFileCount        int
	EntropyMaxFile        float64 // max Shannon entropy across all files (0-8)

	// Version / dependency delta (features 18-20)
	DependencyDelta      int     // # deps added vs previous version (can be negative)
	PreviousVersionCount int     // total number of published versions
	DaysBetweenVersions  float64 // avg days between the last 3 version releases

	// Ecosystem popularity signals (features 21-23)
	StarCount        int
	ForkCount        int
	NamespaceAgeDays int // age of the owning org/user namespace in days
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

// FeatureMeans and FeatureStdDevs contain z-score normalization statistics
// computed from the trained model dataset (resources/models/scaler_stats.json).
// These values were produced by scripts/train_ml_model.py on 2026-03-06.
// Update whenever the model is retrained.
var FeatureMeans = [FeatureVectorSize]float32{
	9.4735,   // [0]  log_downloads
	3.2159,   // [1]  maintainer_count
	786.5998, // [2]  age_days
	107.6925, // [3]  days_since_update
	0.4189,   // [4]  vuln_count
	0.0266,   // [5]  malware_reports
	0.6683,   // [6]  verified_flags
	0.4178,   // [7]  has_install_script
	1.5797,   // [8]  install_script_kb
	0.1448,   // [9]  has_preinstall
	0.1889,   // [10] has_postinstall
	0.3524,   // [11] maintainer_change_count
	0.0070,   // [12] maintainer_velocity
	1484.767, // [13] domain_age_days
	0.1858,   // [14] executable_binary_count
	1.2570,   // [15] network_code_files
	2.4407,   // [16] log_total_files
	4.7618,   // [17] entropy_max_file
	1.1554,   // [18] dependency_delta
	1.8660,   // [19] log_version_count
	57.4083,  // [20] days_between_versions
	4.5383,   // [21] log_stars
	2.7612,   // [22] log_forks
	970.8500, // [23] namespace_age_days
	0.0344,   // [24] download_star_anomaly
}

var FeatureStdDevs = [FeatureVectorSize]float32{
	4.2145,   // [0]
	1.7344,   // [1]
	824.5095, // [2]
	121.2384, // [3]
	0.7070,   // [4]
	0.2125,   // [5]
	0.9464,   // [6]
	0.4932,   // [7]  binary 0/1
	4.2164,   // [8]
	0.3519,   // [9]
	0.3914,   // [10]
	0.7706,   // [11]
	0.0286,   // [12]
	1465.122, // [13]
	0.6708,   // [14]
	1.3426,   // [15]
	1.0117,   // [16]
	1.3660,   // [17]
	4.9371,   // [18]
	1.1974,   // [19]
	59.4247,  // [20]
	3.1188,   // [21]
	2.0472,   // [22]
	983.2851, // [23]
	0.1535,   // [24]
}

// NormalizeFeatures applies z-score normalization using training statistics.
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
