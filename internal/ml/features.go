package ml

import (
	"math"
	"time"
)

// FeatureVectorSize is the number of features used by the model.
// Extended from 25 to 30 to cover advanced supply chain attack signals (2026).
const FeatureVectorSize = 30

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
	// StarCount and ForkCount are the GitHub stars/forks count.
	// Set HasGitHubData=true only when you have actually fetched these values from GitHub.
	// When HasGitHubData=false the download_star_anomaly detector (feature [24]) is suppressed
	// to avoid false positives on packages where we simply haven't queried GitHub.
	StarCount        int
	ForkCount        int
	NamespaceAgeDays int  // age of the owning org/user namespace in days
	HasGitHubData    bool // true = StarCount/ForkCount came from the GitHub API

	// Advanced supply chain signals (features 25-29, added for 2026 attack detection)
	HasCredentialHarvestingPattern bool // code reads ~/.ssh, ~/.aws, ~/.kube etc.
	HasOSPersistencePattern        bool // installs systemd/cron/launchd/Run key persistence
	HasAntiForensicsPattern        bool // self-deleting scripts, evidence cleanup
	HasCompoundObfuscation         bool // base64+exec, eval+fetch, or similar combo
	NewDependencyCount             int  // number of new deps added vs previous version
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
//	[25] HasCredentialHarvestingPattern — reads credential files (0/1)
//	[26] HasOSPersistencePattern        — installs persistence mechanisms (0/1)
//	[27] HasAntiForensicsPattern        — self-deleting scripts, cleanup (0/1)
//	[28] HasCompoundObfuscation         — dangerous signal combinations (0/1)
//	[29] NewDependencyCount             — deps added vs previous version
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

	// [24] DownloadStarRatioAnomaly — high downloads with confirmed zero community signals.
	// Only computed when HasGitHubData=true so that packages where we simply did not
	// query GitHub are not penalised.  This prevents train/serve skew: the training
	// data only sets anomaly>0 when the registry metadata confirmed "no repository",
	// so inference must mirror that condition rather than treating StarCount=0 (unset)
	// as confirmed zero stars.
	anomaly := 0.0
	if data.HasGitHubData && data.StarCount == 0 && data.ForkCount == 0 && data.DownloadCount > 10000 {
		anomaly = math.Log1p(float64(data.DownloadCount)) / 10.0
		if anomaly > 1.0 {
			anomaly = 1.0
		}
	}
	features[24] = float32(anomaly)

	// [25] HasCredentialHarvestingPattern (0/1) — very strong malware signal
	if data.HasCredentialHarvestingPattern {
		features[25] = 1.0
	}

	// [26] HasOSPersistencePattern (0/1) — strong malware signal
	if data.HasOSPersistencePattern {
		features[26] = 1.0
	}

	// [27] HasAntiForensicsPattern (0/1) — strong malware signal
	if data.HasAntiForensicsPattern {
		features[27] = 1.0
	}

	// [28] HasCompoundObfuscation (0/1) — combined dangerous operations
	if data.HasCompoundObfuscation {
		features[28] = 1.0
	}

	// [29] NewDependencyCount (capped at 10)
	ndc := data.NewDependencyCount
	if ndc > 10 {
		ndc = 10
	}
	if ndc < 0 {
		ndc = 0
	}
	features[29] = float32(ndc)

	return features
}

// FeatureMeans and FeatureStdDevs contain z-score normalization statistics
// computed from the trained model dataset (resources/models/scaler_stats.json).
// These values were produced by scripts/train_ml_model.py on 2026-03-07 using
// real malicious package data (413 real samples, 47 confirmed malicious) combined
// with 30,000 synthetic samples. AUC=0.9256, F1=0.8991, FPR=0.004.
// Production threshold: 0.40 (from real-data calibration, not synthetic test set).
// Update whenever the model is retrained.
var FeatureMeans = [FeatureVectorSize]float32{
	8.6336,    // [0]  log_downloads
	3.0340,    // [1]  maintainer_count
	863.7800,  // [2]  age_days
	100.6505,  // [3]  days_since_update
	0.3227,    // [4]  vuln_count
	0.0181,    // [5]  malware_reports
	0.5991,    // [6]  verified_flags
	0.4002,    // [7]  has_install_script
	1.6441,    // [8]  install_script_kb
	0.1573,    // [9]  has_preinstall
	0.2025,    // [10] has_postinstall
	0.3029,    // [11] maintainer_change_count
	0.0080,    // [12] maintainer_velocity
	1368.9699, // [13] domain_age_days
	0.1642,    // [14] executable_binary_count
	1.1356,    // [15] network_code_files
	2.3529,    // [16] log_total_files
	4.8091,    // [17] entropy_max_file
	1.4168,    // [18] dependency_delta
	1.9741,    // [19] log_version_count
	57.5615,   // [20] days_between_versions
	4.1669,    // [21] log_stars
	2.5384,    // [22] log_forks
	1009.5655, // [23] namespace_age_days
	0.0290,    // [24] download_star_anomaly
	0.0,       // [25] has_credential_harvesting (new — passthrough until retrain)
	0.0,       // [26] has_os_persistence (new — passthrough until retrain)
	0.0,       // [27] has_anti_forensics (new — passthrough until retrain)
	0.0,       // [28] has_compound_obfuscation (new — passthrough until retrain)
	0.0,       // [29] new_dependency_count (new — passthrough until retrain)
}

var FeatureStdDevs = [FeatureVectorSize]float32{
	4.7660,    // [0]  log_downloads
	1.7296,    // [1]  maintainer_count
	1036.4093, // [2]  age_days
	147.8479,  // [3]  days_since_update
	0.6153,    // [4]  vuln_count
	0.1731,    // [5]  malware_reports
	0.9207,    // [6]  verified_flags
	0.4899,    // [7]  has_install_script
	4.7617,    // [8]  install_script_kb
	0.3641,    // [9]  has_preinstall
	0.4019,    // [10] has_postinstall
	0.8459,    // [11] maintainer_change_count
	0.0392,    // [12] maintainer_velocity
	1451.1911, // [13] domain_age_days
	0.6145,    // [14] executable_binary_count
	1.3557,    // [15] network_code_files
	1.0634,    // [16] log_total_files
	1.5142,    // [17] entropy_max_file
	4.6145,    // [18] dependency_delta
	1.2847,    // [19] log_version_count
	64.0913,   // [20] days_between_versions
	3.3991,    // [21] log_stars
	2.2319,    // [22] log_forks
	1100.5909, // [23] namespace_age_days
	0.1425,    // [24] download_star_anomaly
	1.0,       // [25] has_credential_harvesting (new — passthrough until retrain)
	1.0,       // [26] has_os_persistence (new — passthrough until retrain)
	1.0,       // [27] has_anti_forensics (new — passthrough until retrain)
	1.0,       // [28] has_compound_obfuscation (new — passthrough until retrain)
	1.0,       // [29] new_dependency_count (new — passthrough until retrain)
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
