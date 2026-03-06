// Package container provides OCI/Docker container image scanning for Falcn.
//
// It supports pulling OCI manifests from Docker Hub, GHCR, Quay.io, GCR, ECR,
// and ACR without requiring a full Docker daemon. Layers are streamed and
// analysed in-memory; package manager databases (dpkg, apk, rpm) are parsed to
// enumerate installed software and cross-reference against the OSV/GitHub
// Advisory vulnerability databases.
package container

import "time"

// ─── Image reference ─────────────────────────────────────────────────────────

// ImageRef is a parsed OCI image reference.
//
//	nginx              → {Registry:"index.docker.io", Name:"library/nginx", Tag:"latest"}
//	ghcr.io/foo/bar:v2 → {Registry:"ghcr.io", Name:"foo/bar", Tag:"v2"}
//	gcr.io/proj/img@sha256:abc → {Registry:"gcr.io", Name:"proj/img", Digest:"sha256:abc"}
type ImageRef struct {
	// Original is the raw string provided by the caller.
	Original string
	// Registry host, e.g. "index.docker.io" or "ghcr.io".
	Registry string
	// Name is the repository path, e.g. "library/nginx" or "myorg/app".
	Name string
	// Tag is the image tag, e.g. "latest" or "3.12-slim". Empty when Digest is set.
	Tag string
	// Digest is the image content-addressable digest, e.g. "sha256:abc123".
	Digest string
}

// ─── OCI manifest & config ───────────────────────────────────────────────────

// ImageManifest is a simplified representation of an OCI Image Manifest v2.
type ImageManifest struct {
	SchemaVersion int            `json:"schemaVersion"`
	MediaType     string         `json:"mediaType"`
	Config        ManifestDescr  `json:"config"`
	Layers        []ManifestDescr `json:"layers"`
	// ResolvedDigest is the digest of this manifest (from the Content-Digest header).
	ResolvedDigest string `json:"resolved_digest,omitempty"`
}

// ManifestDescr describes a blob (config or layer) inside a manifest.
type ManifestDescr struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// ImageConfig is a simplified OCI image configuration blob.
type ImageConfig struct {
	Architecture string          `json:"architecture"`
	OS           string          `json:"os"`
	OSVersion    string          `json:"os.version,omitempty"`
	Author       string          `json:"author,omitempty"`
	Created      *time.Time      `json:"created,omitempty"`
	Config       ContainerConfig `json:"config"`
	RootFS       RootFS          `json:"rootfs"`
	History      []HistoryEntry  `json:"history"`
}

// ContainerConfig contains the runtime configuration of the image.
type ContainerConfig struct {
	User         string            `json:"User,omitempty"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	Env          []string          `json:"Env,omitempty"`
	Entrypoint   []string          `json:"Entrypoint,omitempty"`
	Cmd          []string          `json:"Cmd,omitempty"`
	Volumes      map[string]struct{} `json:"Volumes,omitempty"`
	WorkingDir   string            `json:"WorkingDir,omitempty"`
	Labels       map[string]string `json:"Labels,omitempty"`
}

// RootFS describes the content-addressable layers of the image.
type RootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

// HistoryEntry is one entry in the image build history (corresponds to a Dockerfile instruction).
type HistoryEntry struct {
	Created    *time.Time `json:"created,omitempty"`
	CreatedBy  string     `json:"created_by,omitempty"`
	Comment    string     `json:"comment,omitempty"`
	EmptyLayer bool       `json:"empty_layer,omitempty"`
}

// ─── Installed packages ───────────────────────────────────────────────────────

// PackageEcosystem identifies the package manager that installed a package.
type PackageEcosystem string

const (
	EcosystemDpkg     PackageEcosystem = "dpkg"     // Debian/Ubuntu
	EcosystemApk      PackageEcosystem = "apk"      // Alpine
	EcosystemRpm      PackageEcosystem = "rpm"       // RHEL/CentOS/Fedora
	EcosystemPip      PackageEcosystem = "pip"       // Python inside image
	EcosystemNpm      PackageEcosystem = "npm"       // Node.js inside image
	EcosystemGoBinary PackageEcosystem = "go-binary" // Go module embedded in binary
)

// InstalledPackage represents a package found in a container image layer.
type InstalledPackage struct {
	// Name is the package name as reported by the package manager.
	Name string `json:"name"`
	// Version is the installed version string.
	Version string `json:"version"`
	// Arch is the CPU architecture, e.g. "amd64".
	Arch string `json:"arch,omitempty"`
	// Source is the upstream source package (dpkg only).
	Source string `json:"source,omitempty"`
	// InstalledSize is the on-disk size in bytes.
	InstalledSize int64 `json:"installed_size,omitempty"`
	// Description is a brief human-readable description of the package.
	Description string `json:"description,omitempty"`
	// Ecosystem identifies the package manager.
	Ecosystem PackageEcosystem `json:"ecosystem"`
	// LayerDigest is the digest of the layer this package was first found in.
	LayerDigest string `json:"layer_digest,omitempty"`
}

// ─── Layer scan result ────────────────────────────────────────────────────────

// LayerAnalysis records what was found in a single image layer.
type LayerAnalysis struct {
	// Digest is the content-addressable digest of this layer blob.
	Digest string `json:"digest"`
	// Size is the compressed layer size in bytes.
	Size int64 `json:"size"`
	// Command is the Dockerfile instruction that created this layer (from image history).
	Command string `json:"command,omitempty"`
	// Packages is the list of packages first introduced in this layer.
	Packages []InstalledPackage `json:"packages,omitempty"`
	// Error records any extraction error for this layer.
	Error string `json:"error,omitempty"`
}

// ─── Security findings ────────────────────────────────────────────────────────

// SecurityFinding is a single security issue found during image analysis.
type SecurityFinding struct {
	// ID is a short, stable identifier for the rule, e.g. "IMG001".
	ID string `json:"id"`
	// Severity is one of "critical", "high", "medium", "low".
	Severity string `json:"severity"`
	// Title is a concise one-line description.
	Title string `json:"title"`
	// Detail provides additional context.
	Detail string `json:"detail,omitempty"`
	// Remediation is an actionable fix.
	Remediation string `json:"remediation,omitempty"`
	// Layer is the layer digest where the issue was found (if applicable).
	Layer string `json:"layer,omitempty"`
}

// ─── Vulnerability record ─────────────────────────────────────────────────────

// PackageVuln maps an installed package to discovered CVEs.
type PackageVuln struct {
	Package   InstalledPackage `json:"package"`
	CVEs      []string         `json:"cves"`
	Severity  string           `json:"severity"`
	FixedIn   string           `json:"fixed_in,omitempty"`
	OSVIDs    []string         `json:"osv_ids,omitempty"`
}

// ─── Full scan result ─────────────────────────────────────────────────────────

// ImageScanResult is the complete output of scanning one container image.
type ImageScanResult struct {
	// Ref is the parsed image reference that was scanned.
	Ref ImageRef `json:"ref"`
	// ResolvedDigest is the manifest digest (sha256:...).
	ResolvedDigest string `json:"resolved_digest"`
	// OS is the operating system of the image, e.g. "linux".
	OS string `json:"os"`
	// Architecture is the CPU architecture, e.g. "amd64".
	Architecture string `json:"architecture"`
	// BaseImage is the FROM image detected from history (best effort).
	BaseImage string `json:"base_image,omitempty"`
	// ImageSizeMB is the total uncompressed image size in megabytes.
	ImageSizeMB float64 `json:"image_size_mb"`
	// LayerCount is the number of filesystem layers in the image.
	LayerCount int `json:"layer_count"`
	// Packages contains all packages enumerated across all layers.
	Packages []InstalledPackage `json:"packages"`
	// PackageCount is the total number of unique installed packages.
	PackageCount int `json:"package_count"`
	// Layers contains per-layer analysis results. Only populated in full mode.
	Layers []LayerAnalysis `json:"layers,omitempty"`
	// Vulnerabilities lists packages with known CVEs.
	Vulnerabilities []PackageVuln `json:"vulnerabilities"`
	// SecurityFindings lists image-level security policy violations.
	SecurityFindings []SecurityFinding `json:"security_findings"`
	// RiskScore is a 0.0–1.0 composite risk score.
	RiskScore float64 `json:"risk_score"`
	// RiskLevel is one of "minimal", "low", "medium", "high", "critical".
	RiskLevel string `json:"risk_level"`
	// ScannedAt is when this scan was completed.
	ScannedAt time.Time `json:"scanned_at"`
	// ScanDurationMs is the wall-clock time taken to complete the scan.
	ScanDurationMs int64 `json:"scan_duration_ms"`
	// Errors contains non-fatal errors encountered during scanning.
	Errors []string `json:"errors,omitempty"`
}

// ─── Scan options ─────────────────────────────────────────────────────────────

// ScanOptions controls the behaviour of a container image scan.
type ScanOptions struct {
	// Light skips layer blob downloads; only the manifest and config are analysed.
	// Much faster but misses installed-package enumeration.
	Light bool
	// Platform overrides the target platform, e.g. "linux/amd64".
	Platform string
	// Username and Password are registry credentials.
	Username string
	Password string
	// Token is a pre-issued registry bearer token.
	Token string
	// Insecure allows HTTP (non-TLS) registry connections.
	Insecure bool
	// MaxLayerSizeMB is the maximum layer size to download; larger layers are skipped.
	// Defaults to 100 MB when zero.
	MaxLayerSizeMB int64
}
