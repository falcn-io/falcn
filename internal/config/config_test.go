package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeValidConfig writes a fully valid config.yaml to the given directory.
// It adjusts paths to directories that actually exist.
func writeValidConfig(t *testing.T, dir string) {
	t.Helper()

	// Create sub-directories that the config requires
	dataDir := filepath.Join(dir, "data")
	migrationsDir := filepath.Join(dir, "migrations")
	require.NoError(t, os.MkdirAll(dataDir, 0755))
	require.NoError(t, os.MkdirAll(migrationsDir, 0755))

	content := fmt.Sprintf(`
app:
  name: "Falcn"
  version: "1.0.0"
  environment: "development"
  debug: false
  log_level: "info"
  data_dir: "%s"
  temp_dir: "/tmp"
  max_workers: 4

server:
  host: "localhost"
  port: 8080
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "60s"
  shutdown_timeout: "30s"

database:
  type: "sqlite"
  database: "./data/falcn.db"
  migrations_path: "%s"
  max_open_conns: 5
  max_idle_conns: 2
  conn_max_lifetime: "5m"

redis:
  enabled: false
  host: "localhost"
  port: 6379

logging:
  level: "info"
  format: "json"
  output: "stdout"
  max_size: 100
  max_backups: 3
  max_age: 28
  compress: true

metrics:
  enabled: false
  provider: "prometheus"
  address: ":9090"
  namespace: "falcn"
  interval: "15s"

security:
  encryption:
    key: "a-32-character-encryption-key!!!"
    algorithm: "aes-256-gcm"
  password_policy:
    min_length: 8
    require_upper: true
    require_lower: true
    require_digit: true
    require_symbol: false

ml:
  enabled: false
  model_path: ""
  threshold: 0.5
  batch_size: 100
  timeout: "30s"
  cache_size: 1000
  update_interval: "24h"

typo_detection:
  enabled: true
  threshold: 0.8
  similarity_threshold: 0.7
  edit_distance_threshold: 2
  max_distance: 3
  phonetic_matching: false
  check_similar_names: true
  check_homoglyphs: false

api:
  rate_limit:
    enabled: false
    rps: 100
    burst: 200
  version: "v1"

scanner:
  max_concurrency: 5
  timeout: "30s"
  retry_attempts: 3
  retry_delay: "1s"
  user_agent: "Falcn/1.0"

rate_limit:
  enabled: false
  rps: 100
  burst: 200
  window: "1m"

policies:
  fail_on_threats: false
  min_threat_level: "medium"

features:
  ml_scoring: false
  advanced_metrics: false
  caching: false
  async_processing: false
  webhooks: false
  bulk_scanning: false
  historical_data: false
  experimental_apis: false
`, dataDir, migrationsDir)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0600))
}

// ──────────────────────────────────────────────
// Manager construction
// ──────────────────────────────────────────────

func TestNewManager_ReturnsNonNilManager(t *testing.T) {
	m := NewManager()
	require.NotNil(t, m)
}

func TestNewManager_GetReturnsNilBeforeLoad(t *testing.T) {
	m := NewManager()
	cfg := m.Get()
	assert.Nil(t, cfg)
}

// ──────────────────────────────────────────────
// Environment helpers (no Load needed)
// ──────────────────────────────────────────────

func TestManager_EnvironmentHelpers_Default(t *testing.T) {
	m := NewManager()
	// env is empty string by default
	assert.False(t, m.IsProduction())
	assert.False(t, m.IsDevelopment())
	assert.False(t, m.IsTesting())
}

// ──────────────────────────────────────────────
// Load — with valid config file
// ──────────────────────────────────────────────

func TestManager_Load_ValidConfig_Succeeds(t *testing.T) {
	dir := t.TempDir()
	writeValidConfig(t, dir)

	m := NewManager()
	err := m.Load(dir)
	require.NoError(t, err)

	cfg := m.Get()
	require.NotNil(t, cfg)
}

func TestManager_Load_ValidConfig_ServerValues(t *testing.T) {
	dir := t.TempDir()
	writeValidConfig(t, dir)

	m := NewManager()
	require.NoError(t, m.Load(dir))

	cfg := m.Get()
	require.NotNil(t, cfg)
	assert.Equal(t, "localhost", cfg.Server.Host)
	assert.Equal(t, 8080, cfg.Server.Port)
}

func TestManager_Load_ValidConfig_LoggingValues(t *testing.T) {
	dir := t.TempDir()
	writeValidConfig(t, dir)

	m := NewManager()
	require.NoError(t, m.Load(dir))

	cfg := m.Get()
	require.NotNil(t, cfg)
	assert.NotEmpty(t, cfg.Logging.Level)
	assert.Equal(t, "json", cfg.Logging.Format)
}

func TestManager_Load_ValidConfig_DatabaseType(t *testing.T) {
	dir := t.TempDir()
	writeValidConfig(t, dir)

	m := NewManager()
	require.NoError(t, m.Load(dir))

	cfg := m.Get()
	require.NotNil(t, cfg)
	assert.Equal(t, "sqlite", cfg.Database.Type)
}

func TestManager_Load_ValidConfig_Environment(t *testing.T) {
	dir := t.TempDir()
	writeValidConfig(t, dir)

	m := NewManager()
	require.NoError(t, m.Load(dir))

	assert.Equal(t, EnvDevelopment, m.GetEnvironment())
	assert.True(t, m.IsDevelopment())
	assert.False(t, m.IsProduction())
	assert.False(t, m.IsTesting())
}

func TestManager_IsProduction_WithProductionConfig(t *testing.T) {
	dir := t.TempDir()
	writeValidConfig(t, dir)

	// Override environment via env var
	t.Setenv("TYPOSENTINEL_APP_ENVIRONMENT", "production")
	// Also need to disable debug for production validation
	t.Setenv("FALCN_APP_DEBUG", "false")

	m := NewManager()
	require.NoError(t, m.Load(dir))

	assert.True(t, m.IsProduction())
}

func TestManager_IsTesting_WithTestingConfig(t *testing.T) {
	dir := t.TempDir()
	writeValidConfig(t, dir)

	t.Setenv("TYPOSENTINEL_APP_ENVIRONMENT", "testing")

	m := NewManager()
	require.NoError(t, m.Load(dir))

	assert.True(t, m.IsTesting())
}

func TestManager_GetEnvironment_Staging(t *testing.T) {
	dir := t.TempDir()
	writeValidConfig(t, dir)
	t.Setenv("TYPOSENTINEL_APP_ENVIRONMENT", "staging")

	m := NewManager()
	require.NoError(t, m.Load(dir))

	assert.Equal(t, EnvStaging, m.GetEnvironment())
}

// ──────────────────────────────────────────────
// Load — validation failures are real errors
// ──────────────────────────────────────────────

func TestManager_Load_NoConfigFile_MissingDirs_ReturnsValidationError(t *testing.T) {
	dir := t.TempDir()
	// No config file written, and no ./data or ./migrations dirs
	m := NewManager()
	err := m.Load(dir)
	// Load returns a validation error because required dirs don't exist
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VALIDATION_ERROR")
}

// ──────────────────────────────────────────────
// LoadConfig helper
// ──────────────────────────────────────────────

func TestLoadConfig_WithValidConfig(t *testing.T) {
	dir := t.TempDir()
	writeValidConfig(t, dir)

	// LoadConfig(configFile) uses Dir of the file
	configFile := filepath.Join(dir, "config.yaml")
	cfg, err := LoadConfig(configFile)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "localhost", cfg.Server.Host)
}

func TestLoadConfig_NonExistentDir_ReturnsError(t *testing.T) {
	// Empty string tries to load from "." which has validation issues
	// but can succeed if the cwd has the required dirs (like when run from project root)
	// Instead, test with a definitely bad config file (malformed YAML)
	dir := t.TempDir()
	badYAML := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(badYAML, []byte(":\n  bad: [yaml"), 0600))

	cfg, err := LoadConfig(badYAML)
	// Malformed YAML should produce an error
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

// ──────────────────────────────────────────────
// NewDefaultConfig
// ──────────────────────────────────────────────

func TestNewDefaultConfig_ReturnsConfig(t *testing.T) {
	cfg := NewDefaultConfig()
	require.NotNil(t, cfg)
}

func TestNewDefaultConfig_HasNonZeroPort(t *testing.T) {
	cfg := NewDefaultConfig()
	require.NotNil(t, cfg)
	// Port default is set to 8080
	assert.Greater(t, cfg.Server.Port, 0)
}

func TestNewDefaultConfig_HasLogLevel(t *testing.T) {
	cfg := NewDefaultConfig()
	require.NotNil(t, cfg)
	assert.NotEmpty(t, cfg.Logging.Level)
}

// ──────────────────────────────────────────────
// Environment constants
// ──────────────────────────────────────────────

func TestEnvironmentConstants(t *testing.T) {
	assert.Equal(t, Environment("development"), EnvDevelopment)
	assert.Equal(t, Environment("testing"), EnvTesting)
	assert.Equal(t, Environment("staging"), EnvStaging)
	assert.Equal(t, Environment("production"), EnvProduction)
}

// ──────────────────────────────────────────────
// SmartDefaultsEngine
// ──────────────────────────────────────────────

func TestNewSmartDefaultsEngine_NotNil(t *testing.T) {
	e := NewSmartDefaultsEngine()
	require.NotNil(t, e)
}

func TestSmartDefaultsEngine_DetectProject_EmptyDir(t *testing.T) {
	e := NewSmartDefaultsEngine()
	dir := t.TempDir()
	info, err := e.DetectProject(dir)
	require.NoError(t, err)
	require.NotNil(t, info)
}

func TestSmartDefaultsEngine_GenerateConfig_AllPresets(t *testing.T) {
	presets := []SecurityPreset{
		PresetQuick, PresetBalanced, PresetThorough, PresetParanoid, PresetEnterprise,
	}
	dir := t.TempDir()
	e := NewSmartDefaultsEngine()

	for _, preset := range presets {
		t.Run(string(preset), func(t *testing.T) {
			cfg, err := e.GenerateConfig(dir, preset)
			require.NoError(t, err)
			assert.NotNil(t, cfg)
		})
	}
}

func TestGetPresetDescription(t *testing.T) {
	for _, preset := range []SecurityPreset{PresetQuick, PresetBalanced, PresetThorough, PresetParanoid, PresetEnterprise} {
		t.Run(string(preset), func(t *testing.T) {
			desc := GetPresetDescription(preset)
			assert.NotEmpty(t, desc)
		})
	}
}

func TestGetProjectTypeDescription(t *testing.T) {
	projectTypes := []ProjectType{
		ProjectTypeNodeJS, ProjectTypePython, ProjectTypeGo,
		ProjectTypeRust, ProjectTypeJava, ProjectTypeRuby,
		ProjectTypePHP, ProjectTypeMultiLang, ProjectTypeUnknown,
	}
	for _, pt := range projectTypes {
		t.Run(string(pt), func(t *testing.T) {
			desc := GetProjectTypeDescription(pt)
			assert.NotEmpty(t, desc)
		})
	}
}

// ──────────────────────────────────────────────
// EnvironmentDetector
// ──────────────────────────────────────────────

func TestEnvironmentDetector_DetectEnvironment_ReturnsInfo(t *testing.T) {
	detector := &EnvironmentDetector{}
	info := detector.DetectEnvironment()
	require.NotNil(t, info)
	assert.GreaterOrEqual(t, info.CPUCores, 1)
}

// ──────────────────────────────────────────────
// ProjectDetector
// ──────────────────────────────────────────────

func TestProjectDetector_DetectProject_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	pd := &ProjectDetector{}
	info, err := pd.DetectProject(dir)
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, ProjectTypeUnknown, info.Type)
}

func TestProjectDetector_DetectProject_GoProject(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.21\n"), 0644))

	pd := &ProjectDetector{}
	info, err := pd.DetectProject(dir)
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, ProjectTypeGo, info.Type)
}

func TestProjectDetector_DetectProject_NodeProject(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"test"}`), 0644))

	pd := &ProjectDetector{}
	info, err := pd.DetectProject(dir)
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, ProjectTypeNodeJS, info.Type)
}

func TestProjectDetector_DetectProject_PythonProject(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.0\n"), 0644))

	pd := &ProjectDetector{}
	info, err := pd.DetectProject(dir)
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, ProjectTypePython, info.Type)
}

// ──────────────────────────────────────────────
// SecurityConfig struct validation (struct-level, no file I/O)
// ──────────────────────────────────────────────

func TestSecurityConfig_Fields(t *testing.T) {
	sc := SecurityConfig{
		JWT: JWTConfig{
			Enabled: false,
		},
		Encryption: EncryptionConfig{
			Key:       "a-32-char-minimum-long-key-here!",
			Algorithm: "aes-256-gcm",
		},
	}
	assert.False(t, sc.JWT.Enabled)
	assert.Equal(t, "aes-256-gcm", sc.Encryption.Algorithm)
}

func TestJWTConfig_Fields(t *testing.T) {
	jc := JWTConfig{
		Enabled: true,
		Secret:  "a-strong-jwt-secret-key-of-32-chars",
		Issuer:  "falcn",
	}
	assert.True(t, jc.Enabled)
	assert.Equal(t, "falcn", jc.Issuer)
}

// ──────────────────────────────────────────────
// EnvironmentInfo struct fields
// ──────────────────────────────────────────────

func TestEnvironmentDetector_CPUAndMemory(t *testing.T) {
	d := &EnvironmentDetector{}
	info := d.DetectEnvironment()
	require.NotNil(t, info)
	// CPU cores should be at least 1
	assert.GreaterOrEqual(t, info.CPUCores, 1)
	// Total memory should be positive
	assert.GreaterOrEqual(t, info.MemoryGB, 0)
}
