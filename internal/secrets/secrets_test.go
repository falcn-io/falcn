package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────────────────────────
// EnvProvider
// ──────────────────────────────────────────────

func TestEnvProvider_Get_Found(t *testing.T) {
	t.Setenv("TEST_SECRET_KEY", "super-secret-value")

	p := EnvProvider{}
	val, err := p.Get("TEST_SECRET_KEY")

	require.NoError(t, err)
	assert.Equal(t, "super-secret-value", val)
}

func TestEnvProvider_Get_NotFound(t *testing.T) {
	// Ensure the var is definitely not set
	os.Unsetenv("FALCN_NONEXISTENT_SECRET_XYZ")

	p := EnvProvider{}
	val, err := p.Get("FALCN_NONEXISTENT_SECRET_XYZ")

	require.Error(t, err)
	assert.Empty(t, val)
	assert.Contains(t, err.Error(), "FALCN_NONEXISTENT_SECRET_XYZ")
}

func TestEnvProvider_Get_EmptyValue_TreatedAsNotFound(t *testing.T) {
	// Setting an env var to "" should be treated as not found
	t.Setenv("FALCN_EMPTY_SECRET", "")

	p := EnvProvider{}
	val, err := p.Get("FALCN_EMPTY_SECRET")

	require.Error(t, err)
	assert.Empty(t, val)
}

// ──────────────────────────────────────────────
// FileProvider creation
// ──────────────────────────────────────────────

func TestNewFileProvider_NonExistentPath_ReturnsError(t *testing.T) {
	fp, err := NewFileProvider("/tmp/does-not-exist-falcn-test-abc123.txt")

	require.Error(t, err)
	assert.Nil(t, fp)
	assert.Contains(t, err.Error(), "secrets file not found")
}

func TestNewFileProvider_ExistingFile_Succeeds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	require.NoError(t, os.WriteFile(path, []byte("KEY=value\n"), 0600))

	fp, err := NewFileProvider(path)

	require.NoError(t, err)
	assert.NotNil(t, fp)
}

// ──────────────────────────────────────────────
// FileProvider.Get
// ──────────────────────────────────────────────

func TestFileProvider_Get_Found(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	content := "DB_PASSWORD=hunter2\nAPI_KEY=abc123def456\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	fp, err := NewFileProvider(path)
	require.NoError(t, err)

	val, err := fp.Get("DB_PASSWORD")
	require.NoError(t, err)
	assert.Equal(t, "hunter2", val)
}

func TestFileProvider_Get_SecondKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	content := "FIRST=one\nSECOND=two\nTHIRD=three\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	fp, err := NewFileProvider(path)
	require.NoError(t, err)

	val, err := fp.Get("SECOND")
	require.NoError(t, err)
	assert.Equal(t, "two", val)
}

func TestFileProvider_Get_NotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	require.NoError(t, os.WriteFile(path, []byte("A=b\n"), 0600))

	fp, err := NewFileProvider(path)
	require.NoError(t, err)

	val, err := fp.Get("MISSING_KEY")
	require.Error(t, err)
	assert.Empty(t, val)
	assert.Contains(t, err.Error(), "MISSING_KEY")
}

func TestFileProvider_Get_WhitespaceAroundKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	// Key with surrounding spaces
	content := "  PADDED_KEY  =  padded_value  \n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	fp, err := NewFileProvider(path)
	require.NoError(t, err)

	val, err := fp.Get("PADDED_KEY")
	require.NoError(t, err)
	assert.Equal(t, "padded_value", val)
}

// ──────────────────────────────────────────────
// ValidateSecret
// ──────────────────────────────────────────────

func TestValidateSecret(t *testing.T) {
	tests := []struct {
		name       string
		secret     string
		secretType string
		wantErr    bool
	}{
		{"token valid", "abcdefghij", "token", false},
		{"token too short", "abc", "token", true},
		{"api_key valid", "1234567890abcdef", "api_key", false},
		{"api_key too short", "tooshort", "api_key", true},
		{"password valid", "password1", "password", false},
		{"password too short", "pass", "password", true},
		{"unknown type no error", "x", "unknown_type", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSecret(tc.secret, tc.secretType)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ──────────────────────────────────────────────
// SecureString
// ──────────────────────────────────────────────

func TestSecureString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantMask string
	}{
		{"short string masked fully", "12345678", "****"},
		{"long string shows prefix and suffix", "1234567890abcdef", "1234****cdef"},
		{"exactly 8 chars is fully masked", "abcdefgh", "****"},
		{"very long string", "abcdef1234567890xyz", "abcd****0xyz"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := SecureString(tc.input)
			assert.Equal(t, tc.wantMask, result)
		})
	}
}

// ──────────────────────────────────────────────
// EnvSecretManager
// ──────────────────────────────────────────────

func TestEnvSecretManager_GetSecret_Found(t *testing.T) {
	t.Setenv("MY_TEST_SECRET", "myvalue")

	mgr := NewEnvSecretManager()
	val, err := mgr.GetSecret("MY_TEST_SECRET")

	require.NoError(t, err)
	assert.Equal(t, "myvalue", val)
}

func TestEnvSecretManager_GetSecret_NotFound(t *testing.T) {
	os.Unsetenv("FALCN_ENV_MGR_MISSING")

	mgr := NewEnvSecretManager()
	val, err := mgr.GetSecret("FALCN_ENV_MGR_MISSING")

	require.Error(t, err)
	assert.Empty(t, val)
}

func TestEnvSecretManager_SetSecret_ReturnsError(t *testing.T) {
	mgr := NewEnvSecretManager()
	err := mgr.SetSecret("key", "value")
	require.Error(t, err)
}

func TestEnvSecretManager_DeleteSecret_ReturnsError(t *testing.T) {
	mgr := NewEnvSecretManager()
	err := mgr.DeleteSecret("key")
	require.Error(t, err)
}

func TestEnvSecretManager_ListSecrets_ReturnsError(t *testing.T) {
	mgr := NewEnvSecretManager()
	list, err := mgr.ListSecrets()
	require.Error(t, err)
	assert.Empty(t, list)
}
