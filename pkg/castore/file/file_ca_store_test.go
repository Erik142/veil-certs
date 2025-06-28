package file

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileCAStore(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "castore_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir) // Clean up the temporary directory

	certPath := filepath.Join(tempDir, "ca.crt")
	keyPath := filepath.Join(tempDir, "ca.key")

	// Initialize FileCAStore
	store := NewFileCAStore(certPath, keyPath)

	// Test CAExists when files do not exist
	assert.False(t, store.CAExists(), "CA should not exist initially")

	// Test SaveCA
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
TEST_CERT
-----END CERTIFICATE-----`)
	keyPEM := []byte(`-----BEGIN PRIVATE KEY-----
TEST_KEY
-----END PRIVATE KEY-----`)

	err = store.SaveCA(certPEM, keyPEM)
	require.NoError(t, err, "SaveCA should not return an error")

	// Verify files are created and have correct permissions
	certInfo, err := os.Stat(certPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), certInfo.Mode().Perm(), "Certificate file permissions should be 0644")

	keyInfo, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), keyInfo.Mode().Perm(), "Key file permissions should be 0600")

	// Test CAExists after saving
	assert.True(t, store.CAExists(), "CA should exist after saving")

	// Test LoadCA
	loadedCertPEM, loadedKeyPEM, err := store.LoadCA()
	require.NoError(t, err, "LoadCA should not return an error")
	assert.Equal(t, certPEM, loadedCertPEM, "Loaded certificate should match original")
	assert.Equal(t, keyPEM, loadedKeyPEM, "Loaded key should match original")

	// Test LoadCA with missing files
	os.Remove(certPath)
	_, _, err = store.LoadCA()
	assert.Error(t, err, "LoadCA should return an error if certificate file is missing")
	assert.Contains(t, err.Error(), "CA certificate file not found", "Error message should indicate missing cert")

	// Recreate cert, remove key
	err = os.WriteFile(certPath, certPEM, 0644)
	require.NoError(t, err)
	os.Remove(keyPath)
	_, _, err = store.LoadCA()
	assert.Error(t, err, "LoadCA should return an error if key file is missing")
	assert.Contains(t, err.Error(), "CA private key file not found", "Error message should indicate missing key")
}
