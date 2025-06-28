package plaintext

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPlainTextPassphraseProvider(t *testing.T) {
	passphrase := "test-passphrase"
	provider := NewPlainTextPassphraseProvider(passphrase)

	assert.NotNil(t, provider)
	// Assert that the underlying struct is of type *PlainTextPassphraseProvider
	// and that its passphrase field is set correctly.
	concreteProvider, ok := provider.(*PlainTextPassphraseProvider)
	require.True(t, ok)
	assert.Equal(t, passphrase, concreteProvider.passphrase)
}

func TestGetPassphrase(t *testing.T) {
	passphrase := "another-test-passphrase"
	provider := NewPlainTextPassphraseProvider(passphrase)

	retrievedPassphrase, err := provider.GetPassphrase()
	require.NoError(t, err)
	assert.Equal(t, passphrase, retrievedPassphrase)

	// Test with empty passphrase
	provider = NewPlainTextPassphraseProvider("")
	retrievedPassphrase, err = provider.GetPassphrase()
	require.NoError(t, err)
	assert.Equal(t, "", retrievedPassphrase)
}
