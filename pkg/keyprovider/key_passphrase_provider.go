package keyprovider

// KeyPassphraseProvider defines the interface for retrieving a key passphrase.
type KeyPassphraseProvider interface {
	GetPassphrase() (string, error)
}
