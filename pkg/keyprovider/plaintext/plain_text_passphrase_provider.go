package plaintext

import (
	"github.com/Erik142/veil-certs/pkg/keyprovider"
	"github.com/sirupsen/logrus"
)

// PlainTextPassphraseProvider implements keyprovider.KeyPassphraseProvider by returning a plain text passphrase.
type PlainTextPassphraseProvider struct {
	passphrase string
	log        *logrus.Entry
}

// NewPlainTextPassphraseProvider creates a new PlainTextPassphraseProvider instance.
func NewPlainTextPassphraseProvider(passphrase string) keyprovider.KeyPassphraseProvider {
	return &PlainTextPassphraseProvider{
		passphrase: passphrase,
		log:        logrus.WithField("component", "PlainTextPassphraseProvider"),
	}
}

// GetPassphrase returns the stored plain text passphrase.
func (self *PlainTextPassphraseProvider) GetPassphrase() (string, error) {
	self.log.Debug("Retrieving plain text passphrase.")
	return self.passphrase, nil
}
