package file

import (
	"fmt"
	"os"

	"github.com/Erik142/veil-certs/pkg/castore"
	"github.com/sirupsen/logrus"
)

// FileCAStore implements castore.CAStore by storing the CA certificate and key in files.
type FileCAStore struct {
	certPath string
	keyPath  string
	log      *logrus.Entry
}

// NewFileCAStore creates a new FileCAStore instance.
func NewFileCAStore(certPath, keyPath string) castore.CAStore {
	return &FileCAStore{
		certPath: certPath,
		keyPath:  keyPath,
		log:      logrus.WithField("component", "FileCAStore"),
	}
}

// SaveCA saves the CA certificate and key to specified files.
func (self *FileCAStore) SaveCA(certPEM, keyPEM []byte) error {
	self.log.Debugf("Saving CA certificate to %s", self.certPath)
	if err := os.WriteFile(self.certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write CA certificate to %s: %w", self.certPath, err)
	}

	self.log.Debugf("Saving CA private key to %s", self.keyPath)
	// Key should have stricter permissions
	if err := os.WriteFile(self.keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA private key to %s: %w", self.keyPath, err)
	}
	self.log.Info("CA certificate and key saved successfully.")
	return nil
}

// LoadCA loads the CA certificate and key from specified files.
func (self *FileCAStore) LoadCA() ([]byte, []byte, error) {
	self.log.Debugf("Loading CA certificate from %s", self.certPath)
	certPEM, err := os.ReadFile(self.certPath)
	if err != nil {
		if os.IsNotExist(err) {
			self.log.Warnf("CA certificate file not found at %s", self.certPath)
			return nil, nil, fmt.Errorf("CA certificate file not found: %w", err)
		}
		return nil, nil, fmt.Errorf("failed to read CA certificate from %s: %w", self.certPath, err)
	}

	self.log.Debugf("Loading CA private key from %s", self.keyPath)
	keyPEM, err := os.ReadFile(self.keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			self.log.Warnf("CA private key file not found at %s", self.keyPath)
			return nil, nil, fmt.Errorf("CA private key file not found: %w", err)
		}
		return nil, nil, fmt.Errorf("failed to read CA private key from %s: %w", self.keyPath, err)
	}
	self.log.Info("CA certificate and key loaded successfully.")
	return certPEM, keyPEM, nil
}

// CAExists checks if the CA certificate and key files exist.
func (self *FileCAStore) CAExists() bool {
	_, errCert := os.Stat(self.certPath)
	_, errKey := os.Stat(self.keyPath)
	return !os.IsNotExist(errCert) && !os.IsNotExist(errKey)
}
