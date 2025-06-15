package castore

// CAStore defines the interface for storing and loading the CA certificate and key.
type CAStore interface {
	SaveCA(certPEM, keyPEM []byte) error
	LoadCA() (certPEM []byte, keyPEM []byte, err error)
	CAExists() bool
}
