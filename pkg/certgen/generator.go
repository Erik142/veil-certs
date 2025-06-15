package certgen

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/netip"
	"time"

	"github.com/Erik142/veil-certs/pkg/ipmanager"
	"github.com/Erik142/veil-certs/pkg/ipmanager/store/inmem"
	"github.com/Erik142/veil-certs/pkg/keyprovider"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert" // Import for Nebula certificate structures
)

// CertificatePair holds a certificate and its private key in PEM format.
type CertificatePair struct {
	CertPEM []byte
	KeyPEM  []byte
}

// CertGenerator provides methods to generate Nebula-compatible certificates.
type CertGenerator struct {
	log       *logrus.Entry
	ipManager *ipmanager.IPLeaseManager
}

// NewCertGenerator creates a new CertGenerator instance.
func NewCertGenerator(subnet string) (*CertGenerator, error) {
	ipManager, err := ipmanager.NewIPLeaseManager(subnet, 1*time.Hour, inmem.NewInMemoryStore())

	return &CertGenerator{
		log:       logrus.WithField("component", "CertGenerator"),
		ipManager: ipManager,
	}, err
}

// GenerateCACertificate generates a self-signed Nebula-compatible CA certificate and private key.
// name: The common name for the CA (e.g., "MyNebulaCA").
// duration: The validity duration for the CA certificate.
// encryptKey: If true, the CA private key will be encrypted with the provided passphrase.
// passphraseProvider: Provides the passphrase for encrypting/decrypting the CA key.
func (self *CertGenerator) GenerateCACertificate(name string, duration time.Duration, encryptKey bool, passphraseProvider keyprovider.KeyPassphraseProvider, subnet string) (*CertificatePair, error) {
	self.log.WithFields(logrus.Fields{
		"name":       name,
		"duration":   duration,
		"encryptKey": encryptKey,
	}).Info("Generating CA certificate.")

	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA keypair: %v", err)
	}

	prefix, err := netip.ParsePrefix(subnet)

	if err != nil {
		return nil, err
	}

	caTemplate := cert.TBSCertificate{
		Name:      name,
		Networks:  []netip.Prefix{prefix},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(duration),
		IsCA:      true, // This is a CA
		Version:   cert.Version1,
		PublicKey: caPub,
	}

	caCert, err := caTemplate.Sign(nil, cert.Curve_CURVE25519, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}

	caCertPEM, err := caCert.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to encode CA cert: %w", err)
	}

	caKeyPEM := cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, caKey)

	self.log.Info("CA certificate generated successfully.")
	return &CertificatePair{
		CertPEM: caCertPEM,
		KeyPEM:  caKeyPEM,
	}, nil
}

// GenerateHostCertificate generates a Nebula-compatible host certificate and private key,
// signed by the provided CA certificate and key.
// caCertPEM: PEM-encoded CA certificate.
// caKeyPEM: PEM-encoded CA private key.
// passphraseProvider: Provides the passphrase for decrypting the CA key if it's encrypted.
// hostName: The common name for the host (e.g., "my-server-1").
// hostIP: The Nebula IP address for the host in CIDR format (e.g., "192.168.100.10/24").
// groups: A slice of strings representing Nebula groups.
// duration: The validity duration for the host certificate.
func (self *CertGenerator) GenerateHostCertificate(caCertPEM, caKeyPEM []byte, passphraseProvider keyprovider.KeyPassphraseProvider, hostName, hostIP string, groups []string, duration time.Duration) (*CertificatePair, error) {
	self.log.WithFields(logrus.Fields{
		"hostname": hostName,
		"ip_cidr":  hostIP,
		"groups":   groups,
		"duration": duration,
	}).Info("Received request to generate host certificate.")

	var prefix netip.Prefix

	// Parse CA certificate
	caCert, _, err := cert.UnmarshalCertificateFromPEM(caCertPEM)

	if err != nil {
		return nil, err
	}

	// Generate a new keypair for the host
	hostPub, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate host keypair: %v", err)
	}

	if hostIP == "" {
		lease, err := self.ipManager.RequestIP(hostName, duration)

		if err != nil {
			return nil, err
		}

		prefix, err = lease.Prefix()

		if err != nil {
			return nil, err
		}

		self.log.Infof("Next IP from IP store: %s", prefix.String())
	} else {
		prefix, err = netip.ParsePrefix(hostIP)

		if err != nil {
			return nil, err
		}
	}

	// Create host certificate details from the request
	details := cert.TBSCertificate{
		Name:      hostName,
		Networks:  []netip.Prefix{prefix},
		Groups:    groups,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(duration),
		IsCA:      false, // This is a host certificate, not a CA
		Version:   cert.Version1,
		PublicKey: hostPub,
	}

	// Sign the new certificate using the CA
	signedCert, err := details.Sign(caCert, cert.Curve_CURVE25519, hostKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign host certificate: %v", err)
	}

	// Encode the certificate and key into Nebula's PEM-style format
	hostCertPEM, err := signedCert.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to encode host cert: %v", err)
	}

	hostKeyPEM := cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, hostKey)

	self.log.Info("Host certificate generated successfully.")

	return &CertificatePair{
		CertPEM: hostCertPEM,
		KeyPEM:  hostKeyPEM,
	}, nil
}
