package certgen

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"time"

	"github.com/Erik142/veil-certs/pkg/ipmanager"
	"github.com/Erik142/veil-certs/pkg/ipmanager/store/inmem"
	"github.com/Erik142/veil-certs/pkg/keyprovider"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
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
func (c *CertGenerator) GenerateCACertificate(name string, duration time.Duration, encryptKey bool, passphraseProvider keyprovider.KeyPassphraseProvider, subnet string) (*CertificatePair, error) {
	c.log.WithFields(logrus.Fields{
		"name":       name,
		"duration":   duration,
		"encryptKey": encryptKey,
	}).Info("Generating CA certificate.")

	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA keypair: %v", err)
	}

	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subnet: %v", err)
	}

	caDetails := cert.NebulaCertificateDetails{
		Name:      name,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(duration),
		IsCA:      true,
		PublicKey: caPub,
		Curve:     cert.Curve_CURVE25519,
		Subnets:   []*net.IPNet{ipNet},
	}

	caCert := &cert.NebulaCertificate{
		Details: caDetails,
	}

	if err := caCert.Sign(caDetails.Curve, caKey); err != nil {
		return nil, fmt.Errorf("failed to sign CA certificate: %v", err)
	}

	caCertPEM, err := caCert.MarshalToPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to encode CA cert: %w", err)
	}

	caKeyPEM := cert.MarshalSigningPrivateKey(caDetails.Curve, caKey)

	c.log.Info("CA certificate generated successfully.")
	return &CertificatePair{
		CertPEM: caCertPEM,
		KeyPEM:  caKeyPEM,
	}, nil
}

// GenerateHostCertificateFromPublicKey generates a Nebula-compatible host certificate from a public key.
func (c *CertGenerator) GenerateHostCertificateFromPublicKey(caCertPEM, caKeyPEM []byte, passphraseProvider keyprovider.KeyPassphraseProvider, hostName, hostIP string, groups []string, duration time.Duration, publicKey []byte) ([]byte, error) {
	c.log.WithFields(logrus.Fields{
		"hostname": hostName,
		"ip_cidr":  hostIP,
		"groups":   groups,
		"duration": duration,
	}).Info("Received request to generate host certificate from public key.")

	// Parse CA certificate
	caCert, _, err := cert.UnmarshalNebulaCertificateFromPEM(caCertPEM)
	if err != nil {
		return nil, err
	}

	// Parse CA private key
	caKey, _, _, err := cert.UnmarshalSigningPrivateKey(caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %v", err)
	}

	var ip *net.IPNet
	var subnet *net.IPNet

	if hostIP == "" {
		lease, err := c.ipManager.RequestIP(hostName, duration)

		if err != nil {
			return nil, err
		}

		if subnet, err = lease.IPNet(); err != nil {
			return nil, err
		}

		c.log.Infof("Received dynamic IP address: %s", lease.String())
	} else {
		if _, subnet, err = net.ParseCIDR(hostIP); err != nil {
			return nil, fmt.Errorf("failed to parse host IP: %v", err)
		}
	}

	ip = subnet

	// Create host certificate details from the request
	details := cert.NebulaCertificateDetails{
		Name:      hostName,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(duration),
		IsCA:      false,
		PublicKey: publicKey,
		Curve:     cert.Curve_CURVE25519,
		Groups:    groups,
		Ips:       []*net.IPNet{ip},
		Subnets:   []*net.IPNet{subnet},
	}

	hostCert := &cert.NebulaCertificate{
		Details: details,
	}

	if err := hostCert.Sign(caCert.Details.Curve, caKey); err != nil {
		return nil, fmt.Errorf("failed to sign host certificate: %v", err)
	}

	// Encode the certificate to PEM format
	certPEM, err := hostCert.MarshalToPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to encode certificate: %v", err)
	}

	c.log.Info("Host certificate generated successfully.")
	return certPEM, nil
}
