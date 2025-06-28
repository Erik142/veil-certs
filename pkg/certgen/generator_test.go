package certgen

import (
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/Erik142/veil-certs/pkg/ipmanager/lease"
	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockKeyPassphraseProvider is a mock implementation of keyprovider.KeyPassphraseProvider
type MockKeyPassphraseProvider struct {
	mock.Mock
}

func (m *MockKeyPassphraseProvider) GetPassphrase() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

// MockIPManager is a mock implementation of ipmanager.IPManager
type MockIPManager struct {
	mock.Mock
}

func (m *MockIPManager) RequestIP(hostID string, requestedLeaseTime time.Duration) (*lease.Lease, error) {
	args := m.Called(hostID, requestedLeaseTime)
	return args.Get(0).(*lease.Lease), args.Error(1)
}

func (m *MockIPManager) ReleaseIP(hostID string, ip net.IP) error {
	args := m.Called(hostID, ip)
	return args.Error(0)
}

func (m *MockIPManager) RenewLease(hostID string, ip net.IP, requestedLeaseTime time.Duration) (*lease.Lease, error) {
	args := m.Called(hostID, ip, requestedLeaseTime)
	return args.Get(0).(*lease.Lease), args.Error(1)
}

func (m *MockIPManager) GetLease(hostID string) (*lease.Lease, error) {
	args := m.Called(hostID)
	return args.Get(0).(*lease.Lease), args.Error(1)
}

func TestNewCertGenerator(t *testing.T) {
	gen, err := NewCertGenerator("192.168.100.0/24")
	require.NoError(t, err)
	assert.NotNil(t, gen)
	assert.NotNil(t, gen.ipManager)
}

func TestGenerateCACertificate(t *testing.T) {
	gen, err := NewCertGenerator("192.168.100.0/24")
	require.NoError(t, err)

	mockPassphraseProvider := new(MockKeyPassphraseProvider)
	mockPassphraseProvider.On("GetPassphrase").Return("testpass", nil)

	certPair, err := gen.GenerateCACertificate(
		"test-ca",
		24*time.Hour,
		false,
		mockPassphraseProvider,
		"192.168.100.0/24",
	)

	require.NoError(t, err)
	assert.NotNil(t, certPair)
	assert.NotEmpty(t, certPair.CertPEM)
	assert.NotEmpty(t, certPair.KeyPEM)

	// Verify the generated CA certificate
	caCert, _, err := cert.UnmarshalNebulaCertificateFromPEM(certPair.CertPEM)
	require.NoError(t, err)
	assert.True(t, caCert.Details.IsCA)
	assert.Equal(t, "test-ca", caCert.Details.Name)
	assert.Len(t, caCert.Details.Subnets, 1)
	assert.Equal(t, "192.168.100.0/24", caCert.Details.Subnets[0].String())
}

func TestGenerateHostCertificateFromPublicKey(t *testing.T) {
	gen, err := NewCertGenerator("192.168.100.0/24")
	require.NoError(t, err)

	mockIPManager := new(MockIPManager)
	gen.ipManager = mockIPManager // Replace the real ipManager with the mock

	mockPassphraseProvider := new(MockKeyPassphraseProvider)
	mockPassphraseProvider.On("GetPassphrase").Return("testpass", nil)

	// Generate a dummy CA certificate and key for testing
	caCertPair, err := gen.GenerateCACertificate(
		"test-ca",
		24*time.Hour,
		false,
		mockPassphraseProvider,
		"192.168.100.0/24",
	)
	require.NoError(t, err)

	// Generate a dummy public key for the host
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Test with dynamic IP
	expectedIP := net.ParseIP("192.168.100.10")
	_, expectedSubnet, _ := net.ParseCIDR("192.168.100.10/32")
	lease := lease.New(expectedIP, "test-host", time.Now().Add(time.Hour), 32)
	mockIPManager.On("RequestIP", "test-host", mock.AnythingOfType("time.Duration")).Return(&lease, nil).Once()

	hostCertPEM, err := gen.GenerateHostCertificateFromPublicKey(
		caCertPair.CertPEM,
		caCertPair.KeyPEM,
		mockPassphraseProvider,
		"test-host",
		"", // Dynamic IP
		[]string{"group1", "group2"},
		12*time.Hour,
		pub,
	)
	require.NoError(t, err)
	assert.NotNil(t, hostCertPEM)

	// Verify the generated host certificate
	hostCert, _, err := cert.UnmarshalNebulaCertificateFromPEM(hostCertPEM)
	require.NoError(t, err)
	assert.False(t, hostCert.Details.IsCA)
	assert.Equal(t, "test-host", hostCert.Details.Name)
	assert.Contains(t, hostCert.Details.Groups, "group1")
	assert.Contains(t, hostCert.Details.Groups, "group2")
	assert.Len(t, hostCert.Details.Ips, 1)
	assert.Equal(t, expectedIP.String(), hostCert.Details.Ips[0].IP.String())
	assert.Len(t, hostCert.Details.Subnets, 1)
	assert.Equal(t, expectedSubnet.String(), hostCert.Details.Subnets[0].String())

	mockIPManager.AssertExpectations(t)

	// Test with static IP
	staticIP := "192.168.100.20/24"
	subnetIP, staticSubnet, _ := net.ParseCIDR(staticIP)
	staticSubnet.IP = subnetIP

	hostCertPEM, err = gen.GenerateHostCertificateFromPublicKey(
		caCertPair.CertPEM,
		caCertPair.KeyPEM,
		mockPassphraseProvider,
		"static-host",
		staticIP, // Static IP
		[]string{"group3"},
		12*time.Hour,
		pub,
	)
	require.NoError(t, err)
	assert.NotNil(t, hostCertPEM)

	hostCert, _, err = cert.UnmarshalNebulaCertificateFromPEM(hostCertPEM)
	require.NoError(t, err)
	assert.False(t, hostCert.Details.IsCA)
	assert.Equal(t, "static-host", hostCert.Details.Name)
	assert.Contains(t, hostCert.Details.Groups, "group3")
	assert.Len(t, hostCert.Details.Ips, 1)
	assert.Equal(t, staticSubnet.IP.String(), hostCert.Details.Ips[0].IP.String())
	assert.Len(t, hostCert.Details.Subnets, 1)
	assert.Equal(t, staticSubnet.String(), hostCert.Details.Subnets[0].String())
}

