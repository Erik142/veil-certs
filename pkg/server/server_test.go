package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Erik142/veil-certs/pkg/certgen"
	"github.com/Erik142/veil-certs/pkg/keyprovider"
	pb "github.com/Erik142/veil-certs/pkg/proto"
)

// MockCAStore is a mock implementation of castore.CAStore
type MockCAStore struct {
	mock.Mock
}

func (m *MockCAStore) SaveCA(certPEM, keyPEM []byte) error {
	args := m.Called(certPEM, keyPEM)
	return args.Error(0)
}

func (m *MockCAStore) LoadCA() ([]byte, []byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Get(1).([]byte), args.Error(2)
}

func (m *MockCAStore) CAExists() bool {
	args := m.Called()
	return args.Bool(0)
}

// MockKeyPassphraseProvider is a mock implementation of keyprovider.KeyPassphraseProvider
type MockKeyPassphraseProvider struct {
	mock.Mock
}

func (m *MockKeyPassphraseProvider) GetPassphrase() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

// MockCertGenerator is a mock implementation of certgen.CertificateGenerator
type MockCertGenerator struct {
	mock.Mock
}

func (m *MockCertGenerator) GenerateCACertificate(name string, duration time.Duration, encryptKey bool, passphraseProvider keyprovider.KeyPassphraseProvider, subnet string) (*certgen.CertificatePair, error) {
	args := m.Called(name, duration, encryptKey, passphraseProvider, subnet)
	return args.Get(0).(*certgen.CertificatePair), args.Error(1)
}

func (m *MockCertGenerator) GenerateHostCertificateFromPublicKey(caCertPEM, caKeyPEM []byte, passphraseProvider keyprovider.KeyPassphraseProvider, hostName, hostIP string, groups []string, duration time.Duration, publicKey []byte) ([]byte, error) {
	args := m.Called(caCertPEM, caKeyPEM, passphraseProvider, hostName, hostIP, groups, duration, publicKey)
	return args.Get(0).([]byte), args.Error(1)
}

func TestNewCertificateServiceServer(t *testing.T) {
	mockCAStore := new(MockCAStore)
	mockPassphraseProvider := new(MockKeyPassphraseProvider)
	mockCertGenerator := new(MockCertGenerator)

	server := NewCertificateServiceServer(mockCAStore, mockPassphraseProvider, mockCertGenerator)

	assert.NotNil(t, server)
	assert.Equal(t, mockCAStore, server.CAStore)
	assert.Equal(t, mockPassphraseProvider, server.PassphraseProvider)
	assert.Equal(t, mockCertGenerator, server.Generator)
}

func TestGenerateHostCertificate_Success(t *testing.T) {
	mockCAStore := new(MockCAStore)
	mockPassphraseProvider := new(MockKeyPassphraseProvider)
	mockCertGenerator := new(MockCertGenerator)

	server := NewCertificateServiceServer(mockCAStore, mockPassphraseProvider, mockCertGenerator)

	// Mock CAStore.LoadCA
	mockCAStore.On("LoadCA").Return([]byte("ca_cert"), []byte("ca_key"), nil).Once()

	// Mock CertGenerator.GenerateHostCertificateFromPublicKey
	expectedCertPEM := []byte("host_cert")
	mockCertGenerator.On("GenerateHostCertificateFromPublicKey",
		[]byte("ca_cert"),
		[]byte("ca_key"),
		mockPassphraseProvider,
		"test-host",
		"192.168.1.1/24",
		[]string{"group1"},
		10*time.Second,
		[]byte("public_key"),
	).Return(expectedCertPEM, nil).Once()

	req := &pb.GenerateHostCertificateRequest{
		Hostname:        "test-host",
		IpCidr:          "192.168.1.1/24",
		Groups:          []string{"group1"},
		DurationSeconds: 10,
		PublicKey:       []byte("public_key"),
	}

	resp, err := server.GenerateHostCertificate(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, expectedCertPEM, resp.CertPem)

	mockCAStore.AssertExpectations(t)
	mockCertGenerator.AssertExpectations(t)
}

func TestGenerateHostCertificate_LoadCAError(t *testing.T) {
	mockCAStore := new(MockCAStore)
	mockPassphraseProvider := new(MockKeyPassphraseProvider)
	mockCertGenerator := new(MockCertGenerator)

	server := NewCertificateServiceServer(mockCAStore, mockPassphraseProvider, mockCertGenerator)

	// Mock CAStore.LoadCA to return an error
	mockCAStore.On("LoadCA").Return(([]byte)(nil), ([]byte)(nil), errors.New("failed to load CA")).Once()

	req := &pb.GenerateHostCertificateRequest{
		Hostname: "test-host",
	}

	resp, err := server.GenerateHostCertificate(context.Background(), req)
	assert.Nil(t, resp)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
	assert.Contains(t, st.Message(), "failed to load CA")

	mockCAStore.AssertExpectations(t)
	mockCertGenerator.AssertExpectations(t) // Should not be called
}

func TestGenerateHostCertificate_GenerateCertError(t *testing.T) {
	mockCAStore := new(MockCAStore)
	mockPassphraseProvider := new(MockKeyPassphraseProvider)
	mockCertGenerator := new(MockCertGenerator)

	server := NewCertificateServiceServer(mockCAStore, mockPassphraseProvider, mockCertGenerator)

	// Mock CAStore.LoadCA
	mockCAStore.On("LoadCA").Return([]byte("ca_cert"), []byte("ca_key"), nil).Once()

	// Mock CertGenerator.GenerateHostCertificateFromPublicKey to return an error
	mockCertGenerator.On("GenerateHostCertificateFromPublicKey",
		mock.AnythingOfType("[]uint8"),
		mock.AnythingOfType("[]uint8"),
		mockPassphraseProvider,
		mock.AnythingOfType("string"),
		mock.AnythingOfType("string"),
		mock.AnythingOfType("[]string"),
		mock.AnythingOfType("time.Duration"),
		mock.AnythingOfType("[]uint8"),
	).Return(([]byte)(nil), errors.New("failed to generate cert")).Once()

	req := &pb.GenerateHostCertificateRequest{
		Hostname:        "test-host",
		IpCidr:          "192.168.1.1/24",
		Groups:          []string{"group1"},
		DurationSeconds: 10,
		PublicKey:       []byte("public_key"),
	}

	resp, err := server.GenerateHostCertificate(context.Background(), req)
	assert.Nil(t, resp)
	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Contains(t, st.Message(), "failed to generate host certificate")

	mockCAStore.AssertExpectations(t)
	mockCertGenerator.AssertExpectations(t)
}

func TestGenerateHostCertificate_InvalidDuration(t *testing.T) {
	mockCAStore := new(MockCAStore)
	mockPassphraseProvider := new(MockKeyPassphraseProvider)
	mockCertGenerator := new(MockCertGenerator)

	server := NewCertificateServiceServer(mockCAStore, mockPassphraseProvider, mockCertGenerator)

	// Mock CAStore.LoadCA
	mockCAStore.On("LoadCA").Return([]byte("ca_cert"), []byte("ca_key"), nil).Once()

	// Mock CertGenerator.GenerateHostCertificateFromPublicKey with default duration
	expectedCertPEM := []byte("host_cert")
	mockCertGenerator.On("GenerateHostCertificateFromPublicKey",
		mock.AnythingOfType("[]uint8"),
		mock.AnythingOfType("[]uint8"),
		mockPassphraseProvider,
		mock.AnythingOfType("string"),
		mock.AnythingOfType("string"),
		mock.AnythingOfType("[]string"),
		90*24*time.Hour, // Expect default duration
		mock.AnythingOfType("[]uint8"),
	).Return(expectedCertPEM, nil).Once()

	req := &pb.GenerateHostCertificateRequest{
		Hostname:        "test-host",
		IpCidr:          "192.168.1.1/24",
		Groups:          []string{"group1"},
		DurationSeconds: 0, // Invalid duration
		PublicKey:       []byte("public_key"),
	}

	resp, err := server.GenerateHostCertificate(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, expectedCertPEM, resp.CertPem)

	mockCAStore.AssertExpectations(t)
	mockCertGenerator.AssertExpectations(t)
}
