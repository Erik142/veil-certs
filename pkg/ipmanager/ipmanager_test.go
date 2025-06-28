package ipmanager

import (
	"net"
	"testing"
	"time"

	"github.com/Erik142/veil-certs/pkg/ipmanager/lease"
	"github.com/Erik142/veil-certs/pkg/ipmanager/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockLeaseStore is a mock implementation of store.LeaseStore
type MockLeaseStore struct {
	mock.Mock
}

func (m *MockLeaseStore) CreateOrUpdateLease(l *lease.Lease) error {
	args := m.Called(l)
	return args.Error(0)
}

func (m *MockLeaseStore) FindLeaseByIP(ip net.IP) (*lease.Lease, error) {
	args := m.Called(ip)
	return args.Get(0).(*lease.Lease), args.Error(1)
}

func (m *MockLeaseStore) FindLeaseByHostID(hostID string) (*lease.Lease, error) {
	args := m.Called(hostID)
	return args.Get(0).(*lease.Lease), args.Error(1)
}

func (m *MockLeaseStore) DeleteLease(ip net.IP) error {
	args := m.Called(ip)
	return args.Error(0)
}

func (m *MockLeaseStore) ListAllLeases() ([]*lease.Lease, error) {
	args := m.Called()
	return args.Get(0).([]*lease.Lease), args.Error(1)
}

func TestNewIPLeaseManager(t *testing.T) {
	mockStore := new(MockLeaseStore)
	manager, err := NewIPLeaseManager("192.168.1.0/24", 1*time.Hour, mockStore)
	require.NoError(t, err)
	assert.NotNil(t, manager)

	// Test invalid CIDR
	_, err = NewIPLeaseManager("invalid-cidr", 1*time.Hour, mockStore)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), ErrInvalidCIDR.Error())
}

func TestRequestIP_ExistingLease(t *testing.T) {
	mockStore := new(MockLeaseStore)
	manager, err := NewIPLeaseManager("192.168.1.0/24", 1*time.Hour, mockStore)
	require.NoError(t, err)

	existingLease := lease.New(net.ParseIP("192.168.1.10"), "host1", time.Now().Add(-time.Hour), 32)
	mockStore.On("FindLeaseByHostID", "host1").Return(&existingLease, nil).Once()
	mockStore.On("CreateOrUpdateLease", mock.AnythingOfType("*lease.Lease")).Return(nil).Once()

	requestedLease, err := manager.RequestIP("host1", 2*time.Hour)
	require.NoError(t, err)
	assert.NotNil(t, requestedLease)
	assert.Equal(t, "host1", requestedLease.HostID)
	assert.True(t, requestedLease.ExpiresAt.After(time.Now()))

	mockStore.AssertExpectations(t)
}

func TestRequestIP_NewLease(t *testing.T) {
	mockStore := new(MockLeaseStore)
	manager, err := NewIPLeaseManager("192.168.1.0/24", 1*time.Hour, mockStore)
	require.NoError(t, err)

	mockStore.On("FindLeaseByHostID", "host2").Return((*lease.Lease)(nil), store.ErrLeaseNotFound).Once()
	mockStore.On("FindLeaseByIP", net.ParseIP("192.168.1.1").To4()).Return((*lease.Lease)(nil), store.ErrLeaseNotFound).Once()
	mockStore.On("CreateOrUpdateLease", mock.AnythingOfType("*lease.Lease")).Return(nil).Once()

	requestedLease, err := manager.RequestIP("host2", 0) // Use default lease time
	require.NoError(t, err)
	assert.NotNil(t, requestedLease)
	assert.Equal(t, "host2", requestedLease.HostID)
	assert.Equal(t, "192.168.1.1/24", requestedLease.String()) // Should get the first available IP
	assert.True(t, requestedLease.ExpiresAt.After(time.Now()))

	mockStore.AssertExpectations(t)
}

func TestRequestIP_NoIPsAvailable(t *testing.T) {
	mockStore := new(MockLeaseStore)
	manager, err := NewIPLeaseManager("192.168.1.254/31", 1*time.Hour, mockStore) // A subnet with only 1 usable IP
	require.NoError(t, err)

	mockStore.On("FindLeaseByHostID", "host3").Return((*lease.Lease)(nil), store.ErrLeaseNotFound).Once()

	_, err = manager.RequestIP("host3", 0)
	assert.Error(t, err)
	assert.Equal(t, ErrNoIPsAvailable, err)

	mockStore.AssertExpectations(t)
}
