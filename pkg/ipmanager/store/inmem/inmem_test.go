package inmem

import (
	"net"
	"testing"
	"time"

	"github.com/Erik142/veil-certs/pkg/ipmanager/lease"
	"github.com/Erik142/veil-certs/pkg/ipmanager/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInMemoryStore(t *testing.T) {
	s := NewInMemoryStore()
	assert.NotNil(t, s)
	assert.NotNil(t, s.leasesByIP)
	assert.NotNil(t, s.leasesByHostID)
	assert.Empty(t, s.leasesByIP)
	assert.Empty(t, s.leasesByHostID)
}

func TestCreateOrUpdateLease(t *testing.T) {
	s := NewInMemoryStore()

	// Create a new lease
	ip1 := net.ParseIP("192.168.1.1")
	lease1 := lease.New(ip1, "host1", time.Now().Add(time.Hour), 24)
	err := s.CreateOrUpdateLease(&lease1)
	require.NoError(t, err)

	// Verify it's in the store
	foundLease, err := s.FindLeaseByIP(ip1)
	require.NoError(t, err)
	assert.Equal(t, lease1, *foundLease)

	foundLease, err = s.FindLeaseByHostID("host1")
	require.NoError(t, err)
	assert.Equal(t, lease1, *foundLease)

	// Update an existing lease (same IP, same hostID)
	lease1.ExpiresAt = time.Now().Add(2 * time.Hour)
	err = s.CreateOrUpdateLease(&lease1)
	require.NoError(t, err)

	foundLease, err = s.FindLeaseByIP(ip1)
	require.NoError(t, err)
	assert.Equal(t, lease1.ExpiresAt, foundLease.ExpiresAt)

	// Update an existing lease (same IP, different hostID - should clean up old hostID index)
	lease2 := lease.New(ip1, "host2", time.Now().Add(time.Hour), 24)
	err = s.CreateOrUpdateLease(&lease2)
	require.NoError(t, err)

	_, err = s.FindLeaseByHostID("host1")
	assert.Equal(t, store.ErrLeaseNotFound, err, "Old hostID index should be cleaned up")

	foundLease, err = s.FindLeaseByHostID("host2")
	require.NoError(t, err)
	assert.Equal(t, lease2, *foundLease)
}

func TestFindLeaseByIP(t *testing.T) {
	s := NewInMemoryStore()
	ip1 := net.ParseIP("192.168.1.1")
	lease1 := lease.New(ip1, "host1", time.Now().Add(time.Hour), 24)
	s.CreateOrUpdateLease(&lease1)

	// Find existing lease
	foundLease, err := s.FindLeaseByIP(ip1)
	require.NoError(t, err)
	assert.Equal(t, lease1, *foundLease)

	// Find non-existent lease
	ip2 := net.ParseIP("192.168.1.2")
	_, err = s.FindLeaseByIP(ip2)
	assert.Equal(t, store.ErrLeaseNotFound, err)
}

func TestFindLeaseByHostID(t *testing.T) {
	s := NewInMemoryStore()
	ip1 := net.ParseIP("192.168.1.1")
	lease1 := lease.New(ip1, "host1", time.Now().Add(time.Hour), 24)
	s.CreateOrUpdateLease(&lease1)

	// Find existing lease
	foundLease, err := s.FindLeaseByHostID("host1")
	require.NoError(t, err)
	assert.Equal(t, lease1, *foundLease)

	// Find non-existent lease
	_, err = s.FindLeaseByHostID("host2")
	assert.Equal(t, store.ErrLeaseNotFound, err)
}

func TestDeleteLease(t *testing.T) {
	s := NewInMemoryStore()
	ip1 := net.ParseIP("192.168.1.1")
	lease1 := lease.New(ip1, "host1", time.Now().Add(time.Hour), 24)
	s.CreateOrUpdateLease(&lease1)

	// Delete existing lease
	err := s.DeleteLease(ip1)
	require.NoError(t, err)

	// Verify it's gone
	_, err = s.FindLeaseByIP(ip1)
	assert.Equal(t, store.ErrLeaseNotFound, err)
	_, err = s.FindLeaseByHostID("host1")
	assert.Equal(t, store.ErrLeaseNotFound, err)

	// Delete non-existent lease (should not error)
	ip2 := net.ParseIP("192.168.1.2")
	err = s.DeleteLease(ip2)
	require.NoError(t, err)
}
