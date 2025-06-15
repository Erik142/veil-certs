package store

import (
	"errors"
	"net"

	"github.com/Erik142/veil-certs/pkg/ipmanager/lease"
)

// We define a store-specific error to be returned by implementations.
var (
	ErrLeaseNotFound = errors.New("lease not found")
)

// LeaseStore defines the interface for any storage backend that manages leases.
// Implementations of this interface must be safe for concurrent use.
type LeaseStore interface {
	// FindLeaseByHostID retrieves a lease using the host's unique identifier.
	FindLeaseByHostID(hostID string) (*lease.Lease, error)
	// FindLeaseByIP retrieves a lease using its IP address.
	FindLeaseByIP(ip net.IP) (*lease.Lease, error)
	// CreateOrUpdateLease saves a new lease or updates an existing one.
	CreateOrUpdateLease(lease *lease.Lease) error
	// DeleteLease removes a lease from the store.
	DeleteLease(ip net.IP) error
}
