package inmem

import (
	"net"
	"sync"

	"github.com/Erik142/veil-certs/pkg/ipmanager/lease"
	"github.com/Erik142/veil-certs/pkg/ipmanager/store"
)

// --- In-Memory Store Implementation ---

// InMemoryStore is an in-memory implementation of the LeaseStore interface.
type InMemoryStore struct {
	mu             sync.RWMutex
	leasesByIP     map[string]lease.Lease // Primary data store, Key: IP Address string
	leasesByHostID map[string]net.IP      // Secondary index, Key: HostID
}

// NewInMemoryStore creates a new, empty in-memory store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		leasesByIP:     make(map[string]lease.Lease),
		leasesByHostID: make(map[string]net.IP),
	}
}

func (self *InMemoryStore) FindLeaseByHostID(hostID string) (*lease.Lease, error) {
	self.mu.RLock()
	defer self.mu.RUnlock()

	ip, ok := self.leasesByHostID[hostID]
	if !ok {
		return nil, store.ErrLeaseNotFound
	}

	lease := self.leasesByIP[ip.String()]
	return &lease, nil
}

func (self *InMemoryStore) FindLeaseByIP(ip net.IP) (*lease.Lease, error) {
	self.mu.RLock()
	defer self.mu.RUnlock()

	lease, ok := self.leasesByIP[ip.String()]
	if !ok {
		return nil, store.ErrLeaseNotFound
	}
	return &lease, nil
}

func (self *InMemoryStore) CreateOrUpdateLease(lease *lease.Lease) error {
	self.mu.Lock()
	defer self.mu.Unlock()

	ipStr := lease.IPAddress.String()

	// Clean up old index if a different host previously owned this IP.
	if oldLease, exists := self.leasesByIP[ipStr]; exists {
		if oldLease.HostID != lease.HostID {
			delete(self.leasesByHostID, oldLease.HostID)
		}
	}

	self.leasesByIP[ipStr] = *lease
	self.leasesByHostID[lease.HostID] = lease.IPAddress
	return nil
}

func (self *InMemoryStore) DeleteLease(ip net.IP) error {
	self.mu.Lock()
	defer self.mu.Unlock()

	ipStr := ip.String()
	lease, ok := self.leasesByIP[ipStr]
	if !ok {
		return nil // Already deleted
	}

	delete(self.leasesByIP, ipStr)
	delete(self.leasesByHostID, lease.HostID)
	return nil
}
