package ipmanager

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Erik142/veil-certs/pkg/ipmanager/lease"
	"github.com/Erik142/veil-certs/pkg/ipmanager/store"
)

// Errors are now more focused on logic, not storage results.
var (
	ErrNoIPsAvailable = errors.New("no available IP addresses in the pool")
	ErrHostMismatch   = errors.New("the lease for this IP is held by a different host")
	ErrInvalidCIDR    = errors.New("invalid CIDR notation")
	ErrLeaseNotHeld   = errors.New("no lease found for the given host ID")
)

// IPManager defines the interface for managing IP leases.
type IPManager interface {
	RequestIP(hostID string, requestedLeaseTime time.Duration) (*lease.Lease, error)
	ReleaseIP(hostID string, ip net.IP) error
	RenewLease(hostID string, ip net.IP, requestedLeaseTime time.Duration) (*lease.Lease, error)
	GetLease(hostID string) (*lease.Lease, error)
}

// IPLeaseManager manages the logic of leasing IPs from a subnet.
// It is stateless and relies on a LeaseStore for all persistence.
type IPLeaseManager struct {
	subnet           *net.IPNet
	store            store.LeaseStore
	defaultLeaseTime time.Duration
}

// NewIPLeaseManager creates a new manager.
// It requires a LeaseStore to handle persistence.
func NewIPLeaseManager(cidr string, defaultLeaseTime time.Duration, store store.LeaseStore) (IPManager, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCIDR, err)
	}

	return &IPLeaseManager{
		subnet:           ipnet,
		store:            store,
		defaultLeaseTime: defaultLeaseTime,
	}, nil
}

func (self *IPLeaseManager) RequestIP(hostID string, requestedLeaseTime time.Duration) (*lease.Lease, error) {
	leaseDuration := requestedLeaseTime
	if leaseDuration <= 0 {
		leaseDuration = self.defaultLeaseTime
	}

	// 1. Check if the host already has a lease.
	if l, err := self.store.FindLeaseByHostID(hostID); err == nil {
		l.ExpiresAt = time.Now().Add(leaseDuration)
		if err := self.store.CreateOrUpdateLease(l); err != nil {
			return nil, fmt.Errorf("failed to renew lease for existing host: %w", err)
		}
		return l, nil
	}

	// 2. Find an available IP by iterating through the subnet.
	for ip := self.subnet.IP.Mask(self.subnet.Mask); self.subnet.Contains(ip); inc(ip) {
		if ip.Equal(self.subnet.IP) || isBroadcast(ip, self.subnet.Mask) {
			continue
		}

		l, err := self.store.FindLeaseByIP(ip)
		if err == store.ErrLeaseNotFound || (err == nil && time.Now().After(l.ExpiresAt)) {
			netmaskBits, _ := self.subnet.Mask.Size()
			newLease := lease.New(
				net.IP(append([]byte{}, ip...)),
				hostID,
				time.Now().Add(leaseDuration),
				netmaskBits,
			)
			if err := self.store.CreateOrUpdateLease(&newLease); err != nil {
				return nil, fmt.Errorf("failed to create lease: %w", err)
			}
			return &newLease, nil
		}
	}

	return nil, ErrNoIPsAvailable
}

func (self *IPLeaseManager) ReleaseIP(hostID string, ip net.IP) error {
	lease, err := self.store.FindLeaseByIP(ip)
	if err == store.ErrLeaseNotFound {
		return nil // Already free
	}
	if err != nil {
		return fmt.Errorf("could not verify lease for release: %w", err)
	}

	if lease.HostID != hostID {
		return ErrHostMismatch
	}

	return self.store.DeleteLease(ip)
}

func (self *IPLeaseManager) RenewLease(hostID string, ip net.IP, requestedLeaseTime time.Duration) (*lease.Lease, error) {
	lease, err := self.store.FindLeaseByIP(ip)
	if err != nil {
		if err == store.ErrLeaseNotFound {
			return nil, ErrLeaseNotHeld // More specific error for the user
		}
		return nil, fmt.Errorf("could not find lease to renew: %w", err)
	}

	if lease.HostID != hostID {
		return nil, ErrHostMismatch
	}

	leaseDuration := requestedLeaseTime
	if leaseDuration <= 0 {
		leaseDuration = self.defaultLeaseTime
	}

	lease.ExpiresAt = time.Now().Add(leaseDuration)
	if err := self.store.CreateOrUpdateLease(lease); err != nil {
		return nil, fmt.Errorf("failed to update lease for renewal: %w", err)
	}
	return lease, nil
}

func (self *IPLeaseManager) GetLease(hostID string) (*lease.Lease, error) {
	lease, err := self.store.FindLeaseByHostID(hostID)
	if err != nil {
		if err == store.ErrLeaseNotFound {
			return nil, ErrLeaseNotHeld
		}
		return nil, err
	}
	return lease, nil
}

// --- Helper Functions (unchanged) ---

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isBroadcast(ip net.IP, mask net.IPMask) bool {
	bcast := make(net.IP, len(ip))
	for i := range ip {
		bcast[i] = ip[i] | ^mask[i]
	}
	return ip.Equal(bcast)
}
