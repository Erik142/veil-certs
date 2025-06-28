package lease

import (
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Lease represents an IP address lease. This struct is shared
// between the manager and the store.
type Lease struct {
	IPAddress net.IP
	HostID    string
	ExpiresAt time.Time
	bits      int
}

func New(ipaddress net.IP, hostId string, expiresAt time.Time, netmaskBits int) Lease {
	return Lease{
		IPAddress: ipaddress,
		HostID:    hostId,
		ExpiresAt: expiresAt,
		bits:      netmaskBits,
	}
}

func (self Lease) Prefix() (netip.Prefix, error) {
	ipstr := fmt.Sprintf("%s/%d", self.IPAddress, self.bits)

	return netip.ParsePrefix(ipstr)
}

func (self Lease) IPNet() (*net.IPNet, error) {
	ip, subnet, err := net.ParseCIDR(self.String())
	subnet.IP = ip

	return subnet, err
}

func (self Lease) String() string {
	if self.IPAddress.String() == "" || self.bits == 0 {
		return ""
	}

	return fmt.Sprintf("%s/%d", self.IPAddress, self.bits)
}
