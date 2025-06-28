package lease

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLease(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	hostID := "test-host"
	expiresAt := time.Now().Add(time.Hour)
	netmaskBits := 24

	l := New(ip, hostID, expiresAt, netmaskBits)

	assert.Equal(t, ip, l.IPAddress)
	assert.Equal(t, hostID, l.HostID)
	assert.Equal(t, expiresAt, l.ExpiresAt)
	assert.Equal(t, netmaskBits, l.bits)
}

func TestLease_Prefix(t *testing.T) {
	// Test with valid IP and bits
	ip := net.ParseIP("192.168.1.1")
	expiresAt := time.Now().Add(time.Hour)
	netmaskBits := 24
	l := New(ip, "host1", expiresAt, netmaskBits)

	prefix, err := l.Prefix()
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.1/24", prefix.String())

	// Test with invalid bits (should return an error)
	l = New(ip, "host1", expiresAt, 33) // Invalid bits for IPv4
	_, err = l.Prefix()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "prefix length out of range")
}

func TestLease_IPNet(t *testing.T) {
	// Test with valid IP and bits
	ip := net.ParseIP("192.168.1.1")
	expiresAt := time.Now().Add(time.Hour)
	netmaskBits := 24
	l := New(ip, "host1", expiresAt, netmaskBits)

	ipNet, err := l.IPNet()
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.1/24", ipNet.String())

	// Test with invalid IP (empty IPAddress)
	l = New(net.IP{}, "host1", expiresAt, netmaskBits)
	ipNet, err = l.IPNet()
	assert.Error(t, err)
	assert.Nil(t, ipNet)

	// Test with invalid bits (should return an error from ParseCIDR)
	l = New(ip, "host1", expiresAt, 33)
	ipNet, err = l.IPNet()
	assert.Error(t, err)
	assert.Nil(t, ipNet)
}

func TestLease_String(t *testing.T) {
	// Test with valid IP and bits
	ip := net.ParseIP("192.168.1.1")
	expiresAt := time.Now().Add(time.Hour)
	netmaskBits := 24
	l := New(ip, "host1", expiresAt, netmaskBits)
	assert.Equal(t, "192.168.1.1/24", l.String())

	// Test with empty IPAddress
	l = New(net.IP{}, "host1", expiresAt, netmaskBits)
	assert.Equal(t, "", l.String())

	// Test with zero bits
	l = New(ip, "host1", expiresAt, 0)
	assert.Equal(t, "", l.String())
}
