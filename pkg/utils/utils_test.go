package utils

import (
	"net"
	"testing"
)

// ipv6LoopbackAvailable reports whether this host can bind an IPv6 loopback
// listener. Without it, the IPv6 test cases below can't be exercised.
func ipv6LoopbackAvailable(t *testing.T) bool {
	t.Helper()
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func TestTCPAddressBindable(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		needsV6 bool
		wantErr bool
	}{
		{
			name: "IPv4 loopback is bindable",
			addr: "127.0.0.1",
		},
		{
			name: "empty address binds all interfaces",
			addr: "",
		},
		{
			// A bare IPv6 literal must be joined with net.JoinHostPort so that the
			// colons in the address are not confused with the host:port separator.
			name:    "IPv6 loopback is bindable",
			addr:    "::1",
			needsV6: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.needsV6 && !ipv6LoopbackAvailable(t) {
				t.Skip("IPv6 loopback not available on this host")
			}

			// Port 0 lets the kernel pick a free ephemeral port so the test does
			// not collide with anything already listening on the host.
			err := TCPAddressBindable(tt.addr, 0)
			if (err != nil) != tt.wantErr {
				t.Errorf("TCPAddressBindable(%q, 0) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
		})
	}
}
