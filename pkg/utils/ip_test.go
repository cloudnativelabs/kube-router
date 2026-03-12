package utils

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIP_Equal(t *testing.T) {
	tests := []struct {
		name     string
		ip1      net.IP
		ip2      net.IP
		expected bool
	}{
		{
			name:     "IPv4 equal",
			ip1:      net.IPv4(192, 168, 1, 1),
			ip2:      net.IPv4(192, 168, 1, 1),
			expected: true,
		},
		{
			name:     "IPv4 not equal",
			ip1:      net.IPv4(192, 168, 1, 1),
			ip2:      net.IPv4(192, 168, 1, 2),
			expected: false,
		},
		{
			name:     "IPv4 mapped IPv6 equal to IPv4",
			ip1:      net.IPv4(192, 168, 1, 1),
			ip2:      net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1},
			expected: true,
		},
		{
			name:     "nil IPs equal",
			ip1:      nil,
			ip2:      nil,
			expected: true,
		},
		{
			name:     "nil and non-nil IP not equal",
			ip1:      nil,
			ip2:      net.IPv4(192, 168, 1, 1),
			expected: false,
		},
		{
			name:     "IPv6 equal",
			ip1:      net.IPv6loopback,
			ip2:      net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ip1.Equal(tt.ip2))
		})
	}
}

func TestIP_To4(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected net.IP
	}{
		{
			name:     "Valid IPv4",
			ip:       net.IPv4(192, 168, 1, 1),
			expected: net.IP{192, 168, 1, 1},
		},
		{
			name:     "IPv4-mapped IPv6",
			ip:       net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1},
			expected: net.IP{192, 168, 1, 1},
		},
		{
			name:     "Pure IPv6",
			ip:       net.IPv6loopback,
			expected: nil,
		},
		{
			name:     "nil IP",
			ip:       nil,
			expected: nil,
		},
		{
			name:     "Invalid length IP",
			ip:       net.IP{1, 2, 3},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ip.To4())
		})
	}
}

func TestIPNet_Contains(t *testing.T) {
	tests := []struct {
		name     string
		network  *net.IPNet
		ip       net.IP
		expected bool
	}{
		{
			name: "IPv4 in network",
			network: &net.IPNet{
				IP:   net.IPv4(192, 168, 1, 0),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			ip:       net.IPv4(192, 168, 1, 1),
			expected: true,
		},
		{
			name: "IPv4 not in network",
			network: &net.IPNet{
				IP:   net.IPv4(192, 168, 1, 0),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			ip:       net.IPv4(192, 168, 2, 1),
			expected: false,
		},
		{
			name: "IPv6 in network",
			network: &net.IPNet{
				IP:   net.IPv6loopback,
				Mask: net.CIDRMask(128, 128),
			},
			ip:       net.IPv6loopback,
			expected: true,
		},
		{
			name: "Mismatched IP versions",
			network: &net.IPNet{
				IP:   net.IPv4(192, 168, 1, 0),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			ip:       net.IPv6loopback,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.network.Contains(tt.ip))
		})
	}
}

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		name        string
		cidr        string
		expectError bool
		expectedIP  net.IP
		expectedNet *net.IPNet
	}{
		{
			name:        "Valid IPv4 CIDR",
			cidr:        "192.168.1.0/24",
			expectError: false,
			expectedIP:  net.IPv4(192, 168, 1, 0),
			expectedNet: &net.IPNet{
				IP:   net.IPv4(192, 168, 1, 0),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
		},
		{
			name:        "Invalid CIDR format",
			cidr:        "192.168.1.0",
			expectError: true,
		},
		{
			name:        "Invalid prefix length",
			cidr:        "192.168.1.0/33",
			expectError: true,
		},
		{
			name:        "Invalid IP address",
			cidr:        "300.168.1.0/24",
			expectError: true,
		},
		{
			name:        "Empty string",
			cidr:        "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, ipNet, err := net.ParseCIDR(tt.cidr)
			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.True(t, tt.expectedIP.Equal(ip))
			assert.True(t, tt.expectedNet.IP.Equal(ipNet.IP))
			assert.Equal(t, tt.expectedNet.Mask, ipNet.Mask)
		})
	}
}

func TestIP_DefaultMask(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected net.IPMask
	}{
		{
			name:     "Class A",
			ip:       net.IPv4(10, 0, 0, 0),
			expected: net.IPv4Mask(255, 0, 0, 0),
		},
		{
			name:     "Class B",
			ip:       net.IPv4(172, 16, 0, 0),
			expected: net.IPv4Mask(255, 255, 0, 0),
		},
		{
			name:     "Class C",
			ip:       net.IPv4(192, 168, 0, 0),
			expected: net.IPv4Mask(255, 255, 255, 0),
		},
		{
			name:     "IPv6 address",
			ip:       net.IPv6loopback,
			expected: nil,
		},
		{
			name:     "nil IP",
			ip:       nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ip.DefaultMask())
		})
	}
}

func TestIP_IsPrivate(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected bool
	}{
		{
			name:     "Private IPv4 10.x.x.x",
			ip:       net.IPv4(10, 0, 0, 1),
			expected: true,
		},
		{
			name:     "Private IPv4 172.16.x.x",
			ip:       net.IPv4(172, 16, 0, 1),
			expected: true,
		},
		{
			name:     "Private IPv4 192.168.x.x",
			ip:       net.IPv4(192, 168, 0, 1),
			expected: true,
		},
		{
			name:     "Public IPv4",
			ip:       net.IPv4(8, 8, 8, 8),
			expected: false,
		},
		{
			name:     "Private IPv6 fc00::/7",
			ip:       net.IP{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			expected: true,
		},
		{
			name:     "Public IPv6",
			ip:       net.IPv6loopback,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ip.IsPrivate())
		})
	}
}

func TestGetSingleIPNet(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected *net.IPNet
	}{
		{
			name: "IPv4 address",
			ip:   net.IPv4(192, 168, 1, 1),
			expected: &net.IPNet{
				IP:   net.IPv4(192, 168, 1, 1),
				Mask: net.CIDRMask(32, 32),
			},
		},
		{
			name: "IPv4-mapped IPv6 address",
			ip:   net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1},
			expected: &net.IPNet{
				IP:   net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1},
				Mask: net.CIDRMask(32, 32),
			},
		},
		{
			name: "IPv6 address",
			ip:   net.IPv6loopback,
			expected: &net.IPNet{
				IP:   net.IPv6loopback,
				Mask: net.CIDRMask(128, 128),
			},
		},
		{
			name: "Another IPv6 address",
			ip:   net.IP{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			expected: &net.IPNet{
				IP:   net.IP{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
				Mask: net.CIDRMask(128, 128),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetSingleIPNet(tt.ip)
			require.NotNil(t, result)
			assert.True(t, tt.expected.IP.Equal(result.IP))
			assert.Equal(t, tt.expected.Mask, result.Mask)
		})
	}
}

func mustParseCIDR(t *testing.T, cidr string) net.IPNet {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("failed to parse CIDR %q: %v", cidr, err)
	}
	return *ipnet
}

func TestIsIPInRanges(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		ranges []string
		want   bool
	}{
		{
			name:   "IP within single range",
			ip:     "10.0.0.5",
			ranges: []string{"10.0.0.0/24"},
			want:   true,
		},
		{
			name:   "IP outside single range",
			ip:     "192.168.1.1",
			ranges: []string{"10.0.0.0/24"},
			want:   false,
		},
		{
			name:   "IP within second of two ranges",
			ip:     "172.16.0.5",
			ranges: []string{"10.0.0.0/24", "172.16.0.0/16"},
			want:   true,
		},
		{
			name:   "IP outside all ranges",
			ip:     "8.8.8.8",
			ranges: []string{"10.0.0.0/8", "172.16.0.0/12"},
			want:   false,
		},
		{
			name:   "empty ranges",
			ip:     "10.0.0.1",
			ranges: []string{},
			want:   false,
		},
		{
			name:   "IPv6 within range",
			ip:     "fd00::5",
			ranges: []string{"fd00::/64"},
			want:   true,
		},
		{
			name:   "IPv6 outside range",
			ip:     "fe80::1",
			ranges: []string{"fd00::/64"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tt.ip)
			assert.NotNil(t, ip, "test IP should be valid")

			ranges := make([]net.IPNet, len(tt.ranges))
			for i, r := range tt.ranges {
				ranges[i] = mustParseCIDR(t, r)
			}

			got := IsIPInRanges(ip, ranges)
			assert.Equal(t, tt.want, got)
		})
	}
}
