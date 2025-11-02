package bgp

import (
	"net"
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/internal/testutils"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestPeerConfig_String(t *testing.T) {
	tests := []struct {
		name     string
		config   PeerConfig
		expected string
	}{
		{
			name:     "empty PeerConfig",
			config:   PeerConfig{},
			expected: "PeerConfig{}",
		},
		{
			name: "LocalIP",
			config: PeerConfig{
				LocalIP: testutils.ValToPtr("192.168.1.1"),
			},
			expected: "PeerConfig{LocalIP: 192.168.1.1}",
		},
		{
			name: "Port",
			config: PeerConfig{
				Port: testutils.ValToPtr(uint32(179)),
			},
			expected: "PeerConfig{Port: 179}",
		},
		{
			name: "RemoteASN",
			config: PeerConfig{
				RemoteASN: testutils.ValToPtr(uint32(65000)),
			},
			expected: "PeerConfig{RemoteASN: 65000}",
		},
		{
			name: "RemoteIP",
			config: PeerConfig{
				RemoteIP: testutils.ValToPtr(net.ParseIP("10.0.0.1")),
			},
			expected: "PeerConfig{RemoteIP: 10.0.0.1}",
		},
		{
			name: "RemoteIP with IPv6",
			config: PeerConfig{
				RemoteIP: testutils.ValToPtr(net.ParseIP("2001:db8::1")),
			},
			expected: "PeerConfig{RemoteIP: 2001:db8::1}",
		},
		{
			name: "Password - should not be printed",
			config: PeerConfig{
				Password: testutils.ValToPtr(utils.Base64String("password")),
			},
			expected: "PeerConfig{}",
		},
		{
			name: "all fields - Password should not be printed",
			config: PeerConfig{
				LocalIP:   testutils.ValToPtr("192.168.1.1"),
				Password:  testutils.ValToPtr(utils.Base64String("password")),
				Port:      testutils.ValToPtr(uint32(179)),
				RemoteASN: testutils.ValToPtr(uint32(65000)),
				RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.1")),
			},
			expected: "PeerConfig{LocalIP: 192.168.1.1, Port: 179, RemoteASN: 65000, RemoteIP: 10.0.0.1}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPeerConfigs_String(t *testing.T) {
	tests := []struct {
		name     string
		configs  PeerConfigs
		expected string
	}{
		{
			name:     "empty PeerConfigs",
			configs:  PeerConfigs{},
			expected: "PeerConfigs[]",
		},
		{
			name: "PeerConfig - password should not be printed",
			configs: PeerConfigs{
				{
					LocalIP:   testutils.ValToPtr("192.168.1.1"),
					Password:  testutils.ValToPtr(utils.Base64String("secret")),
					Port:      testutils.ValToPtr(uint32(179)),
					RemoteASN: testutils.ValToPtr(uint32(65000)),
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.1")),
				},
			},
			expected: "PeerConfigs[PeerConfig{LocalIP: 192.168.1.1, Port: 179, RemoteASN: 65000, RemoteIP: 10.0.0.1}]",
		},
		{
			name: "multiple PeerConfigs - passwords should not be printed",
			configs: PeerConfigs{
				{
					LocalIP:   testutils.ValToPtr("192.168.1.1"),
					Password:  testutils.ValToPtr(utils.Base64String("secret")),
					RemoteASN: testutils.ValToPtr(uint32(65000)),
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.1")),
				},
				{
					Port:      testutils.ValToPtr(uint32(1790)),
					RemoteASN: testutils.ValToPtr(uint32(65001)),
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.2")),
				},
				{
					RemoteIP: testutils.ValToPtr(net.ParseIP("10.0.0.3")),
				},
			},
			expected: "PeerConfigs[PeerConfig{LocalIP: 192.168.1.1, RemoteASN: 65000, RemoteIP: 10.0.0.1},PeerConfig{Port: 1790, RemoteASN: 65001, RemoteIP: 10.0.0.2},PeerConfig{RemoteIP: 10.0.0.3}]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.configs.String())
		})
	}
}

func Test_NewPeerConfigs(t *testing.T) {
	tcs := []struct {
		name                string
		remoteIPs           []string
		remoteASNs          []uint32
		ports               []uint32
		b64EncodedPasswords []string
		localIPs            []string
		localAddress        string
		errStringContains   string
	}{
		{
			name: "all fields set to nil",
		},
		{
			name:              "number of remote IPs and remote ASNs don't match",
			remoteIPs:         []string{"10.0.0.1", "10.0.0.2"},
			remoteASNs:        []uint32{1234},
			errStringContains: "the number of IPs and ASN numbers must be equal",
		},
		{
			name:                "number of remote IPs and passwords don't match",
			remoteIPs:           []string{"10.0.0.1", "10.0.0.2"},
			remoteASNs:          []uint32{1234, 2345},
			b64EncodedPasswords: []string{"fakepassword"},
			errStringContains:   "number of passwords",
		},
		{
			name:              "number of remote IPs and ports don't match",
			remoteIPs:         []string{"10.0.0.1", "10.0.0.2"},
			remoteASNs:        []uint32{1234, 2345},
			ports:             []uint32{8080},
			errStringContains: "number of ports",
		},
		{
			name:              "number of remote IPs and local IPs don't match",
			remoteIPs:         []string{"10.0.0.1", "10.0.0.2"},
			remoteASNs:        []uint32{1234, 2345},
			localIPs:          []string{"1.1.1.1"},
			errStringContains: "number of localIPs",
		},
		{
			name:              "remoteASN contains a reserved ASN number",
			remoteIPs:         []string{"10.0.0.1", "10.0.0.2"},
			remoteASNs:        []uint32{0, 2345},
			errStringContains: "reserved ASN",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPeerConfigs(tc.remoteIPs, tc.remoteASNs, tc.ports, tc.b64EncodedPasswords, tc.localIPs, tc.localAddress)
			if tc.errStringContains != "" {
				assert.ErrorContains(t, err, tc.errStringContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
