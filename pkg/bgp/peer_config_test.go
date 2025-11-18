package bgp

import (
	"net"
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/internal/testutils"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/goccy/go-yaml"
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
			name: "Password should not be printed",
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
			expected: "PeerConfig{Port: 179, LocalIP: 192.168.1.1, RemoteASN: 65000, RemoteIP: 10.0.0.1}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(st *testing.T) {
			result := tt.config.String()
			assert.Equal(st, tt.expected, result)
		})
	}
}

func TestPeerConfig_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expected      PeerConfig
		errorContains string
	}{
		{
			name:     "empty YAML",
			expected: PeerConfig{},
		},
		{
			name:          "remote IP not set returns error",
			input:         []byte(`remoteasn: 1234`),
			errorContains: "remoteip cannot be empty",
		},
		{
			name:          "remote asn not set returns error",
			input:         []byte(`remoteip: 1.1.1.1`),
			errorContains: "remoteasn cannot be empty",
		},
		{
			name: "invalid remote IP",
			input: []byte(`remoteip: 1234.12
remoteasn: 1234`),
			errorContains: "is not a valid IP address",
		},
		{
			name: "valid peer config YAML",
			input: []byte(`remoteip: 1.1.1.1
remoteasn: 1234
password: aGVsbG8=
`),
			expected: PeerConfig{
				Password:  testutils.ValToPtr(utils.Base64String("hello")),
				RemoteIP:  testutils.ValToPtr(net.ParseIP("1.1.1.1")),
				RemoteASN: testutils.ValToPtr(uint32(1234)),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(st *testing.T) {
			var actual PeerConfig
			err := yaml.Unmarshal(tt.input, &actual)
			if tt.errorContains != "" {
				assert.ErrorContains(st, err, tt.errorContains)
			} else {
				assert.NoError(st, err)
				assert.Equal(st, tt.expected, actual)
			}
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
			expected: "PeerConfigs[PeerConfig{Port: 179, LocalIP: 192.168.1.1, RemoteASN: 65000, RemoteIP: 10.0.0.1}]",
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
					Port:      testutils.ValToPtr(uint32(179)),
					RemoteASN: testutils.ValToPtr(uint32(65001)),
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.2")),
				},
				{
					RemoteIP: testutils.ValToPtr(net.ParseIP("10.0.0.3")),
				},
			},
			expected: "PeerConfigs[PeerConfig{LocalIP: 192.168.1.1, RemoteASN: 65000, RemoteIP: 10.0.0.1},PeerConfig{Port: 179, RemoteASN: 65001, RemoteIP: 10.0.0.2},PeerConfig{RemoteIP: 10.0.0.3}]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(st *testing.T) {
			assert.Equal(st, tt.expected, tt.configs.String())
		})
	}
}

func TestPeerConfigs_LocalIPs(t *testing.T) {
	tests := []struct {
		name     string
		pcs      PeerConfigs
		expected []string
	}{
		{
			name: "peer configs with no local IP set returns empty strings",
			pcs: PeerConfigs{
				{
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.1")),
					RemoteASN: testutils.ValToPtr(uint32(1234)),
				},
				{
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.2")),
					RemoteASN: testutils.ValToPtr(uint32(1235)),
				},
			},
			expected: []string{"", ""},
		},
		{
			name: "peer configs with local IPs returns list of IPs as strings",
			pcs: PeerConfigs{
				{
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.1")),
					RemoteASN: testutils.ValToPtr(uint32(1234)),
					LocalIP:   testutils.ValToPtr("192.168.0.1"),
				},
				{
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.2")),
					RemoteASN: testutils.ValToPtr(uint32(1235)),
					LocalIP:   testutils.ValToPtr("192.168.0.2"),
				},
			},
			expected: []string{"192.168.0.1", "192.168.0.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(st *testing.T) {
			actual := tt.pcs.LocalIPs()
			assert.Equal(st, tt.expected, actual)
		})
	}
}

func TestPeerConfigs_Ports(t *testing.T) {
	tests := []struct {
		name     string
		pcs      PeerConfigs
		expected []uint32
	}{
		{
			name: "peer configs with no ports set returns default ports",
			pcs: PeerConfigs{
				{
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.1")),
					RemoteASN: testutils.ValToPtr(uint32(1234)),
				},
				{
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.2")),
					RemoteASN: testutils.ValToPtr(uint32(1235)),
				},
			},
			expected: []uint32{options.DefaultBgpPort, options.DefaultBgpPort},
		},
		{
			name: "peer configs with ports set returns list of ports",
			pcs: PeerConfigs{
				{
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.1")),
					RemoteASN: testutils.ValToPtr(uint32(1234)),
					Port:      testutils.ValToPtr(uint32(1790)),
				},
				{
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.2")),
					RemoteASN: testutils.ValToPtr(uint32(1235)),
					Port:      testutils.ValToPtr(uint32(1791)),
				},
			},
			expected: []uint32{1790, 1791},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(st *testing.T) {
			actual := tt.pcs.Ports()
			assert.Equal(st, tt.expected, actual)
		})
	}
}

func Test_NewPeerConfigs(t *testing.T) {
	tests := []struct {
		name                string
		remoteIPs           []string
		remoteASNs          []uint32
		ports               []uint32
		b64EncodedPasswords []string
		localIPs            []string
		localAddress        string
		errorContains       string
	}{
		{
			name: "all fields set to nil returns nothing",
		},
		{
			name:          "number of remote IPs and remote ASNs don't match returns error",
			remoteIPs:     []string{"10.0.0.1", "10.0.0.2"},
			remoteASNs:    []uint32{1234},
			errorContains: "the number of IPs and ASN numbers must be equal",
		},
		{
			name:                "number of remote IPs and passwords don't match returns error",
			remoteIPs:           []string{"10.0.0.1", "10.0.0.2"},
			remoteASNs:          []uint32{1234, 2345},
			b64EncodedPasswords: []string{"fakepassword"},
			errorContains:       "number of passwords",
		},
		{
			name:          "number of remote IPs and ports don't match returns error",
			remoteIPs:     []string{"10.0.0.1", "10.0.0.2"},
			remoteASNs:    []uint32{1234, 2345},
			ports:         []uint32{8080},
			errorContains: "number of ports",
		},
		{
			name:          "number of remote IPs and local IPs don't match returns error",
			remoteIPs:     []string{"10.0.0.1", "10.0.0.2"},
			remoteASNs:    []uint32{1234, 2345},
			localIPs:      []string{"1.1.1.1"},
			errorContains: "number of localIPs",
		},
		{
			name:          "remoteASN contains a reserved ASN number returns error",
			remoteIPs:     []string{"10.0.0.1", "10.0.0.2"},
			remoteASNs:    []uint32{0, 2345},
			errorContains: "reserved ASN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPeerConfigs(tt.remoteIPs, tt.remoteASNs, tt.ports, tt.b64EncodedPasswords, tt.localIPs, tt.localAddress)
			if tt.errorContains != "" {
				assert.ErrorContains(t, err, tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
