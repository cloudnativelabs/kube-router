package bgp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
