package tunnels

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GenerateTunnelName(t *testing.T) {
	testcases := []struct {
		name       string
		nodeIP     string
		tunnelName string
	}{
		{
			"IP less than 12 characters after removing '.'",
			"10.0.0.1",
			"tun-e443169117a",
		},
		{
			"IP has 12 characters after removing '.'",
			"100.200.300.400",
			"tun-9033d7906c7",
		},
		{
			"IPv6 tunnel names are properly handled and consistent",
			"2001:db8:42:2::/64",
			"tun-ba56986ef05",
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			tunnelName := GenerateTunnelName(testcase.nodeIP)
			assert.Lessf(t, len(tunnelName), 16, "the maximum length of the tunnel name should never exceed"+
				"15 characters as 16 characters is the maximum length of a Unix interface name")
			assert.Equal(t, testcase.tunnelName, tunnelName, "did not get expected tunnel interface name")
		})
	}
}
