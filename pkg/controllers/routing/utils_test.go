package routing

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_stringSliceToIPs(t *testing.T) {
	t.Run("When receive an empty slice it returns an empty ip slice", func(t *testing.T) {
		ips, err := stringSliceToIPs([]string{})
		assert.Nil(t, err)
		assert.Equal(t, []net.IP{}, ips)
	})
	t.Run("When receive an ip string slice it returns an ip slice", func(t *testing.T) {
		ips, err := stringSliceToIPs([]string{"192.168.0.1", "10.0.0.1"})
		assert.Nil(t, err)
		assert.Equal(t, []net.IP{net.ParseIP("192.168.0.1"), net.ParseIP("10.0.0.1")}, ips)
	})
	t.Run("When receive an invalid ip string slice it returns an error", func(t *testing.T) {
		ips, err := stringSliceToIPs([]string{"500.168.0.1"})
		assert.Equal(t, "could not parse \"500.168.0.1\" as an IP", err.Error())
		assert.Nil(t, ips)
		ips, err = stringSliceToIPs([]string{"invalid"})
		assert.Equal(t, "could not parse \"invalid\" as an IP", err.Error())
		assert.Nil(t, ips)
	})
}

func Test_stringSliceToIPNets(t *testing.T) {
	t.Run("When receive an empty slice it returns an empty ip slice", func(t *testing.T) {
		ips, err := stringSliceToIPNets([]string{})
		assert.Nil(t, err)
		assert.Equal(t, []net.IPNet{}, ips)
	})
	t.Run("When receive an ip string slice it returns an ip slice ignoring trailing spaces", func(t *testing.T) {
		ips, err := stringSliceToIPNets([]string{" 192.168.0.1/24", "10.0.0.1/16 "})
		assert.Nil(t, err)
		_, firstIPNet, _ := net.ParseCIDR("192.168.0.1/24")
		_, secondIPNet, _ := net.ParseCIDR("10.0.0.1/16")
		assert.Equal(t, []net.IPNet{*firstIPNet, *secondIPNet}, ips)
	})
	t.Run("When receive an invalid ip string slice it returns an error", func(t *testing.T) {
		ips, err := stringSliceToIPNets([]string{"500.168.0.1/24"})
		assert.Equal(t, "could not parse \"500.168.0.1/24\" as an CIDR", err.Error())
		assert.Nil(t, ips)
		ips, err = stringSliceToIPNets([]string{"10.0.0.1/80"})
		assert.Equal(t, "could not parse \"10.0.0.1/80\" as an CIDR", err.Error())
		assert.Nil(t, ips)
	})
}

func Test_stringSliceB64Decode(t *testing.T) {
	tests := []struct {
		name      string
		input     []string
		expected  []string
		errorText string
	}{
		{
			name:     "valid values",
			input:    []string{"cGFzc3dvcmQ=", "c2VjcmV0"},
			expected: []string{"password", "secret"},
		},
		{
			name:      "invalid value is not returned in error",
			input:     []string{"sensitive-value"},
			errorText: "could not parse value as a base64 encoded string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := stringSliceB64Decode(tt.input)
			if tt.errorText != "" {
				assert.EqualError(t, err, tt.errorText)
				assert.Nil(t, actual)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
