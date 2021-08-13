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

func Test_validateCommunity(t *testing.T) {
	t.Run("BGP community specified as a 32-bit integer should pass validation", func(t *testing.T) {
		assert.Nil(t, validateCommunity("4294967041"))
		assert.Nil(t, validateCommunity("4294967295"))
	})
	t.Run("BGP community specified as 2 16-bit integers should pass validation", func(t *testing.T) {
		assert.Nil(t, validateCommunity("65535:65281"))
		assert.Nil(t, validateCommunity("65535:65535"))
	})
	t.Run("Well known BGP communities passed as a string should pass validation", func(t *testing.T) {
		assert.Nil(t, validateCommunity("no-export"))
		assert.Nil(t, validateCommunity("internet"))
		assert.Nil(t, validateCommunity("planned-shut"))
		assert.Nil(t, validateCommunity("accept-own"))
		assert.Nil(t, validateCommunity("blackhole"))
		assert.Nil(t, validateCommunity("no-advertise"))
		assert.Nil(t, validateCommunity("no-peer"))
	})
	t.Run("BGP community that is greater than 32-bit integer should fail validation", func(t *testing.T) {
		assert.Error(t, validateCommunity("4294967296"))
	})
	t.Run("BGP community that is greater than 2 16-bit integers should fail validation", func(t *testing.T) {
		assert.Error(t, validateCommunity("65536:65535"))
		assert.Error(t, validateCommunity("65535:65536"))
		assert.Error(t, validateCommunity("65536:65536"))
	})
	t.Run("BGP community that is not a number should fail validation", func(t *testing.T) {
		assert.Error(t, validateCommunity("0xFFFFFFFF"))
		assert.Error(t, validateCommunity("community"))
	})
}
