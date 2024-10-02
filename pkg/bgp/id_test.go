package bgp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ValidateCommunity(t *testing.T) {
	t.Run("BGP community specified as a 32-bit integer should pass validation", func(t *testing.T) {
		assert.Nil(t, ValidateCommunity("4294967041"))
		assert.Nil(t, ValidateCommunity("4294967295"))
	})
	t.Run("BGP community specified as 2 16-bit integers should pass validation", func(t *testing.T) {
		assert.Nil(t, ValidateCommunity("65535:65281"))
		assert.Nil(t, ValidateCommunity("65535:65535"))
	})
	t.Run("Well known BGP communities passed as a string should pass validation", func(t *testing.T) {
		assert.Nil(t, ValidateCommunity("no-export"))
		assert.Nil(t, ValidateCommunity("internet"))
		assert.Nil(t, ValidateCommunity("planned-shut"))
		assert.Nil(t, ValidateCommunity("accept-own"))
		assert.Nil(t, ValidateCommunity("blackhole"))
		assert.Nil(t, ValidateCommunity("no-advertise"))
		assert.Nil(t, ValidateCommunity("no-peer"))
	})
	t.Run("BGP community that is greater than 32-bit integer should fail validation", func(t *testing.T) {
		assert.Error(t, ValidateCommunity("4294967296"))
	})
	t.Run("BGP community that is greater than 2 16-bit integers should fail validation", func(t *testing.T) {
		assert.Error(t, ValidateCommunity("65536:65535"))
		assert.Error(t, ValidateCommunity("65535:65536"))
		assert.Error(t, ValidateCommunity("65536:65536"))
	})
	t.Run("BGP community that is not a number should fail validation", func(t *testing.T) {
		assert.Error(t, ValidateCommunity("0xFFFFFFFF"))
		assert.Error(t, ValidateCommunity("community"))
	})
}
