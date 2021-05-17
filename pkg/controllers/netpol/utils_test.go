package netpol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_NewNetworkPolicyController(t *testing.T) {
	t.Run("Node Port range specified with a hyphen should pass validation", func(t *testing.T) {
		portRange, err := validateNodePortRange("1000-2000")
		assert.Nil(t, err)
		assert.NotEmpty(t, portRange)
	})
	t.Run("Node Port range specified with a colon should pass validation", func(t *testing.T) {
		portRange, err := validateNodePortRange("1000:2000")
		assert.Nil(t, err)
		assert.NotEmpty(t, portRange)
	})
	t.Run("Node Port range specified with a high port range should work", func(t *testing.T) {
		portRange, err := validateNodePortRange("40000:42767")
		assert.Nil(t, err)
		assert.NotEmpty(t, portRange)
		portRange, err = validateNodePortRange("50000:65535")
		assert.Nil(t, err)
		assert.NotEmpty(t, portRange)
	})
	t.Run("Node Port range specified with a higher start number should fail validation", func(t *testing.T) {
		portRange, err := validateNodePortRange("2000:1000")
		assert.Error(t, err)
		assert.Empty(t, portRange)
	})
	t.Run("Node Port range specified with same start and end port should fail validation", func(t *testing.T) {
		portRange, err := validateNodePortRange("2000:2000")
		assert.Error(t, err)
		assert.Empty(t, portRange)
	})
	t.Run("Node Port range specified with a port number higher than 16-bits unsigned should fail validation", func(t *testing.T) {
		portRange, err := validateNodePortRange("65535:65537")
		assert.Error(t, err)
		assert.Empty(t, portRange)
	})
}
