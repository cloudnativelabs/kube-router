package netpol

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

func testNamePrefix(t *testing.T, testString string, isIPv6 bool) {
	if isIPv6 {
		assert.Truef(t, strings.HasPrefix(testString, "inet6:"), "%s is IPv6 and should begin with inet6:", testString)
	}
}

func Test_policySourcePodIPSetName(t *testing.T) {
	t.Run("Check IPv4 and IPv6 names are correct", func(t *testing.T) {
		setName := policySourcePodIPSetName("foo", "bar", v1.IPv4Protocol)
		testNamePrefix(t, setName, false)
		setName = policySourcePodIPSetName("foo", "bar", v1.IPv6Protocol)
		testNamePrefix(t, setName, true)
	})
}

func Test_policyDestinationPodIPSetName(t *testing.T) {
	t.Run("Check IPv4 and IPv6 names are correct", func(t *testing.T) {
		setName := policyDestinationPodIPSetName("foo", "bar", v1.IPv4Protocol)
		testNamePrefix(t, setName, false)
		setName = policyDestinationPodIPSetName("foo", "bar", v1.IPv6Protocol)
		testNamePrefix(t, setName, true)
	})
}

func Test_policyIndexedSourcePodIPSetName(t *testing.T) {
	t.Run("Check IPv4 and IPv6 names are correct", func(t *testing.T) {
		setName := policyIndexedSourcePodIPSetName("foo", "bar", 1, v1.IPv4Protocol)
		testNamePrefix(t, setName, false)
		setName = policyIndexedSourcePodIPSetName("foo", "bar", 1, v1.IPv6Protocol)
		testNamePrefix(t, setName, true)
	})
}

func Test_policyIndexedDestinationPodIPSetName(t *testing.T) {
	t.Run("Check IPv4 and IPv6 names are correct", func(t *testing.T) {
		setName := policyIndexedDestinationPodIPSetName("foo", "bar", 1, v1.IPv4Protocol)
		testNamePrefix(t, setName, false)
		setName = policyIndexedDestinationPodIPSetName("foo", "bar", 1, v1.IPv6Protocol)
		testNamePrefix(t, setName, true)
	})
}

func Test_policyIndexedSourceIPBlockIPSetName(t *testing.T) {
	t.Run("Check IPv4 and IPv6 names are correct", func(t *testing.T) {
		setName := policyIndexedSourceIPBlockIPSetName("foo", "bar", 1, v1.IPv4Protocol)
		testNamePrefix(t, setName, false)
		setName = policyIndexedSourceIPBlockIPSetName("foo", "bar", 1, v1.IPv6Protocol)
		testNamePrefix(t, setName, true)
	})
}

func Test_policyIndexedDestinationIPBlockIPSetName(t *testing.T) {
	t.Run("Check IPv4 and IPv6 names are correct", func(t *testing.T) {
		setName := policyIndexedDestinationIPBlockIPSetName("foo", "bar", 1, v1.IPv4Protocol)
		testNamePrefix(t, setName, false)
		setName = policyIndexedDestinationIPBlockIPSetName("foo", "bar", 1, v1.IPv6Protocol)
		testNamePrefix(t, setName, true)
	})
}

func Test_policyIndexedIngressNamedPortIPSetName(t *testing.T) {
	t.Run("Check IPv4 and IPv6 names are correct", func(t *testing.T) {
		setName := policyIndexedIngressNamedPortIPSetName("foo", "bar", 1, 1, v1.IPv4Protocol)
		testNamePrefix(t, setName, false)
		setName = policyIndexedIngressNamedPortIPSetName("foo", "bar", 1, 1, v1.IPv6Protocol)
		testNamePrefix(t, setName, true)
	})
}

func Test_policyIndexedEgressNamedPortIPSetName(t *testing.T) {
	t.Run("Check IPv4 and IPv6 names are correct", func(t *testing.T) {
		setName := policyIndexedEgressNamedPortIPSetName("foo", "bar", 1, 1, v1.IPv4Protocol)
		testNamePrefix(t, setName, false)
		setName = policyIndexedEgressNamedPortIPSetName("foo", "bar", 1, 1, v1.IPv6Protocol)
		testNamePrefix(t, setName, true)
	})
}
