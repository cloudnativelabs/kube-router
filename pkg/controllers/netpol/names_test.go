package netpol

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	api "k8s.io/api/core/v1"
)

const maxIPSetNameLen = 31

// namer wraps every name helper behind one signature so the tests can iterate over all of them
type namer struct {
	name   string
	prefix string
	fn     func(ns, name string, rule, port int, family api.IPFamily) string
	// ipset is true for helpers whose output is an ipset name subject to the 31 character limit
	ipset bool
	// rule and port record which indices the helper must incorporate into the name
	rule, port bool
}

func allNamers() []namer {
	return []namer{
		{
			name:   "podFirewallChain",
			prefix: kubePodFirewallChainPrefix,
			fn: func(ns, n string, _, _ int, _ api.IPFamily) string {
				return podFirewallChainName(ns, n, "1")
			},
			ipset: false,
			rule:  false,
			port:  false,
		},
		{
			name:   "networkPolicyChain",
			prefix: kubeNetworkPolicyChainPrefix,
			fn: func(ns, n string, _, _ int, f api.IPFamily) string {
				return networkPolicyChainName(ns, n, "1", f)
			},
			ipset: false,
			rule:  false,
			port:  false,
		},
		{
			name:   "targetSrcPod",
			prefix: kubeSourceIPSetPrefix,
			fn: func(ns, n string, _, _ int, f api.IPFamily) string {
				return policySourcePodIPSetName(ns, n, f)
			},
			ipset: true,
			rule:  false,
			port:  false,
		},
		{
			name:   "targetDstPod",
			prefix: kubeDestinationIPSetPrefix,
			fn: func(ns, n string, _, _ int, f api.IPFamily) string {
				return policyDestinationPodIPSetName(ns, n, f)
			},
			ipset: true,
			rule:  false,
			port:  false,
		},
		{
			name:   "srcPod",
			prefix: kubeSourceIPSetPrefix,
			fn: func(ns, n string, r, _ int, f api.IPFamily) string {
				return policyIndexedSourcePodIPSetName(ns, n, r, f)
			},
			ipset: true,
			rule:  true,
			port:  false,
		},
		{
			name:   "dstPod",
			prefix: kubeDestinationIPSetPrefix,
			fn: func(ns, n string, r, _ int, f api.IPFamily) string {
				return policyIndexedDestinationPodIPSetName(ns, n, r, f)
			},
			ipset: true,
			rule:  true,
			port:  false,
		},
		{
			name:   "srcIPBlock",
			prefix: kubeSourceIPSetPrefix,
			fn: func(ns, n string, r, _ int, f api.IPFamily) string {
				return policyIndexedSourceIPBlockIPSetName(ns, n, r, f)
			},
			ipset: true,
			rule:  true,
			port:  false,
		},
		{
			name:   "dstIPBlock",
			prefix: kubeDestinationIPSetPrefix,
			fn: func(ns, n string, r, _ int, f api.IPFamily) string {
				return policyIndexedDestinationIPBlockIPSetName(ns, n, r, f)
			},
			ipset: true,
			rule:  true,
			port:  false,
		},
		{
			name:   "srcIPBlockExcept",
			prefix: kubeSourceIPSetPrefix,
			fn: func(ns, n string, r, _ int, f api.IPFamily) string {
				return indexedSourceIPBlockExceptSetName(ns, n, r, f)
			},
			ipset: false,
			rule:  true,
			port:  false,
		},
		{
			name:   "dstIPBlockExcept",
			prefix: kubeDestinationIPSetPrefix,
			fn: func(ns, n string, r, _ int, f api.IPFamily) string {
				return indexedDestinationIPBlockExceptSetName(ns, n, r, f)
			},
			ipset: false,
			rule:  true,
			port:  false,
		},
		{
			name:   "ingressNamedPort",
			prefix: kubeDestinationIPSetPrefix,
			fn:     policyIndexedIngressNamedPortIPSetName,
			ipset:  true,
			rule:   true,
			port:   true,
		},
		{
			name:   "egressNamedPort",
			prefix: kubeDestinationIPSetPrefix,
			fn:     policyIndexedEgressNamedPortIPSetName,
			ipset:  true,
			rule:   true,
			port:   true,
		},
		{
			name:   "srcIPBlockChain",
			prefix: kubeNetworkPolicyChainPrefix,
			fn: func(ns, n string, r, _ int, f api.IPFamily) string {
				return indexedSourceIPBlockChainName(ns, n, r, f)
			},
			ipset: false,
			rule:  true,
			port:  false,
		},
		{
			name:   "dstIPBlockChain",
			prefix: kubeNetworkPolicyChainPrefix,
			fn: func(ns, n string, r, _ int, f api.IPFamily) string {
				return indexedDestinationIPBlockChainName(ns, n, r, f)
			},
			ipset: false,
			rule:  true,
			port:  false,
		},
	}
}

func TestNameBoundaryCollisions(t *testing.T) {
	for _, n := range allNamers() {
		t.Run(n.name, func(t *testing.T) {
			a := n.fn("a", "bc", 1, 1, api.IPv4Protocol)
			b := n.fn("ab", "c", 1, 1, api.IPv4Protocol)
			assert.NotEqual(t, a, b, "namespace/name boundary must be part of the hash")
		})
	}
}

func TestNameIndexCollisions(t *testing.T) {
	for _, n := range allNamers() {
		t.Run(n.name, func(t *testing.T) {
			base := n.fn("ns", "pol", 1, 1, api.IPv4Protocol)
			if n.rule {
				assert.NotEqual(t, base, n.fn("ns", "pol", 2, 1, api.IPv4Protocol), "rule index must change the name")
			} else {
				assert.Equal(t, base, n.fn("ns", "pol", 2, 1, api.IPv4Protocol), "rule index should be unused")
			}
			if n.port {
				assert.NotEqual(t, base, n.fn("ns", "pol", 1, 2, api.IPv4Protocol), "port index must change the name")
			} else {
				assert.Equal(t, base, n.fn("ns", "pol", 1, 2, api.IPv4Protocol), "port index should be unused")
			}
			if n.rule && n.port {
				a := n.fn("ns", "pol", 1, 12, api.IPv4Protocol)
				b := n.fn("ns", "pol", 11, 2, api.IPv4Protocol)
				assert.NotEqual(t, a, b, "rule index and named port index must be separate parts")
			}
		})
	}
}

func TestNameKindsAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for _, n := range allNamers() {
		name := n.fn("ns", "pol", 0, 0, api.IPv4Protocol)
		if other, ok := seen[name]; ok {
			t.Errorf("%s and %s produce the same name %s", n.name, other, name)
		}
		seen[name] = n.name
	}
}

func TestNameFamiliesAreDistinct(t *testing.T) {
	for _, n := range allNamers() {
		t.Run(n.name, func(t *testing.T) {
			v4 := n.fn("ns", "pol", 0, 0, api.IPv4Protocol)
			v6 := n.fn("ns", "pol", 0, 0, api.IPv6Protocol)
			if n.name == "podFirewallChain" {
				assert.Equal(t, v4, v6, "pod firewall chains are shared across families")
				return
			}
			assert.NotEqual(t, v4, v6)
		})
	}
}

func TestNameFormat(t *testing.T) {
	longNS := strings.Repeat("n", 63)
	longName := strings.Repeat("p", 253)
	for _, n := range allNamers() {
		for _, f := range []api.IPFamily{api.IPv4Protocol, api.IPv6Protocol} {
			t.Run(n.name+"/"+string(f), func(t *testing.T) {
				name := n.fn(longNS, longName, 99, 99, f)
				base := strings.TrimPrefix(name, "inet6:")
				if n.ipset && f == api.IPv6Protocol {
					assert.True(t, strings.HasPrefix(name, "inet6:"), "%s should begin with inet6:", name)
				} else {
					assert.False(t, strings.HasPrefix(name, "inet6:"), "%s should not begin with inet6:", name)
				}
				assert.True(t, strings.HasPrefix(base, n.prefix), "%s should begin with %s", base, n.prefix)
				assert.Len(t, base, len(n.prefix)+16)
				if n.ipset {
					assert.LessOrEqual(t, len(name), maxIPSetNameLen)
				}
			})
		}
	}
}

// Pinned outputs make accidental encoding changes show up in review, since changing them renames every object
func TestNamePinnedOutputs(t *testing.T) {
	assert.Equal(t, "KUBE-POD-FW-G66Z676XOE2BPNQM", podFirewallChainName("foo", "bar", "1"))
	assert.Equal(t, "KUBE-NWPLCY-SLHYQ5BEDZLHZJKH", networkPolicyChainName("foo", "bar", "1", api.IPv4Protocol))
	assert.Equal(t, "KUBE-SRC-RZIRFJ7BD4MY2C42", indexedSourcePodSetName("foo", "bar", 1, api.IPv4Protocol))
}

// testPolicyChainName returns the IPv4 chain name for an nsA policy at sync version "1"
func testPolicyChainName(policyName string) string {
	return networkPolicyChainName("nsA", policyName, "1", api.IPv4Protocol)
}
