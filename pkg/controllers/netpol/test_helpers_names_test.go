package netpol

import api "k8s.io/api/core/v1"

// testPolicyChainName returns the IPv4 chain name for an nsA policy at sync version "1"
func testPolicyChainName(policyName string) string {
	return networkPolicyChainName("nsA", policyName, "1", api.IPv4Protocol)
}
