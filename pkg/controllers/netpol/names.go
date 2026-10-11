package netpol

import (
	"crypto/sha256"
	"encoding/base32"
	"strconv"
	"strings"

	api "k8s.io/api/core/v1"
)

// legacyHashedName reproduces the original naming scheme: parts are concatenated without any separator
func legacyHashedName(prefix string, parts ...string) string {
	hash := sha256.Sum256([]byte(strings.Join(parts, "")))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return prefix + encoded[:16]
}

func podFirewallChainName(namespace, podName string, version string) string {
	return legacyHashedName(kubePodFirewallChainPrefix, namespace, podName, version)
}

func networkPolicyChainName(namespace, policyName string, version string, ipFamily api.IPFamily) string {
	return legacyHashedName(kubeNetworkPolicyChainPrefix, namespace, policyName, version, string(ipFamily))
}

// The helpers below return bare names (no "inet6:" family prefix). The iptables backend wraps them with ipSetName(),
// while the nftables backend uses them as-is because its sets live inside a per-IP-family table.

func sourcePodSetName(namespace, policyName string, ipFamily api.IPFamily) string {
	return legacyHashedName(kubeSourceIPSetPrefix, namespace, policyName, string(ipFamily))
}

func destinationPodSetName(namespace, policyName string, ipFamily api.IPFamily) string {
	return legacyHashedName(kubeDestinationIPSetPrefix, namespace, policyName, string(ipFamily))
}

func indexedSourcePodSetName(namespace, policyName string, ingressRuleNo int, ipFamily api.IPFamily) string {
	return legacyHashedName(kubeSourceIPSetPrefix, namespace, policyName, "ingressrule", strconv.Itoa(ingressRuleNo),
		string(ipFamily), "pod")
}

func indexedDestinationPodSetName(namespace, policyName string, egressRuleNo int, ipFamily api.IPFamily) string {
	return legacyHashedName(kubeDestinationIPSetPrefix, namespace, policyName, "egressrule", strconv.Itoa(egressRuleNo),
		string(ipFamily), "pod")
}

func indexedSourceIPBlockSetName(namespace, policyName string, ingressRuleNo int, ipFamily api.IPFamily) string {
	return legacyHashedName(kubeSourceIPSetPrefix, namespace, policyName, "ingressrule", strconv.Itoa(ingressRuleNo),
		string(ipFamily), "ipblock")
}

func indexedSourceIPBlockExceptSetName(
	namespace, policyName string, ingressRuleNo int, ipFamily api.IPFamily) string {
	return legacyHashedName(kubeSourceIPSetPrefix, namespace, policyName, "ingressrule", strconv.Itoa(ingressRuleNo),
		string(ipFamily), "ipblockexcept")
}

func indexedDestinationIPBlockSetName(
	namespace, policyName string, egressRuleNo int, ipFamily api.IPFamily) string {
	return legacyHashedName(kubeDestinationIPSetPrefix, namespace, policyName, "egressrule", strconv.Itoa(egressRuleNo),
		string(ipFamily), "ipblock")
}

func indexedDestinationIPBlockExceptSetName(
	namespace, policyName string, egressRuleNo int, ipFamily api.IPFamily) string {
	return legacyHashedName(kubeDestinationIPSetPrefix, namespace, policyName, "egressrule", strconv.Itoa(egressRuleNo),
		string(ipFamily), "ipblockexcept")
}

func indexedIngressNamedPortSetName(
	namespace, policyName string, ingressRuleNo, namedPortNo int, ipFamily api.IPFamily) string {
	return legacyHashedName(kubeDestinationIPSetPrefix, namespace, policyName, "ingressrule",
		strconv.Itoa(ingressRuleNo), strconv.Itoa(namedPortNo), string(ipFamily), "namedport")
}

func indexedEgressNamedPortSetName(
	namespace, policyName string, egressRuleNo, namedPortNo int, ipFamily api.IPFamily) string {
	return legacyHashedName(kubeDestinationIPSetPrefix, namespace, policyName, "egressrule",
		strconv.Itoa(egressRuleNo), strconv.Itoa(namedPortNo), string(ipFamily), "namedport")
}

// indexedSourceIPBlockChainName returns the name of a per-rule sub-chain used when an ingress ipBlock rule has except
// CIDRs. Isolating the except-return inside a sub-chain ensures that the return only exits back to the policy chain,
// not past all remaining policy rules.
func indexedSourceIPBlockChainName(namespace, policyName string, ingressRuleNo int, ipFamily api.IPFamily) string {
	return legacyHashedName(kubeNetworkPolicyChainPrefix, namespace, policyName, "ingressrule",
		strconv.Itoa(ingressRuleNo), string(ipFamily), "ipblockchain")
}

// indexedDestinationIPBlockChainName is the egress counterpart of indexedSourceIPBlockChainName
func indexedDestinationIPBlockChainName(namespace, policyName string, egressRuleNo int, ipFamily api.IPFamily) string {
	return legacyHashedName(kubeNetworkPolicyChainPrefix, namespace, policyName, "egressrule",
		strconv.Itoa(egressRuleNo), string(ipFamily), "ipblockchain")
}

func policySourcePodIPSetName(namespace, policyName string, ipFamily api.IPFamily) string {
	return ipSetName(sourcePodSetName(namespace, policyName, ipFamily), ipFamily)
}

func policyDestinationPodIPSetName(namespace, policyName string, ipFamily api.IPFamily) string {
	return ipSetName(destinationPodSetName(namespace, policyName, ipFamily), ipFamily)
}

func policyIndexedSourcePodIPSetName(namespace, policyName string, ingressRuleNo int, ipFamily api.IPFamily) string {
	return ipSetName(indexedSourcePodSetName(namespace, policyName, ingressRuleNo, ipFamily), ipFamily)
}

func policyIndexedDestinationPodIPSetName(
	namespace, policyName string, egressRuleNo int, ipFamily api.IPFamily) string {
	return ipSetName(indexedDestinationPodSetName(namespace, policyName, egressRuleNo, ipFamily), ipFamily)
}

func policyIndexedSourceIPBlockIPSetName(
	namespace, policyName string, ingressRuleNo int, ipFamily api.IPFamily) string {
	return ipSetName(indexedSourceIPBlockSetName(namespace, policyName, ingressRuleNo, ipFamily), ipFamily)
}

func policyIndexedDestinationIPBlockIPSetName(
	namespace, policyName string, egressRuleNo int, ipFamily api.IPFamily) string {
	return ipSetName(indexedDestinationIPBlockSetName(namespace, policyName, egressRuleNo, ipFamily), ipFamily)
}

func policyIndexedIngressNamedPortIPSetName(
	namespace, policyName string, ingressRuleNo, namedPortNo int, ipFamily api.IPFamily) string {
	return ipSetName(indexedIngressNamedPortSetName(namespace, policyName, ingressRuleNo, namedPortNo, ipFamily),
		ipFamily)
}

func policyIndexedEgressNamedPortIPSetName(
	namespace, policyName string, egressRuleNo, namedPortNo int, ipFamily api.IPFamily) string {
	return ipSetName(indexedEgressNamedPortSetName(namespace, policyName, egressRuleNo, namedPortNo, ipFamily),
		ipFamily)
}
