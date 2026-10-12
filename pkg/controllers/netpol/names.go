package netpol

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strconv"

	api "k8s.io/api/core/v1"
)

// Kinds keep the different object types that share a prefix apart
const (
	kindPodFw               = "podfw"
	kindPolicy              = "policy"
	kindTargetSrcPod        = "target-src-pod"
	kindTargetDstPod        = "target-dst-pod"
	kindSrcPod              = "src-pod"
	kindDstPod              = "dst-pod"
	kindSrcIPBlock          = "src-ipblock"
	kindSrcIPBlockExcept    = "src-ipblock-except"
	kindDstIPBlock          = "dst-ipblock"
	kindDstIPBlockExcept    = "dst-ipblock-except"
	kindSrcIPBlockChain     = "src-ipblock-chain"
	kindDstIPBlockChain     = "dst-ipblock-chain"
	kindIngressNamedPortSet = "ingress-namedport"
	kindEgressNamedPortSet  = "egress-namedport"
)

// hashedName builds PREFIX + base32(sha256(kind, parts...))[:16]. Every field is length-prefixed so that
// ("a","bc") and ("ab","c") can't hash to the same value, and kind is hashed first so that object types sharing a
// prefix stay apart. Changing this encoding renames every object on upgrade, which is only safe because stale-object
// GC selects by prefix and never recomputes old names. The 16 character length keeps "inet6:" + prefix within the
// 31 character ipset name limit.
func hashedName(prefix, kind string, parts ...string) string {
	h := sha256.New()
	for _, p := range append([]string{kind}, parts...) {
		fmt.Fprintf(h, "%d:%s", len(p), p)
	}
	return prefix + base32.StdEncoding.EncodeToString(h.Sum(nil))[:16]
}

func podFirewallChainName(namespace, podName string, version string) string {
	return hashedName(kubePodFirewallChainPrefix, kindPodFw, namespace, podName, version)
}

func networkPolicyChainName(namespace, policyName string, version string, ipFamily api.IPFamily) string {
	return hashedName(kubeNetworkPolicyChainPrefix, kindPolicy, namespace, policyName, version, string(ipFamily))
}

// The helpers below return bare names (no "inet6:" family prefix). The iptables backend wraps them with ipSetName(),
// while the nftables backend uses them as-is because its sets live inside a per-IP-family table.

func sourcePodSetName(namespace, policyName string, ipFamily api.IPFamily) string {
	return hashedName(kubeSourceIPSetPrefix, kindTargetSrcPod, namespace, policyName, string(ipFamily))
}

func destinationPodSetName(namespace, policyName string, ipFamily api.IPFamily) string {
	return hashedName(kubeDestinationIPSetPrefix, kindTargetDstPod, namespace, policyName, string(ipFamily))
}

func indexedSourcePodSetName(namespace, policyName string, ingressRuleNo int, ipFamily api.IPFamily) string {
	return hashedName(kubeSourceIPSetPrefix, kindSrcPod, namespace, policyName, strconv.Itoa(ingressRuleNo),
		string(ipFamily))
}

func indexedDestinationPodSetName(namespace, policyName string, egressRuleNo int, ipFamily api.IPFamily) string {
	return hashedName(kubeDestinationIPSetPrefix, kindDstPod, namespace, policyName, strconv.Itoa(egressRuleNo),
		string(ipFamily))
}

func indexedSourceIPBlockSetName(namespace, policyName string, ingressRuleNo int, ipFamily api.IPFamily) string {
	return hashedName(kubeSourceIPSetPrefix, kindSrcIPBlock, namespace, policyName, strconv.Itoa(ingressRuleNo),
		string(ipFamily))
}

func indexedSourceIPBlockExceptSetName(
	namespace, policyName string, ingressRuleNo int, ipFamily api.IPFamily) string {
	return hashedName(kubeSourceIPSetPrefix, kindSrcIPBlockExcept, namespace, policyName, strconv.Itoa(ingressRuleNo),
		string(ipFamily))
}

func indexedDestinationIPBlockSetName(
	namespace, policyName string, egressRuleNo int, ipFamily api.IPFamily) string {
	return hashedName(kubeDestinationIPSetPrefix, kindDstIPBlock, namespace, policyName, strconv.Itoa(egressRuleNo),
		string(ipFamily))
}

func indexedDestinationIPBlockExceptSetName(
	namespace, policyName string, egressRuleNo int, ipFamily api.IPFamily) string {
	return hashedName(kubeDestinationIPSetPrefix, kindDstIPBlockExcept, namespace, policyName, strconv.Itoa(egressRuleNo),
		string(ipFamily))
}

func indexedIngressNamedPortSetName(
	namespace, policyName string, ingressRuleNo, namedPortNo int, ipFamily api.IPFamily) string {
	return hashedName(kubeDestinationIPSetPrefix, kindIngressNamedPortSet, namespace, policyName,
		strconv.Itoa(ingressRuleNo), strconv.Itoa(namedPortNo), string(ipFamily))
}

func indexedEgressNamedPortSetName(
	namespace, policyName string, egressRuleNo, namedPortNo int, ipFamily api.IPFamily) string {
	return hashedName(kubeDestinationIPSetPrefix, kindEgressNamedPortSet, namespace, policyName,
		strconv.Itoa(egressRuleNo), strconv.Itoa(namedPortNo), string(ipFamily))
}

// indexedSourceIPBlockChainName returns the name of a per-rule sub-chain used when an ingress ipBlock rule has except
// CIDRs. Isolating the except-return inside a sub-chain ensures that the return only exits back to the policy chain,
// not past all remaining policy rules.
func indexedSourceIPBlockChainName(namespace, policyName string, ingressRuleNo int, ipFamily api.IPFamily) string {
	return hashedName(kubeNetworkPolicyChainPrefix, kindSrcIPBlockChain, namespace, policyName,
		strconv.Itoa(ingressRuleNo), string(ipFamily))
}

// indexedDestinationIPBlockChainName is the egress counterpart of indexedSourceIPBlockChainName
func indexedDestinationIPBlockChainName(namespace, policyName string, egressRuleNo int, ipFamily api.IPFamily) string {
	return hashedName(kubeNetworkPolicyChainPrefix, kindDstIPBlockChain, namespace, policyName,
		strconv.Itoa(egressRuleNo), string(ipFamily))
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
