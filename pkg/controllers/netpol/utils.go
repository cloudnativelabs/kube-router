package netpol

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	api "k8s.io/api/core/v1"
	klog "k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
)

const (
	PodCompleted api.PodPhase = "Completed"
)

// isPodUpdateNetPolRelevant reports whether a pod update can change what a full sync programs. A sync only reads pods
// through isNetPolActionable (targets, peers and local pods alike), so a pod that is not actionable before and after
// the update contributes nothing, and an update that leaves an actionable pod's IPs, host IP and labels alone changes
// nothing either (a Pending to Running transition, a status refresh, a finalizer removal). What matters:
//  1. Does the pod enter or leave the actionable state (IP assigned, finished, ...)?
//  2. For a pod that stays actionable: did its IPs or host IP change (changes how policy is applied on the host)?
//  3. For a pod that stays actionable: did its labels change (potentially changes which NetworkPolicies select it)?
func isPodUpdateNetPolRelevant(oldPod, newPod *api.Pod) bool {
	if isNetPolActionable(oldPod) != isNetPolActionable(newPod) {
		return true
	}
	if !isNetPolActionable(newPod) {
		return false
	}
	return newPod.Status.PodIP != oldPod.Status.PodIP ||
		!reflect.DeepEqual(newPod.Status.PodIPs, oldPod.Status.PodIPs) ||
		newPod.Status.HostIP != oldPod.Status.HostIP ||
		!reflect.DeepEqual(newPod.Labels, oldPod.Labels)
}

func isNetPolActionable(pod *api.Pod) bool {
	return !isFinished(pod) && pod.Status.PodIP != "" && !pod.Spec.HostNetwork
}

func isFinished(pod *api.Pod) bool {
	//nolint:exhaustive // We don't care about PodPending, PodRunning, PodUnknown here as we want those to fall
	// into the false case
	switch pod.Status.Phase {
	case api.PodFailed, api.PodSucceeded, PodCompleted:
		return true
	}
	return false
}

func validateNodePortRange(nodePortOption string) (string, error) {
	const portBitSize = 16

	nodePortValidator := regexp.MustCompile(`^([0-9]+)[:-]([0-9]+)$`)
	if matched := nodePortValidator.MatchString(nodePortOption); !matched {
		return "", fmt.Errorf(
			"failed to parse node port range given: '%s' please see specification in help text", nodePortOption)
	}
	matches := nodePortValidator.FindStringSubmatch(nodePortOption)
	if len(matches) != 3 {
		return "", fmt.Errorf("could not parse port number from range given: '%s'", nodePortOption)
	}
	port1, err := strconv.ParseUint(matches[1], 10, portBitSize)
	if err != nil {
		return "", fmt.Errorf("could not parse first port number from range given: '%s'", nodePortOption)
	}
	port2, err := strconv.ParseUint(matches[2], 10, portBitSize)
	if err != nil {
		return "", fmt.Errorf("could not parse second port number from range given: '%s'", nodePortOption)
	}
	if port1 >= port2 {
		return "", fmt.Errorf("port 1 is greater than or equal to port 2 in range given: '%s'", nodePortOption)
	}
	return fmt.Sprintf("%d:%d", port1, port2), nil
}

func getIPsFromPods(pods []podInfo, family api.IPFamily) []string {
	var ips []string
	for _, pod := range pods {
		//nolint:exhaustive // we don't need exhaustive searching for IP Families
		switch family {
		case api.IPv4Protocol:
			ip, err := getPodIPv4Address(pod)
			if err != nil {
				klog.Warningf("Could not get IPv4 addresses of all pods: %v", err)
				continue
			}
			ips = append(ips, ip)
		case api.IPv6Protocol:
			ip, err := getPodIPv6Address(pod)
			if err != nil {
				klog.Warningf("Could not get IPv6 addresses of all pods: %v", err)
				continue
			}
			ips = append(ips, ip)
		}
	}
	return ips
}

func (npc *NetworkPolicyControllerIptables) createGenericHashIPSet(
	ipsetName, hashType string, ips []string, ipFamily api.IPFamily) {
	setEntries := make([][]string, 0)
	for _, ip := range ips {
		setEntries = append(setEntries, []string{ip, utils.OptionTimeout, "0"})
	}
	npc.ipSetHandlers[ipFamily].RefreshSet(ipsetName, setEntries, hashType)
}

// createPolicyIndexedIPSet creates a policy based ipset and indexes it as an active ipset
func (npc *NetworkPolicyControllerIptables) createPolicyIndexedIPSet(
	activePolicyIPSets map[string]bool, ipsetName, hashType string, ips []string, ipFamily api.IPFamily) {
	activePolicyIPSets[ipsetName] = true
	npc.createGenericHashIPSet(ipsetName, hashType, ips, ipFamily)
}

// createPodWithPortPolicyRule handles the case where port details are provided by the ingress/egress rule and creates
// an iptables rule that matches on both the source/dest IPs and the port. kind is the comment tag for the rule's
// direction (cmtIngressPods or cmtEgressPods).
func (npc *NetworkPolicyControllerIptables) createPodWithPortPolicyRule(ports []protocolAndPort,
	policy networkPolicyInfo, policyName string, srcSetName string, dstSetName string, ipFamily api.IPFamily,
	kind string) error {
	for _, portProtocol := range ports {
		comment := polRuleComment(policy, kind)
		if err := npc.appendRuleToPolicyChain(policyName, comment, srcSetName, dstSetName, portProtocol.protocol,
			portProtocol.port, portProtocol.endport, ipFamily); err != nil {
			return err
		}
	}
	return nil
}

func getPodIPv6Address(pod podInfo) (string, error) {
	for _, ip := range pod.ips {
		if netutils.IsIPv6String(ip.IP) {
			return ip.IP, nil
		}
	}
	return "", fmt.Errorf("pod %s:%s has no IPv6Address, available addresses: %s",
		pod.namespace, pod.name, pod.ips)
}

func getPodIPv4Address(pod podInfo) (string, error) {
	for _, ip := range pod.ips {
		if netutils.IsIPv4String(ip.IP) {
			return ip.IP, nil
		}
	}
	return "", fmt.Errorf("pod %s:%s has no IPv4Address, available addresses: %s",
		pod.namespace, pod.name, pod.ips)
}

func getPodIPForFamily(pod podInfo, ipFamily api.IPFamily) (string, error) {
	//nolint:exhaustive // we don't need exhaustive searching for IP Families
	switch ipFamily {
	case api.IPv4Protocol:
		if ip, err := getPodIPv4Address(pod); err != nil {
			return "", err
		} else {
			return ip, nil
		}
	case api.IPv6Protocol:
		if ip, err := getPodIPv6Address(pod); err != nil {
			return "", err
		} else {
			return ip, nil
		}
	}

	return "", fmt.Errorf("did not recognize IP Family for pod: %s:%s family: %s", pod.namespace, pod.name,
		ipFamily)
}

func ipSetName(setName string, ipFamily api.IPFamily) string {
	if ipFamily == api.IPv4Protocol {
		return utils.IPSetName(setName, false)
	} else {
		return utils.IPSetName(setName, true)
	}
}
