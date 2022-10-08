package utils

import (
	"fmt"
	"net"
	"strings"

	v1core "k8s.io/api/core/v1"
	netutils "k8s.io/utils/net"
)

const (
	// deprecated - we now use multiple CIDRs, so it is better for users to use kube-router.io/pod-cidrs which allows
	// you to express all of the cidrs you want to advertise from a given node
	podCIDRAnnotation  = "kube-router.io/pod-cidr"
	podCIDRsAnnotation = "kube-router.io/pod-cidrs"
)

// GetPodCidrFromNodeSpec reads the pod CIDR allocated to the node from API node object and returns it
func GetPodCidrFromNodeSpec(node *v1core.Node) (string, error) {
	if cidr, ok := node.Annotations[podCIDRAnnotation]; ok {
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			return "", fmt.Errorf("error parsing pod CIDR in node annotation: %v", err)
		}

		return cidr, nil
	}

	if node.Spec.PodCIDR == "" {
		return "", fmt.Errorf("node.Spec.PodCIDR not set for node: %v", node.Name)
	}

	return node.Spec.PodCIDR, nil
}

// GetPodCIDRsFromNodeSpecDualStack reads the IPv4 and IPv6 pod CIDR allocated
// to the node from API node object and returns them
func GetPodCIDRsFromNodeSpecDualStack(node *v1core.Node) ([]string, []string, error) {
	var podIPv4CIDRs, podIPv6CIDRs []string

	if podCIDRs, ok := node.Annotations[podCIDRsAnnotation]; ok {
		for _, cidr := range strings.Split(podCIDRs, ",") {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return podIPv4CIDRs, podIPv6CIDRs, fmt.Errorf("error parsing pod CIDR in node annotation: %v", err)
			}
			if netutils.IsIPv4CIDRString(cidr) {
				podIPv4CIDRs = append(podIPv4CIDRs, cidr)
			}
			if netutils.IsIPv6CIDRString(cidr) {
				podIPv6CIDRs = append(podIPv6CIDRs, cidr)
			}
		}
		return podIPv4CIDRs, podIPv6CIDRs, nil
	}

	if len(node.Spec.PodCIDRs) == 0 {
		return nil, nil, fmt.Errorf("node.Spec.PodCIDRs empty for node: %v", node.Name)
	}

	for _, podCIDR := range node.Spec.PodCIDRs {
		if netutils.IsIPv4CIDRString(podCIDR) {
			podIPv4CIDRs = append(podIPv4CIDRs, podCIDR)
		}
		if netutils.IsIPv6CIDRString(podCIDR) {
			podIPv6CIDRs = append(podIPv6CIDRs, podCIDR)
		}
	}

	return podIPv4CIDRs, podIPv6CIDRs, nil
}
