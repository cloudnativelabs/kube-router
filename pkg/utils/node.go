package utils

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/vishvananda/netlink"

	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// GetNodeObject returns the node API object for the node
func GetNodeObject(clientset kubernetes.Interface, hostnameOverride string) (*apiv1.Node, error) {
	// assuming kube-router is running as pod, first check env NODE_NAME
	nodeName := os.Getenv("NODE_NAME")
	if nodeName != "" {
		node, err := clientset.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
		if err == nil {
			return node, nil
		}
	}

	// if env NODE_NAME is not set then check if node is register with hostname
	hostName, _ := os.Hostname()
	node, err := clientset.CoreV1().Nodes().Get(context.Background(), hostName, metav1.GetOptions{})
	if err == nil {
		return node, nil
	}

	// if env NODE_NAME is not set and node is not registered with hostname, then use host name override
	if hostnameOverride != "" {
		node, err = clientset.CoreV1().Nodes().Get(context.Background(), hostnameOverride, metav1.GetOptions{})
		if err == nil {
			return node, nil
		}
	}

	return nil, fmt.Errorf("failed to identify the node by NODE_NAME, hostname or --hostname-override")
}

// GetNodeIP returns the most valid external facing IP address for a node.
// Order of preference:
// 1. NodeInternalIP
// 2. NodeExternalIP (Only set on cloud providers usually)
func GetNodeIP(node *apiv1.Node) (net.IP, error) {
	addresses := node.Status.Addresses
	addressMap := make(map[apiv1.NodeAddressType][]apiv1.NodeAddress)
	for i := range addresses {
		addressMap[addresses[i].Type] = append(addressMap[addresses[i].Type], addresses[i])
	}
	if addresses, ok := addressMap[apiv1.NodeInternalIP]; ok {
		return net.ParseIP(addresses[0].Address), nil
	}
	if addresses, ok := addressMap[apiv1.NodeExternalIP]; ok {
		return net.ParseIP(addresses[0].Address), nil
	}
	return nil, errors.New("host IP unknown")
}

// GetMTUFromNodeIP returns the MTU by detecting it from the IP on the node and figuring in tunneling configurations
func GetMTUFromNodeIP(nodeIP net.IP, overlayEnabled bool) (int, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return 0, errors.New("failed to get list of links")
	}
	for _, link := range links {
		addresses, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return 0, errors.New("failed to get list of addr")
		}
		for _, addr := range addresses {
			if addr.IPNet.IP.Equal(nodeIP) {
				linkMTU := link.Attrs().MTU
				if overlayEnabled {
					return linkMTU - 20, nil // -20 to accommodate IPIP header
				}
				return linkMTU, nil
			}
		}
	}
	return 0, errors.New("failed to find interface with specified node IP")
}

// GetNextFamilyNodeIP is used in the dual stack case and returns the Node IP from
// the address family that is not the same as that returned from GetNodeIP
func GetNextFamilyNodeIP(node *apiv1.Node, firstNodeIP net.IP) (net.IP, error) {
	addresses := node.Status.Addresses
	addressMap := make(map[apiv1.NodeAddressType][]apiv1.NodeAddress)
	for i := range addresses {
		addressMap[addresses[i].Type] = append(addressMap[addresses[i].Type], addresses[i])
	}
	for _, address := range addressMap[apiv1.NodeInternalIP] {
		if !MatchAddressFamily(net.ParseIP(address.Address), firstNodeIP) {
			return net.ParseIP(address.Address), nil
		}
	}

	for _, address := range addressMap[apiv1.NodeExternalIP] {
		if !MatchAddressFamily(net.ParseIP(address.Address), firstNodeIP) {
			return net.ParseIP(address.Address), nil
		}
	}

	return nil, errors.New("Unable to find suitable next IP for dual-stack")
}

// IsNodeDualStack returns true after finding both an IPv4 and IPv6 address in either
// NodeInternalIP or NodeExternalIP, else returns false.  Consider changing to look at
// IPv6DualStack feature gate when promoted to core
func IsNodeDualStack(node *apiv1.Node) bool {
	hasv4 := false
	hasv6 := false

	addresses := node.Status.Addresses
	for i := range addresses {
		if addresses[i].Type == apiv1.NodeInternalIP || addresses[i].Type == apiv1.NodeExternalIP {
			if net.ParseIP(addresses[i].Address).To4() != nil {
				hasv4 = true
			} else if net.ParseIP(addresses[i].Address).To16() != nil {
				hasv6 = true
			}
			if hasv4 && hasv6 {
				return true
			}
		}
	}
	return false
}
