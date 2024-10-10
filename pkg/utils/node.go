package utils

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/vishvananda/netlink"

	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
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

// GetPrimaryNodeIP returns the most valid external facing IP address for a node.
// Order of preference:
// 1. NodeInternalIP
// 2. NodeExternalIP (Only set on cloud providers usually)
func GetPrimaryNodeIP(node *apiv1.Node) (net.IP, error) {
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

// GetNodeWeight returns the node's weight based on the node's annotations
func GetNodeWeight(node *apiv1.Node, weightAnnotation string) (int, error) {
	var weight int
	var err error

	if weightString, found := node.ObjectMeta.Annotations[weightAnnotation]; found {
		if weight, err = strconv.Atoi(weightString); err == nil {
			return weight, nil
		}
	} else {
		err = fmt.Errorf("weight annotation '%s' not found on node %s", weightAnnotation, node.GetName())
	}

	return -1, err
}

// GetNodeEgressIP returns the node's egress ip or nil if no ip address was specified for the node
func GetNodeEgressIP(node *apiv1.Node, egressIPAnnotation string) net.IP {
	var egressIP net.IP

	if egressIPString, found := node.ObjectMeta.Annotations[egressIPAnnotation]; found {
		egressIP = net.ParseIP(egressIPString)
		if egressIP == nil {
			klog.Warningf("Egress IP annotation '%s' for node '%s' has invalid value '%s'. Using node ip for egress.",
				egressIPAnnotation, node.Name, egressIPString)
		}
	} else {
		klog.V(1).Infof("Egress IP annotation '%s' not found on node '%s'. Using node ip for egress.", egressIPAnnotation, node.Name)
	}

	return egressIP
}

// addressMap is a mapping of address types to a list of addresses of that type.
// It preallocates the slices of addresses.
type addressMap map[apiv1.NodeAddressType][]apiv1.NodeAddress

// add adds an address of the given type to the address map. If the given type
// was not already in the map, it creates a new preallocated entry for it.
func (m addressMap) add(address apiv1.NodeAddress) {
	if _, ok := m[address.Type]; ok {
		m[address.Type] = append(m[address.Type], address)
	} else {
		// There can be at most 2 addresses of the same type.
		m[address.Type] = make([]apiv1.NodeAddress, 2)
		m[address.Type] = append(m[address.Type], address)
	}
}

// GetAllNodeIPs returns all internal and external IP addresses grouped as IPv4 and IPv6
func GetAllNodeIPs(node *apiv1.Node) (map[apiv1.NodeAddressType][]net.IP, map[apiv1.NodeAddressType][]net.IP) {
	ipAddrv4 := make(map[apiv1.NodeAddressType][]net.IP)
	ipAddrv6 := make(map[apiv1.NodeAddressType][]net.IP)
	addresses := node.Status.Addresses
	addressesPerType := make(addressMap)
	for _, address := range addresses {
		addressesPerType.add(address)
	}
	if internalAddresses, ok := addressesPerType[apiv1.NodeInternalIP]; ok {
		for _, address := range internalAddresses {
			if netutils.IsIPv4String(address.Address) {
				ipAddrv4[apiv1.NodeInternalIP] = append(ipAddrv4[apiv1.NodeInternalIP], net.ParseIP(address.Address))
			}
			if netutils.IsIPv6String(address.Address) {
				ipAddrv6[apiv1.NodeInternalIP] = append(ipAddrv6[apiv1.NodeInternalIP], net.ParseIP(address.Address))
			}
		}
	}
	if externalAddresses, ok := addressesPerType[apiv1.NodeExternalIP]; ok {
		for _, address := range externalAddresses {
			if netutils.IsIPv4String(address.Address) {
				ipAddrv4[apiv1.NodeExternalIP] = append(ipAddrv4[apiv1.NodeExternalIP], net.ParseIP(address.Address))
			}
			if netutils.IsIPv6String(address.Address) {
				ipAddrv6[apiv1.NodeExternalIP] = append(ipAddrv6[apiv1.NodeExternalIP], net.ParseIP(address.Address))
			}
		}
	}

	return ipAddrv4, ipAddrv6
}

func FindBestIPv6NodeAddress(priIP net.IP, intExtIPv6Addresses map[apiv1.NodeAddressType][]net.IP) net.IP {
	if priIP != nil && priIP.To4() == nil && priIP.To16() != nil {
		// the NRC's primary IP is already an IPv6 address, so we'll use that
		return priIP
	}
	// the NRC's primary IP is not an IPv6, let's try to find the best available IPv6 address out of our
	// available node addresses to use as the nextHop for our route
	if intExtIPv6Addresses != nil {
		if len(intExtIPv6Addresses[apiv1.NodeInternalIP]) > 0 {
			return intExtIPv6Addresses[apiv1.NodeInternalIP][0]
		} else if len(intExtIPv6Addresses[apiv1.NodeExternalIP]) > 0 {
			return intExtIPv6Addresses[apiv1.NodeExternalIP][0]
		}
	}
	return nil
}

func FindBestIPv4NodeAddress(priIP net.IP, intExtIPv4Addresses map[apiv1.NodeAddressType][]net.IP) net.IP {
	if priIP != nil && priIP.To4() != nil {
		// the NRC's primary IP is already an IPv6 address, so we'll use that
		return priIP
	}
	// the NRC's primary IP is not an IPv6, let's try to find the best available IPv6 address out of our
	// available node addresses to use as the nextHop for our route
	if intExtIPv4Addresses != nil {
		if len(intExtIPv4Addresses[apiv1.NodeInternalIP]) > 0 {
			return intExtIPv4Addresses[apiv1.NodeInternalIP][0]
		} else if len(intExtIPv4Addresses[apiv1.NodeExternalIP]) > 0 {
			return intExtIPv4Addresses[apiv1.NodeExternalIP][0]
		}
	}
	return nil
}

// GetMTUFromNodeIP returns the MTU by detecting it from the IP on the node and figuring in tunneling configurations
func GetMTUFromNodeIP(nodeIP net.IP) (int, error) {
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
				return linkMTU, nil
			}
		}
	}
	return 0, errors.New("failed to find interface with specified node IP")
}
