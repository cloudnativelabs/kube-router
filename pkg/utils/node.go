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
	netutils "k8s.io/utils/net"
)

// nodeAddressMap contains Kubernetes node address types (apiv1.NodeAddressType) grouped by Kubernetes Node Object
// address type (internal / external).
type nodeAddressMap map[apiv1.NodeAddressType][]apiv1.NodeAddress

// addressMap contains net.IP addresses grouped by Kubernetes Node Object address type (internal / external).
type addressMap map[apiv1.NodeAddressType][]net.IP

// KRNode is a struct that holds information about a node that is used by kube-router.
type KRNode struct {
	NodeIPv4Addrs addressMap
	NodeIPv6Addrs addressMap
	NodeName      string
	PrimaryIP     net.IP
}

// LocalKRNode is a struct that holds information about this kube-router node.
type LocalKRNode struct {
	KRNode
	NodeInterfaceName string
	linkQ             LocalLinkQuerier
	sloppyTCP         SysctlConfig
}

// NodeIPAware is an interface that provides methods to get the node's IP addresses in various data structures.
type NodeIPAware interface {
	FindBestIPv4NodeAddress() net.IP
	FindBestIPv6NodeAddress() net.IP
	GetNodeIPv4Addrs() []net.IP
	GetNodeIPv6Addrs() []net.IP
	GetNodeIPAddrs() []net.IP
	GetPrimaryNodeIP() net.IP
}

// NodeInterfaceAware is an interface that provides methods to get the node's interface name, MTU, and subnet. This
// interface is a collection of functions that are only available if you are running on the node itself, as kube-router
// determines this by looking at the node's interfaces and parsing the address data there. If you attempt to call these
// functions on a remote node, they will return nil or an error.
type NodeInterfaceAware interface {
	GetNodeInterfaceName() string
	GetNodeMTU() (int, error)
}

// NodeFamilyAware is an interface that provides methods to check if a node is IPv4 or IPv6 capable.
type NodeFamilyAware interface {
	IsIPv4Capable() bool
	IsIPv6Capable() bool
}

// NodeNameAware is an interface that provides a method to get the node's name.
type NodeNameAware interface {
	GetNodeName() string
}

// NodeIPAndFamilyAware is an interface that combines the NodeIPAware and NodeFamilyAware interfaces.
type NodeIPAndFamilyAware interface {
	NodeIPAware
	NodeFamilyAware
}

type NodeConfigAware interface {
	SloppyTCP() *SysctlConfig
}

// NodeAware is an interface that combines the NodeIPAware, NodeInterfaceAware, NodeFamilyAware, and NodeNameAware
// interfaces.
type NodeAware interface {
	NodeConfigAware
	NodeIPAware
	NodeInterfaceAware
	NodeFamilyAware
	NodeNameAware
}

// GetNodeIPv4Addrs returns the node's IPv4 addresses as defined by the Kubernetes Node Object.
func (n *KRNode) GetNodeIPv4Addrs() []net.IP {
	var nodeIPs []net.IP
	nodeIPs = append(nodeIPs, n.NodeIPv4Addrs[apiv1.NodeInternalIP]...)
	nodeIPs = append(nodeIPs, n.NodeIPv4Addrs[apiv1.NodeExternalIP]...)
	return nodeIPs
}

// GetNodeIPv6Addrs returns the node's IPv6 addresses as defined by the Kubernetes Node Object.
func (n *KRNode) GetNodeIPv6Addrs() []net.IP {
	var nodeIPs []net.IP
	nodeIPs = append(nodeIPs, n.NodeIPv6Addrs[apiv1.NodeInternalIP]...)
	nodeIPs = append(nodeIPs, n.NodeIPv6Addrs[apiv1.NodeExternalIP]...)
	return nodeIPs
}

// GetPrimaryNodeIP returns the node's primary IP address which for the purposes of kube-router is defined as the first
// internal address defined on the Kubernetes node object. If no internal address is defined, the first external address
// is used.
func (n *KRNode) GetPrimaryNodeIP() net.IP {
	return n.PrimaryIP
}

// GetNodeInterfaceName returns the node's interface name as defined by the primary IP address. This function is only
// available if you are running on the node itself, as kube-router determines this by looking at the node's interfaces
// and parsing the address data there. If you attempt to call this function on a remote node, it will return nil.
func (n *LocalKRNode) GetNodeInterfaceName() string {
	return n.NodeInterfaceName
}

// IsIPv4Capable returns true if the node has at least one IPv4 address defined in the Kubernetes Node Object.
func (n *KRNode) IsIPv4Capable() bool {
	return len(n.NodeIPv4Addrs[apiv1.NodeInternalIP]) > 0 || len(n.NodeIPv4Addrs[apiv1.NodeExternalIP]) > 0
}

// IsIPv6Capable returns true if the node has at least one IPv6 address defined in the Kubernetes Node Object.
func (n *KRNode) IsIPv6Capable() bool {
	return len(n.NodeIPv6Addrs[apiv1.NodeInternalIP]) > 0 || len(n.NodeIPv6Addrs[apiv1.NodeExternalIP]) > 0
}

// GetNodeName returns the node's name as defined by the Kubernetes Node Object.
func (n *KRNode) GetNodeName() string {
	return n.NodeName
}

func (n *LocalKRNode) SloppyTCP() *SysctlConfig {
	return &n.sloppyTCP
}

// FindBestIPv6NodeAddress returns the best available IPv6 address for the node. If the primary IP is already an IPv6
// address, it will return that. Otherwise, it will return the first internal or external IPv6 address defined in the
// Kubernetes Node Object.
func (n *KRNode) FindBestIPv6NodeAddress() net.IP {
	if n.PrimaryIP != nil && n.PrimaryIP.To4() == nil && n.PrimaryIP.To16() != nil {
		// the NRC's primary IP is already an IPv6 address, so we'll use that
		return n.PrimaryIP
	}
	// the NRC's primary IP is not an IPv6, let's try to find the best available IPv6 address out of our
	// available node addresses to use as the nextHop for our route
	if n.NodeIPv6Addrs != nil {
		if len(n.NodeIPv6Addrs[apiv1.NodeInternalIP]) > 0 {
			return n.NodeIPv6Addrs[apiv1.NodeInternalIP][0]
		} else if len(n.NodeIPv6Addrs[apiv1.NodeExternalIP]) > 0 {
			return n.NodeIPv6Addrs[apiv1.NodeExternalIP][0]
		}
	}
	return nil
}

// FindBestIPv4NodeAddress returns the best available IPv4 address for the node. If the primary IP is already an IPv4
// address, it will return that. Otherwise, it will return the first internal or external IPv4 address defined in the
// Kubernetes Node Object.
func (n *KRNode) FindBestIPv4NodeAddress() net.IP {
	if n.PrimaryIP != nil && n.PrimaryIP.To4() != nil {
		// the NRC's primary IP is already an IPv6 address, so we'll use that
		return n.PrimaryIP
	}
	// the NRC's primary IP is not an IPv6, let's try to find the best available IPv6 address out of our
	// available node addresses to use as the nextHop for our route
	if n.NodeIPv4Addrs != nil {
		if len(n.NodeIPv4Addrs[apiv1.NodeInternalIP]) > 0 {
			return n.NodeIPv4Addrs[apiv1.NodeInternalIP][0]
		} else if len(n.NodeIPv4Addrs[apiv1.NodeExternalIP]) > 0 {
			return n.NodeIPv4Addrs[apiv1.NodeExternalIP][0]
		}
	}
	return nil
}

// GetNodeMTU returns the MTU of the interface that the node's primary IP address is assigned to. This function is only
// available if you are running on the node itself, as kube-router determines this by looking at the node's interfaces
// and parsing the address data there. If you attempt to call this function on a remote node, it will return an error.
func (n *LocalKRNode) GetNodeMTU() (int, error) {
	links, err := n.linkQ.LinkList()
	if err != nil {
		return 0, fmt.Errorf("failed to get list of links: %w", err)
	}
	for _, link := range links {
		addresses, err := n.linkQ.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return 0, fmt.Errorf("failed to get list of addr: %w", err)
		}
		for _, addr := range addresses {
			if addr.IP.Equal(n.PrimaryIP) {
				linkMTU := link.Attrs().MTU
				return linkMTU, nil
			}
		}
	}
	return 0, errors.New("failed to find interface with specified node IP")
}

// GetNodeIPAddrs returns all of the node's IP addresses (whether internal or external) as defined by the Kubernetes
// Node Object.
func (n *KRNode) GetNodeIPAddrs() []net.IP {
	var nodeIPs []net.IP
	ipv4IPs := n.GetNodeIPv4Addrs()
	nodeIPs = append(nodeIPs, ipv4IPs...)
	ipv6IPs := n.GetNodeIPv6Addrs()
	nodeIPs = append(nodeIPs, ipv6IPs...)
	return nodeIPs
}

// NewKRNode creates a new KRNode object from a Kubernetes Node Object. This function is used when kube-router is
// running on the node itself and has access to the node's interfaces and address data. If you attempt to run this on
// a remote node, it will result in an error as it will not be able to find the correct subnet / interface information.
// For this use-case use NewRemoteKRNode instead. It will also return an error if the node does not have any IPv4 or
// IPv6 addresses defined in the Kubernetes Node Object.
func NewKRNode(node *apiv1.Node, linkQ LocalLinkQuerier, enableIPv4, enableIPv6 bool) (*LocalKRNode, error) {
	if linkQ == nil {
		linkQ = &netlink.Handle{}
	}

	primaryNodeIP, err := getPrimaryNodeIP(node)
	if err != nil {
		return nil, fmt.Errorf("error getting primary NodeIP: %w", err)
	}

	ipv4Addrs, ipv6Addrs := getAllNodeIPs(node)
	if enableIPv4 && len(ipv4Addrs[apiv1.NodeInternalIP]) < 1 &&
		len(ipv4Addrs[apiv1.NodeExternalIP]) < 1 {
		return nil, fmt.Errorf("IPv4 was enabled, but no IPv4 address was found on the node")
	}

	if enableIPv6 && len(ipv6Addrs[apiv1.NodeInternalIP]) < 1 &&
		len(ipv6Addrs[apiv1.NodeExternalIP]) < 1 {
		return nil, fmt.Errorf("IPv6 was enabled, but no IPv6 address was found on the node")
	}

	_, nodeInterfaceName, err := GetNodeSubnet(primaryNodeIP, linkQ)
	if err != nil {
		return nil, fmt.Errorf("error getting node subnet: %w", err)
	}

	krNode := &LocalKRNode{
		KRNode: KRNode{
			NodeName:      node.Name,
			PrimaryIP:     primaryNodeIP,
			NodeIPv4Addrs: ipv4Addrs,
			NodeIPv6Addrs: ipv6Addrs,
		},
		linkQ:             linkQ,
		NodeInterfaceName: nodeInterfaceName,
		// Purposefully set the value of sloppyTCP to 0. This ensures the machine's sloppy_tcp setting remains
		// unchanged when there are no services with both Maglev and DSR enabled.
		sloppyTCP: SysctlConfig{
			name:  IPv4IPVSSloppyTCP,
			value: 0,
		},
	}

	return krNode, nil
}

// NewRemoteKRNode creates a new KRNode object from a Kubernetes Node Object. This function is used when kube-router is
// attempting to parse a remote node and does not have access to the node's interfaces and address data. It will return
// an error if the node does not have any IPv4 or IPv6 addresses defined in the Kubernetes Node Object.
func NewRemoteKRNode(node *apiv1.Node) (*KRNode, error) {
	primaryNodeIP, err := getPrimaryNodeIP(node)
	if err != nil {
		return nil, fmt.Errorf("error getting primary NodeIP: %w", err)
	}

	ipv4Addrs, ipv6Addrs := getAllNodeIPs(node)

	krNode := &KRNode{
		NodeName:      node.Name,
		PrimaryIP:     primaryNodeIP,
		NodeIPv4Addrs: ipv4Addrs,
		NodeIPv6Addrs: ipv6Addrs,
	}

	return krNode, nil
}

// GetNodeObject returns the node API object for the node
func GetNodeObject(clientset kubernetes.Interface, hostnameOverride string) (*apiv1.Node, error) {
	// if env NODE_NAME is not set and node is not registered with hostname, then use host name override
	if hostnameOverride != "" {
		node, err := clientset.CoreV1().Nodes().Get(context.Background(), hostnameOverride, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("unable to get node %s, due to: %w", hostnameOverride, err)
		}
		return node, nil
	}

	// assuming kube-router is running as pod, first check env NODE_NAME
	nodeName := os.Getenv("NODE_NAME")
	if nodeName != "" {
		node, err := clientset.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("unable to get node %s, due to: %w", nodeName, err)
		}
		return node, nil
	}

	// if env NODE_NAME is not set then check if node is register with hostname
	hostName, _ := os.Hostname()
	node, err := clientset.CoreV1().Nodes().Get(context.Background(), hostName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to identify the node by NODE_NAME, %s or --hostname-override: %w", hostName, err)
	}

	return node, nil
}

// getPrimaryNodeIP returns the most valid external facing IP address for a node.
// Order of preference:
// 1. NodeInternalIP
// 2. NodeExternalIP (usually only set on cloud providers usually)
func getPrimaryNodeIP(node *apiv1.Node) (net.IP, error) {
	addresses := node.Status.Addresses
	addressMap := make(nodeAddressMap)
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

// getAllNodeIPs returns all internal and external IP addresses grouped as IPv4 and IPv6 in a map that is indexed by
// the Kubernetes Node Object address type (internal / external).
func getAllNodeIPs(node *apiv1.Node) (addressMap, addressMap) {
	ipAddrv4 := make(addressMap)
	ipAddrv6 := make(addressMap)
	addresses := node.Status.Addresses
	addressesPerType := make(nodeAddressMap)
	for _, address := range addresses {
		addressesPerType[address.Type] = append(addressesPerType[address.Type], address)
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

// GetNodeSubnet returns the subnet and interface name for a given node IP
func GetNodeSubnet(nodeIP net.IP, linkQ LocalLinkQuerier) (net.IPNet, string, error) {
	if linkQ == nil {
		linkQ = &netlink.Handle{}
	}

	links, err := linkQ.LinkList()
	if err != nil {
		return net.IPNet{}, "", fmt.Errorf("failed to get list of links: %w", err)
	}

	for _, link := range links {
		addresses, err := linkQ.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return net.IPNet{}, "", fmt.Errorf("failed to get list of addrs: %w", err)
		}
		for _, addr := range addresses {
			if addr.IP.Equal(nodeIP) {
				return *addr.IPNet, link.Attrs().Name, nil
			}
		}
	}

	return net.IPNet{}, "", errors.New("failed to find interface with specified node ip")
}
