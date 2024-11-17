package pkg

import (
	"context"
	"net"
	"sync"
	"time"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/vishvananda/netlink"
)

const (
	HeartBeatCompNetworkRoutesController = iota
	HeartBeatCompLoadBalancerController
	HeartBeatCompNetworkPolicyController
	HeartBeatCompNetworkServicesController
	HeartBeatCompHairpinController
	HeartBeatCompHostRouteSync
	HeartBeatCompMetricsController
)

var (
	HeartBeatCompNames = map[int]string{
		HeartBeatCompNetworkRoutesController:   "NetworkRoutesController",
		HeartBeatCompLoadBalancerController:    "LoadBalancerController",
		HeartBeatCompNetworkPolicyController:   "NetworkPolicyController",
		HeartBeatCompNetworkServicesController: "NetworkServicesController",
		HeartBeatCompHairpinController:         "HairpinController",
		HeartBeatCompHostRouteSync:             "HostRouteSync",
		HeartBeatCompMetricsController:         "MetricsController",
	}
)

// ControllerHeartbeat is the structure to hold the heartbeats sent by controllers
type ControllerHeartbeat struct {
	Component     int
	LastHeartBeat time.Time
}

// RouteSyncer is an interface that defines the methods needed to sync routes to the kernel's routing table
type RouteSyncer interface {
	AddInjectedRoute(dst *net.IPNet, route *netlink.Route)
	DelInjectedRoute(dst *net.IPNet)
	Run(healthChan chan<- *ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup)
	SyncLocalRouteTable() error
	AddBGPPathLister(pl BGPPathLister)
}

// TunnelNamer is an interface that defines the methods needed to generate tunnel names
type TunnelNamer interface {
	GenerateTunnelName(nodeIP string) string
}

// TunnelCleaner is an interface that defines the methods needed to clean up tunnels
type TunnelCleaner interface {
	TunnelNamer
	CleanupTunnel(destinationSubnet *net.IPNet, tunnelName string)
}

// TunnelCreator is an interface that defines the methods needed to set up overlay tunnels
type TunnelCreator interface {
	SetupOverlayTunnel(tunnelName string, nextHop net.IP, nextHopSubnet *net.IPNet) (netlink.Link, error)
	EncapType() string
	EncapPort() uint16
}

// Tunneler is an interface that defines the methods needed to manage tunnels
type Tunneler interface {
	TunnelCleaner
	TunnelCreator
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

// NodeAware is an interface that combines the NodeIPAware, NodeInterfaceAware, NodeFamilyAware, and NodeNameAware
// interfaces.
type NodeAware interface {
	NodeIPAware
	NodeInterfaceAware
	NodeFamilyAware
	NodeNameAware
}

type RouteInjector interface {
	InjectRoute(subnet *net.IPNet, gw net.IP) (bool, error)
}

type BGPPathLister interface {
	ListPath(ctx context.Context, r *gobgpapi.ListPathRequest, fn func(*gobgpapi.Destination)) error
}

type OverlayConfig struct {
	EnableOverlay bool
	OverlayType   string
}
