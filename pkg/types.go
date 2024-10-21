package pkg

import (
	"net"
	"sync"

	"github.com/vishvananda/netlink"
)

// RouteSyncer is an interface that defines the methods needed to sync routes to the kernel's routing table
type RouteSyncer interface {
	AddInjectedRoute(dst *net.IPNet, route *netlink.Route)
	DelInjectedRoute(dst *net.IPNet)
	Run(stopCh <-chan struct{}, wg *sync.WaitGroup)
	SyncLocalRouteTable()
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

type OverlayConfig struct {
	EnableOverlay bool
	OverlayType   string
}
