package bgp

import (
	"github.com/cloudnativelabs/kube-router/v2/pkg"
	gobgpapi "github.com/osrg/gobgp/v3/api"
	"k8s.io/klog/v2"
)

type PathHandler struct {
	PeerLister    PeerLister
	RouteInjector pkg.RouteInjector
	RouteSyncer   pkg.RouteSyncer
	TunnelCleaner pkg.TunnelCleaner
}

func (ph *PathHandler) Changed(path *gobgpapi.Path) error {
	klog.V(2).Infof("Path Looks Like: %s", path.String())
	dst, nextHop, err := ParsePath(path)
	if err != nil {
		return err
	}
	tunnelName := ph.TunnelCleaner.GenerateTunnelName(nextHop.String())

	// If we've made it this far, then it is likely that the node is holding a destination route for this path already.
	// If the path we've received from GoBGP is a withdrawal, we should clean up any lingering routes that may exist
	// on the host (rather than creating a new one or updating an existing one), and then return.
	if path.IsWithdraw {
		klog.V(2).Infof("Removing route: '%s via %s' from peer in the routing table", dst, nextHop)

		// The path might be withdrawn because the peer became unestablished or it may be withdrawn because just the
		// path was withdrawn. Check to see if the peer is still established before deciding whether to clean the
		// tunnel and tunnel routes or whether to just delete the destination route.
		peerEstablished, err := IsPeerEstablished(ph.PeerLister, nextHop.String())
		if err != nil {
			klog.Errorf("encountered error while checking peer status: %v", err)
		}
		if err == nil && !peerEstablished {
			klog.V(1).Infof("Peer '%s' was not found any longer, removing tunnel and routes",
				nextHop.String())
			// Also delete route from state map so that it doesn't get re-synced after deletion
			ph.RouteSyncer.DelInjectedRoute(dst)
			ph.TunnelCleaner.CleanupTunnel(dst, tunnelName)
			return nil
		}

		// Also delete route from state map so that it doesn't get re-synced after deletion
		ph.RouteSyncer.DelInjectedRoute(dst)
		return nil
	}

	// If this is not a withdraw, then we need to process the route. This takes care of creating any necessary tunnels,
	// and adding any necessary host routes depending on the user's config
	_, err = ph.RouteInjector.InjectRoute(dst, nextHop)
	return err
}
