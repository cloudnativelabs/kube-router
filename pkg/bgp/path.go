package bgp

import (
	"github.com/cloudnativelabs/kube-router/v2/pkg"
	gobgpapi "github.com/osrg/gobgp/v3/api"
	"k8s.io/klog/v2"
)

func PathChanged(path *gobgpapi.Path, pl PeerLister, rs pkg.RouteSyncer, tc pkg.TunnelCleaner) error {
	klog.V(2).Infof("Path Looks Like: %s", path.String())
	dst, nextHop, err := ParsePath(path)
	if err != nil {
		return err
	}
	tunnelName := tc.GenerateTunnelName(nextHop.String())

	// If we've made it this far, then it is likely that the node is holding a destination route for this path already.
	// If the path we've received from GoBGP is a withdrawal, we should clean up any lingering routes that may exist
	// on the host (rather than creating a new one or updating an existing one), and then return.
	if path.IsWithdraw {
		klog.V(2).Infof("Removing route: '%s via %s' from peer in the routing table", dst, nextHop)

		// The path might be withdrawn because the peer became unestablished or it may be withdrawn because just the
		// path was withdrawn. Check to see if the peer is still established before deciding whether to clean the
		// tunnel and tunnel routes or whether to just delete the destination route.
		peerEstablished, err := IsPeerEstablished(pl, nextHop.String())
		if err != nil {
			klog.Errorf("encountered error while checking peer status: %v", err)
		}
		if err == nil && !peerEstablished {
			klog.V(1).Infof("Peer '%s' was not found any longer, removing tunnel and routes",
				nextHop.String())
			// Also delete route from state map so that it doesn't get re-synced after deletion
			rs.DelInjectedRoute(dst)
			tc.CleanupTunnel(dst, tunnelName)
			return nil
		}

		// Also delete route from state map so that it doesn't get re-synced after deletion
		rs.DelInjectedRoute(dst)
		return nil
	}

	return nil
}
