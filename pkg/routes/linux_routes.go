package routes

import (
	"fmt"
	"net"

	"github.com/cloudnativelabs/kube-router/v2/pkg"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"k8s.io/klog/v2"
)

const (
	// Taken from: https://github.com/torvalds/linux/blob/master/include/uapi/linux/rtnetlink.h#L284
	ZebraOriginator = 0x11
)

// DeleteByDestination attempts to safely find all routes based upon its destination subnet and delete them
func DeleteByDestination(destinationSubnet *net.IPNet) error {
	routes, err := netlink.RouteListFiltered(nl.FAMILY_ALL, &netlink.Route{
		Dst: destinationSubnet, Protocol: ZebraOriginator,
	}, netlink.RT_FILTER_DST|netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return fmt.Errorf("failed to get routes from netlink: %v", err)
	}
	for i, r := range routes {
		klog.V(2).Infof("Found route to remove: %s", r.String())
		if err = netlink.RouteDel(&routes[i]); err != nil {
			return fmt.Errorf("failed to remove route due to %v", err)
		}
	}
	return nil
}

func InjectRoute(subnet *net.IPNet, gw net.IP, ipa utils.NodeIPAware, tn pkg.Tunneler, rs pkg.RouteSyncer,
	oc pkg.OverlayConfig) error {
	var route *netlink.Route
	var err error
	var link netlink.Link

	tunnelName := tn.GenerateTunnelName(gw.String())
	checkNHSameSubnet := func(needle net.IP, haystack []net.IP) bool {
		for _, nodeIP := range haystack {
			nodeSubnet, _, err := utils.GetNodeSubnet(nodeIP, nil)
			if err != nil {
				klog.Warningf("unable to get subnet for node IP: %s, err: %v... skipping", nodeIP, err)
				continue
			}
			// If we've found a subnet that contains our nextHop then we're done here
			if nodeSubnet.Contains(needle) {
				return true
			}
		}
		return false
	}

	// Determine if we are in the same subnet as the gateway (next hop)
	var sameSubnet bool
	if gw.To4() != nil {
		sameSubnet = checkNHSameSubnet(gw, ipa.GetNodeIPv4Addrs())
	} else if gw.To16() != nil {
		sameSubnet = checkNHSameSubnet(gw, ipa.GetNodeIPv6Addrs())
	}

	// create IPIP tunnels only when node is not in same subnet or overlay-type is set to 'full'
	// if the user has disabled overlays, don't create tunnels. If we're not creating a tunnel, check to see if there is
	// any cleanup that needs to happen.
	if shouldCreateTunnel(oc, sameSubnet) {
		link, err = tn.SetupOverlayTunnel(tunnelName, gw, subnet)
		if err != nil {
			return err
		}
	} else {
		// knowing that a tunnel shouldn't exist for this route, check to see if there are any lingering tunnels /
		// routes that need to be cleaned up.
		tn.CleanupTunnel(subnet, tunnelName)
	}

	switch {
	case link != nil:
		// if we set up an overlay tunnel link, then use it for destination routing
		var bestIPForFamily net.IP
		if subnet.IP.To4() != nil {
			bestIPForFamily = ipa.FindBestIPv4NodeAddress()
		} else {
			// Need to activate the ip command in IPv6 mode
			bestIPForFamily = ipa.FindBestIPv6NodeAddress()
		}
		if bestIPForFamily == nil {
			return fmt.Errorf("not able to find an appropriate configured IP address on node for destination "+
				"IP family: %s", subnet.String())
		}
		route = &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Src:       bestIPForFamily,
			Dst:       subnet,
			Protocol:  ZebraOriginator,
		}
	case sameSubnet:
		// if the nextHop is within the same subnet, add a route for the destination so that traffic can bet routed
		// at layer 2 and minimize the need to traverse a router
		// First check that destination and nexthop are in the same IP family
		dstIsIPv4 := subnet.IP.To4() != nil
		gwIsIPv4 := gw.To4() != nil
		if dstIsIPv4 != gwIsIPv4 {
			return fmt.Errorf("not able to add route as destination %s and gateway %s are not in the same IP family - "+
				"this shouldn't ever happen from IPs that kube-router advertises, but if it does report it as a bug",
				subnet.IP, gw)
		}
		route = &netlink.Route{
			Dst:      subnet,
			Gw:       gw,
			Protocol: ZebraOriginator,
		}
	default:
		// otherwise, let BGP do its thing, nothing to do here
		return nil
	}

	// Alright, everything is in place, and we have our route configured, let's add it to the host's routing table
	klog.V(2).Infof("Inject route: '%s via %s' from peer to routing table", subnet, gw)
	rs.AddInjectedRoute(subnet, route)
	// Immediately sync the local route table regardless of timer
	rs.SyncLocalRouteTable()
	return nil
}

func shouldCreateTunnel(oc pkg.OverlayConfig, sameSubnet bool) bool {
	if !oc.EnableOverlay {
		return false
	}
	if oc.OverlayType == "full" {
		return true
	}
	if oc.OverlayType == "subnet" && !sameSubnet {
		return true
	}
	return false
}
