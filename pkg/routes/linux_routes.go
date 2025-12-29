package routes

import (
	"context"
	"fmt"
	"net"

	"github.com/cloudnativelabs/kube-router/v2/internal/nlretry"
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
	ctx := context.Background()
	routes, err := nlretry.RouteListFiltered(ctx, nl.FAMILY_ALL, &netlink.Route{
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
