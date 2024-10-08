package proxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/cri"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/docker/docker/client"
	"github.com/moby/ipvs"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

const (
	ipv4NetMaskBits  = 32
	ipv4DefaultRoute = "0.0.0.0/0"
	ipv6NetMaskBits  = 128
	ipv6DefaultRoute = "::/0"

	// TODO: it's bad to rely on eth0 here. While this is inside the container's namespace and is determined by the
	// container runtime and so far we've been able to count on this being reliably set to eth0, it is possible that
	// this may shift sometime in the future with a different runtime. It would be better to find a reliable way to
	// determine the interface name from inside the container.
	assumedContainerIfaceName = "eth0"

	procFSBasePath       = "/proc"
	procFSCWDRelPath     = "cwd"
	sysFSBasePath        = "/sys"
	sysFSNetClassRelPath = "class/net"
	sysFSIfLinkRelPath   = "iflink"
)

// LinuxNetworking interface contains all linux networking subsystem calls
//
//go:generate moq -out linux_networking_moq.go . LinuxNetworking
type LinuxNetworking interface {
	ipvsCalls
	netlinkCalls
}

type linuxNetworking struct {
	ipvsHandle *ipvs.Handle
}

type netlinkCalls interface {
	ipAddrAdd(iface netlink.Link, ip string, nodeIP string, addRoute bool) error
	ipAddrDel(iface netlink.Link, ip string, nodeIP string) error
	getContainerPidWithDocker(containerID string) (int, error)
	getContainerPidWithCRI(runtimeEndpoint string, containerID string) (int, error)
	getKubeDummyInterface() (netlink.Link, error)
	setupRoutesForExternalIPForDSR(serviceInfo serviceInfoMap, setupIPv4, setupIPv6 bool) error
	configureContainerForDSR(vip, endpointIP, containerID string, pid int,
		hostNetworkNamespaceHandle netns.NsHandle) error
	setupPolicyRoutingForDSR(setupIPv4, setupIPv6 bool) error
	findIfaceLinkForPid(pid int) (int, error)
}

func (ln *linuxNetworking) ipAddrDel(iface netlink.Link, ip string, nodeIP string) error {
	var netMask net.IPMask
	parsedIP := net.ParseIP(ip)
	parsedNodeIP := net.ParseIP(nodeIP)
	if parsedIP.To4() != nil {
		// If the IP family of the NodeIP and the VIP IP don't match, we can't proceed
		if parsedNodeIP.To4() == nil {
			return fmt.Errorf("nodeIP %s does not match family for VIP IP: %s, unable to proceed", ip, nodeIP)
		}

		netMask = net.CIDRMask(ipv4NetMaskBits, ipv4NetMaskBits)
	} else {
		// If the IP family of the NodeIP and the VIP IP don't match, we can't proceed
		if parsedNodeIP.To4() != nil {
			return fmt.Errorf("nodeIP %s does not match family for VIP IP: %s, unable to proceed", ip, nodeIP)
		}

		if strings.HasPrefix(ip, "fe80:") {
			klog.V(2).Infof("Ignoring link-local IP address: %s", ip)
			return nil
		}

		netMask = net.CIDRMask(ipv6NetMaskBits, ipv6NetMaskBits)
	}

	naddr := &netlink.Addr{IPNet: &net.IPNet{IP: parsedIP, Mask: netMask}, Scope: syscall.RT_SCOPE_LINK}
	err := netlink.AddrDel(iface, naddr)
	if err != nil {
		if err.Error() != IfaceHasNoAddr {
			klog.Errorf("Failed to verify is external ip %s is assocated with dummy interface %s due to %s",
				ip, iface.Attrs().Name, err.Error())
			return err
		} else {
			klog.Warningf("got an IfaceHasNoAddr error while trying to delete address %s from netlink %s: %v (this "+
				"is not normally bad enough to stop processing)", ip, iface.Attrs().Name, err)
		}
	}

	// Delete VIP addition to "local" rt table also, fail silently if not found (DSR special case)
	// #nosec G204
	nRoute := &netlink.Route{
		Type:      unix.RTN_LOCAL,
		Dst:       &net.IPNet{IP: parsedIP, Mask: netMask},
		LinkIndex: iface.Attrs().Index,
		Table:     syscall.RT_TABLE_LOCAL,
		Protocol:  unix.RTPROT_KERNEL,
		Scope:     syscall.RT_SCOPE_HOST,
		Src:       parsedNodeIP,
	}
	err = netlink.RouteDel(nRoute)
	if err != nil {
		if !strings.Contains(err.Error(), "no such process") {
			klog.Errorf("Failed to delete route to service VIP %s configured on %s. Error: %v",
				ip, iface.Attrs().Name, err)
		} else {
			klog.Warningf("got a No such process error while trying to remove route: %v (this is not normally bad "+
				"enough to stop processing)", err)
			return nil
		}
	}

	return err
}

// utility method to assign an IP to an interface. Mainly used to assign service VIP's
// to kube-dummy-if. Also when DSR is used, used to assign VIP to dummy interface
// inside the container.
func (ln *linuxNetworking) ipAddrAdd(iface netlink.Link, ip string, nodeIP string, addRoute bool) error {
	var netMask net.IPMask
	var isIPv6 bool
	parsedIP := net.ParseIP(ip)
	parsedNodeIP := net.ParseIP(nodeIP)
	if parsedIP.To4() != nil {
		// If we're supposed to add a route and the IP family of the NodeIP and the VIP IP don't match, we can't proceed
		if addRoute && parsedNodeIP.To4() == nil {
			return fmt.Errorf("nodeIP %s does not match family for VIP IP: %s, unable to proceed", ip, nodeIP)
		}

		netMask = net.CIDRMask(ipv4NetMaskBits, ipv4NetMaskBits)
		isIPv6 = false
	} else {
		// If we're supposed to add a route and the IP family of the NodeIP and the VIP IP don't match, we can't proceed
		if addRoute && parsedNodeIP.To4() != nil {
			return fmt.Errorf("nodeIP %s does not match family for VIP IP: %s, unable to proceed", ip, nodeIP)
		}

		netMask = net.CIDRMask(ipv6NetMaskBits, ipv6NetMaskBits)
		isIPv6 = true
	}

	ipPrefix := &net.IPNet{IP: parsedIP, Mask: netMask}
	naddr := &netlink.Addr{IPNet: ipPrefix, Scope: syscall.RT_SCOPE_LINK}
	err := netlink.AddrAdd(iface, naddr)
	if err != nil && err.Error() != IfaceHasAddr {
		klog.Errorf("failed to assign cluster ip %s to dummy interface: %s", naddr.IPNet.IP.String(), err.Error())
		return err
	}

	// When a service VIP is assigned to a dummy interface and accessed from host, in some of the
	// case Linux source IP selection logix selects VIP itself as source leading to problems
	// to avoid this an explicit entry is added to use node IP as source IP when accessing
	// VIP from the host. Please see https://github.com/cloudnativelabs/kube-router/issues/376
	if !addRoute {
		return nil
	}

	kubeDummyLink, err := netlink.LinkByName(KubeDummyIf)
	if err != nil {
		klog.Errorf("failed to get %s link due to %v", KubeDummyIf, err)
		return err
	}
	nRoute := &netlink.Route{
		Type:      unix.RTN_LOCAL,
		Dst:       ipPrefix,
		LinkIndex: kubeDummyLink.Attrs().Index,
		Table:     syscall.RT_TABLE_LOCAL,
		Protocol:  unix.RTPROT_KERNEL,
		Scope:     syscall.RT_SCOPE_HOST,
		Src:       parsedNodeIP,
	}
	err = netlink.RouteReplace(nRoute)
	if err != nil {
		klog.Errorf("Failed to replace route to service VIP %s configured on %s. Error: %v",
			ip, KubeDummyIf, err)
		return err
	}

	// IPv6 address adds in iproute2 appear to create some misc routes that will interfere with the source routing that
	// we attempt to do below and cuased the issue commented on above. We need to remove those before we attempt to
	// create the source route below. See: https://github.com/cloudnativelabs/kube-router/issues/1698
	if isIPv6 {
		nRoute := &netlink.Route{
			Dst:   &net.IPNet{IP: parsedIP, Mask: netMask},
			Table: unix.RT_TABLE_UNSPEC,
		}
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, nRoute,
			netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
		if err != nil {
			klog.Errorf("failed to list routes for interface %s: %v", iface.Attrs().Name, err)
			return err
		}
		for idx, route := range routes {
			klog.V(1).Infof("Checking route %s for interface %s...", route, iface.Attrs().Name)
			// Looking for routes where the destination matches our VIP AND the source is either nil or not the node IP
			if route.Src == nil || !route.Src.Equal(parsedNodeIP) {
				klog.V(1).Infof("Deleting route %s for interface %s...", route, iface.Attrs().Name)
				err = netlink.RouteDel(&routes[idx])
				if err != nil {
					klog.Errorf("failed to delete route %s for interface %s: %v", route, iface.Attrs().Name, err)
				}
			}
		}
	}

	return nil
}

func (ln *linuxNetworking) ipvsGetServices() ([]*ipvs.Service, error) {
	return ln.ipvsHandle.GetServices()
}

func (ln *linuxNetworking) ipvsGetDestinations(ipvsSvc *ipvs.Service) ([]*ipvs.Destination, error) {
	return ln.ipvsHandle.GetDestinations(ipvsSvc)
}

func (ln *linuxNetworking) ipvsDelDestination(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error {
	return ln.ipvsHandle.DelDestination(ipvsSvc, ipvsDst)
}

func (ln *linuxNetworking) ipvsNewDestination(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error {
	return ln.ipvsHandle.NewDestination(ipvsSvc, ipvsDst)
}

func (ln *linuxNetworking) ipvsUpdateDestination(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error {
	return ln.ipvsHandle.UpdateDestination(ipvsSvc, ipvsDst)
}

func (ln *linuxNetworking) ipvsDelService(ipvsSvc *ipvs.Service) error {
	return ln.ipvsHandle.DelService(ipvsSvc)
}

func (ln *linuxNetworking) ipvsUpdateService(ipvsSvc *ipvs.Service) error {
	return ln.ipvsHandle.UpdateService(ipvsSvc)
}

func (ln *linuxNetworking) ipvsNewService(ipvsSvc *ipvs.Service) error {
	return ln.ipvsHandle.NewService(ipvsSvc)
}

// ipvsAddService upserts an IPVS service by taking a look at the list of IPVS services passed in.
//
// If it finds that it matches a service already in the array, then it will ensure that the service matches the
// information it has updatingwhatever doesn't match.
//
// If it doesn't find a match, then it will create a new IPVS service and save it. Upon successfully saving the service
// it will append it to the list of passed services to ensure future calls within the same run of the upstream sync
// function don't try to have it create the same service again by accident
func (ln *linuxNetworking) ipvsAddService(svcs []*ipvs.Service, vip net.IP, protocol, port uint16,
	persistent bool, persistentTimeout int32, scheduler string, flags schedFlags) ([]*ipvs.Service, *ipvs.Service,
	error) {

	var err error
	if len(svcs) == 0 {
		klog.Info("IPVS service map was blank, if kube-router is just starting this is to be expected, but otherwise" +
			"should not happen")
	}
	for _, svc := range svcs {
		klog.V(2).Infof("Comparing vip (%s:%s) protocol (%d:%d) and port (%d:%d)",
			vip, svc.Address, protocol, svc.Protocol, port, svc.Port)
		if vip.Equal(svc.Address) && protocol == svc.Protocol && port == svc.Port {
			klog.V(2).Info("Service matched VIP")
			if (persistent && (svc.Flags&ipvsPersistentFlagHex) == 0) ||
				(!persistent && (svc.Flags&ipvsPersistentFlagHex) != 0) ||
				svc.Timeout != uint32(persistentTimeout) {
				ipvsSetPersistence(svc, persistent, persistentTimeout)

				err = ln.ipvsUpdateService(svc)
				if err != nil {
					return svcs, nil, fmt.Errorf("failed to update IPVS persitence / session-affinity for %s due to: %v",
						ipvsServiceString(svc), err)
				}
				klog.V(2).Infof("Updated persistence/session-affinity for service: %s",
					ipvsServiceString(svc))
			}

			if changedIpvsSchedFlags(svc, flags) {
				ipvsSetSchedFlags(svc, flags)

				err = ln.ipvsUpdateService(svc)
				if err != nil {
					return svcs, nil, fmt.Errorf("failed to update IPVS scheduler flags for %s due to: %v",
						ipvsServiceString(svc), err)
				}
				klog.V(2).Infof("Updated scheduler flags for service: %s", ipvsServiceString(svc))
			}

			if scheduler != svc.SchedName {
				svc.SchedName = scheduler
				err = ln.ipvsUpdateService(svc)
				if err != nil {
					return svcs, nil, fmt.Errorf("failed to update the scheduler for %s due to %v",
						ipvsServiceString(svc), err)
				}
				klog.V(2).Infof("Updated schedule for the service: %s", ipvsServiceString(svc))
			}

			klog.V(2).Infof("ipvs service %s already exists so returning", ipvsServiceString(svc))
			return svcs, svc, nil
		}
	}

	var ipvsFamily uint16
	var ipMask uint32
	if vip.To4() != nil {
		ipvsFamily = syscall.AF_INET
		ipMask = uint32(ipv4NetMaskBits)
	} else {
		ipvsFamily = syscall.AF_INET6
		ipMask = uint32(ipv6NetMaskBits)
	}
	svc := ipvs.Service{
		Address:       vip,
		AddressFamily: ipvsFamily,
		Protocol:      protocol,
		Port:          port,
		SchedName:     scheduler,
		Netmask:       ipMask,
	}

	ipvsSetPersistence(&svc, persistent, persistentTimeout)
	ipvsSetSchedFlags(&svc, flags)

	klog.V(1).Infof("%s didn't match any existing IPVS services, creating a new IPVS service",
		ipvsServiceString(&svc))
	err = ln.ipvsNewService(&svc)
	if err != nil {
		return svcs, nil, fmt.Errorf("failed to create new service %s due to: %v", ipvsServiceString(&svc), err)
	}

	// We add the just created service to the list of existing IPVS services because the calling logic here is a little
	// dumb and in order to save execution time it doesn't re-list IPVS services from the system between syncs of a
	// given service type so we may end up trying to create this service again
	svcs = append(svcs, &svc)

	klog.V(1).Infof("Successfully added service: %s", ipvsServiceString(&svc))
	return svcs, &svc, nil
}

// ipvsAddFWMarkService: creates an IPVS service using FWMARK
func (ln *linuxNetworking) ipvsAddFWMarkService(svcs []*ipvs.Service, fwMark uint32, family, protocol, port uint16,
	persistent bool, persistentTimeout int32, scheduler string, flags schedFlags) (*ipvs.Service, error) {
	var netmaskForFamily uint32
	switch family {
	case syscall.AF_INET:
		netmaskForFamily = ipv4NetMaskBits
	case syscall.AF_INET6:
		netmaskForFamily = ipv6NetMaskBits
	}
	for _, svc := range svcs {
		if fwMark == svc.FWMark {
			if (persistent && (svc.Flags&ipvsPersistentFlagHex) == 0) ||
				(!persistent && (svc.Flags&ipvsPersistentFlagHex) != 0) {
				ipvsSetPersistence(svc, persistent, persistentTimeout)

				if changedIpvsSchedFlags(svc, flags) {
					ipvsSetSchedFlags(svc, flags)
				}

				err := ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, fmt.Errorf("failed to update persistence flags for service %s due to %v",
						ipvsServiceString(svc), err)
				}
				klog.V(2).Infof("Updated persistence/session-affinity for service: %s",
					ipvsServiceString(svc))
			}

			if changedIpvsSchedFlags(svc, flags) {
				ipvsSetSchedFlags(svc, flags)

				err := ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, fmt.Errorf("failed to update scheduler flags for service %s due to %v",
						ipvsServiceString(svc), err)
				}
				klog.V(2).Infof("Updated scheduler flags for service: %s", ipvsServiceString(svc))
			}

			if scheduler != svc.SchedName {
				svc.SchedName = scheduler
				err := ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, fmt.Errorf("failed to update the scheduler for the service %s due to %v",
						ipvsServiceString(svc), err)
				}
				klog.V(2).Infof("Updated schedule for the service: %s", ipvsServiceString(svc))
			}

			if svc.AddressFamily != family {
				svc.AddressFamily = family
				svc.Netmask = netmaskForFamily
				err := ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, fmt.Errorf("failed to update the address family for service %s due to %v",
						ipvsServiceString(svc), err)
				}
				klog.V(2).Infof("Updated address family for the service: %s", ipvsServiceString(svc))
			}

			klog.V(2).Infof("ipvs service %s already exists so returning", ipvsServiceString(svc))
			return svc, nil
		}
	}

	// Even though it may seem unintuitive to require a Netmask on an fwmark service, I found that it was necessary in
	// order to get IPVS IPv6 services to work correctly. After reviewing the code, it the only difference between the
	// netlink command that we build here and the one that ipvsadm was building was the netmask, after adding it, it
	// began to work
	svc := ipvs.Service{
		FWMark:        fwMark,
		AddressFamily: family,
		Netmask:       netmaskForFamily,
		SchedName:     ipvs.RoundRobin,
	}

	ipvsSetPersistence(&svc, persistent, persistentTimeout)
	ipvsSetSchedFlags(&svc, flags)

	err := ln.ipvsNewService(&svc)
	if err != nil {
		return nil, err
	}
	klog.Infof("Successfully added service: %s", ipvsServiceString(&svc))
	return &svc, nil
}

func (ln *linuxNetworking) ipvsAddServer(service *ipvs.Service, dest *ipvs.Destination) error {
	err := ln.ipvsNewDestination(service, dest)
	if err == nil {
		klog.V(2).Infof("Successfully added destination %s to the service %s",
			ipvsDestinationString(dest), ipvsServiceString(service))
		return nil
	}

	if strings.Contains(err.Error(), IpvsServerExists) {
		err = ln.ipvsUpdateDestination(service, dest)
		if err != nil {
			return fmt.Errorf("failed to update ipvs destination %s to the ipvs service %s due to : %s",
				ipvsDestinationString(dest), ipvsServiceString(service), err.Error())
		}
		klog.V(2).Infof("ipvs destination %s already exists in the ipvs service %s so not adding destination",
			ipvsDestinationString(dest), ipvsServiceString(service))
	} else {
		return fmt.Errorf("failed to add ipvs destination %s to the ipvs service %s due to : %s",
			ipvsDestinationString(dest), ipvsServiceString(service), err.Error())
	}
	return nil
}

// For DSR it is required that we dont assign the VIP to any interface to avoid martian packets
// http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html
// setupPolicyRoutingForDSR: setups policy routing so that FWMARKed packets are delivered locally
func (ln *linuxNetworking) setupPolicyRoutingForDSR(setupIPv4, setupIPv6 bool) error {
	err := utils.RouteTableAdd(customDSRRouteTableID, customDSRRouteTableName)
	if err != nil {
		return fmt.Errorf("failed to setup policy routing required for DSR due to %v", err)
	}

	loNetLink, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to get loopback interface due to %v", err)
	}

	if setupIPv4 {
		nFamily := netlink.FAMILY_V4
		_, defaultRouteCIDR, err := net.ParseCIDR(ipv4DefaultRoute)
		if err != nil {
			//nolint:goconst // This is a static value and should not be changed
			return fmt.Errorf("failed to parse default (%s) route (this is statically defined, so if you see this "+
				"error please report because something has gone very wrong) due to: %v", ipv4DefaultRoute, err)
		}
		nRoute := &netlink.Route{
			Type:      unix.RTN_LOCAL,
			Dst:       defaultRouteCIDR,
			LinkIndex: loNetLink.Attrs().Index,
			Table:     customDSRRouteTableID,
		}
		routes, err := netlink.RouteListFiltered(nFamily, nRoute, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
		if err != nil || len(routes) < 1 {
			err = netlink.RouteAdd(nRoute)
			if err != nil {
				return fmt.Errorf("failed to add route to custom route table for DSR due to: %v", err)
			}
		}
	}

	if setupIPv6 {
		nFamily := netlink.FAMILY_V6
		_, defaultRouteCIDR, err := net.ParseCIDR(ipv6DefaultRoute)
		if err != nil {
			return fmt.Errorf("failed to parse default (%s) route (this is statically defined, so if you see this "+
				"error please report because something has gone very wrong) due to: %v", ipv6DefaultRoute, err)
		}
		nRoute := &netlink.Route{
			Type:      unix.RTN_LOCAL,
			Dst:       defaultRouteCIDR,
			LinkIndex: loNetLink.Attrs().Index,
			Table:     customDSRRouteTableID,
		}
		routes, err := netlink.RouteListFiltered(nFamily, nRoute, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
		if err != nil || len(routes) < 1 {
			err = netlink.RouteAdd(nRoute)
			if err != nil {
				return fmt.Errorf("failed to add route to custom route table for DSR due to: %v", err)
			}
		}
	}

	return nil
}

// For DSR it is required that node needs to know how to route external IP. Otherwise when endpoint
// directly responds back with source IP as external IP kernel will treat as martian packet.
// To prevent martian packets add route to external IP through the `kube-bridge` interface
// setupRoutesForExternalIPForDSR: setups routing so that kernel does not think return packets as martians
func (ln *linuxNetworking) setupRoutesForExternalIPForDSR(serviceInfoMap serviceInfoMap,
	setupIPv4, setupIPv6 bool) error {
	err := utils.RouteTableAdd(externalIPRouteTableID, externalIPRouteTableName)
	if err != nil {
		return fmt.Errorf("failed to setup policy routing required for DSR due to %v", err)
	}

	setupIPRulesAndRoutes := func(isIPv6 bool) error {
		nFamily := netlink.FAMILY_V4
		_, defaultPrefixCIDR, err := net.ParseCIDR(ipv4DefaultRoute)
		if isIPv6 {
			nFamily = netlink.FAMILY_V6
			_, defaultPrefixCIDR, err = net.ParseCIDR(ipv6DefaultRoute)
		}
		if err != nil {
			return fmt.Errorf("failed to parse default route (this is statically defined, so if you see this "+
				"error please report because something has gone very wrong) due to: %v", err)
		}

		nRule := &netlink.Rule{
			Priority: defaultDSRPolicyRulePriority,
			Src:      defaultPrefixCIDR,
			Table:    externalIPRouteTableID,
		}
		rules, err := netlink.RuleListFiltered(nFamily, nRule,
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_SRC|netlink.RT_FILTER_PRIORITY)
		if err != nil {
			return fmt.Errorf("failed to list rule for external IP's and verify if `ip rule add prio 32765 from all "+
				"lookup external_ip` exists due to: %v", err)
		}

		if len(rules) < 1 {
			err = netlink.RuleAdd(nRule)
			if err != nil {
				klog.Infof("Failed to add policy rule `ip rule add prio 32765 from all lookup external_ip` due to %v",
					err)
				return fmt.Errorf("failed to add policy rule `ip rule add prio 32765 from all lookup external_ip` "+
					"due to %v", err)
			}
		}

		kubeBridgeLink, err := netlink.LinkByName(KubeBridgeIf)
		if err != nil {
			return fmt.Errorf("failed to get kube-bridge interface due to %v", err)
		}

		activeExternalIPs := make(map[string]bool)
		for _, svc := range serviceInfoMap {
			for _, externalIP := range svc.externalIPs {
				// Verify the DSR annotation exists
				if !svc.directServerReturn {
					klog.V(1).Infof("Skipping service %s/%s as it does not have DSR annotation",
						svc.namespace, svc.name)
					continue
				}

				activeExternalIPs[externalIP] = true

				nSrcIP := net.ParseIP(externalIP)
				nRoute := &netlink.Route{
					Src:       nSrcIP,
					LinkIndex: kubeBridgeLink.Attrs().Index,
					Table:     externalIPRouteTableID,
				}

				routes, err := netlink.RouteListFiltered(nFamily, nRoute,
					netlink.RT_FILTER_SRC|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
				if err != nil {
					return fmt.Errorf("failed to list route for external IP's due to: %s", err)
				}
				if len(routes) < 1 {
					err = netlink.RouteAdd(nRoute)
					if err != nil {
						klog.Errorf("Failed to add route for %s in custom route table for external IP's due to: %v",
							externalIP, err)
						continue
					}
				}
			}
		}

		// check if there are any pbr in externalIPRouteTableID for external IP's
		routes, err := netlink.RouteList(nil, nFamily)
		if err != nil {
			return fmt.Errorf("failed to list route for external IP's due to: %s", err)
		}
		for idx, route := range routes {
			ip := route.Src.String()
			if !activeExternalIPs[ip] {
				err = netlink.RouteDel(&routes[idx])
				if err != nil {
					klog.Errorf("Failed to del route for %v in custom route table for external IP's due to: %s",
						ip, err)
					continue
				}
			}
		}

		return nil
	}

	if setupIPv4 {
		err = setupIPRulesAndRoutes(false)
		if err != nil {
			return err
		}
	}
	if setupIPv6 {
		err = setupIPRulesAndRoutes(true)
		if err != nil {
			return err
		}
	}

	return nil
}

// getContainerPidWithDocker get the PID for a given docker container ID which allows, among other things, for us to
// enter the network namespace of the pod
func (ln *linuxNetworking) getContainerPidWithDocker(containerID string) (int, error) {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return 0, fmt.Errorf("failed to get docker client due to %v", err)
	}
	defer utils.CloseCloserDisregardError(dockerClient)

	containerSpec, err := dockerClient.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return 0, fmt.Errorf("failed to get docker container spec due to %v", err)
	}

	return containerSpec.State.Pid, nil
}

// getContainerPidWithCRI get the PID for a given compatible CRI (cri-o / containerd / etc.) container ID which allows,
// among other things, for us to enter the network namespace of the pod
func (ln *linuxNetworking) getContainerPidWithCRI(runtimeEndpoint string, containerID string) (int, error) {
	if runtimeEndpoint == "" {
		return 0, fmt.Errorf("runtimeEndpoint is not specified")
	}

	rs, err := cri.NewRemoteRuntimeService(runtimeEndpoint, cri.DefaultConnectionTimeout)
	if err != nil {
		return 0, err
	}
	defer utils.CloseCloserDisregardError(rs)

	info, err := rs.ContainerInfo(containerID)
	if err != nil {
		return 0, err
	}

	return info.Pid, nil
}

// findIfaceLinkForPid finds the interface link number inside the network namespace of the passed pid.
//
// It is extremely unfortunate, that we have to go through /proc for this functionality. Ideally, we could use
// unix.Setns to enter the mount namespace for the PID and then just look through the sysfs filesystem to find this
// information. Unfortunately, there appear to be problems doing this in Golang and the only way it appears to work
// correctly is if you know all of the various PIDs you might need to join before the application is launched.
// See the following for more details:
//   - https://github.com/golang/go/issues/8676
//   - https://stackoverflow.com/questions/25704661/calling-setns-from-go-returns-einval-for-mnt-namespace
//
// Additionally, we can't us nsenter because we need access to the basic tools that kube-router has on the host and
// we can't guarantee that even basic commands like ls or cat will be available inside the container's NS filesystem.
func (ln *linuxNetworking) findIfaceLinkForPid(pid int) (int, error) {
	var ifaceID int

	listAvailableIfaces := func() {
		ifacesPath := path.Join(procFSBasePath, strconv.Itoa(pid), procFSCWDRelPath, sysFSBasePath,
			sysFSNetClassRelPath)
		entries, err := os.ReadDir(ifacesPath)
		if err != nil {
			klog.Warningf("Could not list: %s due to: %v", ifacesPath, err)
			klog.Warning("If above error was 'no such file or directory' it may be that you haven't enabled " +
				"'hostPID=true' in your kube-router deployment")
			return
		}
		var sb strings.Builder
		for _, e := range entries {
			sb.WriteString(e.Name() + " ")
		}
		klog.Warningf("Able to see the following interfaces: %s", sb.String())
		klog.Warning("If one of the above is not eth0 it is likely, that the assumption that we've hardcoded in " +
			"kube-router is wrong, please report this as a bug along with this output")
	}

	ifaceSysPath := path.Join(procFSBasePath, strconv.Itoa(pid), procFSCWDRelPath, sysFSBasePath, sysFSNetClassRelPath,
		assumedContainerIfaceName, sysFSIfLinkRelPath)
	output, err := os.ReadFile(ifaceSysPath)
	if err != nil {
		listAvailableIfaces()
		return ifaceID, fmt.Errorf("unable to read the ifaceID inside the container from %s, output was: %s, error "+
			"was: %v", ifaceSysPath, string(output), err)
	}

	ifaceID, err = strconv.Atoi(strings.TrimSuffix(string(output), "\n"))
	if ifaceID == 0 || err != nil {
		listAvailableIfaces()
		return ifaceID, fmt.Errorf("unable to find the ifaceID inside the container from %s, output was: %s, error "+
			"was %v", ifaceSysPath, string(output), err)
	}

	return ifaceID, nil
}

func (ln *linuxNetworking) configureContainerForDSR(
	vip, endpointIP, containerID string, pid int, hostNetworkNamespaceHandle netns.NsHandle) error {
	var ipTunLink netlink.Link
	parsedEIP := net.ParseIP(endpointIP)
	if parsedEIP == nil {
		return fmt.Errorf("failed to parse endpoint IP %s", endpointIP)
	}
	if parsedEIP.To4() != nil {
		ipTunLink = &netlink.Iptun{
			LinkAttrs: netlink.LinkAttrs{Name: KubeTunnelIfv4},
			Local:     parsedEIP,
		}
	} else {
		ipTunLink = &netlink.Ip6tnl{
			LinkAttrs: netlink.LinkAttrs{Name: KubeTunnelIfv6},
			Local:     parsedEIP,
		}
	}
	endpointNamespaceHandle, err := netns.GetFromPid(pid)
	if err != nil {
		return fmt.Errorf("failed to get endpoint namespace (containerID=%s, pid=%d, error=%v)",
			containerID, pid, err)
	}
	defer utils.CloseCloserDisregardError(&endpointNamespaceHandle)

	// LINUX NAMESPACE SHIFT - It is important to note that from here until the end of the function (or until an error)
	// all subsequent commands are executed from within the container's network namespace and NOT the host's namespace.
	err = netns.Set(endpointNamespaceHandle)
	if err != nil {
		return fmt.Errorf("failed to enter endpoint namespace (containerID=%s, pid=%d, error=%v)",
			containerID, pid, err)
	}

	// This is just for logging, and that is why we close it immediately after getting it
	activeNetworkNamespaceHandle, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get activeNetworkNamespace due to %v", err)
	}
	klog.V(2).Infof("Current network namespace after netns. Set to container network namespace: %s",
		activeNetworkNamespaceHandle.String())
	_ = activeNetworkNamespaceHandle.Close()

	// create an ipip tunnel interface inside the endpoint container
	tunIf, err := netlink.LinkByName(ipTunLink.Attrs().Name)
	if err != nil {
		if err.Error() != IfaceNotFound {
			attemptNamespaceResetAfterError(hostNetworkNamespaceHandle)
			return fmt.Errorf("failed to verify if ipip tunnel interface exists in endpoint %s namespace due "+
				"to %v", endpointIP, err)
		}

		klog.V(2).Infof("Could not find tunnel interface %s in endpoint %s so creating one.",
			ipTunLink.Attrs().Name, endpointIP)
		err = netlink.LinkAdd(ipTunLink)
		if err != nil {
			attemptNamespaceResetAfterError(hostNetworkNamespaceHandle)
			return fmt.Errorf("failed to add ipip tunnel interface in endpoint namespace due to %v", err)
		}

		// this is ugly, but ran into issue multiple times where interface did not come up quickly.
		for retry := 0; retry < 60; retry++ {
			time.Sleep(interfaceWaitSleepTime)
			tunIf, err = netlink.LinkByName(ipTunLink.Attrs().Name)
			if err == nil {
				break
			}
			if err.Error() == IfaceNotFound {
				klog.V(3).Infof("Waiting for tunnel interface %s to come up in the pod, retrying",
					ipTunLink.Attrs().Name)
				continue
			} else {
				break
			}
		}

		if err != nil {
			attemptNamespaceResetAfterError(hostNetworkNamespaceHandle)
			return fmt.Errorf("failed to get %s tunnel interface handle due to %v", ipTunLink.Attrs().Name, err)
		}

		klog.V(2).Infof("Successfully created tunnel interface %s in endpoint %s.",
			ipTunLink.Attrs().Name, endpointIP)
	}

	// bring the tunnel interface up
	err = netlink.LinkSetUp(tunIf)
	if err != nil {
		attemptNamespaceResetAfterError(hostNetworkNamespaceHandle)
		return fmt.Errorf("failed to bring up ipip tunnel interface in endpoint namespace due to %v", err)
	}

	// assign VIP to the KUBE_TUNNEL_IF interface
	err = ln.ipAddrAdd(tunIf, vip, "", false)
	if err != nil && err.Error() != IfaceHasAddr {
		attemptNamespaceResetAfterError(hostNetworkNamespaceHandle)
		return fmt.Errorf("failed to assign vip %s to kube-tunnel-if interface", vip)
	}
	klog.Infof("Successfully assigned VIP: %s in endpoint %s.", vip, endpointIP)

	// disable rp_filter on all interface
	sysctlErr := utils.SetSysctlSingleTemplate(utils.IPv4ConfRPFilterTemplate, "kube-tunnel-if", 0)
	if sysctlErr != nil {
		attemptNamespaceResetAfterError(hostNetworkNamespaceHandle)
		return fmt.Errorf("failed to disable rp_filter on kube-tunnel-if in the endpoint container: %s",
			sysctlErr.Error())
	}

	sysctlErr = utils.SetSysctlSingleTemplate(utils.IPv4ConfRPFilterTemplate, assumedContainerIfaceName, 0)
	if sysctlErr != nil {
		attemptNamespaceResetAfterError(hostNetworkNamespaceHandle)
		return fmt.Errorf("failed to disable rp_filter on eth0 in the endpoint container: %s", sysctlErr.Error())
	}

	sysctlErr = utils.SetSysctlSingleTemplate(utils.IPv4ConfRPFilterTemplate, "all", 0)
	if sysctlErr != nil {
		attemptNamespaceResetAfterError(hostNetworkNamespaceHandle)
		return fmt.Errorf("failed to disable rp_filter on `all` in the endpoint container: %s", sysctlErr.Error())
	}

	klog.Infof("Successfully disabled rp_filter in endpoint %s.", endpointIP)

	err = netns.Set(hostNetworkNamespaceHandle)
	if err != nil {
		return fmt.Errorf("failed to set hostNetworkNamespace handle due to %v", err)
	}
	activeNetworkNamespaceHandle, err = netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get activeNetworkNamespace handle due to %v", err)
	}
	klog.Infof("Current network namespace after revert namespace to host network namespace: %s",
		activeNetworkNamespaceHandle.String())
	_ = activeNetworkNamespaceHandle.Close()
	return nil
}

func (ln *linuxNetworking) getKubeDummyInterface() (netlink.Link, error) {
	var dummyVipInterface netlink.Link
	dummyVipInterface, err := netlink.LinkByName(KubeDummyIf)
	if err != nil && err.Error() == IfaceNotFound {
		klog.V(1).Infof("Could not find dummy interface: %s to assign cluster ip's, creating one",
			KubeDummyIf)
		err = netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: KubeDummyIf}})
		if err != nil {
			return nil, fmt.Errorf("failed to add dummy interface: %v", err)
		}
		dummyVipInterface, err = netlink.LinkByName(KubeDummyIf)
		if err != nil {
			return nil, fmt.Errorf("failed to get dummy interface: %v", err)
		}
		err = netlink.LinkSetUp(dummyVipInterface)
		if err != nil {
			return nil, fmt.Errorf("failed to bring dummy interface up: %v", err)
		}
	}
	return dummyVipInterface, nil
}

func newLinuxNetworking(tcpTimeout, tcpFinTimeout, udpTimeout time.Duration) (*linuxNetworking, error) {
	ln := &linuxNetworking{}
	ipvsHandle, err := ipvs.New("")
	if err != nil {
		return nil, err
	}
	ipvsConfig := &ipvs.Config{
		TimeoutTCP:    tcpTimeout,
		TimeoutTCPFin: tcpFinTimeout,
		TimeoutUDP:    udpTimeout,
	}
	err = ipvsHandle.SetConfig(ipvsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to configure IPVS config with timeouts: %v", err)
	}
	ln.ipvsHandle = ipvsHandle
	return ln, nil
}
