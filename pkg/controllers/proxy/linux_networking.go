package proxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/cri"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/docker/docker/client"
	"github.com/moby/ipvs"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

const (
	ipv4NetMaskBits = 32
	ipv6NetMaskBits = 128

	WeightedRoundRobin      string = "wrr"
	WeightedLeastConnection string = "wlc"
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
	prepareEndpointForDsrWithDocker(containerID string, endpointIP string, vip string) error
	getKubeDummyInterface() (netlink.Link, error)
	setupRoutesForExternalIPForDSR(serviceInfo serviceInfoMap, setupIPv4, setupIPv6 bool) error
	prepareEndpointForDsrWithCRI(runtimeEndpoint, containerID, endpointIP, vip string) error
	configureContainerForDSR(vip, endpointIP, containerID string, pid int,
		hostNetworkNamespaceHandle netns.NsHandle) error
	setupPolicyRoutingForDSR(setupIPv4, setupIPv6 bool) error
}

func (ln *linuxNetworking) ipAddrDel(iface netlink.Link, ip string, nodeIP string) error {
	var netMask net.IPMask
	var ipRouteCmdArgs []string
	parsedIP := net.ParseIP(ip)
	parsedNodeIP := net.ParseIP(nodeIP)
	if parsedIP.To4() != nil {
		// If the IP family of the NodeIP and the VIP IP don't match, we can't proceed
		if parsedNodeIP.To4() == nil {
			return fmt.Errorf("nodeIP %s does not match family for VIP IP: %s, unable to proceed", ip, nodeIP)
		}

		netMask = net.CIDRMask(ipv4NetMaskBits, ipv4NetMaskBits)
		ipRouteCmdArgs = make([]string, 0)
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
		ipRouteCmdArgs = []string{"-6"}
	}

	naddr := &netlink.Addr{IPNet: &net.IPNet{IP: parsedIP, Mask: netMask}, Scope: syscall.RT_SCOPE_LINK}
	err := netlink.AddrDel(iface, naddr)
	if err != nil {
		if err.Error() != IfaceHasNoAddr {
			klog.Errorf("Failed to verify is external ip %s is assocated with dummy interface %s due to %s",
				ip, KubeDummyIf, err.Error())
			return err
		} else {
			klog.Warningf("got an IfaceHasNoAddr error while trying to delete address from netlink: %v (this is not "+
				"normally bad enough to stop processing)", err)
		}
	}

	// Delete VIP addition to "local" rt table also, fail silently if not found (DSR special case)
	// #nosec G204
	ipRouteCmdArgs = append(ipRouteCmdArgs, "route", "delete", "local", ip, "dev", KubeDummyIf,
		"table", "local", "proto", "kernel", "scope", "host", "src", nodeIP, "table", "local")
	out, err := exec.Command("ip", ipRouteCmdArgs...).CombinedOutput()
	if err != nil {
		if !strings.Contains(string(out), "No such process") {
			klog.Errorf("Failed to delete route to service VIP %s configured on %s. Error: %v, Output: %s",
				ip, KubeDummyIf, err, out)
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
	var ipRouteCmdArgs []string
	parsedIP := net.ParseIP(ip)
	parsedNodeIP := net.ParseIP(nodeIP)
	if parsedIP.To4() != nil {
		// If we're supposed to add a route and the IP family of the NodeIP and the VIP IP don't match, we can't proceed
		if addRoute && parsedNodeIP.To4() == nil {
			return fmt.Errorf("nodeIP %s does not match family for VIP IP: %s, unable to proceed", ip, nodeIP)
		}

		netMask = net.CIDRMask(ipv4NetMaskBits, ipv4NetMaskBits)
		ipRouteCmdArgs = make([]string, 0)
	} else {
		// If we're supposed to add a route and the IP family of the NodeIP and the VIP IP don't match, we can't proceed
		if addRoute && parsedNodeIP.To4() != nil {
			return fmt.Errorf("nodeIP %s does not match family for VIP IP: %s, unable to proceed", ip, nodeIP)
		}

		netMask = net.CIDRMask(ipv6NetMaskBits, ipv6NetMaskBits)
		ipRouteCmdArgs = []string{"-6"}
	}

	naddr := &netlink.Addr{IPNet: &net.IPNet{IP: parsedIP, Mask: netMask}, Scope: syscall.RT_SCOPE_LINK}
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

	// TODO: netlink.RouteReplace which is replacement for below command is not working as expected. Call succeeds but
	// route is not replaced. For now do it with command.
	// #nosec G204
	ipRouteCmdArgs = append(ipRouteCmdArgs, "route", "replace", "local", ip, "dev", KubeDummyIf,
		"table", "local", "proto", "kernel", "scope", "host", "src", nodeIP, "table", "local")

	out, err := exec.Command("ip", ipRouteCmdArgs...).CombinedOutput()
	if err != nil {
		klog.Errorf("Failed to replace route to service VIP %s configured on %s. Error: %v, Output: %s",
			ip, KubeDummyIf, err, out)
		return err
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

func (nsc *NetworkServicesController) newNodeEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			nsc.OnNodeUpdate(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			nsc.OnNodeUpdate(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			nsc.OnNodeUpdate(obj)
		},
	}
}

// For DSR it is required that we dont assign the VIP to any interface to avoid martian packets
// http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html
// setupPolicyRoutingForDSR: setups policy routing so that FWMARKed packets are delivered locally
func (ln *linuxNetworking) setupPolicyRoutingForDSR(setupIPv4, setupIPv6 bool) error {
	b, err := os.ReadFile("/etc/iproute2/rt_tables")
	if err != nil {
		return fmt.Errorf("failed to setup policy routing required for DSR due to %v", err)
	}

	if !strings.Contains(string(b), customDSRRouteTableName) {
		f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("failed to setup policy routing required for DSR due to %v", err)
		}
		defer utils.CloseCloserDisregardError(f)
		if _, err = f.WriteString(customDSRRouteTableID + " " + customDSRRouteTableName + "\n"); err != nil {
			return fmt.Errorf("failed to setup policy routing required for DSR due to %v", err)
		}
	}

	if setupIPv4 {
		out, err := exec.Command("ip", "route", "list", "table", customDSRRouteTableID).Output()
		if err != nil || !strings.Contains(string(out), " lo ") {
			if err = exec.Command("ip", "route", "add", "local", "default", "dev", "lo", "table",
				customDSRRouteTableID).Run(); err != nil {
				return fmt.Errorf("failed to add route in custom route table due to: %v", err)
			}
		}
	}
	if setupIPv6 {
		out, err := exec.Command("ip", "-6", "route", "list", "table", customDSRRouteTableID).Output()
		if err != nil || !strings.Contains(string(out), " lo ") {
			if err = exec.Command("ip", "-6", "route", "add", "local", "default", "dev", "lo", "table",
				customDSRRouteTableID).Run(); err != nil {
				return fmt.Errorf("failed to add route in custom route table due to: %v", err)
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
	b, err := os.ReadFile("/etc/iproute2/rt_tables")
	if err != nil {
		return fmt.Errorf("failed to setup external ip routing table required for DSR due to %v", err)
	}

	if !strings.Contains(string(b), externalIPRouteTableName) {
		f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("failed setup external ip routing table required for DSR due to %v", err)
		}
		defer utils.CloseCloserDisregardError(f)
		if _, err = f.WriteString(externalIPRouteTableID + " " + externalIPRouteTableName + "\n"); err != nil {
			return fmt.Errorf("failed setup external ip routing table required for DSR due to %v", err)
		}
	}

	setupIPRulesAndRoutes := func(ipArgs []string) error {
		out, err := runIPCommandsWithArgs(ipArgs, "rule", "list").Output()
		if err != nil {
			return fmt.Errorf("failed to verify if `ip rule add prio 32765 from all lookup external_ip` exists due to: %v",
				err)
		}

		if !(strings.Contains(string(out), externalIPRouteTableName) ||
			strings.Contains(string(out), externalIPRouteTableID)) {
			err = runIPCommandsWithArgs(ipArgs, "rule", "add", "prio", "32765", "from", "all", "lookup",
				externalIPRouteTableID).Run()
			if err != nil {
				klog.Infof("Failed to add policy rule `ip rule add prio 32765 from all lookup external_ip` due to %v",
					err.Error())
				return fmt.Errorf("failed to add policy rule `ip rule add prio 32765 from all lookup external_ip` "+
					"due to %v", err)
			}
		}

		out, _ = runIPCommandsWithArgs(ipArgs, "route", "list", "table", externalIPRouteTableID).Output()
		outStr := string(out)
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

				if !strings.Contains(outStr, externalIP) {
					if err = runIPCommandsWithArgs(ipArgs, "route", "add", externalIP, "dev", "kube-bridge", "table",
						externalIPRouteTableID).Run(); err != nil {
						klog.Errorf("Failed to add route for %s in custom route table for external IP's due to: %v",
							externalIP, err)
						continue
					}
				}
			}
		}

		// check if there are any pbr in externalIPRouteTableID for external IP's
		if len(outStr) > 0 {
			// clean up stale external IPs
			for _, line := range strings.Split(strings.Trim(outStr, "\n"), "\n") {
				route := strings.Split(strings.Trim(line, " "), " ")
				ip := route[0]
				if !activeExternalIPs[ip] {
					args := []string{"route", "del", "table", externalIPRouteTableID}
					args = append(args, route...)
					if err = runIPCommandsWithArgs(ipArgs, args...).Run(); err != nil {
						klog.Errorf("Failed to del route for %v in custom route table for external IP's due to: %s",
							ip, err)
						continue
					}
				}
			}
		}

		return nil
	}

	if setupIPv4 {
		err = setupIPRulesAndRoutes([]string{})
		if err != nil {
			return err
		}
	}
	if setupIPv6 {
		err = setupIPRulesAndRoutes([]string{"-6"})
		if err != nil {
			return err
		}
	}

	return nil
}

// This function does the following
// - get the pod corresponding to the endpoint ip
// - get the container id from pod spec
// - from the container id, use docker client to get the pid
// - enter process network namespace and create ipip tunnel
// - add VIP to the tunnel interface
// - disable rp_filter
// WARN: This method is deprecated and will be removed once docker-shim is removed from kubelet.
func (ln *linuxNetworking) prepareEndpointForDsrWithDocker(containerID string, endpointIP string, vip string) error {

	// Its possible switch namespaces may never work safely in GO without hacks.
	//	 https://groups.google.com/forum/#!topic/golang-nuts/ss1gEOcehjk/discussion
	//	 https://www.weave.works/blog/linux-namespaces-and-go-don-t-mix
	// Dont know if same issue, but seen namespace issue, so adding
	// logs and boilerplate code and verbose logs for diagnosis

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var activeNetworkNamespaceHandle netns.NsHandle

	hostNetworkNamespaceHandle, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get namespace due to %v", err)
	}
	defer utils.CloseCloserDisregardError(&hostNetworkNamespaceHandle)

	activeNetworkNamespaceHandle, err = netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get namespace due to %v", err)
	}
	klog.V(1).Infof("Current network namespace before netns.Set: %s", activeNetworkNamespaceHandle.String())
	defer utils.CloseCloserDisregardError(&activeNetworkNamespaceHandle)

	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return fmt.Errorf("failed to get docker client due to %v", err)
	}
	defer utils.CloseCloserDisregardError(dockerClient)

	containerSpec, err := dockerClient.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return fmt.Errorf("failed to get docker container spec due to %v", err)
	}

	pid := containerSpec.State.Pid
	return ln.configureContainerForDSR(vip, endpointIP, containerID, pid, hostNetworkNamespaceHandle)
}

// The same as prepareEndpointForDsr but using CRI instead of docker.
func (ln *linuxNetworking) prepareEndpointForDsrWithCRI(runtimeEndpoint, containerID, endpointIP, vip string) error {

	// It's possible switch namespaces may never work safely in GO without hacks.
	//	 https://groups.google.com/forum/#!topic/golang-nuts/ss1gEOcehjk/discussion
	//	 https://www.weave.works/blog/linux-namespaces-and-go-don-t-mix
	// Dont know if same issue, but seen namespace issue, so adding
	// logs and boilerplate code and verbose logs for diagnosis

	if runtimeEndpoint == "" {
		return fmt.Errorf("runtimeEndpoint is not specified")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNetworkNamespaceHandle, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get host namespace due to %v", err)
	}
	klog.V(1).Infof("current network namespace before netns.Set: %s", hostNetworkNamespaceHandle.String())
	defer utils.CloseCloserDisregardError(&hostNetworkNamespaceHandle)

	rs, err := cri.NewRemoteRuntimeService(runtimeEndpoint, cri.DefaultConnectionTimeout)
	if err != nil {
		return err
	}
	defer utils.CloseCloserDisregardError(rs)

	info, err := rs.ContainerInfo(containerID)
	if err != nil {
		return err
	}

	pid := info.Pid
	return ln.configureContainerForDSR(vip, endpointIP, containerID, pid, hostNetworkNamespaceHandle)
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

	// TODO: it's bad to rely on eth0 here. While this is inside the container's namespace and is determined by the
	// container runtime and so far we've been able to count on this being reliably set to eth0, it is possible that
	// this may shift sometime in the future with a different runtime. It would be better to find a reliable way to
	// determine the interface name from inside the container.
	sysctlErr = utils.SetSysctlSingleTemplate(utils.IPv4ConfRPFilterTemplate, "eth0", 0)
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

func newLinuxNetworking() (*linuxNetworking, error) {
	ln := &linuxNetworking{}
	ipvsHandle, err := ipvs.New("")
	if err != nil {
		return nil, err
	}
	ln.ipvsHandle = ipvsHandle
	return ln, nil
}
