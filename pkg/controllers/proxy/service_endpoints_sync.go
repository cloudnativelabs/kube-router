package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ccoveille/go-safecast/v2"
	"github.com/cloudnativelabs/kube-router/v2/internal/nlretry"
	"github.com/cloudnativelabs/kube-router/v2/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/moby/ipvs"
	"github.com/vishvananda/netlink"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

// sync the ipvs service and server details configured to reflect the desired state of Kubernetes services
// and endpoints as learned from services and endpoints information from the api server
func (nsc *NetworkServicesController) syncIpvsServices(serviceInfoMap serviceInfoMap,
	endpointsInfoMap endpointSliceInfoMap) error {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		if nsc.MetricsEnabled {
			metrics.ControllerIpvsServicesSyncTime.Observe(endTime.Seconds())
		}
		klog.V(1).Infof("sync ipvs services took %v", endTime)
	}()

	var err error
	var syncErrors bool

	// map to track all active IPVS services and servers that are setup during sync of
	// cluster IP, nodeport and external IP services
	activeServiceEndpointMap := make(map[string][]string)

	klog.V(1).Info("Syncing ClusterIP Services")
	err = nsc.setupClusterIPServices(serviceInfoMap, endpointsInfoMap, activeServiceEndpointMap)
	if err != nil {
		syncErrors = true
		klog.Errorf("Error setting up IPVS services for service cluster IP's: %s", err.Error())
	}

	klog.V(1).Info("Syncing NodePort Services")
	err = nsc.setupNodePortServices(serviceInfoMap, endpointsInfoMap, activeServiceEndpointMap)
	if err != nil {
		syncErrors = true
		klog.Errorf("Error setting up IPVS services for service nodeport's: %s", err.Error())
	}

	klog.V(1).Info("Syncing ExternalIP Services")
	err = nsc.setupExternalIPServices(serviceInfoMap, endpointsInfoMap, activeServiceEndpointMap)
	if err != nil {
		syncErrors = true
		klog.Errorf("Error setting up IPVS services for service external IP's and load balancer IP's: %s",
			err.Error())
	}

	klog.V(1).Info("Setting up NodePort Health Checks for LB services")
	err = nsc.nphc.UpdateServicesInfo(serviceInfoMap, endpointsInfoMap)
	if err != nil {
		syncErrors = true
		klog.Errorf("Error setting up NodePort Health Checks for LB Services: %v", err)
	}

	klog.V(1).Info("Cleaning Up Stale VIPs from dummy interface")
	err = nsc.cleanupStaleVIPs(activeServiceEndpointMap)
	if err != nil {
		syncErrors = true
		klog.Errorf("Error cleaning up stale VIP's configured on the dummy interface: %s", err.Error())
	}

	klog.V(1).Info("Cleaning Up Stale VIPs from IPVS")
	err = nsc.cleanupStaleIPVSConfig(activeServiceEndpointMap)
	if err != nil {
		syncErrors = true
		klog.Errorf("Error cleaning up stale IPVS services and servers: %s", err.Error())
	}

	klog.V(1).Info("Syncing IPVS Firewall")
	err = nsc.syncIpvsFirewall()
	if err != nil {
		syncErrors = true
		klog.Errorf("Error syncing ipvs svc iptables rules to permit traffic to service VIP's: %s", err.Error())
	}

	klog.V(1).Info("Setting up DSR Services")
	err = nsc.setupForDSR(serviceInfoMap)
	if err != nil {
		syncErrors = true
		klog.Errorf("Error setting up necessary policy based routing configuration needed for "+
			"direct server return: %s", err.Error())
	}

	if syncErrors {
		klog.V(1).Info("One or more errors encountered during sync of IPVS services and servers " +
			"to desired state")
	} else {
		klog.V(1).Info("IPVS servers and services are synced to desired state")
	}

	return nil
}

func (nsc *NetworkServicesController) setupClusterIPServices(serviceInfoMap serviceInfoMap,
	endpointsInfoMap endpointSliceInfoMap, activeServiceEndpointMap map[string][]string) error {
	ipvsSvcs, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return fmt.Errorf("failed get list of IPVS services due to: %v", err)
	}

	for k, svc := range serviceInfoMap {
		endpoints := endpointsInfoMap[k]
		// First we check to see if this is a local service and that it has any active endpoints, if it doesn't there
		// isn't any use doing any of the below work, let's save some compute cycles and break fast
		if *svc.intTrafficPolicy == v1.ServiceInternalTrafficPolicyLocal && !hasActiveEndpoints(endpoints) {
			klog.V(1).Infof("Skipping setting up ClusterIP service %s/%s as it does not have active endpoints",
				svc.namespace, svc.name)
			continue
		}

		protocol := convertSvcProtoToSysCallProto(svc.protocol)
		clusterIPs := getAllClusterIPs(svc)
		ipv4NodeIP := nsc.krNode.FindBestIPv4NodeAddress()
		ipv6NodeIP := nsc.krNode.FindBestIPv6NodeAddress()
		dummyVipInterface, err := nsc.ln.getKubeDummyInterface()
		if err != nil {
			return fmt.Errorf("failed creating dummy interface: %v", err)
		}
		sPort, err := safecast.Convert[uint16](svc.port)
		if err != nil {
			return fmt.Errorf("failed to convert service port to uint16: %v", err)
		}

		for family, famClusIPs := range clusterIPs {
			var nodeIP string
			//nolint:exhaustive // we don't need exhaustive searching for IP Families
			switch family {
			case v1.IPv4Protocol:
				nodeIP = ipv4NodeIP.String()
			case v1.IPv6Protocol:
				nodeIP = ipv6NodeIP.String()
			}

			for _, clusterIP := range famClusIPs {
				var svcID string
				var ipvsSvc *ipvs.Service
				// assign cluster IP of the service to the dummy interface so that its routable from the pod's on the
				// node
				err = nsc.ln.ipAddrAdd(dummyVipInterface, clusterIP.String(), nodeIP, true)
				if err != nil {
					// Not logging an error here because it was already logged in the ipAddrAdd function
					continue
				}

				// create IPVS service for the service to be exposed through the cluster ip
				ipvsSvcs, svcID, ipvsSvc = nsc.addIPVSService(ipvsSvcs, activeServiceEndpointMap, svc, clusterIP,
					protocol, sPort)
				// We weren't able to create the IPVS service, so we won't be able to add endpoints to it
				if svcID == "" {
					// not logging an error here because it was already logged in the addIPVSService function
					continue
				}

				// add IPVS remote server to the IPVS service
				nsc.addEndpointsToIPVSService(endpoints, activeServiceEndpointMap, svc, svcID, ipvsSvc, clusterIP, true)
			}
		}
	}

	return nil
}

func (nsc *NetworkServicesController) addIPVSService(ipvsSvcs []*ipvs.Service, svcEndpointMap map[string][]string,
	svc *serviceInfo, vip net.IP, protocol uint16, port uint16) ([]*ipvs.Service, string, *ipvs.Service) {
	// Note: downstream calls to nsc.ln.ipvsAddService may insert additional services to ipvsSvcs slice if it finds
	// that it needs to create additional services. Don't count on this slice staying stable between calls
	ipvsSvcs, ipvsService, err := nsc.ln.ipvsAddService(ipvsSvcs, vip, protocol, port,
		svc.sessionAffinity, svc.sessionAffinityTimeoutSeconds, svc.scheduler, svc.flags)
	if err != nil {
		klog.Errorf("failed to create ipvs service for %s:%d due to: %s", vip, port, err.Error())
		return ipvsSvcs, "", ipvsService
	}

	svcID := generateIPPortID(vip.String(), svc.protocol, strconv.Itoa(int(port)))
	svcEndpointMap[svcID] = make([]string, 0)

	return ipvsSvcs, svcID, ipvsService
}

func (nsc *NetworkServicesController) addEndpointsToIPVSService(endpoints []endpointSliceInfo,
	svcEndpointMap map[string][]string, svc *serviceInfo, svcID string, ipvsSvc *ipvs.Service, vip net.IP,
	isClusterIP bool) {
	var family v1.IPFamily
	if vip.To4() != nil {
		family = v1.IPv4Protocol
	} else {
		family = v1.IPv6Protocol
	}

	if len(endpoints) < 1 {
		klog.Infof("No endpoints detected for service VIP: %s, skipping adding endpoints...", vip)
	}
	for _, endpoint := range endpoints {
		// Conditions on which to add an endpoint on this node:
		// 1) Service is not a local service
		// 2) Service is a local service, but has no active endpoints on this node
		// 3) Service is a local service, has active endpoints on this node, and this endpoint is one of them
		if !endpoint.isLocal {
			if isClusterIP && *svc.intTrafficPolicy == v1.ServiceInternalTrafficPolicyLocal {
				klog.V(2).Info("service has an internal traffic policy of local, but endpoint is not, continuing...")
				continue
			} else if !isClusterIP && *svc.extTrafficPolicy == v1.ServiceExternalTrafficPolicyLocal {
				klog.V(2).Info("service has an external traffic policy of local, but endpoint is not, continuing...")
				continue
			}
		}
		var syscallINET uint16
		eIP := net.ParseIP(endpoint.ip)

		//nolint:exhaustive // we don't need exhaustive searching for IP Families
		switch family {
		case v1.IPv4Protocol:
			if endpoint.isIPv6 {
				klog.V(3).Infof("not adding endpoint %s to service %s with VIP %s because families don't "+
					"match", endpoint.ip, svc.name, vip)
				continue
			}
			syscallINET = syscall.AF_INET
		case v1.IPv6Protocol:
			if endpoint.isIPv4 {
				klog.V(3).Infof("not adding endpoint %s to service %s with VIP %s because families don't "+
					"match", endpoint.ip, svc.name, vip)
				continue
			}
			syscallINET = syscall.AF_INET6
		}

		ePort, err := safecast.Convert[uint16](endpoint.port)
		if err != nil {
			klog.Errorf("failed to convert endpoint port to uint16: %v", err)
			continue
		}

		dst := ipvs.Destination{
			Address:       eIP,
			AddressFamily: syscallINET,
			Port:          ePort,
			Weight:        1,
		}
		err = nsc.ln.ipvsAddServer(ipvsSvc, &dst)
		if err != nil {
			klog.Errorf("encountered error adding endpoint to service: %v", err)
			continue
		}
		svcEndpointMap[svcID] = append(svcEndpointMap[svcID],
			generateEndpointID(endpoint.ip, strconv.Itoa(endpoint.port)))
	}
}

func (nsc *NetworkServicesController) setupNodePortServices(serviceInfoMap serviceInfoMap,
	endpointsInfoMap endpointSliceInfoMap, activeServiceEndpointMap map[string][]string) error {
	ipvsSvcs, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return errors.New("Failed get list of IPVS services due to: " + err.Error())
	}

	// For each Service in our service map
	for k, svc := range serviceInfoMap {
		protocol := convertSvcProtoToSysCallProto(svc.protocol)

		if svc.nodePort == 0 {
			// service is not NodePort type
			continue
		}

		endpoints := endpointsInfoMap[k]
		// First we check to see if this is a local service and that it has any active endpoints, if it doesn't there
		// isn't any use doing any of the below work, let's save some compute cycles and break fast
		if *svc.extTrafficPolicy == v1.ServiceExternalTrafficPolicyLocal && !hasActiveEndpoints(endpoints) {
			klog.V(1).Infof("Skipping setting up NodePort service %s/%s as it does not have active endpoints",
				svc.namespace, svc.name)
			continue
		}

		nPort, err := safecast.Convert[uint16](svc.nodePort)
		if err != nil {
			return fmt.Errorf("failed to convert node port to uint16: %v", err)
		}

		var svcID string
		var ipvsSvc *ipvs.Service
		if nsc.nodeportBindOnAllIP {
			// Bind on all interfaces instead of just the primary interface
			addrMap, err := getAllLocalIPs()
			if err != nil {
				klog.Errorf("Could not get list of system addresses for ipvs services: %s", err.Error())
				continue
			}

			// Check that any addrs were actually found
			addrsFound := false
			for _, addrs := range addrMap {
				if len(addrs) > 0 {
					addrsFound = true
				}
				if addrsFound {
					break
				}
			}
			if !addrsFound {
				klog.Errorf("No IP addresses returned for nodeport service creation!")
				continue
			}

			// Create the services
			for _, addrs := range addrMap {
				for _, addr := range addrs {

					ipvsSvcs, svcID, ipvsSvc = nsc.addIPVSService(ipvsSvcs, activeServiceEndpointMap, svc, addr,
						protocol, nPort)
					// We weren't able to create the IPVS service, so we won't be able to add endpoints to it
					if svcID == "" {
						continue
					}
					nsc.addEndpointsToIPVSService(endpoints, activeServiceEndpointMap, svc, svcID, ipvsSvc, addr, false)
				}
			}
		} else {
			ipvsSvcs, svcID, ipvsSvc = nsc.addIPVSService(ipvsSvcs, activeServiceEndpointMap, svc,
				nsc.krNode.GetPrimaryNodeIP(), protocol, nPort)
			// We weren't able to create the IPVS service, so we won't be able to add endpoints to it
			if svcID == "" {
				continue
			}
			nsc.addEndpointsToIPVSService(endpoints, activeServiceEndpointMap, svc, svcID, ipvsSvc,
				nsc.krNode.GetPrimaryNodeIP(), false)
		}
	}

	return nil
}

func (nsc *NetworkServicesController) setupExternalIPServices(serviceInfoMap serviceInfoMap,
	endpointsInfoMap endpointSliceInfoMap, activeServiceEndpointMap map[string][]string) error {
	for k, svc := range serviceInfoMap {
		endpoints := endpointsInfoMap[k]
		// First we check to see if this is a local service and that it has any active endpoints, if it doesn't there
		// isn't any use doing any of the below work, let's save some compute cycles and break fast
		if *svc.extTrafficPolicy == v1.ServiceExternalTrafficPolicyLocal && !hasActiveEndpoints(endpoints) {
			klog.V(1).Infof("Skipping setting up IPVS service for external IP and LoadBalancer IP "+
				"for the service %s/%s as it does not have active endpoints\n", svc.namespace, svc.name)
			continue
		}

		extIPs := getAllExternalIPs(svc, !svc.skipLbIps)
		// Check that any addrs were actually found
		addrsFound := false
		for _, addrs := range extIPs {
			if len(addrs) > 0 {
				addrsFound = true
			}
			if addrsFound {
				break
			}
		}
		if !addrsFound {
			klog.V(1).Infof("no external IP addresses returned for service %s:%s skipping...",
				svc.namespace, svc.name)
			continue
		}

		for _, addrs := range extIPs {
			for _, externalIP := range addrs {
				if svc.directServerReturn && svc.directServerReturnMethod == tunnelInterfaceType {
					// for a DSR service, do the work necessary to set up the IPVS service for DSR, then use the FW mark
					// that was generated to add this external IP to the activeServiceEndpointMap
					err := nsc.setupExternalIPForDSRService(svc, externalIP, endpoints, activeServiceEndpointMap)
					if err != nil {
						return fmt.Errorf("failed to setup DSR endpoint %s: %v", externalIP, err)
					}
					continue
				}

				// for a non-DSR service, do the work necessary to setup the IPVS service, then use its IP, protocol,
				// and port to add this external IP to the activeServiceEndpointMap
				err := nsc.setupExternalIPForService(svc, externalIP, endpoints, activeServiceEndpointMap)
				if err != nil {
					return fmt.Errorf("failed to setup service endpoint %s: %v", externalIP, err)
				}
			}
		}
	}
	nsc.setupSloppyTCP(serviceInfoMap)

	return nil
}

func (nsc *NetworkServicesController) setupSloppyTCP(serviceInfoMap serviceInfoMap) {
	var sloppyTCPVal int8 = 0
	for _, svc := range serviceInfoMap {
		// Enable sloppy TCP if any DSR service with Maglev hashing is configured
		if svc.directServerReturn && svc.scheduler == IpvsMaglevHashing {
			sloppyTCPVal = 1
			break
		}
	}

	// enable/disable sloppy_tcp sysctl based on sloppyTCPVal
	sloppyTCP := nsc.krNode.SloppyTCP()
	if sloppyTCP.CachedVal() != sloppyTCPVal {
		sysctlErr := sloppyTCP.WriteVal(sloppyTCPVal)
		if sysctlErr != nil {
			klog.Errorf("Failed to set IPVS sloppy TCP to %d: %s", sloppyTCPVal, sysctlErr.Error())
			return
		}
		klog.Infof("IPVS sloppy TCP set to %d", sloppyTCPVal)
	}
}

// setupExternalIPForService does the basic work to setup a non-DSR based external IP for service. This includes adding
// the IPVS service to the host if it is missing, and setting up the dummy interface to be able to receive traffic on
// the node.
func (nsc *NetworkServicesController) setupExternalIPForService(svc *serviceInfo, externalIP net.IP,
	endpoints []endpointSliceInfo, svcEndpointMap map[string][]string) error {
	// Get everything we need to get setup to process the external IP
	protocol := convertSvcProtoToSysCallProto(svc.protocol)
	var nodeIP net.IP
	var svcID string
	var ipvsExternalIPSvc *ipvs.Service

	if externalIP.To4() != nil {
		nodeIP = nsc.krNode.FindBestIPv4NodeAddress()
	} else {
		nodeIP = nsc.krNode.FindBestIPv6NodeAddress()
	}

	dummyVipInterface, err := nsc.ln.getKubeDummyInterface()
	if err != nil {
		return fmt.Errorf("failed creating dummy interface: %v", err)
	}

	ipvsSvcs, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return fmt.Errorf("failed get list of IPVS services due to: %v", err)
	}

	sPort, err := safecast.Convert[uint16](svc.port)
	if err != nil {
		return fmt.Errorf("failed to convert service port to uint16: %v", err)
	}

	// ensure director with vip assigned
	err = nsc.ln.ipAddrAdd(dummyVipInterface, externalIP.String(), nodeIP.String(), true)
	if err != nil && err.Error() != IfaceHasAddr {
		return fmt.Errorf("failed to assign external ip %s to dummy interface %s due to %v",
			externalIP, KubeDummyIf, err)
	}

	// create IPVS service for the service to be exposed through the external ip
	_, svcID, ipvsExternalIPSvc = nsc.addIPVSService(ipvsSvcs, svcEndpointMap, svc, externalIP, protocol, sPort)
	if svcID == "" {
		return fmt.Errorf("failed to create ipvs service for external ip: %s", externalIP)
	}

	// ensure there is NO iptables mangle table rule to FW mark the packet
	fwMark := nsc.lookupFWMarkByService(externalIP.String(), svc.protocol, strconv.Itoa(svc.port))
	switch {
	case fwMark == 0:
		klog.V(2).Infof("no FW mark found for service, nothing to cleanup")
	case fwMark != 0:
		klog.V(2).Infof("the following service '%s:%s:%d' had fwMark associated with it: %d doing "+
			"additional cleanup", externalIP, svc.protocol, svc.port, fwMark)
		if err = nsc.cleanupDSRService(fwMark); err != nil {
			return fmt.Errorf("failed to cleanup DSR service: %v", err)
		}
	}

	// add pod endpoints to the IPVS service
	nsc.addEndpointsToIPVSService(endpoints, svcEndpointMap, svc, svcID, ipvsExternalIPSvc, externalIP, false)

	return nil
}

// setupExternalIPForDSRService does the basic setup necessary to set up an External IP service for DSR. This includes
// generating a unique FW mark for the service, setting up the mangle rules to apply the FW mark, setting up IPVS to
// work with the FW mark, and ensuring that the IP doesn't exist on the dummy interface so that the traffic doesn't
// accidentally ingress the packet and change it.
//
// For external IPs (which are meant for ingress traffic) configured for DSR, kube-router sets up IPVS services
// based on FWMARK to enable direct server return functionality. DSR requires a director without a VIP
// http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html to avoid martian packets
func (nsc *NetworkServicesController) setupExternalIPForDSRService(svcIn *serviceInfo, externalIP net.IP,
	endpoints []endpointSliceInfo, svcEndpointMap map[string][]string) error {
	// Look across all endpoints of the service and see if any of the pods behind this service have hostNetwork: true
	// set. In this case, we cannot perform DSR, so give a warning and short-circuit.
	svc, err := nsc.getServiceForServiceInfo(svcIn)
	if err != nil {
		return fmt.Errorf("encountered Kubernetes error %v while resolving service info (%s:%s) to service", err,
			svcIn.namespace, svcIn.name)
	}
	pods, err := nsc.getPodListForService(svc)
	if err != nil {
		return fmt.Errorf("encountered Kubernetes error %v while resolving service (%s:%s) to a list of pods", err,
			svc.Namespace, svc.Name)
	}
	for _, pod := range pods.Items {
		if pod.Spec.HostNetwork {
			klog.Errorf("detected pod (%s:%s) with hostNetwork: true while attempting to setup DSR for service "+
				"(%s:%s) - DSR does not work with hostNetwork: true pods, skipping!", pod.Namespace, pod.Name,
				svc.Namespace, svc.Name)
			return nil
		}
	}

	// Get everything we need to get setup to process the external IP
	protocol := convertSvcProtoToSysCallProto(svcIn.protocol)
	var nodeIP net.IP
	var family v1.IPFamily
	var sysFamily uint16
	if externalIP.To4() != nil {
		nodeIP = nsc.krNode.FindBestIPv4NodeAddress()
		family = v1.IPv4Protocol
		sysFamily = syscall.AF_INET
	} else {
		nodeIP = nsc.krNode.FindBestIPv6NodeAddress()
		family = v1.IPv6Protocol
		sysFamily = syscall.AF_INET6
	}

	dummyVipInterface, err := nsc.ln.getKubeDummyInterface()
	if err != nil {
		return errors.New("Failed getting dummy interface: " + err.Error())
	}

	ipvsSvcs, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return errors.New("Failed get list of IPVS services due to: " + err.Error())
	}

	fwMark, err := nsc.generateUniqueFWMark(externalIP.String(), svcIn.protocol, strconv.Itoa(svcIn.port))
	if err != nil {
		return fmt.Errorf("failed to generate FW mark")
	}

	sInPort, err := safecast.Convert[uint16](svcIn.port)
	if err != nil {
		return fmt.Errorf("failed to convert serviceIn port to uint16: %v", err)
	}

	ipvsExternalIPSvc, err := nsc.ln.ipvsAddFWMarkService(ipvsSvcs, fwMark, sysFamily, protocol, sInPort,
		svcIn.sessionAffinity, svcIn.sessionAffinityTimeoutSeconds, svcIn.scheduler, svcIn.flags)
	if err != nil {
		return fmt.Errorf("failed to create IPVS service for FWMark service: %d (external IP: %s) due to: %s",
			fwMark, externalIP, err.Error())
	}

	externalIPServiceID := fmt.Sprint(fwMark)

	// ensure there is iptables mangle table rule to FWMARK the packet
	err = nsc.setupMangleTableRule(externalIP.String(), svcIn.protocol, strconv.Itoa(svcIn.port), externalIPServiceID)
	if err != nil {
		return fmt.Errorf("failed to setup mangle table rule to forward the traffic to external IP")
	}

	// ensure VIP less director. we dont assign VIP to any interface
	err = nsc.ln.ipAddrDel(dummyVipInterface, externalIP.String(), nodeIP.String())
	if err != nil && err.Error() != IfaceHasNoAddr {
		return fmt.Errorf("failed to delete external ip address from dummyVipInterface due to %v", err)
	}

	// do policy routing to deliver the packet locally so that IPVS can pick the packet
	err = routeVIPTrafficToDirector(fwMark, family)
	if err != nil {
		return fmt.Errorf("failed to setup ip rule to lookup traffic to external IP: %s through custom "+
			"route table due to %v", externalIP, err)
	}

	// add pod endpoints to the IPVS service (this is pretty much a repetition of addEndpointsToIPVSService, however,
	// we duplicate the logic here, because DSR requires a bit of extra stuff)
	for _, endpoint := range endpoints {
		// Conditions on which to add an endpoint on this node:
		// 1) Service is not a local service
		// 2) Service is a local service, but has no active endpoints on this node
		// 3) Service is a local service, has active endpoints on this node, and this endpoint is one of them
		if *svcIn.extTrafficPolicy == v1.ServiceExternalTrafficPolicyLocal && !endpoint.isLocal {
			continue
		}
		var syscallINET uint16
		eIP := net.ParseIP(endpoint.ip)

		//nolint:exhaustive // we don't need exhaustive searching for IP Families
		switch family {
		case v1.IPv4Protocol:
			if eIP.To4() == nil {
				klog.V(3).Infof("not adding endpoint %s to service %s with VIP %s because families don't "+
					"match", endpoint.ip, svcIn.name, externalIP)
				continue
			}
			syscallINET = syscall.AF_INET
		case v1.IPv6Protocol:
			if eIP.To4() != nil {
				klog.V(3).Infof("not adding endpoint %s to service %s with VIP %s because families don't "+
					"match", endpoint.ip, svcIn.name, externalIP)
				continue
			}
			syscallINET = syscall.AF_INET6
		}

		ePort, err := safecast.Convert[uint16](endpoint.port)
		if err != nil {
			return fmt.Errorf("failed to convert endpoint port to uint16: %v", err)
		}

		// create the basic IPVS destination record
		dst := ipvs.Destination{
			Address:         eIP,
			AddressFamily:   syscallINET,
			ConnectionFlags: ipvs.ConnectionFlagTunnel,
			Port:            ePort,
			Weight:          1,
		}

		// add the destination for the IPVS service for this external IP
		if err = nsc.ln.ipvsAddServer(ipvsExternalIPSvc, &dst); err != nil {
			return fmt.Errorf("unable to add destination %s to externalIP service %s: %v",
				endpoint.ip, externalIP, err)
		}

		// It's only for local endpoints that we can enter the container's namespace and add DSR receivers inside it.
		// If we aren't local, then we should skip this step so that we don't accidentally throw an error.
		if endpoint.isLocal {
			// add the external IP to a virtual interface inside the pod so that the pod can receive it
			if err = nsc.addDSRIPInsidePodNetNamespace(externalIP.String(), endpoint.ip); err != nil {
				return fmt.Errorf("unable to setup DSR receiver inside pod: %v", err)
			}
		}

		svcEndpointMap[externalIPServiceID] = append(svcEndpointMap[externalIPServiceID],
			generateEndpointID(endpoint.ip, strconv.Itoa(endpoint.port)))
	}

	return nil
}

func (nsc *NetworkServicesController) setupForDSR(serviceInfoMap serviceInfoMap) error {
	klog.V(1).Infof("Setting up policy routing required for Direct Server Return functionality.")
	err := nsc.ln.setupPolicyRoutingForDSR(nsc.krNode.IsIPv4Capable(), nsc.krNode.IsIPv6Capable())
	if err != nil {
		return errors.New("Failed setup PBR for DSR due to: " + err.Error())
	}
	klog.V(1).Infof("Custom routing table %s required for Direct Server Return is setup as expected.",
		customDSRRouteTableName)

	klog.V(1).Infof("Setting up custom route table required to add routes for external IP's.")
	err = nsc.ln.setupRoutesForExternalIPForDSR(serviceInfoMap, nsc.krNode.IsIPv4Capable(), nsc.krNode.IsIPv6Capable())
	if err != nil {
		klog.Errorf("failed setup custom routing table required to add routes for external IP's due to: %v",
			err)
		return fmt.Errorf("failed setup custom routing table required to add routes for external IP's due to: %v",
			err)
	}
	klog.V(1).Infof("Custom routing table required for Direct Server Return (%s) is setup as expected.",
		externalIPRouteTableName)
	return nil
}

func (nsc *NetworkServicesController) cleanupStaleVIPs(activeServiceEndpointMap map[string][]string) error {
	// cleanup stale IPs on dummy interface
	klog.V(1).Info("Cleaning up if any, old service IPs on dummy interface")
	// This represents "ip - protocol - port" that is created as the key to activeServiceEndpointMap in
	// generateIPPortID()
	const expectedServiceIDParts = 3
	addrActive := make(map[string]bool)
	for k := range activeServiceEndpointMap {
		// verify active and its a generateIPPortID() type service
		if strings.Contains(k, "-") {
			parts := strings.SplitN(k, "-", expectedServiceIDParts)
			addrActive[parts[0]] = true
		}
	}

	cleanupStaleVIPsForFamily := func(intfc netlink.Link, netlinkFamily int) error {
		addrs, err := nlretry.AddrList(context.Background(), intfc, netlinkFamily)
		if err != nil {
			return errors.New("Failed to list dummy interface IPs: " + err.Error())
		}
		for _, addr := range addrs {
			isActive := addrActive[addr.IP.String()]
			if !isActive {
				klog.V(1).Infof("Found an IP %s which is no longer needed so cleaning up", addr.IP.String())
				var nodeIPForFamily net.IP
				if addr.IP.To4() != nil {
					nodeIPForFamily = nsc.krNode.FindBestIPv4NodeAddress()
				} else {
					nodeIPForFamily = nsc.krNode.FindBestIPv6NodeAddress()
				}

				err := nsc.ln.ipAddrDel(intfc, addr.IP.String(), nodeIPForFamily.String())
				if err != nil {
					klog.Errorf("Failed to delete stale IP %s due to: %s",
						addr.IP.String(), err.Error())
					continue
				}
			}
		}

		return nil
	}

	dummyVipInterface, err := nsc.ln.getKubeDummyInterface()
	if err != nil {
		return fmt.Errorf("failed creating dummy interface: %v", err)
	}
	err = cleanupStaleVIPsForFamily(dummyVipInterface, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to remove stale IPv4 VIPs: %v", err)
	}
	err = cleanupStaleVIPsForFamily(dummyVipInterface, netlink.FAMILY_V6)
	if err != nil {
		return fmt.Errorf("failed to remove stale IPv6 VIPs: %v", err)
	}

	return nil
}

func (nsc *NetworkServicesController) cleanupStaleIPVSConfig(activeServiceEndpointMap map[string][]string) error {
	ipvsSvcs, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return errors.New("failed get list of IPVS services due to: " + err.Error())
	}

	// cleanup stale ipvs service and servers
	klog.V(1).Info("Cleaning up if any, old ipvs service and servers which are no longer needed")

	prettyMap, _ := json.MarshalIndent(activeServiceEndpointMap, "  ", "    ")
	klog.V(3).Infof("Current active service map:\n%s", prettyMap)
	var protocol string
	for _, ipvsSvc := range ipvsSvcs {
		// Note that this isn't all that safe of an assumption because FWMark services have a completely different
		// protocol. So do SCTP services. However, we don't deal with SCTP in kube-router and FWMark is handled below.
		protocol = convertSysCallProtoToSvcProto(ipvsSvc.Protocol)
		// FWMark services by definition don't have a protocol, so we exclude those from the conditional so that they
		// can be cleaned up correctly.
		if protocol == noneProtocol && ipvsSvc.FWMark == 0 {
			klog.Warningf("failed to convert protocol %d to a valid IPVS protocol for service: %s skipping",
				ipvsSvc.Protocol, ipvsSvc.Address.String())
			continue
		}

		var key string
		switch {
		case ipvsSvc.Address != nil:
			key = generateIPPortID(ipvsSvc.Address.String(), protocol, strconv.Itoa(int(ipvsSvc.Port)))
		case ipvsSvc.FWMark != 0:
			key = fmt.Sprint(ipvsSvc.FWMark)
		default:
			continue
		}

		endpointIDs, ok := activeServiceEndpointMap[key]
		// Only delete the service if it's not there anymore to prevent flapping
		// old: if !ok || len(endpointIDs) == 0 {
		if !ok {
			klog.V(3).Infof("didn't find key: %s in above map", key)
			excluded := false
			for _, excludedCidr := range nsc.excludedCidrs {
				if excludedCidr.Contains(ipvsSvc.Address) {
					excluded = true
					break
				}
			}

			if excluded {
				klog.V(1).Infof("Ignoring deletion of an IPVS service %s in an excluded cidr",
					ipvsServiceString(ipvsSvc))
				continue
			}

			klog.V(1).Infof("Found a IPVS service %s which is no longer needed so cleaning up",
				ipvsServiceString(ipvsSvc))
			if ipvsSvc.FWMark != 0 {
				_, _, _, err = nsc.lookupServiceByFWMark(ipvsSvc.FWMark)
				if err != nil {
					klog.V(1).Infof("no FW mark found for service, nothing to cleanup: %v", err)
				} else if err = nsc.cleanupDSRService(ipvsSvc.FWMark); err != nil {
					klog.Errorf("failed to cleanup DSR service: %v", err)
				}
			}
			err = nsc.ln.ipvsDelService(ipvsSvc)
			if err != nil {
				klog.Errorf("Failed to delete stale IPVS service %s due to: %s",
					ipvsServiceString(ipvsSvc), err.Error())
				continue
			}
		} else {
			dsts, err := nsc.ln.ipvsGetDestinations(ipvsSvc)
			if err != nil {
				klog.Errorf("Failed to get list of servers from ipvs service")
			}
			for _, dst := range dsts {
				validEp := false
				for _, epID := range endpointIDs {
					if epID == generateEndpointID(dst.Address.String(), strconv.Itoa(int(dst.Port))) {
						validEp = true
						break
					}
				}
				if !validEp {
					klog.V(1).Infof("Found a destination %s in service %s which is no longer needed so "+
						"cleaning up", ipvsDestinationString(dst), ipvsServiceString(ipvsSvc))
					err = nsc.ipvsDeleteDestination(ipvsSvc, dst)
					if err != nil {
						klog.Errorf("Failed to delete destination %s from ipvs service %s",
							ipvsDestinationString(dst), ipvsServiceString(ipvsSvc))
					}
				}
			}
		}
	}
	return nil
}

// cleanupDSRService takes an FW mark was its only input and uses that to lookup the service and then remove DSR
// specific pieces of that service that may be left-over from the service provisioning.
func (nsc *NetworkServicesController) cleanupDSRService(fwMark uint32) error {
	ipAddress, proto, port, err := nsc.lookupServiceByFWMark(fwMark)
	if err != nil {
		return fmt.Errorf("no service was found for FW mark: %d, service may not be all the way cleaned up: %v",
			fwMark, err)
	}

	// abstract cleanup as anonymous function so that we can reuse it for both IPv4 and IPv6
	cleanupTables := func(iptablesBinary string) {
		klog.V(2).Infof("service %s:%s:%d was found, continuing with DSR service cleanup", ipAddress, proto, port)
		mangleTableRulesDump := bytes.Buffer{}
		var mangleTableRules []string
		if err := utils.SaveInto(iptablesBinary, "mangle", &mangleTableRulesDump); err != nil {
			klog.Errorf("failed to run iptables-save: %v", err)
		} else {
			mangleTableRules = strings.Split(mangleTableRulesDump.String(), "\n")
		}

		// All of the iptables-save output here prints FW marks in hexadecimal, if we are doing string searching, our search
		// input needs to be in hex also
		fwMarkStr := strconv.FormatInt(int64(fwMark), 16)
		for _, mangleTableRule := range mangleTableRules {
			if strings.Contains(mangleTableRule, ipAddress) && strings.Contains(mangleTableRule, fwMarkStr) {
				klog.V(2).Infof("found mangle rule to cleanup: %s", mangleTableRule)

				// When we cleanup the iptables rule, we need to pass FW mark as an int string rather than a hex string
				err = nsc.cleanupMangleTableRule(ipAddress, proto, strconv.Itoa(port), strconv.Itoa(int(fwMark)))
				if err != nil {
					klog.Errorf("failed to verify and cleanup any mangle table rule to FORWARD the traffic "+
						"to external IP due to: %v", err)
					continue
				} else {
					// cleanupMangleTableRule will clean all rules in the table, so there is no need to continue looping
					break
				}
			}
		}
	}

	if nsc.krNode.IsIPv4Capable() {
		cleanupTables("iptables-save")
	}
	if nsc.krNode.IsIPv6Capable() {
		cleanupTables("ip6tables-save")
	}

	// cleanup the fwMarkMap to ensure that we don't accidentally build state
	delete(nsc.fwMarkMap, fwMark)
	return nil
}
