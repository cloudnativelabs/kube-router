package proxy

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/docker/libnetwork/ipvs"
	"github.com/golang/glog"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/sets"
)

// sync the ipvs service and server details configured to reflect the desired state of Kubernetes services
// and endpoints as learned from services and endpoints information from the api server
func (nsc *NetworkServicesController) syncIpvsServices(serviceInfoMap serviceInfoMap, endpointsInfoMap endpointsInfoMap) error {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		if nsc.MetricsEnabled {
			metrics.ControllerIpvsServicesSyncTime.Observe(endTime.Seconds())
		}
		glog.V(1).Infof("sync ipvs services took %v", endTime)
	}()

	var err error
	var syncErrors bool

	// map to track all active IPVS services and servers that are setup during sync of
	// cluster IP, nodeport and external IP services
	activeServiceEndpointMap := make(map[string][]string)

	err = nsc.setupClusterIPServices(serviceInfoMap, endpointsInfoMap, activeServiceEndpointMap)
	if err != nil {
		syncErrors = true
		glog.Errorf("Error setting up IPVS services for service cluster IP's: %s", err.Error())
	}
	err = nsc.setupNodePortServices(serviceInfoMap, endpointsInfoMap, activeServiceEndpointMap)
	if err != nil {
		syncErrors = true
		glog.Errorf("Error setting up IPVS services for service nodeport's: %s", err.Error())
	}
	err = nsc.setupExternalIPServices(serviceInfoMap, endpointsInfoMap, activeServiceEndpointMap)
	if err != nil {
		syncErrors = true
		glog.Errorf("Error setting up IPVS services for service external IP's and load balancer IP's: %s", err.Error())
	}
	err = nsc.cleanupStaleVIPs(activeServiceEndpointMap)
	if err != nil {
		syncErrors = true
		glog.Errorf("Error cleaning up stale VIP's configured on the dummy interface: %s", err.Error())
	}
	err = nsc.cleanupStaleIPVSConfig(activeServiceEndpointMap)
	if err != nil {
		syncErrors = true
		glog.Errorf("Error cleaning up stale IPVS services and servers: %s", err.Error())
	}
	err = nsc.syncIpvsFirewall()
	if err != nil {
		syncErrors = true
		glog.Errorf("Error syncing ipvs svc iptables rules to permit traffic to service VIP's: %s", err.Error())
	}
	err = nsc.setupForDSR(serviceInfoMap)
	if err != nil {
		syncErrors = true
		glog.Errorf("Error setting up necessary policy based routing configuration needed for direct server return: %s", err.Error())
	}

	if syncErrors {
		glog.V(1).Info("One or more errors encountered during sync of IPVS services and servers to desired state")
	} else {
		glog.V(1).Info("IPVS servers and services are synced to desired state")
	}

	return nil
}

func (nsc *NetworkServicesController) setupClusterIPServices(serviceInfoMap serviceInfoMap, endpointsInfoMap endpointsInfoMap, activeServiceEndpointMap map[string][]string) error {
	ipvsSvcs, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return errors.New("Failed get list of IPVS services due to: " + err.Error())
	}
	for k, svc := range serviceInfoMap {
		var protocol uint16

		switch svc.protocol {
		case "tcp":
			protocol = syscall.IPPROTO_TCP
		case "udp":
			protocol = syscall.IPPROTO_UDP
		default:
			protocol = syscall.IPPROTO_NONE
		}

		endpoints := endpointsInfoMap[k]
		dummyVipInterface, err := nsc.ln.getKubeDummyInterface()
		if err != nil {
			return errors.New("Failed creating dummy interface: " + err.Error())
		}
		// assign cluster IP of the service to the dummy interface so that its routable from the pod's on the node
		err = nsc.ln.ipAddrAdd(dummyVipInterface, svc.clusterIP.String(), true)
		if err != nil {
			continue
		}

		// create IPVS service for the service to be exposed through the cluster ip
		ipvsClusterVipSvc, err := nsc.ln.ipvsAddService(ipvsSvcs, svc.clusterIP, protocol, uint16(svc.port), svc.sessionAffinity, svc.scheduler, svc.flags)
		if err != nil {
			glog.Errorf("Failed to create ipvs service for cluster ip: %s", err.Error())
			continue
		}
		var clusterServiceId = generateIpPortId(svc.clusterIP.String(), svc.protocol, strconv.Itoa(svc.port))
		activeServiceEndpointMap[clusterServiceId] = make([]string, 0)

		// add IPVS remote server to the IPVS service
		for _, endpoint := range endpoints {
			dst := ipvs.Destination{
				Address:       net.ParseIP(endpoint.ip),
				AddressFamily: syscall.AF_INET,
				Port:          uint16(endpoint.port),
				Weight:        1,
			}

			err := nsc.ln.ipvsAddServer(ipvsClusterVipSvc, &dst)
			if err != nil {
				glog.Errorf(err.Error())
			} else {
				activeServiceEndpointMap[clusterServiceId] = append(activeServiceEndpointMap[clusterServiceId], endpoint.ip)
			}
		}
	}
	return nil
}

func (nsc *NetworkServicesController) setupNodePortServices(serviceInfoMap serviceInfoMap, endpointsInfoMap endpointsInfoMap, activeServiceEndpointMap map[string][]string) error {
	ipvsSvcs, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return errors.New("Failed get list of IPVS services due to: " + err.Error())
	}
	for k, svc := range serviceInfoMap {
		var protocol uint16

		switch svc.protocol {
		case "tcp":
			protocol = syscall.IPPROTO_TCP
		case "udp":
			protocol = syscall.IPPROTO_UDP
		default:
			protocol = syscall.IPPROTO_NONE
		}

		if svc.nodePort == 0 {
			// service is not NodePort type
			continue
		}
		endpoints := endpointsInfoMap[k]
		if svc.local && !hasActiveEndpoints(svc, endpoints) {
			glog.V(1).Infof("Skipping setting up NodePort service %s/%s as it does not have active endpoints\n", svc.namespace, svc.name)
			continue
		}

		// create IPVS service for the service to be exposed through the nodeport
		var ipvsNodeportSvcs []*ipvs.Service

		var nodeServiceIds []string

		if nsc.nodeportBindOnAllIp {
			// bind on all interfaces instead
			addrs, err := getAllLocalIPs()

			if err != nil {
				glog.Errorf("Could not get list of system addresses for ipvs services: %s", err.Error())
				continue
			}

			if len(addrs) == 0 {
				glog.Errorf("No IP addresses returned for nodeport service creation!")
				continue
			}

			ipvsNodeportSvcs = make([]*ipvs.Service, len(addrs))
			nodeServiceIds = make([]string, len(addrs))

			for i, addr := range addrs {
				ipvsNodeportSvcs[i], err = nsc.ln.ipvsAddService(ipvsSvcs, addr.IP, protocol, uint16(svc.nodePort), svc.sessionAffinity, svc.scheduler, svc.flags)
				if err != nil {
					glog.Errorf("Failed to create ipvs service for node port due to: %s", err.Error())
					continue
				}

				nodeServiceIds[i] = generateIpPortId(addr.IP.String(), svc.protocol, strconv.Itoa(svc.nodePort))
				activeServiceEndpointMap[nodeServiceIds[i]] = make([]string, 0)
			}
		} else {
			ipvsNodeportSvcs = make([]*ipvs.Service, 1)
			ipvsNodeportSvcs[0], err = nsc.ln.ipvsAddService(ipvsSvcs, nsc.nodeIP, protocol, uint16(svc.nodePort), svc.sessionAffinity, svc.scheduler, svc.flags)
			if err != nil {
				glog.Errorf("Failed to create ipvs service for node port due to: %s", err.Error())
				continue
			}

			nodeServiceIds = make([]string, 1)
			nodeServiceIds[0] = generateIpPortId(nsc.nodeIP.String(), svc.protocol, strconv.Itoa(svc.nodePort))
			activeServiceEndpointMap[nodeServiceIds[0]] = make([]string, 0)
		}

		for _, endpoint := range endpoints {
			dst := ipvs.Destination{
				Address:       net.ParseIP(endpoint.ip),
				AddressFamily: syscall.AF_INET,
				Port:          uint16(endpoint.port),
				Weight:        1,
			}
			for i := 0; i < len(ipvsNodeportSvcs); i++ {
				if !svc.local || (svc.local && endpoint.isLocal) {
					err := nsc.ln.ipvsAddServer(ipvsNodeportSvcs[i], &dst)
					if err != nil {
						glog.Errorf(err.Error())
					} else {
						activeServiceEndpointMap[nodeServiceIds[i]] = append(activeServiceEndpointMap[nodeServiceIds[i]], endpoint.ip)
					}
				}
			}
		}
	}
	return nil
}

func (nsc *NetworkServicesController) setupExternalIPServices(serviceInfoMap serviceInfoMap, endpointsInfoMap endpointsInfoMap, activeServiceEndpointMap map[string][]string) error {
	ipvsSvcs, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return errors.New("Failed get list of IPVS services due to: " + err.Error())
	}
	for k, svc := range serviceInfoMap {
		var protocol uint16

		switch svc.protocol {
		case "tcp":
			protocol = syscall.IPPROTO_TCP
		case "udp":
			protocol = syscall.IPPROTO_UDP
		default:
			protocol = syscall.IPPROTO_NONE
		}

		endpoints := endpointsInfoMap[k]

		dummyVipInterface, err := nsc.ln.getKubeDummyInterface()
		if err != nil {
			return errors.New("Failed creating dummy interface: " + err.Error())
		}

		externalIpServices := make([]externalIPService, 0)
		// create IPVS service for the service to be exposed through the external IP's
		// For external IP (which are meant for ingress traffic) Kube-router setsup IPVS services
		// based on FWMARK to enable Direct server return functionality. DSR requires a director
		// without a VIP http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html
		// to avoid martian packets
		extIPSet := sets.NewString(svc.externalIPs...)
		if !svc.skipLbIps {
			extIPSet = extIPSet.Union(sets.NewString(svc.loadBalancerIPs...))
		}

		if extIPSet.Len() == 0 {
			// service is not LoadBalancer type and no external IP's are configured
			continue
		}

		if svc.local && !hasActiveEndpoints(svc, endpoints) {
			glog.V(1).Infof("Skipping setting up IPVS service for external IP and LoadBalancer IP for the service %s/%s as it does not have active endpoints\n", svc.namespace, svc.name)
			continue
		}
		for _, externalIP := range extIPSet.List() {
			var externalIpServiceId string
			if svc.directServerReturn && svc.directServerReturnMethod == "tunnel" {
				ipvsExternalIPSvc, err := nsc.ln.ipvsAddFWMarkService(net.ParseIP(externalIP), protocol, uint16(svc.port), svc.sessionAffinity, svc.scheduler, svc.flags)
				if err != nil {
					glog.Errorf("Failed to create ipvs service for External IP: %s due to: %s", externalIP, err.Error())
					continue
				}
				externalIpServices = append(externalIpServices, externalIPService{ipvsSvc: ipvsExternalIPSvc, externalIp: externalIP})
				fwMark := generateFwmark(externalIP, svc.protocol, strconv.Itoa(svc.port))
				externalIpServiceId = fmt.Sprint(fwMark)

				// ensure there is iptables mangle table rule to FWMARK the packet
				err = setupMangleTableRule(externalIP, svc.protocol, strconv.Itoa(svc.port), externalIpServiceId)
				if err != nil {
					glog.Errorf("Failed to setup mangle table rule to FMWARD the traffic to external IP")
					continue
				}

				// ensure VIP less director. we dont assign VIP to any interface
				err = nsc.ln.ipAddrDel(dummyVipInterface, externalIP)

				// do policy routing to deliver the packet locally so that IPVS can pick the packet
				err = routeVIPTrafficToDirector("0x" + fmt.Sprintf("%x", fwMark))
				if err != nil {
					glog.Errorf("Failed to setup ip rule to lookup traffic to external IP: %s through custom "+
						"route table due to %s", externalIP, err.Error())
					continue
				}
			} else {
				// ensure director with vip assigned
				err := nsc.ln.ipAddrAdd(dummyVipInterface, externalIP, true)
				if err != nil && err.Error() != IFACE_HAS_ADDR {
					glog.Errorf("Failed to assign external ip %s to dummy interface %s due to %s", externalIP, KUBE_DUMMY_IF, err.Error())
				}

				// create IPVS service for the service to be exposed through the external ip
				ipvsExternalIPSvc, err := nsc.ln.ipvsAddService(ipvsSvcs, net.ParseIP(externalIP), protocol, uint16(svc.port), svc.sessionAffinity, svc.scheduler, svc.flags)
				if err != nil {
					glog.Errorf("Failed to create ipvs service for external ip: %s due to %s", externalIP, err.Error())
					continue
				}
				externalIpServices = append(externalIpServices, externalIPService{ipvsSvc: ipvsExternalIPSvc, externalIp: externalIP})
				externalIpServiceId = generateIpPortId(externalIP, svc.protocol, strconv.Itoa(svc.port))

				// ensure there is NO iptables mangle table rule to FWMARK the packet
				fwMark := fmt.Sprint(generateFwmark(externalIP, svc.protocol, strconv.Itoa(svc.port)))
				err = nsc.ln.cleanupMangleTableRule(externalIP, svc.protocol, strconv.Itoa(svc.port), fwMark)
				if err != nil {
					glog.Errorf("Failed to verify and cleanup any mangle table rule to FMWARD the traffic to external IP due to " + err.Error())
					continue
				}
			}

			activeServiceEndpointMap[externalIpServiceId] = make([]string, 0)
			for _, endpoint := range endpoints {
				if !svc.local || (svc.local && endpoint.isLocal) {
					activeServiceEndpointMap[externalIpServiceId] = append(activeServiceEndpointMap[externalIpServiceId], endpoint.ip)
				}
			}
		}

		// add IPVS remote server to the IPVS service
		for _, endpoint := range endpoints {
			dst := ipvs.Destination{
				Address:       net.ParseIP(endpoint.ip),
				AddressFamily: syscall.AF_INET,
				Port:          uint16(endpoint.port),
				Weight:        1,
			}

			for _, externalIpService := range externalIpServices {
				if svc.local && !endpoint.isLocal {
					continue
				}

				if svc.directServerReturn && svc.directServerReturnMethod == "tunnel" {
					dst.ConnectionFlags = ipvs.ConnectionFlagTunnel
				}

				// add server to IPVS service
				err := nsc.ln.ipvsAddServer(externalIpService.ipvsSvc, &dst)
				if err != nil {
					glog.Errorf(err.Error())
				}

				// For now just support IPVS tunnel mode, we can add other ways of DSR in future
				if svc.directServerReturn && svc.directServerReturnMethod == "tunnel" {

					podObj, err := nsc.getPodObjectForEndpoint(endpoint.ip)
					if err != nil {
						glog.Errorf("Failed to find endpoint with ip: " + endpoint.ip + ". so skipping peparing endpoint for DSR")
						continue
					}

					// we are only concerned with endpoint pod running on current node
					if strings.Compare(podObj.Status.HostIP, nsc.nodeIP.String()) != 0 {
						continue
					}

					containerID := strings.TrimPrefix(podObj.Status.ContainerStatuses[0].ContainerID, "docker://")
					if containerID == "" {
						glog.Errorf("Failed to find container id for the endpoint with ip: " + endpoint.ip + " so skipping peparing endpoint for DSR")
						continue
					}

					err = nsc.ln.prepareEndpointForDsr(containerID, endpoint.ip, externalIpService.externalIp)
					if err != nil {
						glog.Errorf("Failed to prepare endpoint %s to do direct server return due to %s", endpoint.ip, err.Error())
					}
				}
			}
		}
	}
	return nil
}

func (nsc *NetworkServicesController) setupForDSR(serviceInfoMap serviceInfoMap) error {
	glog.V(1).Infof("Setting up policy routing required for Direct Server Return functionality.")
	err := nsc.ln.setupPolicyRoutingForDSR()
	if err != nil {
		return errors.New("Failed setup PBR for DSR due to: " + err.Error())
	}
	glog.V(1).Infof("Custom routing table " + customDSRRouteTableName + " required for Direct Server Return is setup as expected.")

	glog.V(1).Infof("Setting up custom route table required to add routes for external IP's.")
	err = nsc.ln.setupRoutesForExternalIPForDSR(serviceInfoMap)
	if err != nil {
		glog.Errorf("Failed setup custom routing table required to add routes for external IP's due to: " + err.Error())
		return errors.New("Failed setup custom routing table required to add routes for external IP's due to: " + err.Error())
	}
	glog.V(1).Infof("Custom routing table " + externalIPRouteTableName + " required for Direct Server Return is setup as expected.")
	return nil
}

func (nsc *NetworkServicesController) cleanupStaleVIPs(activeServiceEndpointMap map[string][]string) error {
	// cleanup stale IPs on dummy interface
	glog.V(1).Info("Cleaning up if any, old service IPs on dummy interface")
	addrActive := make(map[string]bool)
	for k := range activeServiceEndpointMap {
		// verify active and its a generateIpPortId() type service
		if strings.Contains(k, "-") {
			parts := strings.SplitN(k, "-", 3)
			addrActive[parts[0]] = true
		}
	}

	dummyVipInterface, err := nsc.ln.getKubeDummyInterface()
	if err != nil {
		return errors.New("Failed creating dummy interface: " + err.Error())
	}
	var addrs []netlink.Addr
	addrs, err = netlink.AddrList(dummyVipInterface, netlink.FAMILY_V4)
	if err != nil {
		return errors.New("Failed to list dummy interface IPs: " + err.Error())
	}
	for _, addr := range addrs {
		isActive := addrActive[addr.IP.String()]
		if !isActive {
			glog.V(1).Infof("Found an IP %s which is no longer needed so cleaning up", addr.IP.String())
			err := nsc.ln.ipAddrDel(dummyVipInterface, addr.IP.String())
			if err != nil {
				glog.Errorf("Failed to delete stale IP %s due to: %s",
					addr.IP.String(), err.Error())
				continue
			}
		}
	}
	return nil
}

func (nsc *NetworkServicesController) cleanupStaleIPVSConfig(activeServiceEndpointMap map[string][]string) error {

	ipvsSvcs, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return errors.New("Failed get list of IPVS services due to: " + err.Error())
	}

	// cleanup stale ipvs service and servers
	glog.V(1).Info("Cleaning up if any, old ipvs service and servers which are no longer needed")
	ipvsSvcs, err = nsc.ln.ipvsGetServices()

	if err != nil {
		return errors.New("Failed to list IPVS services: " + err.Error())
	}
	var protocol string
	for _, ipvsSvc := range ipvsSvcs {
		if ipvsSvc.Protocol == syscall.IPPROTO_TCP {
			protocol = "tcp"
		} else {
			protocol = "udp"
		}
		var key string
		if ipvsSvc.Address != nil {
			key = generateIpPortId(ipvsSvc.Address.String(), protocol, strconv.Itoa(int(ipvsSvc.Port)))
		} else if ipvsSvc.FWMark != 0 {
			key = fmt.Sprint(ipvsSvc.FWMark)
		} else {
			continue
		}

		endpoints, ok := activeServiceEndpointMap[key]
		// Only delete the service if it's not there anymore to prevent flapping
		// old: if !ok || len(endpoints) == 0 {
		if !ok {
			glog.V(1).Infof("Found a IPVS service %s which is no longer needed so cleaning up",
				ipvsServiceString(ipvsSvc))
			err := nsc.ln.ipvsDelService(ipvsSvc)
			if err != nil {
				glog.Errorf("Failed to delete stale IPVS service %s due to: %s",
					ipvsServiceString(ipvsSvc), err.Error())
				continue
			}
		} else {
			dsts, err := nsc.ln.ipvsGetDestinations(ipvsSvc)
			if err != nil {
				glog.Errorf("Failed to get list of servers from ipvs service")
			}
			for _, dst := range dsts {
				validEp := false
				for _, ep := range endpoints {
					if ep == dst.Address.String() {
						validEp = true
						break
					}
				}
				if !validEp {
					glog.V(1).Infof("Found a destination %s in service %s which is no longer needed so cleaning up",
						ipvsDestinationString(dst), ipvsServiceString(ipvsSvc))
					err = nsc.ipvsDeleteDestination(ipvsSvc, dst)
					if err != nil {
						glog.Errorf("Failed to delete destination %s from ipvs service %s",
							ipvsDestinationString(dst), ipvsServiceString(ipvsSvc))
					}
				}
			}
		}
	}
	return nil
}
