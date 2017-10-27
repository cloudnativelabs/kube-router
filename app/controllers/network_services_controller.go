package controllers

import (
	"errors"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/app/options"
	"github.com/cloudnativelabs/kube-router/app/watchers"
	"github.com/cloudnativelabs/kube-router/utils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/docker/docker/client"
	"github.com/docker/libnetwork/ipvs"
	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/net/context"
	api "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	KUBE_DUMMY_IF      = "kube-dummy-if"
	KUBE_TUNNEL_IF     = "kube-tunnel-if"
	IFACE_NOT_FOUND    = "Link not found"
	IFACE_HAS_ADDR     = "file exists"
	IPVS_SERVER_EXISTS = "file exists"
	namespace          = "kube_router"
)

var (
	h                        *ipvs.Handle
	serviceBackendActiveConn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_backend_active_connections",
		Help:      "Active conntection to backend of service",
	}, []string{"namespace", "service_name", "backend"})
	serviceBackendInactiveConn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_backend_inactive_connections",
		Help:      "Active conntection to backend of service",
	}, []string{"namespace", "service_name", "backend"})
	serviceBackendPpsIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_backend_pps_in",
		Help:      "Incoming packets per second",
	}, []string{"namespace", "service_name", "backend"})
	serviceBackendPpsOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_backend_pps_out",
		Help:      "Outoging packets per second",
	}, []string{"namespace", "service_name", "backend"})
)

// NetworkServicesController enables local node as network service proxy through IPVS/LVS.
// Support only Kubernetes network services of type NodePort, ClusterIP, and LoadBalancer. For each service a
// IPVS service is created and for each service endpoint a server is added to the IPVS service.
// As services and endpoints are updated, network service controller gets the updates from
// the kubernetes api server and syncs the ipvs configuration to reflect state of services
// and endpoints

// NetworkServicesController struct stores information needed by the controller
type NetworkServicesController struct {
	nodeIP              net.IP
	nodeHostName        string
	syncPeriod          time.Duration
	mu                  sync.Mutex
	serviceMap          serviceInfoMap
	endpointsMap        endpointsInfoMap
	podCidr             string
	masqueradeAll       bool
	globalHairpin       bool
	client              *kubernetes.Clientset
	nodeportBindOnAllIp bool
}

// internal representation of kubernetes service
type serviceInfo struct {
	name                     string
	namespace                string
	clusterIP                net.IP
	port                     int
	protocol                 string
	nodePort                 int
	sessionAffinity          bool
	directServerReturn       bool
	scheduler                string
	directServerReturnMethod string
	hairpin                  bool
	externalIPs              []string
}

// map of all services, with unique service id(namespace name, service name, port) as key
type serviceInfoMap map[string]*serviceInfo

// internal representation of endpoints
type endpointsInfo struct {
	ip   string
	port int
}

// map of all endpoints, with unique service id(namespace name, service name, port) as key
type endpointsInfoMap map[string][]endpointsInfo

// Run periodically sync ipvs configuration to reflect desired state of services and endpoints
func (nsc *NetworkServicesController) Run(stopCh <-chan struct{}, wg *sync.WaitGroup) error {

	t := time.NewTicker(nsc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	glog.Infof("Starting network services controller")

	// enable masquerade rule
	err := ensureMasqueradeIptablesRule(nsc.masqueradeAll, nsc.podCidr)
	if err != nil {
		return errors.New("Failed to do add masqurade rule in POSTROUTING chain of nat table due to: %s" + err.Error())
	}

	// register metrics
	prometheus.MustRegister(serviceBackendActiveConn)
	prometheus.MustRegister(serviceBackendInactiveConn)
	prometheus.MustRegister(serviceBackendPpsIn)
	prometheus.MustRegister(serviceBackendPpsOut)
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":8080", nil)

	// enable ipvs connection tracking
	err = ensureIpvsConntrack()
	if err != nil {
		return errors.New("Failed to do sysctl net.ipv4.vs.conntrack=1 due to: %s" + err.Error())
	}

	// loop forever unitl notified to stop on stopCh
	for {
		select {
		case <-stopCh:
			glog.Infof("Shutting down network services controller")
			return nil
		default:
		}

		if watchers.PodWatcher.HasSynced() && watchers.NetworkPolicyWatcher.HasSynced() {
			glog.Infof("Performing periodic syn of the ipvs services and server to reflect desired state of kubernetes services and endpoints")
			nsc.sync()
		} else {
			continue
		}

		select {
		case <-stopCh:
			glog.Infof("Shutting down network services controller")
			return nil
		case <-t.C:
		}
	}
}

func (nsc *NetworkServicesController) sync() {
	nsc.mu.Lock()
	defer nsc.mu.Unlock()

	nsc.serviceMap = buildServicesInfo()
	nsc.endpointsMap = buildEndpointsInfo()
	err := nsc.syncHairpinIptablesRules()
	if err != nil {
		glog.Errorf("Error syncing hairpin iptable rules: %s", err.Error())
	}
	nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
	nsc.publishMetrics(nsc.serviceMap)
}

// OnEndpointsUpdate handle change in endpoints update from the API server
func (nsc *NetworkServicesController) OnEndpointsUpdate(endpointsUpdate *watchers.EndpointsUpdate) {

	nsc.mu.Lock()
	defer nsc.mu.Unlock()

	glog.Infof("Received endpoints update from watch API")
	if !(watchers.ServiceWatcher.HasSynced() && watchers.EndpointsWatcher.HasSynced()) {
		glog.Infof("Skipping ipvs server sync as local cache is not synced yet")
	}

	// build new endpoints map to reflect the change
	newEndpointsMap := buildEndpointsInfo()

	if len(newEndpointsMap) != len(nsc.endpointsMap) || !reflect.DeepEqual(newEndpointsMap, nsc.endpointsMap) {
		nsc.endpointsMap = newEndpointsMap
		nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
	} else {
		glog.Infof("Skipping ipvs server sync on endpoints update because nothing changed")
	}
}

// OnServiceUpdate handle change in service update from the API server
func (nsc *NetworkServicesController) OnServiceUpdate(serviceUpdate *watchers.ServiceUpdate) {

	nsc.mu.Lock()
	defer nsc.mu.Unlock()

	glog.Infof("Received service update from watch API")
	if !(watchers.ServiceWatcher.HasSynced() && watchers.EndpointsWatcher.HasSynced()) {
		glog.Infof("Skipping ipvs server sync as local cache is not synced yet")
	}

	// build new services map to reflect the change
	newServiceMap := buildServicesInfo()

	if len(newServiceMap) != len(nsc.serviceMap) || !reflect.DeepEqual(newServiceMap, nsc.serviceMap) {
		nsc.serviceMap = newServiceMap
		nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
	} else {
		glog.Infof("Skipping ipvs server sync on service update because nothing changed")
	}
}

type externalIPService struct {
	ipvsSvc    *ipvs.Service
	externalIp string
}

// sync the ipvs service and server details configured to reflect the desired state of services and endpoint
// as learned from services and endpoints information from the api server
func (nsc *NetworkServicesController) syncIpvsServices(serviceInfoMap serviceInfoMap, endpointsInfoMap endpointsInfoMap) error {

	start := time.Now()
	defer func() {
		glog.Infof("sync ipvs servers took %v", time.Since(start))
	}()

	dummyVipInterface, err := getKubeDummyInterface()
	if err != nil {
		return errors.New("Failed creating dummy interface: " + err.Error())
	}

	glog.Infof("Setting up policy routing required for Direct Server Return functionality.")
	err = setupPolicyRoutingForDSR()
	if err != nil {
		return errors.New("Failed setup PBR for DSR due to: " + err.Error())
	}
	glog.Infof("Custom routing table " + customDSRRouteTableName + "required for Direct Server Return is setup as expected.")

	// map of active services and service endpoints
	activeServiceEndpointMap := make(map[string][]string)

	for k, svc := range serviceInfoMap {
		var protocol uint16
		if svc.protocol == "tcp" {
			protocol = syscall.IPPROTO_TCP
		} else {
			protocol = syscall.IPPROTO_UDP
		}

		// assign cluster IP of the service to the dummy interface so that its routable from the pod's on the node
		vip := &netlink.Addr{IPNet: &net.IPNet{IP: svc.clusterIP, Mask: net.IPv4Mask(255, 255, 255, 255)}, Scope: syscall.RT_SCOPE_LINK}
		err := netlink.AddrAdd(dummyVipInterface, vip)
		if err != nil && err.Error() != IFACE_HAS_ADDR {
			glog.Errorf("Failed to assign cluster ip %s to dummy interface %s", svc.clusterIP.String(), err.Error())
			continue
		}

		// create IPVS service for the service to be exposed through the cluster ip
		ipvsClusterVipSvc, err := ipvsAddService(svc.clusterIP, protocol, uint16(svc.port), svc.sessionAffinity, svc.scheduler)
		if err != nil {
			glog.Errorf("Failed to create ipvs service for cluster ip: %s", err.Error())
			continue
		}
		var clusterServiceId = generateIpPortId(svc.clusterIP.String(), svc.protocol, strconv.Itoa(svc.port))
		activeServiceEndpointMap[clusterServiceId] = make([]string, 0)

		// create IPVS service for the service to be exposed through the nodeport
		var ipvsNodeportSvc *ipvs.Service
		var nodeServiceId string
		if svc.nodePort != 0 {
			var vip net.IP
			if vip = nsc.nodeIP; nsc.nodeportBindOnAllIp {
				vip = net.ParseIP("127.0.0.1")
			}
			ipvsNodeportSvc, err = ipvsAddService(vip, protocol, uint16(svc.nodePort), svc.sessionAffinity, svc.scheduler)
			if err != nil {
				glog.Errorf("Failed to create ipvs service for node port due to: %s", err.Error())
				continue
			}
			if nsc.nodeportBindOnAllIp {
				nodeServiceId = generateIpPortId("127.0.0.1", svc.protocol, strconv.Itoa(svc.nodePort))
			} else {
				nodeServiceId = generateIpPortId(nsc.nodeIP.String(), svc.protocol, strconv.Itoa(svc.nodePort))
			}
			activeServiceEndpointMap[nodeServiceId] = make([]string, 0)
		}

		endpoints := endpointsInfoMap[k]

		externalIpServices := make([]externalIPService, 0)
		// create IPVS service for the service to be exposed through the external IP's
		// For external IP (which are meant for ingress traffic) Kube-router setsup IPVS services
		// based on FWMARK to enable Direct server return functionality. DSR requires a director
		// without a VIP http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html
		// to avoid martian packets
		for _, externalIP := range svc.externalIPs {
			ipvsExternalIPSvc, err := ipvsAddFWMarkService(net.ParseIP(externalIP), protocol, uint16(svc.port), svc.sessionAffinity, svc.scheduler)
			if err != nil {
				glog.Errorf("Failed to create ipvs service for External IP: %s due to: %s", externalIP, err.Error())
				continue
			}
			externalIpServices = append(externalIpServices, externalIPService{ipvsSvc: ipvsExternalIPSvc, externalIp: externalIP})
			fwMark := generateFwmark(externalIP, svc.protocol, strconv.Itoa(svc.port))
			externalIpServiceId := fmt.Sprint(fwMark)

			// ensure there is iptable mangle table rule to FWMARK the packet
			err = setupMangleTableRule(externalIP, svc.protocol, strconv.Itoa(svc.port), externalIpServiceId)
			if err != nil {
				glog.Errorf("Failed to setup mangle table rule to FMWARD the traffic to external IP")
				continue
			}

			// in VIP less directory we dont assign VIP to any interface, so we do policy routing
			// to deliver the packet locally so that IPVS can pick the packet
			err = routeVIPTrafficToDirector("0x" + fmt.Sprintf("%x", fwMark))
			if err != nil {
				glog.Errorf("Failed to setup ip rule to lookup traffic to external IP: %s through custom "+
					"route table due to ", externalIP, err.Error())
				continue
			}

			activeServiceEndpointMap[externalIpServiceId] = make([]string, 0)
			for _, endpoint := range endpoints {
				activeServiceEndpointMap[externalIpServiceId] =
					append(activeServiceEndpointMap[externalIpServiceId], endpoint.ip)
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

			err := ipvsAddServer(ipvsClusterVipSvc, &dst)
			if err != nil {
				glog.Errorf(err.Error())
			}

			activeServiceEndpointMap[clusterServiceId] =
				append(activeServiceEndpointMap[clusterServiceId], endpoint.ip)

			if svc.nodePort != 0 {
				err := ipvsAddServer(ipvsNodeportSvc, &dst)
				if err != nil {
					glog.Errorf(err.Error())
				}

				activeServiceEndpointMap[nodeServiceId] =
					append(activeServiceEndpointMap[clusterServiceId], endpoint.ip)
			}

			for _, externalIpService := range externalIpServices {

				if svc.directServerReturn && svc.directServerReturnMethod == "tunnel" {
					dst.ConnectionFlags = ipvs.ConnectionFlagTunnel
				}

				// add server to IPVS service
				err := ipvsAddServer(externalIpService.ipvsSvc, &dst)
				if err != nil {
					glog.Errorf(err.Error())
				}

				// For now just support IPVS tunnel mode, we can add other ways of DSR in future
				if svc.directServerReturn && svc.directServerReturnMethod == "tunnel" {

					podObj, err := getPodObjectForEndpoint(endpoint.ip)
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

					err = prepareEndpointForDsr(containerID, endpoint.ip, externalIpService.externalIp)
					if err != nil {
						glog.Errorf("Failed to prepare endpoint %s to do direct server return due to %s", endpoint.ip, err.Error())
					}
				}
			}
		}
	}

	// cleanup stale ipvs service and servers
	glog.Infof("Cleaning up if any, old ipvs service and servers which are no longer needed")
	ipvsSvcs, err := h.GetServices()
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
		if !ok {
			glog.Infof("Found a IPVS service %s which is no longer needed so cleaning up",
				ipvsServiceString(ipvsSvc))
			err := h.DelService(ipvsSvc)
			if err != nil {
				glog.Errorf("Failed to delete stale IPVS service %s due to:",
					ipvsServiceString(ipvsSvc), err.Error())
				continue
			}
		} else {
			dsts, err := h.GetDestinations(ipvsSvc)
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
					glog.Infof("Found a destination %s in service %s which is no longer needed so cleaning up",
						ipvsDestinationString(dst), ipvsServiceString(ipvsSvc))
					err := h.DelDestination(ipvsSvc, dst)
					if err != nil {
						glog.Errorf("Failed to delete destination %s from ipvs service %s",
							ipvsDestinationString(dst), ipvsServiceString(ipvsSvc))
					}
				}
			}
		}
	}
	glog.Infof("IPVS servers and services are synced to desired state!!")
	return nil
}

func getPodObjectForEndpoint(endpointIP string) (*api.Pod, error) {
	for _, pod := range watchers.PodWatcher.List() {
		if strings.Compare(pod.Status.PodIP, endpointIP) == 0 {
			return pod, nil
		}
	}
	return nil, errors.New("Failed to find pod with ip " + endpointIP)
}

// This function does the following
// - get the pod corresponding to the endpoint ip
// - get the container id from pod spec
// - from the container id, use docker client to get the pid
// - enter process network namespace and create ipip tunnel
// - add VIP to the tunnel interface
// - disable rp_filter
func prepareEndpointForDsr(containerId string, endpointIP string, vip string) error {

	currentNamespaceHandle, err := netns.Get()
	if err != nil {
		return errors.New("Failed to get namespace due to " + err.Error())
	}

	client, err := client.NewEnvClient()
	if err != nil {
		return errors.New("Failed to get docker client due to " + err.Error())
	}

	containerSpec, err := client.ContainerInspect(context.Background(), containerId)
	if err != nil {
		return errors.New("Failed to get docker container spec due to " + err.Error())
	}

	pid := containerSpec.State.Pid
	endpointNamespaceHandle, err := netns.GetFromPid(pid)
	if err != nil {
		return errors.New("Failed to get endpoint namespace due to " + err.Error())
	}

	err = netns.Set(endpointNamespaceHandle)
	if err != nil {
		return errors.New("Failed to enter to endpoint namespace due to " + err.Error())
	}

	// TODO: fix boilerplate `netns.Set(currentNamespaceHandle)` code. Need a robust
	// way to switch back to old namespace, pretty much many things will go wrong

	// create a ipip tunnel interface inside the endpoint container
	tunIf, err := netlink.LinkByName(KUBE_TUNNEL_IF)
	if err != nil {
		if err.Error() != IFACE_NOT_FOUND {
			netns.Set(currentNamespaceHandle)
			return errors.New("Failed to verify if ipip tunnel interface exists in endpoint " + endpointIP + " namespace due to " + err.Error())
		}

		glog.Infof("Could not find tunnel interface " + KUBE_TUNNEL_IF + " in endpoint " + endpointIP + " so creating one.")
		ipTunLink := netlink.Iptun{
			LinkAttrs: netlink.LinkAttrs{Name: KUBE_TUNNEL_IF},
			Local:     net.ParseIP(endpointIP),
		}
		err = netlink.LinkAdd(&ipTunLink)
		if err != nil {
			netns.Set(currentNamespaceHandle)
			return errors.New("Failed to add ipip tunnel interface in endpoint namespace due to " + err.Error())
		}

		// TODO: this is ugly, but ran into issue multiple times where interface did not come up quickly.
		// need to find the root cause
		for retry := 0; retry < 60; retry++ {
			time.Sleep(1000 * time.Millisecond)
			tunIf, err = netlink.LinkByName(KUBE_TUNNEL_IF)
			if err != nil && err.Error() == IFACE_NOT_FOUND {
				continue
			}
		}

		if err != nil {
			netns.Set(currentNamespaceHandle)
			return errors.New("Failed to get " + KUBE_TUNNEL_IF + " tunnel interface handle due to " + err.Error())
		}

		glog.Infof("Successfully created tunnel interface " + KUBE_TUNNEL_IF + " in endpoint " + endpointIP + ".")
	}

	// bring the tunnel interface up
	err = netlink.LinkSetUp(tunIf)
	if err != nil {
		netns.Set(currentNamespaceHandle)
		return errors.New("Failed to bring up ipip tunnel interface in endpoint namespace due to " + err.Error())
	}

	// assign VIP to the KUBE_TUNNEL_IF interface
	netlinkVip := &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP(vip),
		Mask: net.IPv4Mask(255, 255, 255, 255)}, Scope: syscall.RT_SCOPE_LINK}
	err = netlink.AddrAdd(tunIf, netlinkVip)
	if err != nil && err.Error() != IFACE_HAS_ADDR {
		netns.Set(currentNamespaceHandle)
		return errors.New("Failed to assign vip " + vip + " to kube-tunnel-if interface ")
	}
	glog.Infof("Successfully assinged VIP: " + vip + " in endpoint " + endpointIP + ".")

	// disable rp_filter on all interface
	err = ioutil.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte(strconv.Itoa(0)), 0640)
	if err != nil {
		netns.Set(currentNamespaceHandle)
		return errors.New("Failed to disable rp_filter in the endpoint container")
	}
	glog.Infof("Successfully disabled rp_filter in endpoint " + endpointIP + ".")

	netns.Set(currentNamespaceHandle)
	return nil
}

func (nsc *NetworkServicesController) publishMetrics(serviceInfoMap serviceInfoMap) error {
	// ipvsSvcs, err := h.GetServices()
	// if err != nil {
	// 	return errors.New("Failed to list IPVS services: " + err.Error())
	// }
	//
	// for _, svc := range serviceInfoMap {
	// 	for _, ipvsSvc := range ipvsSvcs {
	// 		if strings.Compare(svc.clusterIP.String(), ipvsSvc.Address.String()) == 0 &&
	// 			svc.protocol == strconv.Itoa(int(ipvsSvc.Protocol)) && uint16(svc.port) == ipvsSvc.Port {
	// 			dsts, err := h.GetDestinations(ipvsSvc)
	// 			if err != nil {
	// 				glog.Errorf("Failed to get list of servers from ipvs service")
	// 			}
	// 			for _, dst := range dsts {
	// 				serviceBackendActiveConn.WithLabelValues(svc.namespace, svc.name, dst.Address.String()).Set(float64(dst.Stats))
	// 				serviceBackendInactiveConn.WithLabelValues(svc.namespace, svc.name, dst.Address.String()).Set(float64(dst.InactConns))
	// 				serviceBackendPpsIn.WithLabelValues(svc.namespace, svc.name, dst.Address.String()).Set(float64(dst.Stats.PPSIn))
	// 				serviceBackendPpsOut.WithLabelValues(svc.namespace, svc.name, dst.Address.String()).Set(float64(dst.Stats.PPSOut))
	// 			}
	// 		}
	// 		if strings.Compare(nsc.nodeIP.String(), ipvsSvc.Address.String()) == 0 &&
	// 			svc.protocol == strconv.Itoa(int(ipvsSvc.Protocol)) && uint16(svc.port) == ipvsSvc.Port {
	// 			dsts, err := h.GetDestinations(ipvsSvc)
	// 			if err != nil {
	// 				glog.Errorf("Failed to get list of servers from ipvs service")
	// 			}
	// 			for _, dst := range dsts {
	// 				serviceBackendActiveConn.WithLabelValues(svc.namespace, svc.name, dst.Address.String()).Set(float64(dst.ActiveConns))
	// 				serviceBackendInactiveConn.WithLabelValues(svc.namespace, svc.name, dst.Address.String()).Set(float64(dst.InactConns))
	// 				serviceBackendPpsIn.WithLabelValues(svc.namespace, svc.name, dst.Address.String()).Set(float64(dst.Stats.PPSIn))
	// 				serviceBackendPpsOut.WithLabelValues(svc.namespace, svc.name, dst.Address.String()).Set(float64(dst.Stats.PPSOut))
	// 			}
	// 		}
	// 	}
	// }
	return nil
}

func buildServicesInfo() serviceInfoMap {
	serviceMap := make(serviceInfoMap)
	for _, svc := range watchers.ServiceWatcher.List() {

		if svc.Spec.ClusterIP == "None" || svc.Spec.ClusterIP == "" {
			glog.Infof("Skipping service name:%s namespace:%s as there is no cluster IP", svc.Name, svc.Namespace)
			continue
		}

		if svc.Spec.Type == "ExternalName" {
			glog.Infof("Skipping service name:%s namespace:%s due to service Type=%s", svc.Name, svc.Namespace, svc.Spec.Type)
			continue
		}

		for _, port := range svc.Spec.Ports {
			svcInfo := serviceInfo{
				clusterIP:   net.ParseIP(svc.Spec.ClusterIP),
				port:        int(port.Port),
				protocol:    strings.ToLower(string(port.Protocol)),
				nodePort:    int(port.NodePort),
				name:        svc.ObjectMeta.Name,
				namespace:   svc.ObjectMeta.Namespace,
				externalIPs: make([]string, len(svc.Spec.ExternalIPs)),
			}
			dsrMethod, ok := svc.ObjectMeta.Annotations["kube-router.io/service.dsr"]
			if ok {
				svcInfo.directServerReturn = true
				svcInfo.directServerReturnMethod = dsrMethod
			}
			svcInfo.scheduler = ipvs.RoundRobin
			schedulingMethod, ok := svc.ObjectMeta.Annotations["kube-router.io/service.scheduler"]
			if ok {
				if schedulingMethod == ipvs.RoundRobin {
					svcInfo.scheduler = ipvs.RoundRobin
				} else if schedulingMethod == ipvs.LeastConnection {
					svcInfo.scheduler = ipvs.LeastConnection
				} else if schedulingMethod == ipvs.DestinationHashing {
					svcInfo.scheduler = ipvs.DestinationHashing
				} else if schedulingMethod == ipvs.SourceHashing {
					svcInfo.scheduler = ipvs.SourceHashing
				}
			}
			copy(svcInfo.externalIPs, svc.Spec.ExternalIPs)
			svcInfo.sessionAffinity = (svc.Spec.SessionAffinity == "ClientIP")
			_, svcInfo.hairpin = svc.ObjectMeta.Annotations["kube-router.io/service.hairpin"]

			svcId := generateServiceId(svc.Namespace, svc.Name, port.Name)
			serviceMap[svcId] = &svcInfo
		}
	}
	return serviceMap
}

func shuffle(endPoints []endpointsInfo) []endpointsInfo {
	for index1 := range endPoints {
		index2 := rand.Intn(index1 + 1)
		endPoints[index1], endPoints[index2] = endPoints[index2], endPoints[index1]
	}
	return endPoints
}

func buildEndpointsInfo() endpointsInfoMap {
	endpointsMap := make(endpointsInfoMap)
	for _, ep := range watchers.EndpointsWatcher.List() {
		for _, epSubset := range ep.Subsets {
			for _, port := range epSubset.Ports {
				svcId := generateServiceId(ep.Namespace, ep.Name, port.Name)
				endpoints := make([]endpointsInfo, 0)
				for _, addr := range epSubset.Addresses {
					endpoints = append(endpoints, endpointsInfo{ip: addr.IP, port: int(port.Port)})
				}
				endpointsMap[svcId] = shuffle(endpoints)
			}
		}
	}
	return endpointsMap
}

// Add an iptable rule to masqurade outbound IPVS traffic. IPVS nat requires that reverse path traffic
// to go through the director for its functioning. So the masquerade rule ensures source IP is modifed
// to node ip, so return traffic from real server (endpoint pods) hits the node/lvs director
func ensureMasqueradeIptablesRule(masqueradeAll bool, podCidr string) error {
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed to initialize iptables executor" + err.Error())
	}
	var args []string
	if masqueradeAll {
		args = []string{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ", "-m", "comment", "--comment", "", "-j", "MASQUERADE"}
		err = iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", args...)
		if err != nil {
			return errors.New("Failed to run iptables command" + err.Error())
		}
	}
	if len(podCidr) > 0 {
		args = []string{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ", "-m", "comment", "--comment", "",
			"!", "-s", podCidr, "-j", "MASQUERADE"}
		err = iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", args...)
		if err != nil {
			return errors.New("Failed to run iptables command" + err.Error())
		}
	}
	glog.Infof("Successfully added iptables masqurade rule")
	return nil
}

// syncHairpinIptablesRules adds/removes iptables rules pertaining to traffic
// from an Endpoint (Pod) to its own service VIP. Rules are only applied if
// enabled globally via CLI argument or a service has an annotation requesting
// it.
func (nsc *NetworkServicesController) syncHairpinIptablesRules() error {
	//TODO: Use ipset?
	//TODO: Log a warning that this will not work without hairpin sysctl set on veth

	// Key is a string that will match iptables.List() rules
	// Value is a string[] with arguments that iptables transaction functions expect
	rulesNeeded := make(map[string][]string, 0)

	// Generate the rules that we need
	for svcName, svcInfo := range nsc.serviceMap {
		if nsc.globalHairpin || svcInfo.hairpin {
			for _, ep := range nsc.endpointsMap[svcName] {
				// Handle ClusterIP Service
				rule, ruleArgs := hairpinRuleFrom(svcInfo.clusterIP.String(), ep.ip, svcInfo.port)
				rulesNeeded[rule] = ruleArgs

				// Handle NodePort Service
				if svcInfo.nodePort != 0 {
					rule, ruleArgs := hairpinRuleFrom(nsc.nodeIP.String(), ep.ip, svcInfo.nodePort)
					rulesNeeded[rule] = ruleArgs
				}
			}
		}
	}

	// Cleanup (if needed) and return if there's no hairpin-mode Services
	if len(rulesNeeded) == 0 {
		glog.Infof("No hairpin-mode enabled services found -- no hairpin rules created")
		err := deleteHairpinIptablesRules()
		if err != nil {
			return errors.New("Error deleting hairpin rules: " + err.Error())
		}
		return nil
	}

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed to initialize iptables executor" + err.Error())
	}

	// TODO: Factor these variables out
	hairpinChain := "KUBE-ROUTER-HAIRPIN"
	hasHairpinChain := false

	// TODO: Factor out this code
	chains, err := iptablesCmdHandler.ListChains("nat")
	if err != nil {
		return errors.New("Failed to list iptables chains: " + err.Error())
	}

	// TODO: Factor out this code
	for _, chain := range chains {
		if chain == hairpinChain {
			hasHairpinChain = true
		}
	}

	// Create a chain for hairpin rules, if needed
	if hasHairpinChain != true {
		err = iptablesCmdHandler.NewChain("nat", hairpinChain)
		if err != nil {
			return errors.New("Failed to create iptables chain \"" + hairpinChain +
				"\": " + err.Error())
		}
	}

	// Create a rule that targets our hairpin chain, if needed
	// TODO: Factor this static rule out
	jumpArgs := []string{"-m", "ipvs", "--vdir", "ORIGINAL", "-j", hairpinChain}
	err = iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", jumpArgs...)
	if err != nil {
		return errors.New("Failed to add hairpin iptables jump rule: %s" + err.Error())
	}

	// Apply the rules we need
	for _, ruleArgs := range rulesNeeded {
		err = iptablesCmdHandler.AppendUnique("nat", hairpinChain, ruleArgs...)
		if err != nil {
			return errors.New("Failed to apply hairpin iptables rule: " + err.Error())
		}
	}

	rulesFromNode, err := iptablesCmdHandler.List("nat", hairpinChain)
	if err != nil {
		return errors.New("Failed to get rules from iptables chain \"" +
			hairpinChain + "\": " + err.Error())
	}

	// Delete invalid/outdated rules
	for _, ruleFromNode := range rulesFromNode {
		_, ruleIsNeeded := rulesNeeded[ruleFromNode]
		if !ruleIsNeeded {
			args := strings.Fields(ruleFromNode)
			if len(args) > 2 {
				args = args[2:] // Strip "-A CHAIN_NAME"

				err = iptablesCmdHandler.Delete("nat", hairpinChain, args...)
				if err != nil {
					glog.Errorf("Unable to delete hairpin rule \"%s\" from chain %s: %e", ruleFromNode, hairpinChain, err)
				} else {
					glog.Info("Deleted invalid/outdated hairpin rule \"%s\" from chain %s", ruleFromNode, hairpinChain)
				}
			} else {
				// Ignore the chain creation rule
				if ruleFromNode == "-N "+hairpinChain {
					continue
				}
				glog.Infof("Not removing invalid hairpin rule \"%s\" from chain %s", ruleFromNode, hairpinChain)
			}
		}
	}

	return nil
}

func hairpinRuleFrom(serviceIP string, endpointIP string, servicePort int) (string, []string) {
	// TODO: Factor hairpinChain out
	hairpinChain := "KUBE-ROUTER-HAIRPIN"

	ruleArgs := []string{"-s", endpointIP + "/32", "-d", endpointIP + "/32",
		"-m", "ipvs", "--vaddr", serviceIP, "--vport", strconv.Itoa(servicePort),
		"-j", "SNAT", "--to-source", serviceIP}

	// Trying to ensure this matches iptables.List()
	ruleString := "-A " + hairpinChain + " -s " + endpointIP + "/32" + " -d " +
		endpointIP + "/32" + " -m ipvs" + " --vaddr " + serviceIP + " --vport " +
		strconv.Itoa(servicePort) + " -j SNAT" + " --to-source " + serviceIP

	return ruleString, ruleArgs
}

func deleteHairpinIptablesRules() error {
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed to initialize iptables executor" + err.Error())
	}

	// TODO: Factor out this code
	chains, err := iptablesCmdHandler.ListChains("nat")
	if err != nil {
		return errors.New("Failed to list iptables chains: " + err.Error())
	}

	// TODO: Factor these variables out
	hairpinChain := "KUBE-ROUTER-HAIRPIN"
	hasHairpinChain := false

	// TODO: Factor out this code
	for _, chain := range chains {
		if chain == hairpinChain {
			hasHairpinChain = true
			break
		}
	}

	// Nothing left to do if hairpin chain doesn't exist
	if !hasHairpinChain {
		return nil
	}

	// TODO: Factor this static jump rule out
	jumpArgs := []string{"-m", "ipvs", "--vdir", "ORIGINAL", "-j", hairpinChain}
	hasHairpinJumpRule, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", jumpArgs...)
	if err != nil {
		return errors.New("Failed to search POSTROUTING iptable rules: " + err.Error())
	}

	// Delete the jump rule to the hairpin chain
	if hasHairpinJumpRule {
		err = iptablesCmdHandler.Delete("nat", "POSTROUTING", jumpArgs...)
		if err != nil {
			glog.Errorf("Unable to delete hairpin jump rule from chain \"POSTROUTING\": %e", err)
		} else {
			glog.Info("Deleted hairpin jump rule from chain \"POSTROUTING\"")
		}
	}

	// Flush and delete the chain for hairpin rules
	err = iptablesCmdHandler.ClearChain("nat", hairpinChain)
	if err != nil {
		return errors.New("Failed to flush iptables chain \"" + hairpinChain +
			"\": " + err.Error())
	}
	err = iptablesCmdHandler.DeleteChain("nat", hairpinChain)
	if err != nil {
		return errors.New("Failed to delete iptables chain \"" + hairpinChain +
			"\": " + err.Error())
	}
	return nil
}

func ensureIpvsConntrack() error {
	return ioutil.WriteFile("/proc/sys/net/ipv4/vs/conntrack", []byte(strconv.Itoa(1)), 0640)
}

func deleteMasqueradeIptablesRule() error {
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed to initialize iptables executor" + err.Error())
	}
	postRoutingChainRules, err := iptablesCmdHandler.List("nat", "POSTROUTING")
	if err != nil {
		return errors.New("Failed to list iptable rules in POSTROUTING chain in nat table" + err.Error())
	}
	for i, rule := range postRoutingChainRules {
		if strings.Contains(rule, "ipvs") && strings.Contains(rule, "MASQUERADE") {
			err = iptablesCmdHandler.Delete("nat", "POSTROUTING", strconv.Itoa(i))
			if err != nil {
				return errors.New("Failed to run iptables command" + err.Error())
			}
			glog.Infof("Deleted iptables masquerade rule: %s", rule)
			break
		}
	}
	return nil
}

func ipvsServiceString(s *ipvs.Service) string {
	var flags, protocol string

	switch s.Protocol {
	case syscall.IPPROTO_TCP:
		protocol = "TCP"
	case syscall.IPPROTO_UDP:
		protocol = "UDP"
	default:
		protocol = "UNKNOWN"
	}

	if s.Flags&0x0001 != 0 {
		flags = flags + "[persistent port]"
	}

	if s.Flags&0x0002 != 0 {
		flags = flags + "[hashed entry]"
	}

	if s.Flags&0x0004 != 0 {
		flags = flags + "[one-packet scheduling]"
	}

	return fmt.Sprintf("%s:%s:%v (Flags: %s)", protocol, s.Address, s.Port, flags)
}

func ipvsDestinationString(d *ipvs.Destination) string {
	return fmt.Sprintf("%s:%v (Weight: %v)", d.Address, d.Port, d.Weight)
}

func ipvsSetPersistence(svc *ipvs.Service, p bool) {
	if p {
		svc.Flags |= 0x0001
		svc.Netmask |= 0xFFFFFFFF
		// TODO: once service manifest supports timeout time remove hardcoding
		svc.Timeout = 180 * 60
	} else {
		svc.Flags &^= 0x0001
		svc.Netmask &^= 0xFFFFFFFF
		svc.Timeout = 0
	}
}

func ipvsAddService(vip net.IP, protocol, port uint16, persistent bool, scheduler string) (*ipvs.Service, error) {
	svcs, err := h.GetServices()
	if err != nil {
		return nil, err
	}

	for _, svc := range svcs {
		if vip.Equal(svc.Address) && protocol == svc.Protocol && port == svc.Port {
			if (persistent && (svc.Flags&0x0001) == 0) || (!persistent && (svc.Flags&0x0001) != 0) {
				ipvsSetPersistence(svc, persistent)

				err = h.UpdateService(svc)
				if err != nil {
					return nil, err
				}
				glog.Infof("Updated persistence/session-affinity for service: %s", ipvsServiceString(svc))
			}

			if scheduler != svc.SchedName {
				svc.SchedName = scheduler
				err = h.UpdateService(svc)
				if err != nil {
					return nil, errors.New("Failed to update the scheduler for the service due to " + err.Error())
				}
				glog.Infof("Updated schedule for the service: %s", ipvsServiceString(svc))
			}
			// TODO: Make this debug output when we get log levels
			// glog.Fatal("ipvs service %s:%s:%s already exists so returning", vip.String(),
			// 	protocol, strconv.Itoa(int(port)))

			return svc, nil
		}
	}

	svc := ipvs.Service{
		Address:       vip,
		AddressFamily: syscall.AF_INET,
		Protocol:      protocol,
		Port:          port,
		SchedName:     scheduler,
	}

	ipvsSetPersistence(&svc, persistent)

	err = h.NewService(&svc)
	if err != nil {
		return nil, err
	}
	glog.Infof("Successfully added service: %s", ipvsServiceString(&svc))
	return &svc, nil
}

// generateFwmark: generate a uint32 hash value using the IP address, port, protocol information
// TODO: collision can rarely happen but still need to be ruled out
// TODO: I ran into issues with FWMARK for any value above 2^15. Either policy
// routing and IPVS FWMARK service was not functioning with value above 2^15
func generateFwmark(ip, protocol, port string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(ip + "-" + protocol + "-" + port))
	return h.Sum32() & 0x3FFF
}

// ipvsAddFWMarkService: creates a IPVS service using FWMARK
func ipvsAddFWMarkService(vip net.IP, protocol, port uint16, persistent bool, scheduler string) (*ipvs.Service, error) {

	var protocolStr string
	if protocol == syscall.IPPROTO_TCP {
		protocolStr = "tcp"
	} else if protocol == syscall.IPPROTO_UDP {
		protocolStr = "udp"
	} else {
		protocolStr = "unknown"
	}

	// generate a FWMARK value unique to the external IP + protocol+ port combination
	fwmark := generateFwmark(vip.String(), protocolStr, fmt.Sprint(port))

	svcs, err := h.GetServices()
	if err != nil {
		return nil, err
	}

	for _, svc := range svcs {
		if fwmark == svc.FWMark {
			if (persistent && (svc.Flags&0x0001) == 0) || (!persistent && (svc.Flags&0x0001) != 0) {
				ipvsSetPersistence(svc, persistent)

				err = h.UpdateService(svc)
				if err != nil {
					return nil, err
				}
				glog.Infof("Updated persistence/session-affinity for service: %s", ipvsServiceString(svc))
			}

			if scheduler != svc.SchedName {
				svc.SchedName = scheduler
				err = h.UpdateService(svc)
				if err != nil {
					return nil, errors.New("Failed to update the scheduler for the service due to " + err.Error())
				}
				glog.Infof("Updated schedule for the service: %s", ipvsServiceString(svc))
			}
			// TODO: Make this debug output when we get log levels
			// glog.Fatal("ipvs service %s:%s:%s already exists so returning", vip.String(),
			// 	protocol, strconv.Itoa(int(port)))

			return svc, nil
		}
	}

	svc := ipvs.Service{
		FWMark:        fwmark,
		AddressFamily: syscall.AF_INET,
		Protocol:      protocol,
		Port:          port,
		SchedName:     ipvs.RoundRobin,
	}

	ipvsSetPersistence(&svc, persistent)

	err = h.NewService(&svc)
	if err != nil {
		return nil, err
	}
	glog.Infof("Successfully added service: %s", ipvsServiceString(&svc))
	return &svc, nil
}

func ipvsAddServer(service *ipvs.Service, dest *ipvs.Destination) error {

	err := h.NewDestination(service, dest)
	if err == nil {
		glog.Infof("Successfully added destination %s to the service %s",
			ipvsDestinationString(dest), ipvsServiceString(service))
		return nil
	}

	if strings.Contains(err.Error(), IPVS_SERVER_EXISTS) {
		err = h.UpdateDestination(service, dest)
		if err != nil {
			return fmt.Errorf("Failed to update ipvs destination %s to the ipvs service %s due to : %s", dest.Address,
				ipvsDestinationString(dest), ipvsServiceString(service), err.Error())
		}
		// TODO: Make this debug output when we get log levels
		// glog.Infof("ipvs destination %s already exists in the ipvs service %s so not adding destination",
		// 	ipvsDestinationString(dest), ipvsServiceString(service))
	} else {
		return fmt.Errorf("Failed to add ipvs destination %s to the ipvs service %s due to : %s", dest.Address,
			ipvsDestinationString(dest), ipvsServiceString(service), err.Error())
	}
	return nil
}

const (
	customDSRRouteTableID   = "78"
	customDSRRouteTableName = "kube-router-dsr"
)

// setupMangleTableRule: setsup iptable rule to FWMARK the traffic to exteranl IP vip
func setupMangleTableRule(ip string, protocol string, port string, fwmark string) error {
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed to initialize iptables executor" + err.Error())
	}
	args := []string{"-d", ip, "-m", protocol, "-p", protocol, "--dport", port, "-j", "MARK", "--set-mark", fwmark}
	err = iptablesCmdHandler.AppendUnique("mangle", "PREROUTING", args...)
	if err != nil {
		return errors.New("Failed to run iptables command to set up FWMARK due to " + err.Error())
	}
	return nil
}

// For DSR it is required that we dont assign the VIP to any interface to avoid martian packets
// http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html
// routeVIPTrafficToDirector: setups policy routing so that FWMARKed packets are deliverd locally
func routeVIPTrafficToDirector(fwmark string) error {
	out, err := exec.Command("ip", "rule", "list").Output()
	if err != nil {
		return errors.New("Failed to verify if `ip rule` exists due to: " + err.Error())
	}
	if !strings.Contains(string(out), fwmark) {
		err = exec.Command("ip", "rule", "add", "fwmark", fwmark, "table", customDSRRouteTableID).Run()
		if err != nil {
			return errors.New("Failed to add policy rule to lookup traffic to VIP through the custom " +
				" routing table due to " + err.Error())
		}
	}
	return nil
}

// For DSR it is required that we dont assign the VIP to any interface to avoid martian packets
// http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html
// setupPolicyRoutingForDSR: setups policy routing so that FWMARKed packets are deliverd locally
func setupPolicyRoutingForDSR() error {
	b, err := ioutil.ReadFile("/etc/iproute2/rt_tables")
	if err != nil {
		return errors.New("Failed to setup policy routing required for DSR due to " + err.Error())
	}
	if !strings.Contains(string(b), customDSRRouteTableName) {
		f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return errors.New("Failed to setup policy routing required for DSR due to " + err.Error())
		}
		if _, err = f.WriteString(customDSRRouteTableID + " " + customDSRRouteTableName); err != nil {
			return errors.New("Failed to setup policy routing required for DSR due to " + err.Error())
		}
	}
	out, err := exec.Command("ip", "route", "list", "table", customDSRRouteTableID).Output()
	if err != nil {
		return errors.New("Failed to verify required default route exists. " +
			"Failed to setup policy routing required for DSR due to " + err.Error())
	}
	if !strings.Contains(string(out), " lo ") {
		if err = exec.Command("ip", "route", "add", "local", "default", "dev", "lo", "table",
			customDSRRouteTableID).Run(); err != nil {
			return errors.New("Failed to add route in custom route table due to: " + err.Error())
		}
	}
	return nil
}

// unique identfier for a load-balanced service (namespace + name + portname)
func generateServiceId(namespace, svcName, port string) string {
	return namespace + "-" + svcName + "-" + port
}

// unique identfier for a load-balanced service (namespace + name + portname)
func generateIpPortId(ip, protocol, port string) string {
	return ip + "-" + protocol + "-" + port
}

func getKubeDummyInterface() (netlink.Link, error) {
	var dummyVipInterface netlink.Link
	dummyVipInterface, err := netlink.LinkByName(KUBE_DUMMY_IF)
	if err != nil && err.Error() == IFACE_NOT_FOUND {
		glog.Infof("Could not find dummy interface: " + KUBE_DUMMY_IF + " to assign cluster ip's, so creating one")
		err = netlink.LinkAdd(&netlink.Dummy{netlink.LinkAttrs{Name: KUBE_DUMMY_IF}})
		if err != nil {
			return nil, errors.New("Failed to add dummy interface:  " + err.Error())
		}
		dummyVipInterface, err = netlink.LinkByName(KUBE_DUMMY_IF)
		err = netlink.LinkSetUp(dummyVipInterface)
		if err != nil {
			return nil, errors.New("Failed to bring dummy interface up: " + err.Error())
		}
	}
	return dummyVipInterface, nil
}

// Cleanup cleans all the configurations (IPVS, iptables, links) done
func (nsc *NetworkServicesController) Cleanup() {
	// cleanup ipvs rules by flush
	glog.Infof("Cleaning up IPVS configuration permanently")

	handle, err := ipvs.New("")
	if err != nil {
		glog.Errorf("Failed to cleanup ipvs rules: %s", err.Error())
		return
	}

	handle.Close()

	// cleanup iptable masqurade rule
	err = deleteMasqueradeIptablesRule()
	if err != nil {
		glog.Errorf("Failed to cleanup iptable masquerade rule due to: %s", err.Error())
		return
	}

	// cleanup iptable hairpin rules
	err = deleteHairpinIptablesRules()
	if err != nil {
		glog.Errorf("Failed to cleanup iptable hairpin rules: %s", err.Error())
		return
	}

	// delete dummy interface used to assign cluster IP's
	dummyVipInterface, err := netlink.LinkByName(KUBE_DUMMY_IF)
	if err != nil {
		if err.Error() != IFACE_NOT_FOUND {
			glog.Infof("Dummy interface: " + KUBE_DUMMY_IF + " does not exist")
		}
	} else {
		err = netlink.LinkDel(dummyVipInterface)
		if err != nil {
			glog.Errorf("Could not delete dummy interface " + KUBE_DUMMY_IF + " due to " + err.Error())
			return
		}
	}
	glog.Infof("Successfully cleaned the ipvs configuration done by kube-router")
}

// NewNetworkServicesController returns NetworkServicesController object
func NewNetworkServicesController(clientset *kubernetes.Clientset, config *options.KubeRouterConfig) (*NetworkServicesController, error) {

	var err error
	h, err = ipvs.New("")
	if err != nil {
		return nil, err
	}
	// &h = handle

	nsc := NetworkServicesController{}
	nsc.syncPeriod = config.IpvsSyncPeriod

	nsc.serviceMap = make(serviceInfoMap)
	nsc.endpointsMap = make(endpointsInfoMap)
	nsc.client = clientset

	nsc.masqueradeAll = false
	if config.MasqueradeAll {
		nsc.masqueradeAll = true
	}

	if config.NodePortBindOnAllIp {
		nsc.nodeportBindOnAllIp = true
	}

	if config.RunRouter {
		cidr, err := utils.GetPodCidrFromNodeSpec(nsc.client, config.HostnameOverride)
		if err != nil {
			return nil, fmt.Errorf("Failed to get pod CIDR details from Node.spec: %s", err.Error())
		}
		nsc.podCidr = cidr
	}

	node, err := utils.GetNodeObject(clientset, config.HostnameOverride)
	if err != nil {
		return nil, err
	}

	nsc.nodeHostName = node.Name
	nodeIP, err := utils.GetNodeIP(node)
	if err != nil {
		return nil, err
	}
	nsc.nodeIP = nodeIP

	watchers.EndpointsWatcher.RegisterHandler(&nsc)
	watchers.ServiceWatcher.RegisterHandler(&nsc)

	rand.Seed(time.Now().UnixNano())

	return &nsc, nil
}
