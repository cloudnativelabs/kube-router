package controllers

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
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
	"github.com/golang/glog"
	"github.com/mqliang/libipvs"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	KUBE_DUMMY_IF      = "kube-dummy-if"
	IFACE_NOT_FOUND    = "Link not found"
	IFACE_HAS_ADDR     = "file exists"
	IPVS_SERVER_EXISTS = "file exists"
)

// Network services controller enables local node as network service proxy through IPVS/LVS.
// Support only Kuberntes network services of type NodePort, ClusterIP. For each service a
// IPVS service is created and for each service endpoint a server is added to the IPVS service.
// As services and endpoints are updated, network service controller gets the updates from
// the kubernetes api server and syncs the ipvs configuration to reflect state of services
// and endpoints

type NetworkServicesController struct {
	nodeIP        net.IP
	nodeHostName  string
	syncPeriod    time.Duration
	mu            sync.Mutex
	serviceMap    serviceInfoMap
	endpointsMap  endpointsInfoMap
	podCidr       string
	masqueradeAll bool
}

// internal representation of kubernetes service
type serviceInfo struct {
	clusterIP net.IP
	port      int
	protocol  string
	nodePort  int
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

// periodically sync ipvs configuration to reflect desired state of services and endpoints
func (nsc *NetworkServicesController) Run(stopCh <-chan struct{}, wg *sync.WaitGroup) {

	t := time.NewTicker(nsc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	glog.Infof("Starting network services controller")

	// enable masquerade rule
	err := ensureMasqueradeIptablesRule(nsc.masqueradeAll, nsc.podCidr)
	if err != nil {
		panic("Failed to do add masqurade rule in POSTROUTING chain of nat table due to: %s" + err.Error())
	}

	// enable ipvs connection tracking
	err = ensureIpvsConntrack()
	if err != nil {
		panic("Failed to do sysctl net.ipv4.vs.conntrack=1 due to: %s" + err.Error())
	}

	// loop forever unitl notified to stop on stopCh
	for {
		select {
		case <-stopCh:
			glog.Infof("Shutting down network services controller")
			return
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
			return
		case <-t.C:
		}
	}
}

func (nsc *NetworkServicesController) sync() {
	nsc.mu.Lock()
	defer nsc.mu.Unlock()

	nsc.serviceMap = buildServicesInfo()
	nsc.endpointsMap = buildEndpointsInfo()
	nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
}

// handle change in endpoints update from the API server
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

// handle change in service update from the API server
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

// sync the ipvs service and server details configured to reflect the desired state of services and endpoint
// as learned from services and endpoints information from the api server
func (nsc *NetworkServicesController) syncIpvsServices(serviceInfoMap serviceInfoMap, endpointsInfoMap endpointsInfoMap) {

	start := time.Now()
	defer func() {
		glog.Infof("sync ipvs servers took %v", time.Since(start))
	}()

	dummyVipInterface := getKubeDummyInterface()

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
		vip := &netlink.Addr{IPNet: &net.IPNet{svc.clusterIP, net.IPv4Mask(255, 255, 255, 255)}, Scope: syscall.RT_SCOPE_LINK}
		err := netlink.AddrAdd(dummyVipInterface, vip)
		if err != nil && err.Error() != IFACE_HAS_ADDR {
			glog.Errorf("Failed to assign cluster ip to dummy interface %s", err)
			continue
		}

		// create IPVS service for the service to be exposed through the cluster ip
		ipvs_cluster_vip_svc, err := ipvsAddService(svc.clusterIP, protocol, uint16(svc.port))
		if err != nil {
			glog.Errorf("Failed to create ipvs service for cluster ip: ", err.Error())
			continue
		}
		var clusterServiceId = generateIpPortId(svc.clusterIP.String(), svc.protocol, strconv.Itoa(svc.port))
		activeServiceEndpointMap[clusterServiceId] = make([]string, 0)

		// create IPVS service for the service to be exposed through the nodeport
		var ipvs_nodeport_svc *libipvs.Service
		var nodeServiceId string
		if svc.nodePort != 0 {
			ipvs_nodeport_svc, err = ipvsAddService(nsc.nodeIP, protocol, uint16(svc.nodePort))
			if err != nil {
				glog.Errorf("Failed to create ipvs service for node port")
				continue
			}
			nodeServiceId = generateIpPortId(nsc.nodeIP.String(), svc.protocol, strconv.Itoa(svc.nodePort))
			activeServiceEndpointMap[nodeServiceId] = make([]string, 0)
		}

		// add IPVS remote server to the IPVS service
		endpoints := endpointsInfoMap[k]
		for _, endpoint := range endpoints {
			dst := libipvs.Destination{
				Address:       net.ParseIP(endpoint.ip),
				AddressFamily: syscall.AF_INET,
				Port:          uint16(endpoint.port),
				Weight:        1,
			}
			err := ipvsAddServer(ipvs_cluster_vip_svc, &dst)
			if err != nil {
				glog.Errorf(err.Error())
			}
			activeServiceEndpointMap[clusterServiceId] = append(activeServiceEndpointMap[clusterServiceId], endpoint.ip)
			if svc.nodePort != 0 {
				err := ipvsAddServer(ipvs_nodeport_svc, &dst)
				activeServiceEndpointMap[nodeServiceId] = append(activeServiceEndpointMap[clusterServiceId], endpoint.ip)
				if err != nil {
					glog.Errorf(err.Error())
				}
			}
		}
	}

	// cleanup stale ipvs service and servers
	glog.Infof("Cleaning up if any, old ipvs service and servers which are no longer needed")
	h, err := libipvs.New()
	if err != nil {
		panic(err)
	}
	ipvsSvcs, err := h.ListServices()
	if err != nil {
		panic(err)
	}
	for _, ipvsSvc := range ipvsSvcs {
		key := generateIpPortId(ipvsSvc.Address.String(), ipvsSvc.Protocol.String(), strconv.Itoa(int(ipvsSvc.Port)))
		endpoints, ok := activeServiceEndpointMap[key]
		if !ok {
			glog.Infof("Found a IPVS service %s:%s:%s which is no longer needed so cleaning up", ipvsSvc.Address.String(), ipvsSvc.Protocol.String(), strconv.Itoa(int(ipvsSvc.Port)))
			err := h.DelService(ipvsSvc)
			if err != nil {
				glog.Errorf("Failed to delete stale IPVS service: ", err.Error())
				continue
			}
		} else {
			dsts, err := h.ListDestinations(ipvsSvc)
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
					glog.Infof("Found a IPVS service %s:%s:%s, destination %s which is no longer needed so cleaning up",
						ipvsSvc.Address.String(), ipvsSvc.Protocol.String(), strconv.Itoa(int(ipvsSvc.Port)), dst.Address.String())
					err := h.DelDestination(ipvsSvc, dst)
					if err != nil {
						glog.Errorf("Failed to delete server from ipvs service")
					}
				}
			}
		}
	}
	glog.Infof("IPVS servers and services are synced to desired state!!")
}

func buildServicesInfo() serviceInfoMap {
	serviceMap := make(serviceInfoMap)
	for _, svc := range watchers.ServiceWatcher.List() {

		if svc.Spec.ClusterIP == "None" || svc.Spec.ClusterIP == "" {
			glog.Infof("Skipping service name:%s namespace:%s as there is no cluster IP", svc.Name, svc.Namespace)
			continue
		}

		if svc.Spec.Type == "LoadBalancer" || svc.Spec.Type == "ExternalName" {
			glog.Infof("Skipping service name:%s namespace:%s due to service Type=%s", svc.Name, svc.Namespace, svc.Spec.Type)
			continue
		}

		for _, port := range svc.Spec.Ports {
			svcInfo := serviceInfo{
				clusterIP: net.ParseIP(svc.Spec.ClusterIP),
				port:      int(port.Port),
				protocol:  strings.ToLower(string(port.Protocol)),
				nodePort:  int(port.NodePort),
			}
			svcId := generateServiceId(svc.Namespace, svc.Name, strconv.Itoa(int(port.Port)))
			serviceMap[svcId] = &svcInfo
		}
	}
	return serviceMap
}

func buildEndpointsInfo() endpointsInfoMap {
	endpointsMap := make(endpointsInfoMap)
	for _, ep := range watchers.EndpointsWatcher.List() {
		for _, ep_subset := range ep.Subsets {
			for _, port := range ep_subset.Ports {
				svcId := generateServiceId(ep.Namespace, ep.Name, strconv.Itoa(int(port.Port)))
				endpoints := make([]endpointsInfo, 0)
				for _, addr := range ep_subset.Addresses {
					endpoints = append(endpoints, endpointsInfo{ip: addr.IP, port: int(port.Port)})
				}
				endpointsMap[svcId] = endpoints
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
	} else {
		args = []string{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ", "-m", "comment", "--comment", "",
			"!", "-s", podCidr, "-j", "MASQUERADE"}
	}
	err = iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", args...)
	if err != nil {
		return errors.New("Failed to run iptables command" + err.Error())
	}
	glog.Infof("Successfully added iptables masqurade rule")
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
			break
		}
	}
	return nil
}

func ipvsAddService(vip net.IP, protocol, port uint16) (*libipvs.Service, error) {
	h, err := libipvs.New()
	if err != nil {
		panic(err)
	}
	svcs, err := h.ListServices()
	if err != nil {
		panic(err)
	}
	for _, svc := range svcs {
		if strings.Compare(vip.String(), svc.Address.String()) == 0 &&
			libipvs.Protocol(protocol) == svc.Protocol && port == svc.Port {
			glog.Infof("ipvs service %s:%s:%s already exists so returning", vip.String(),
				libipvs.Protocol(protocol), strconv.Itoa(int(port)))
			return svc, nil
		}
	}
	svc := libipvs.Service{
		Address:       vip,
		AddressFamily: syscall.AF_INET,
		Protocol:      libipvs.Protocol(protocol),
		Port:          port,
		SchedName:     libipvs.RoundRobin,
	}
	if err := h.NewService(&svc); err != nil {
		return nil, fmt.Errorf("Failed to create service: %s:%s:%s", vip.String(), libipvs.Protocol(protocol), strconv.Itoa(int(port)))
	}
	glog.Infof("Successfully added service: %s:%s:%s", vip.String(), libipvs.Protocol(protocol), strconv.Itoa(int(port)))
	return &svc, nil
}

func ipvsAddServer(service *libipvs.Service, dest *libipvs.Destination) error {
	h, err := libipvs.New()
	if err != nil {
		panic(err)
	}

	err = h.NewDestination(service, dest)
	if err == nil {
		glog.Infof("Successfully added destination %s:%s to the service %s:%s:%s", dest.Address,
			strconv.Itoa(int(dest.Port)), service.Address, service.Protocol, strconv.Itoa(int(service.Port)))
		return nil
	}

	if strings.Contains(err.Error(), IPVS_SERVER_EXISTS) {
		glog.Infof("ipvs destination %s:%s already exists in the ipvs service %s:%s:%s so not adding destination", dest.Address,
			strconv.Itoa(int(dest.Port)), service.Address, service.Protocol, strconv.Itoa(int(service.Port)))
	} else {
		return fmt.Errorf("Failed to add ipvs destination %s:%s to the ipvs service %s:%s:%s due to : %s", dest.Address,
			strconv.Itoa(int(dest.Port)), service.Address, service.Protocol, strconv.Itoa(int(service.Port)), err.Error())
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

func getKubeDummyInterface() netlink.Link {
	var dummyVipInterface netlink.Link
	dummyVipInterface, err := netlink.LinkByName(KUBE_DUMMY_IF)
	if err != nil && err.Error() == IFACE_NOT_FOUND {
		glog.Infof("Could not find dummy interface: " + KUBE_DUMMY_IF + " to assign cluster ip's, so creating one")
		err = netlink.LinkAdd(&netlink.Dummy{netlink.LinkAttrs{Name: KUBE_DUMMY_IF}})
		if err != nil {
			panic("Failed to add dummy interface:  " + err.Error())
		}
		dummyVipInterface, err = netlink.LinkByName(KUBE_DUMMY_IF)
		err = netlink.LinkSetUp(dummyVipInterface)
		if err != nil {
			panic("Failed to bring dummy interface up: " + err.Error())
		}
	}
	return dummyVipInterface
}

// clean up all the configurations (IPVS, iptables, links)
func (nsc *NetworkServicesController) Cleanup() {

	// cleanup ipvs rules by flush
	h, err := libipvs.New()
	if err != nil {
		panic(err)
	}
	glog.Infof("Cleaning up IPVS configuration permanently")
	err = h.Flush()
	if err != nil {
		glog.Errorf("Failed to cleanup ipvs rules: ", err.Error())
		return
	}

	// cleanup iptable masqurade rule
	err = deleteMasqueradeIptablesRule()
	if err != nil {
		glog.Errorf("Failed to cleanup iptable masquerade rule due to: ", err.Error())
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
			glog.Errorf("Could not delete dummy interface: "+KUBE_DUMMY_IF, err.Error())
			return
		}
	}
	glog.Infof("Successfully cleaned the ipvs configuration done by kube-router")
}

func NewNetworkServicesController(clientset *kubernetes.Clientset, config *options.KubeRouterConfig) (*NetworkServicesController, error) {

	nsc := NetworkServicesController{}
	nsc.syncPeriod = config.IpvsSyncPeriod

	nsc.serviceMap = make(serviceInfoMap)
	nsc.endpointsMap = make(endpointsInfoMap)

	nsc.masqueradeAll = true
	if config.RunRouter {
		subnet, cidrLen, err := utils.GetPodCidrDetails(config.CniConfFile)
		if err != nil {
			return nil, fmt.Errorf("Failed to get pod CIDR details from CNI conf file: %s", err.Error())
		}
		nsc.masqueradeAll = false
		nsc.podCidr = subnet + "/" + strconv.Itoa(cidrLen)
	}

	nodeHostName, err := os.Hostname()
	if err != nil {
		panic(err.Error())
	}
	nsc.nodeHostName = nodeHostName

	node, err := clientset.Core().Nodes().Get(nodeHostName, v1.GetOptions{})
	if err != nil {
		panic(err.Error())
	}
	nodeIP, err := getNodeIP(node)
	if err != nil {
		panic(err.Error())
	}
	nsc.nodeIP = nodeIP

	watchers.EndpointsWatcher.RegisterHandler(&nsc)
	watchers.ServiceWatcher.RegisterHandler(&nsc)

	return &nsc, nil
}
