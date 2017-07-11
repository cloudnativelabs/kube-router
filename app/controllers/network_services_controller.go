package controllers

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
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
	"k8s.io/client-go/kubernetes"
)

const (
	KUBE_DUMMY_IF      = "kube-dummy-if"
	IFACE_NOT_FOUND    = "Link not found"
	IFACE_HAS_ADDR     = "file exists"
	IPVS_SERVER_EXISTS = "file exists"
)

var (
	h libipvs.IPVSHandle
)

// Network services controller enables local node as network service proxy through IPVS/LVS.
// Support only Kubernetes network services of type NodePort, ClusterIP, and LoadBalancer. For each service a
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
	globalHairpin bool
	client        *kubernetes.Clientset
}

// internal representation of kubernetes service
type serviceInfo struct {
	clusterIP       net.IP
	port            int
	protocol        string
	nodePort        int
	sessionAffinity bool
	hairpin         bool
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
func (nsc *NetworkServicesController) syncIpvsServices(serviceInfoMap serviceInfoMap, endpointsInfoMap endpointsInfoMap) error {

	start := time.Now()
	defer func() {
		glog.Infof("sync ipvs servers took %v", time.Since(start))
	}()

	dummyVipInterface, err := getKubeDummyInterface()
	if err != nil {
		return errors.New("Failed creating dummy interface: " + err.Error())
	}

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
		ipvs_cluster_vip_svc, err := ipvsAddService(svc.clusterIP, protocol, uint16(svc.port), svc.sessionAffinity)
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
			ipvs_nodeport_svc, err = ipvsAddService(nsc.nodeIP, protocol, uint16(svc.nodePort), svc.sessionAffinity)
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

			activeServiceEndpointMap[clusterServiceId] =
				append(activeServiceEndpointMap[clusterServiceId], endpoint.ip)

			if svc.nodePort != 0 {
				err := ipvsAddServer(ipvs_nodeport_svc, &dst)
				if err != nil {
					glog.Errorf(err.Error())
				}

				activeServiceEndpointMap[nodeServiceId] =
					append(activeServiceEndpointMap[clusterServiceId], endpoint.ip)
			}
		}
	}

	// cleanup stale ipvs service and servers
	glog.Infof("Cleaning up if any, old ipvs service and servers which are no longer needed")
	ipvsSvcs, err := h.ListServices()
	if err != nil {
		return errors.New("Failed to list IPVS services: " + err.Error())
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
				clusterIP: net.ParseIP(svc.Spec.ClusterIP),
				port:      int(port.Port),
				protocol:  strings.ToLower(string(port.Protocol)),
				nodePort:  int(port.NodePort),
			}

			svcInfo.sessionAffinity = (svc.Spec.SessionAffinity == "ClientIP")
			_, svcInfo.hairpin = svc.ObjectMeta.Annotations["kube-router.io/hairpin-mode"]

			svcId := generateServiceId(svc.Namespace, svc.Name, port.Name)
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
				svcId := generateServiceId(ep.Namespace, ep.Name, port.Name)
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
			break
		}
	}
	return nil
}

func ipvsAddService(vip net.IP, protocol, port uint16, persistent bool) (*libipvs.Service, error) {
	svcs, err := h.ListServices()
	if err != nil {
		return nil, err
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

	if persistent {
		// set bit to enable service persistence
		svc.Flags.Flags |= (1 << 24)
		svc.Flags.Mask |= 0xFFFFFFFF
		// TODO: once service manifest supports timeout time remove hardcoding
		svc.Timeout = 180 * 60
	}
	if err := h.NewService(&svc); err != nil {
		return nil, fmt.Errorf("Failed to create service: %s:%s:%s", vip.String(), libipvs.Protocol(protocol), strconv.Itoa(int(port)))
	}
	glog.Infof("Successfully added service: %s:%s:%s", vip.String(), libipvs.Protocol(protocol), strconv.Itoa(int(port)))
	return &svc, nil
}

func ipvsAddServer(service *libipvs.Service, dest *libipvs.Destination) error {

	err := h.NewDestination(service, dest)
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

// clean up all the configurations (IPVS, iptables, links)
func (nsc *NetworkServicesController) Cleanup() {
	// cleanup ipvs rules by flush
	glog.Infof("Cleaning up IPVS configuration permanently")
	err := h.Flush()
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

	// cleanup iptable hairpin rules
	err = deleteHairpinIptablesRules()
	if err != nil {
		glog.Errorf("Failed to cleanup iptable hairpin rules: ", err.Error())
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

	handle, err := libipvs.New()
	if err != nil {
		return nil, err
	}
	h = handle

	nsc := NetworkServicesController{}
	nsc.syncPeriod = config.IpvsSyncPeriod

	nsc.serviceMap = make(serviceInfoMap)
	nsc.endpointsMap = make(endpointsInfoMap)
	nsc.client = clientset

	nsc.masqueradeAll = false
	if config.MasqueradeAll {
		nsc.masqueradeAll = true
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
	nodeIP, err := getNodeIP(node)
	if err != nil {
		return nil, err
	}
	nsc.nodeIP = nodeIP

	watchers.EndpointsWatcher.RegisterHandler(&nsc)
	watchers.ServiceWatcher.RegisterHandler(&nsc)

	return &nsc, nil
}
