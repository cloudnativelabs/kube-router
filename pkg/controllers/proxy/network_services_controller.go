package proxy

import (
	"errors"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/docker/docker/client"
	"github.com/docker/libnetwork/ipvs"
	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/net/context"

	api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	KUBE_DUMMY_IF      = "kube-dummy-if"
	KUBE_TUNNEL_IF     = "kube-tunnel-if"
	IFACE_NOT_FOUND    = "Link not found"
	IFACE_HAS_ADDR     = "file exists"
	IFACE_HAS_NO_ADDR  = "cannot assign requested address"
	IPVS_SERVER_EXISTS = "file exists"

	svcDSRAnnotation       = "kube-router.io/service.dsr"
	svcSchedulerAnnotation = "kube-router.io/service.scheduler"
	svcHairpinAnnotation   = "kube-router.io/service.hairpin"
	svcLocalAnnotation     = "kube-router.io/service.local"
	svcSkipLbIpsAnnotation = "kube-router.io/service.skiplbips"

	LeaderElectionRecordAnnotationKey = "control-plane.alpha.kubernetes.io/leader"
)

var (
	h      *ipvs.Handle
	NodeIP net.IP
)

type ipvsCalls interface {
	ipvsNewService(ipvsSvc *ipvs.Service) error
	ipvsAddService(svcs []*ipvs.Service, vip net.IP, protocol, port uint16, persistent bool, scheduler string) (*ipvs.Service, error)
	ipvsDelService(ipvsSvc *ipvs.Service) error
	ipvsUpdateService(ipvsSvc *ipvs.Service) error
	ipvsGetServices() ([]*ipvs.Service, error)
	ipvsAddServer(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination, local bool, podCidr string) error
	ipvsNewDestination(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error
	ipvsUpdateDestination(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error
	ipvsGetDestinations(ipvsSvc *ipvs.Service) ([]*ipvs.Destination, error)
	ipvsDelDestination(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error
	ipvsAddFWMarkService(vip net.IP, protocol, port uint16, persistent bool, scheduler string) (*ipvs.Service, error)
}

type netlinkCalls interface {
	ipAddrAdd(iface netlink.Link, ip string) error
	ipAddrDel(iface netlink.Link, ip string) error
	prepareEndpointForDsr(containerId string, endpointIP string, vip string) error
	getKubeDummyInterface() (netlink.Link, error)
	setupRoutesForExternalIPForDSR(serviceInfoMap) error
	setupPolicyRoutingForDSR() error
	cleanupMangleTableRule(ip string, protocol string, port string, fwmark string) error
}

// LinuxNetworking interface contains all linux networking subsystem calls
//go:generate moq -out network_services_controller_moq.go . LinuxNetworking
type LinuxNetworking interface {
	ipvsCalls
	netlinkCalls
}

type linuxNetworking struct {
	ipvsHandle *ipvs.Handle
}

func (ln *linuxNetworking) ipAddrDel(iface netlink.Link, ip string) error {
	naddr := &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP(ip), Mask: net.IPv4Mask(255, 255, 255, 255)}, Scope: syscall.RT_SCOPE_LINK}
	err := netlink.AddrDel(iface, naddr)
	if err != nil && err.Error() != IFACE_HAS_NO_ADDR {
		glog.Errorf("Failed to verify is external ip %s is assocated with dummy interface %s due to %s",
			naddr.IPNet.IP.String(), KUBE_DUMMY_IF, err.Error())
	}
	return err
}

func (ln *linuxNetworking) ipAddrAdd(iface netlink.Link, ip string) error {
	naddr := &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP(ip), Mask: net.IPv4Mask(255, 255, 255, 255)}, Scope: syscall.RT_SCOPE_LINK}
	err := netlink.AddrAdd(iface, naddr)
	if err != nil && err.Error() != IFACE_HAS_ADDR {
		glog.Errorf("Failed to assign cluster ip %s to dummy interface: %s",
			naddr.IPNet.IP.String(), err.Error())
		return err
	}

	// TODO: netlink.RouteReplace which is replacement for below command is not working as expected. Call succeeds but
	// route is not replaced. For now do it with command.
	out, err := exec.Command("ip", "route", "replace", "local", ip, "dev", KUBE_DUMMY_IF, "table", "local", "proto", "kernel", "scope", "host", "src",
		NodeIP.String(), "table", "local").CombinedOutput()
	if err != nil {
		glog.Errorf("Failed to replace route to service VIP %s configured on %s. Error: %v, Output: %s", ip, KUBE_DUMMY_IF, err, out)
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

func newLinuxNetworking() (*linuxNetworking, error) {
	ln := &linuxNetworking{}
	ipvsHandle, err := ipvs.New("")
	if err != nil {
		return nil, err
	}
	ln.ipvsHandle = ipvsHandle
	return ln, nil
}

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
	client              kubernetes.Interface
	nodeportBindOnAllIp bool
	MetricsEnabled      bool
	ln                  LinuxNetworking
	readyForUpdates     bool

	svcLister cache.Indexer
	epLister  cache.Indexer
	podLister cache.Indexer

	ServiceEventHandler   cache.ResourceEventHandler
	EndpointsEventHandler cache.ResourceEventHandler
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
	skipLbIps                bool
	externalIPs              []string
	loadBalancerIPs          []string
	local                    bool
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
func (nsc *NetworkServicesController) Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) error {

	t := time.NewTicker(nsc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	glog.Infof("Starting network services controller")

	// enable masquerad rule
	err := ensureMasqueradeIptablesRule(nsc.masqueradeAll, nsc.podCidr)
	if err != nil {
		return errors.New("Failed to do add masquerad rule in POSTROUTING chain of nat table due to: %s" + err.Error())
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
			glog.Info("Shutting down network services controller")
			return nil
		default:
		}

		glog.V(1).Info("Performing periodic sync of ipvs services")
		err := nsc.sync()
		if err != nil {
			glog.Errorf("Error during periodic ipvs sync: " + err.Error())
		} else {
			healthcheck.SendHeartBeat(healthChan, "NSC")
		}
		nsc.readyForUpdates = true
		select {
		case <-stopCh:
			glog.Info("Shutting down network services controller")
			return nil
		case <-t.C:
		}
	}
}

func (nsc *NetworkServicesController) sync() error {
	var err error
	nsc.mu.Lock()
	defer nsc.mu.Unlock()

	nsc.serviceMap = nsc.buildServicesInfo()
	nsc.endpointsMap = nsc.buildEndpointsInfo()
	err = nsc.syncHairpinIptablesRules()
	if err != nil {
		glog.Errorf("Error syncing hairpin iptable rules: %s", err.Error())
	}

	err = nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
	if err != nil {
		glog.Errorf("Error syncing IPVS services: %s", err.Error())
		return err
	}

	if nsc.MetricsEnabled {
		nsc.publishMetrics(nsc.serviceMap)
	}
	return nil
}

func (nsc *NetworkServicesController) publishMetrics(serviceInfoMap serviceInfoMap) error {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		glog.V(2).Infof("Publishing IPVS metrics took %v", endTime)
		metrics.ControllerIpvsMetricsExportTime.WithLabelValues().Set(float64(endTime))
	}()

	ipvsSvcs, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return errors.New("Failed to list IPVS services: " + err.Error())
	}

	glog.V(1).Info("Publishing IPVS metrics")
	for _, svc := range serviceInfoMap {
		var protocol uint16
		var pushMetric bool
		var svcVip string

		switch aProtocol := svc.protocol; aProtocol {
		case "tcp":
			protocol = syscall.IPPROTO_TCP
		case "udp":
			protocol = syscall.IPPROTO_UDP
		default:
			protocol = syscall.IPPROTO_NONE
		}
		for _, ipvsSvc := range ipvsSvcs {

			switch svcAddress := ipvsSvc.Address.String(); svcAddress {
			case svc.clusterIP.String():
				if protocol == ipvsSvc.Protocol && uint16(svc.port) == ipvsSvc.Port {
					pushMetric = true
					svcVip = svc.clusterIP.String()
				} else {
					pushMetric = false
				}
			case nsc.nodeIP.String():
				if protocol == ipvsSvc.Protocol && uint16(svc.port) == ipvsSvc.Port {
					pushMetric = true
					svcVip = nsc.nodeIP.String()
				} else {
					pushMetric = false
				}
			default:
				svcVip = ""
				pushMetric = false
			}

			if pushMetric {
				glog.V(3).Infof("Publishing metrics for %s/%s (%s:%d/%s)", svc.namespace, svc.name, svcVip, svc.port, svc.protocol)
				metrics.ServiceBpsIn.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.BPSIn))
				metrics.ServiceBpsOut.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.BPSOut))
				metrics.ServiceBytesIn.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.BytesIn))
				metrics.ServiceBytesOut.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.BytesOut))
				metrics.ServiceCPS.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.CPS))
				metrics.ServicePacketsIn.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.PacketsIn))
				metrics.ServicePacketsOut.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.PacketsOut))
				metrics.ServicePpsIn.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.PPSIn))
				metrics.ServicePpsOut.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.PPSOut))
				metrics.ServiceTotalConn.WithLabelValues(svc.namespace, svc.name, svcVip, svc.protocol, strconv.Itoa(svc.port)).Set(float64(ipvsSvc.Stats.Connections))
				metrics.ControllerIpvsServices.WithLabelValues().Set(float64(len(ipvsSvcs)))
			}
		}
	}
	return nil
}

// OnEndpointsUpdate handle change in endpoints update from the API server
func (nsc *NetworkServicesController) OnEndpointsUpdate(obj interface{}) {
	ep, ok := obj.(*api.Endpoints)
	if !ok {
		glog.Error("could not convert endpoints update object to *v1.Endpoints")
		return
	}

	if isEndpointsForLeaderElection(ep) {
		return
	}

	glog.V(1).Infof("Received update to endpoint: %s/%s from watch API", ep.Namespace, ep.Name)
	if !nsc.readyForUpdates {
		glog.V(3).Infof("Skipping update to endpoint: %s/%s, controller still performing bootup full-sync", ep.Namespace, ep.Name)
		return
	}
	nsc.mu.Lock()
	defer nsc.mu.Unlock()

	// build new service and endpoints map to reflect the change
	newServiceMap := nsc.buildServicesInfo()
	newEndpointsMap := nsc.buildEndpointsInfo()

	if len(newEndpointsMap) != len(nsc.endpointsMap) || !reflect.DeepEqual(newEndpointsMap, nsc.endpointsMap) {
		nsc.endpointsMap = newEndpointsMap
		nsc.serviceMap = newServiceMap
		glog.V(1).Infof("Syncing IPVS services sync for update to endpoint: %s/%s", ep.Namespace, ep.Name)
		nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
	} else {
		glog.V(1).Infof("Skipping IPVS services sync on endpoint: %s/%s update as nothing changed", ep.Namespace, ep.Name)
	}
}

// OnServiceUpdate handle change in service update from the API server
func (nsc *NetworkServicesController) OnServiceUpdate(obj interface{}) {
	svc, ok := obj.(*api.Service)
	if !ok {
		glog.Error("could not convert service update object to *v1.Service")
		return
	}

	glog.V(1).Infof("Received update to service: %s/%s from watch API", svc.Namespace, svc.Name)
	if !nsc.readyForUpdates {
		glog.V(3).Infof("Skipping update to service: %s/%s, controller still performing bootup full-sync", svc.Namespace, svc.Name)
		return
	}
	nsc.mu.Lock()
	defer nsc.mu.Unlock()

	// build new service and endpoints map to reflect the change
	newServiceMap := nsc.buildServicesInfo()
	newEndpointsMap := nsc.buildEndpointsInfo()

	if len(newServiceMap) != len(nsc.serviceMap) || !reflect.DeepEqual(newServiceMap, nsc.serviceMap) {
		nsc.endpointsMap = newEndpointsMap
		nsc.serviceMap = newServiceMap
		glog.V(1).Infof("Syncing IPVS services sync on update to service: %s/%s", svc.Namespace, svc.Name)
		nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
	} else {
		glog.V(1).Infof("Skipping syncing IPVS services for update to service: %s/%s as nothing changed", svc.Namespace, svc.Name)
	}
}

type externalIPService struct {
	ipvsSvc    *ipvs.Service
	externalIp string
}

// sync the ipvs service and server details configured to reflect the desired state of services and endpoint
// as learned from services and endpoints information from the api server
func (nsc *NetworkServicesController) syncIpvsServices(serviceInfoMap serviceInfoMap, endpointsInfoMap endpointsInfoMap) error {

	var ipvsSvcs []*ipvs.Service

	// Conntrack exits with non zero exit code when exiting if 0 flow entries have been deleted, use regex to check output and don't Error when matching
	re := regexp.MustCompile("([[:space:]]0 flow entries have been deleted.)")

	start := time.Now()

	defer func() {
		endTime := time.Since(start)
		if nsc.MetricsEnabled {
			metrics.ControllerIpvsServicesSyncTime.WithLabelValues().Set(float64(endTime))
		}
		glog.V(1).Infof("sync ipvs services took %v", endTime)
	}()

	dummyVipInterface, err := nsc.ln.getKubeDummyInterface()
	if err != nil {
		return errors.New("Failed creating dummy interface: " + err.Error())
	}

	glog.V(1).Infof("Setting up policy routing required for Direct Server Return functionality.")
	err = nsc.ln.setupPolicyRoutingForDSR()
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

	// map of active services and service endpoints
	activeServiceEndpointMap := make(map[string][]string)

	ipvsSvcs, err = nsc.ln.ipvsGetServices()
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

		// assign cluster IP of the service to the dummy interface so that its routable from the pod's on the node
		err := nsc.ln.ipAddrAdd(dummyVipInterface, svc.clusterIP.String())
		if err != nil {
			continue
		}

		// create IPVS service for the service to be exposed through the cluster ip
		ipvsClusterVipSvc, err := nsc.ln.ipvsAddService(ipvsSvcs, svc.clusterIP, protocol, uint16(svc.port), svc.sessionAffinity, svc.scheduler)
		if err != nil {
			glog.Errorf("Failed to create ipvs service for cluster ip: %s", err.Error())
			continue
		}
		var clusterServiceId = generateIpPortId(svc.clusterIP.String(), svc.protocol, strconv.Itoa(svc.port))
		activeServiceEndpointMap[clusterServiceId] = make([]string, 0)

		// create IPVS service for the service to be exposed through the nodeport
		var ipvsNodeportSvcs []*ipvs.Service

		var nodeServiceIds []string

		if svc.nodePort != 0 {
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
					ipvsNodeportSvcs[i], err = nsc.ln.ipvsAddService(ipvsSvcs, addr.IP, protocol, uint16(svc.nodePort), svc.sessionAffinity, svc.scheduler)
					if err != nil {
						glog.Errorf("Failed to create ipvs service for node port due to: %s", err.Error())
						continue
					}

					nodeServiceIds[i] = generateIpPortId(addr.IP.String(), svc.protocol, strconv.Itoa(svc.nodePort))
					activeServiceEndpointMap[nodeServiceIds[i]] = make([]string, 0)
				}
			} else {
				ipvsNodeportSvcs = make([]*ipvs.Service, 1)
				ipvsNodeportSvcs[0], err = nsc.ln.ipvsAddService(ipvsSvcs, nsc.nodeIP, protocol, uint16(svc.nodePort), svc.sessionAffinity, svc.scheduler)
				if err != nil {
					glog.Errorf("Failed to create ipvs service for node port due to: %s", err.Error())
					continue
				}

				nodeServiceIds = make([]string, 1)
				nodeServiceIds[0] = generateIpPortId(nsc.nodeIP.String(), svc.protocol, strconv.Itoa(svc.nodePort))
				activeServiceEndpointMap[nodeServiceIds[0]] = make([]string, 0)
			}
		}

		endpoints := endpointsInfoMap[k]

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

		for _, externalIP := range extIPSet.List() {
			var externalIpServiceId string
			if svc.directServerReturn && svc.directServerReturnMethod == "tunnel" {
				ipvsExternalIPSvc, err := nsc.ln.ipvsAddFWMarkService(net.ParseIP(externalIP), protocol, uint16(svc.port), svc.sessionAffinity, svc.scheduler)
				if err != nil {
					glog.Errorf("Failed to create ipvs service for External IP: %s due to: %s", externalIP, err.Error())
					continue
				}
				externalIpServices = append(externalIpServices, externalIPService{ipvsSvc: ipvsExternalIPSvc, externalIp: externalIP})
				fwMark := generateFwmark(externalIP, svc.protocol, strconv.Itoa(svc.port))
				externalIpServiceId = fmt.Sprint(fwMark)

				// ensure there is iptable mangle table rule to FWMARK the packet
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
				err := nsc.ln.ipAddrAdd(dummyVipInterface, externalIP)
				if err != nil && err.Error() != IFACE_HAS_ADDR {
					glog.Errorf("Failed to assign external ip %s to dummy interface %s due to %s", externalIP, KUBE_DUMMY_IF, err.Error())
				}

				// create IPVS service for the service to be exposed through the external ip
				ipvsExternalIPSvc, err := nsc.ln.ipvsAddService(ipvsSvcs, net.ParseIP(externalIP), protocol, uint16(svc.port), svc.sessionAffinity, svc.scheduler)
				if err != nil {
					glog.Errorf("Failed to create ipvs service for external ip: %s due to %s", externalIP, err.Error())
					continue
				}
				externalIpServices = append(externalIpServices, externalIPService{ipvsSvc: ipvsExternalIPSvc, externalIp: externalIP})
				externalIpServiceId = generateIpPortId(externalIP, svc.protocol, strconv.Itoa(svc.port))

				// ensure there is NO iptable mangle table rule to FWMARK the packet
				fwMark := fmt.Sprint(generateFwmark(externalIP, svc.protocol, strconv.Itoa(svc.port)))
				err = nsc.ln.cleanupMangleTableRule(externalIP, svc.protocol, strconv.Itoa(svc.port), fwMark)
				if err != nil {
					glog.Errorf("Failed to verify and cleanup any mangle table rule to FMWARD the traffic to external IP due to " + err.Error())
					continue
				}
			}

			activeServiceEndpointMap[externalIpServiceId] = make([]string, 0)
			for _, endpoint := range endpoints {
				isLocal, _ := isLocalEndpoint(endpoint.ip, nsc.podCidr)
				if !svc.local || (svc.local && isLocal) {
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

			err := nsc.ln.ipvsAddServer(ipvsClusterVipSvc, &dst, svc.local, nsc.podCidr)
			if err != nil {
				glog.Errorf(err.Error())
			}

			isLocal, err := isLocalEndpoint(endpoint.ip, nsc.podCidr)
			if !svc.local || (svc.local && isLocal) {
				activeServiceEndpointMap[clusterServiceId] = append(activeServiceEndpointMap[clusterServiceId], endpoint.ip)
			}

			if svc.nodePort != 0 {
				for i := 0; i < len(ipvsNodeportSvcs); i++ {
					err := nsc.ln.ipvsAddServer(ipvsNodeportSvcs[i], &dst, svc.local, nsc.podCidr)
					if err != nil {
						glog.Errorf(err.Error())
					}

					if !svc.local || (svc.local && isLocal) {
						activeServiceEndpointMap[nodeServiceIds[i]] = append(activeServiceEndpointMap[clusterServiceId], endpoint.ip)
					}
				}
			}

			for _, externalIpService := range externalIpServices {

				if svc.directServerReturn && svc.directServerReturnMethod == "tunnel" {
					dst.ConnectionFlags = ipvs.ConnectionFlagTunnel
				}

				// add server to IPVS service
				err := nsc.ln.ipvsAddServer(externalIpService.ipvsSvc, &dst, svc.local, nsc.podCidr)
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

	// cleanup stale IPs on dummy interface
	glog.V(1).Info("Cleaning up if any, old service IPs on dummy interface")
	addrActive := make(map[string]bool)
	for k, endpoints := range activeServiceEndpointMap {
		// verify active and its a generateIpPortId() type service
		if len(endpoints) > 0 && strings.Contains(k, "-") {
			parts := strings.SplitN(k, "-", 3)
			addrActive[parts[0]] = true
		}
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
					err := nsc.ln.ipvsDelDestination(ipvsSvc, dst)
					if err != nil {
						glog.Errorf("Failed to delete destination %s from ipvs service %s",
							ipvsDestinationString(dst), ipvsServiceString(ipvsSvc))
					}

					// flush conntrack when endpoint for a UDP service changes
					if ipvsSvc.Protocol == syscall.IPPROTO_UDP {
						out, err := exec.Command("conntrack", "-D", "--orig-dst", dst.Address.String(), "-p", "udp", "--dport", strconv.Itoa(int(dst.Port))).CombinedOutput()
						if err != nil {
							if matched := re.MatchString(string(out)); !matched {
								glog.Error("Failed to delete conntrack entry for endpoint: " + dst.Address.String() + ":" + strconv.Itoa(int(dst.Port)) + " due to " + err.Error())
							}
						}
						glog.V(1).Infof("Deleted conntrack entry for endpoint: " + dst.Address.String() + ":" + strconv.Itoa(int(dst.Port)))
					}
				}
			}
		}
	}
	glog.V(1).Info("IPVS servers and services are synced to desired state")
	return nil
}

func isLocalEndpoint(ip, podCidr string) (bool, error) {
	_, ipnet, err := net.ParseCIDR(podCidr)
	if err != nil {
		return false, err
	}
	if ipnet.Contains(net.ParseIP(ip)) {
		return true, nil
	}
	return false, nil
}

func (nsc *NetworkServicesController) getPodObjectForEndpoint(endpointIP string) (*api.Pod, error) {
	for _, obj := range nsc.podLister.List() {
		pod := obj.(*api.Pod)
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
func (ln *linuxNetworking) prepareEndpointForDsr(containerId string, endpointIP string, vip string) error {

	// FIXME: its possible switch namespaces may never work safely in GO without hacks.
	//	 https://groups.google.com/forum/#!topic/golang-nuts/ss1gEOcehjk/discussion
	//	 https://www.weave.works/blog/linux-namespaces-and-go-don-t-mix
	// Dont know if same issue, but seen namespace issue, so adding
	// logs and boilerplate code and verbose logs for diagnosis

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var activeNetworkNamespaceHandle netns.NsHandle

	hostNetworkNamespaceHandle, err := netns.Get()
	if err != nil {
		return errors.New("Failed to get namespace due to " + err.Error())
	}
	defer hostNetworkNamespaceHandle.Close()

	activeNetworkNamespaceHandle, err = netns.Get()
	glog.V(1).Infof("Current network namespace before netns.Set: " + activeNetworkNamespaceHandle.String())
	activeNetworkNamespaceHandle.Close()

	dockerClient, err := client.NewEnvClient()
	if err != nil {
		return errors.New("Failed to get docker client due to " + err.Error())
	}
	defer dockerClient.Close()

	containerSpec, err := dockerClient.ContainerInspect(context.Background(), containerId)
	if err != nil {
		return errors.New("Failed to get docker container spec due to " + err.Error())
	}

	pid := containerSpec.State.Pid
	endpointNamespaceHandle, err := netns.GetFromPid(pid)
	if err != nil {
		return errors.New("Failed to get endpoint namespace due to " + err.Error())
	}
	defer endpointNamespaceHandle.Close()

	err = netns.Set(endpointNamespaceHandle)
	if err != nil {
		return errors.New("Failed to enter to endpoint namespace due to " + err.Error())
	}

	activeNetworkNamespaceHandle, err = netns.Get()
	glog.V(2).Infof("Current network namespace after netns. Set to container network namespace: " + activeNetworkNamespaceHandle.String())
	activeNetworkNamespaceHandle.Close()

	// TODO: fix boilerplate `netns.Set(hostNetworkNamespaceHandle)` code. Need a robust
	// way to switch back to old namespace, pretty much all things will go wrong if we dont switch back

	// create a ipip tunnel interface inside the endpoint container
	tunIf, err := netlink.LinkByName(KUBE_TUNNEL_IF)
	if err != nil {
		if err.Error() != IFACE_NOT_FOUND {
			netns.Set(hostNetworkNamespaceHandle)
			activeNetworkNamespaceHandle, err = netns.Get()
			glog.V(2).Infof("Current network namespace after revert namespace to host network namespace: " + activeNetworkNamespaceHandle.String())
			activeNetworkNamespaceHandle.Close()
			return errors.New("Failed to verify if ipip tunnel interface exists in endpoint " + endpointIP + " namespace due to " + err.Error())
		}

		glog.V(2).Infof("Could not find tunnel interface " + KUBE_TUNNEL_IF + " in endpoint " + endpointIP + " so creating one.")
		ipTunLink := netlink.Iptun{
			LinkAttrs: netlink.LinkAttrs{Name: KUBE_TUNNEL_IF},
			Local:     net.ParseIP(endpointIP),
		}
		err = netlink.LinkAdd(&ipTunLink)
		if err != nil {
			netns.Set(hostNetworkNamespaceHandle)
			activeNetworkNamespaceHandle, err = netns.Get()
			glog.V(2).Infof("Current network namespace after revert namespace to host network namespace: " + activeNetworkNamespaceHandle.String())
			activeNetworkNamespaceHandle.Close()
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
			netns.Set(hostNetworkNamespaceHandle)
			activeNetworkNamespaceHandle, err = netns.Get()
			glog.V(2).Infof("Current network namespace after revert namespace to host network namespace: " + activeNetworkNamespaceHandle.String())
			activeNetworkNamespaceHandle.Close()
			return errors.New("Failed to get " + KUBE_TUNNEL_IF + " tunnel interface handle due to " + err.Error())
		}

		glog.V(2).Infof("Successfully created tunnel interface " + KUBE_TUNNEL_IF + " in endpoint " + endpointIP + ".")
	}

	// bring the tunnel interface up
	err = netlink.LinkSetUp(tunIf)
	if err != nil {
		netns.Set(hostNetworkNamespaceHandle)
		activeNetworkNamespaceHandle, err = netns.Get()
		glog.Infof("Current network namespace after revert namespace to host network namespace: " + activeNetworkNamespaceHandle.String())
		activeNetworkNamespaceHandle.Close()
		return errors.New("Failed to bring up ipip tunnel interface in endpoint namespace due to " + err.Error())
	}

	// assign VIP to the KUBE_TUNNEL_IF interface
	err = ln.ipAddrAdd(tunIf, vip)
	if err != nil && err.Error() != IFACE_HAS_ADDR {
		netns.Set(hostNetworkNamespaceHandle)
		activeNetworkNamespaceHandle, err = netns.Get()
		glog.V(2).Infof("Current network namespace after revert namespace to host network namespace: " + activeNetworkNamespaceHandle.String())
		activeNetworkNamespaceHandle.Close()
		return errors.New("Failed to assign vip " + vip + " to kube-tunnel-if interface ")
	}
	glog.Infof("Successfully assinged VIP: " + vip + " in endpoint " + endpointIP + ".")

	// disable rp_filter on all interface
	err = ioutil.WriteFile("/proc/sys/net/ipv4/conf/kube-tunnel-if/rp_filter", []byte(strconv.Itoa(0)), 0640)
	if err != nil {
		netns.Set(hostNetworkNamespaceHandle)
		activeNetworkNamespaceHandle, err = netns.Get()
		glog.Infof("Current network namespace after revert namespace to host network namespace: " + activeNetworkNamespaceHandle.String())
		activeNetworkNamespaceHandle.Close()
		return errors.New("Failed to disable rp_filter on kube-tunnel-if in the endpoint container")
	}

	err = ioutil.WriteFile("/proc/sys/net/ipv4/conf/eth0/rp_filter", []byte(strconv.Itoa(0)), 0640)
	if err != nil {
		netns.Set(hostNetworkNamespaceHandle)
		activeNetworkNamespaceHandle, err = netns.Get()
		glog.Infof("Current network namespace after revert namespace to host network namespace: " + activeNetworkNamespaceHandle.String())
		activeNetworkNamespaceHandle.Close()
		return errors.New("Failed to disable rp_filter on eth0 in the endpoint container")
	}

	err = ioutil.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte(strconv.Itoa(0)), 0640)
	if err != nil {
		netns.Set(hostNetworkNamespaceHandle)
		activeNetworkNamespaceHandle, err = netns.Get()
		glog.V(2).Infof("Current network namespace after revert namespace to host network namespace: " + activeNetworkNamespaceHandle.String())
		activeNetworkNamespaceHandle.Close()
		return errors.New("Failed to disable rp_filter on `all` in the endpoint container")
	}

	glog.Infof("Successfully disabled rp_filter in endpoint " + endpointIP + ".")

	netns.Set(hostNetworkNamespaceHandle)
	activeNetworkNamespaceHandle, err = netns.Get()
	glog.Infof("Current network namespace after revert namespace to host network namespace: " + activeNetworkNamespaceHandle.String())
	activeNetworkNamespaceHandle.Close()
	return nil
}

func (nsc *NetworkServicesController) buildServicesInfo() serviceInfoMap {
	serviceMap := make(serviceInfoMap)
	for _, obj := range nsc.svcLister.List() {
		svc := obj.(*api.Service)

		if svc.Spec.ClusterIP == "None" || svc.Spec.ClusterIP == "" {
			glog.V(2).Infof("Skipping service name:%s namespace:%s as there is no cluster IP", svc.Name, svc.Namespace)
			continue
		}

		if svc.Spec.Type == "ExternalName" {
			glog.V(2).Infof("Skipping service name:%s namespace:%s due to service Type=%s", svc.Name, svc.Namespace, svc.Spec.Type)
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
				local:       false,
			}
			dsrMethod, ok := svc.ObjectMeta.Annotations[svcDSRAnnotation]
			if ok {
				svcInfo.directServerReturn = true
				svcInfo.directServerReturnMethod = dsrMethod
			}
			svcInfo.scheduler = ipvs.RoundRobin
			schedulingMethod, ok := svc.ObjectMeta.Annotations[svcSchedulerAnnotation]
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
			for _, lbIngress := range svc.Status.LoadBalancer.Ingress {
				if len(lbIngress.IP) > 0 {
					svcInfo.loadBalancerIPs = append(svcInfo.loadBalancerIPs, lbIngress.IP)
				}
			}
			svcInfo.sessionAffinity = svc.Spec.SessionAffinity == "ClientIP"
			_, svcInfo.hairpin = svc.ObjectMeta.Annotations[svcHairpinAnnotation]
			_, svcInfo.local = svc.ObjectMeta.Annotations[svcLocalAnnotation]
			_, svcInfo.skipLbIps = svc.ObjectMeta.Annotations[svcSkipLbIpsAnnotation]
			if svc.Spec.ExternalTrafficPolicy == api.ServiceExternalTrafficPolicyTypeLocal {
				svcInfo.local = true
			}

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

func (nsc *NetworkServicesController) buildEndpointsInfo() endpointsInfoMap {
	endpointsMap := make(endpointsInfoMap)
	for _, obj := range nsc.epLister.List() {
		ep := obj.(*api.Endpoints)

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

// Add an iptable rule to masquerad outbound IPVS traffic. IPVS nat requires that reverse path traffic
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
		//TODO: ipset should be used for destination podCidr(s) match after multiple podCidr(s) per node get supported
		args = []string{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ", "-m", "comment", "--comment", "",
			"!", "-s", podCidr, "!", "-d", podCidr, "-j", "MASQUERADE"}
		err = iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", args...)
		if err != nil {
			return errors.New("Failed to run iptables command" + err.Error())
		}
	}
	glog.V(1).Info("Successfully added iptables masquerad rule")
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
		glog.V(1).Info("No hairpin-mode enabled services found -- no hairpin rules created")
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
					glog.V(1).Info("Deleted invalid/outdated hairpin rule \"%s\" from chain %s", ruleFromNode, hairpinChain)
				}
			} else {
				// Ignore the chain creation rule
				if ruleFromNode == "-N "+hairpinChain {
					continue
				}
				glog.V(1).Infof("Not removing invalid hairpin rule \"%s\" from chain %s", ruleFromNode, hairpinChain)
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
			glog.V(1).Info("Deleted hairpin jump rule from chain \"POSTROUTING\"")
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
			glog.V(2).Infof("Deleted iptables masquerade rule: %s", rule)
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

func (ln *linuxNetworking) ipvsAddService(svcs []*ipvs.Service, vip net.IP, protocol, port uint16, persistent bool, scheduler string) (*ipvs.Service, error) {

	var err error
	for _, svc := range svcs {
		if vip.Equal(svc.Address) && protocol == svc.Protocol && port == svc.Port {
			if (persistent && (svc.Flags&0x0001) == 0) || (!persistent && (svc.Flags&0x0001) != 0) {
				ipvsSetPersistence(svc, persistent)

				err = ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, err
				}
				glog.V(2).Infof("Updated persistence/session-affinity for service: %s", ipvsServiceString(svc))
			}

			if scheduler != svc.SchedName {
				svc.SchedName = scheduler
				err = ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, errors.New("Failed to update the scheduler for the service due to " + err.Error())
				}
				glog.V(2).Infof("Updated schedule for the service: %s", ipvsServiceString(svc))
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

	err = ln.ipvsNewService(&svc)
	if err != nil {
		return nil, err
	}
	glog.V(1).Infof("Successfully added service: %s", ipvsServiceString(&svc))
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
func (ln *linuxNetworking) ipvsAddFWMarkService(vip net.IP, protocol, port uint16, persistent bool, scheduler string) (*ipvs.Service, error) {

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

	svcs, err := ln.ipvsGetServices()
	if err != nil {
		return nil, err
	}

	for _, svc := range svcs {
		if fwmark == svc.FWMark {
			if (persistent && (svc.Flags&0x0001) == 0) || (!persistent && (svc.Flags&0x0001) != 0) {
				ipvsSetPersistence(svc, persistent)

				err = ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, err
				}
				glog.V(2).Infof("Updated persistence/session-affinity for service: %s", ipvsServiceString(svc))
			}

			if scheduler != svc.SchedName {
				svc.SchedName = scheduler
				err = ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, errors.New("Failed to update the scheduler for the service due to " + err.Error())
				}
				glog.V(2).Infof("Updated schedule for the service: %s", ipvsServiceString(svc))
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

	err = ln.ipvsNewService(&svc)
	if err != nil {
		return nil, err
	}
	glog.Infof("Successfully added service: %s", ipvsServiceString(&svc))
	return &svc, nil
}

func (ln *linuxNetworking) ipvsAddServer(service *ipvs.Service, dest *ipvs.Destination, local bool, podCidr string) error {
	//for service.local enabled svc, only forward traffic to the pod on local node
	if local {
		_, ipnet, err := net.ParseCIDR(podCidr)
		if err != nil {
			glog.Infof("Failed to ParseCIDR %s for adding destination %s to the service %s",
				podCidr, ipvsDestinationString(dest), ipvsServiceString(service))
			return nil
		}
		if !ipnet.Contains(dest.Address) {
			return nil
		}
	}

	err := ln.ipvsNewDestination(service, dest)
	if err == nil {
		glog.V(2).Infof("Successfully added destination %s to the service %s",
			ipvsDestinationString(dest), ipvsServiceString(service))
		return nil
	}

	if strings.Contains(err.Error(), IPVS_SERVER_EXISTS) {
		err = ln.ipvsUpdateDestination(service, dest)
		if err != nil {
			return fmt.Errorf("Failed to update ipvs destination %s to the ipvs service %s due to : %s",
				ipvsDestinationString(dest), ipvsServiceString(service), err.Error())
		}
		// TODO: Make this debug output when we get log levels
		// glog.Infof("ipvs destination %s already exists in the ipvs service %s so not adding destination",
		// 	ipvsDestinationString(dest), ipvsServiceString(service))
	} else {
		return fmt.Errorf("Failed to add ipvs destination %s to the ipvs service %s due to : %s",
			ipvsDestinationString(dest), ipvsServiceString(service), err.Error())
	}
	return nil
}

const (
	customDSRRouteTableID    = "78"
	customDSRRouteTableName  = "kube-router-dsr"
	externalIPRouteTableId   = "79"
	externalIPRouteTableName = "external_ip"
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

func (ln *linuxNetworking) cleanupMangleTableRule(ip string, protocol string, port string, fwmark string) error {
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed to initialize iptables executor" + err.Error())
	}
	args := []string{"-d", ip, "-m", protocol, "-p", protocol, "--dport", port, "-j", "MARK", "--set-mark", fwmark}
	exists, err := iptablesCmdHandler.Exists("mangle", "PREROUTING", args...)
	if err != nil {
		return errors.New("Failed to cleanup iptables command to set up FWMARK due to " + err.Error())
	}
	if exists {
		err = iptablesCmdHandler.Delete("mangle", "PREROUTING", args...)
		if err != nil {
			return errors.New("Failed to cleanup iptables command to set up FWMARK due to " + err.Error())
		}
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
		err = exec.Command("ip", "rule", "add", "prio", "32764", "fwmark", fwmark, "table", customDSRRouteTableID).Run()
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
func (ln *linuxNetworking) setupPolicyRoutingForDSR() error {
	b, err := ioutil.ReadFile("/etc/iproute2/rt_tables")
	if err != nil {
		return errors.New("Failed to setup policy routing required for DSR due to " + err.Error())
	}

	if !strings.Contains(string(b), customDSRRouteTableName) {
		f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return errors.New("Failed to setup policy routing required for DSR due to " + err.Error())
		}
		defer f.Close()
		if _, err = f.WriteString(customDSRRouteTableID + " " + customDSRRouteTableName + "\n"); err != nil {
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

// For DSR it is required that node needs to know how to route exteranl IP. Otherwise when endpoint
// directly responds back with source IP as external IP kernel will treat as martian packet.
// To prevent martian packets add route to exteranl IP through the `kube-bridge` interface
// setupRoutesForExternalIPForDSR: setups routing so that kernel does not think return packets as martians

func (ln *linuxNetworking) setupRoutesForExternalIPForDSR(serviceInfoMap serviceInfoMap) error {
	b, err := ioutil.ReadFile("/etc/iproute2/rt_tables")
	if err != nil {
		return errors.New("Failed to setup external ip routing table required for DSR due to " + err.Error())
	}

	if !strings.Contains(string(b), externalIPRouteTableName) {
		f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return errors.New("Failed setup external ip routing table required for DSR due to " + err.Error())
		}
		defer f.Close()
		if _, err = f.WriteString(externalIPRouteTableId + " " + externalIPRouteTableName + "\n"); err != nil {
			return errors.New("Failed setup external ip routing table required for DSR due to " + err.Error())
		}
	}

	out, err := exec.Command("ip", "route", "list", "table", externalIPRouteTableId).Output()
	if err != nil {
		return errors.New("Failed to verify required routing table for external IP's exists. " +
			"Failed to setup policy routing required for DSR due to " + err.Error())
	}

	out, err = exec.Command("ip", "rule", "list").Output()
	if err != nil {
		return errors.New("Failed to verify if `ip rule add prio 32765 from all lookup external_ip` exists due to: " + err.Error())
	}

	if !(strings.Contains(string(out), externalIPRouteTableName) || strings.Contains(string(out), externalIPRouteTableId)) {
		err = exec.Command("ip", "rule", "add", "prio", "32765", "from", "all", "lookup", externalIPRouteTableId).Run()
		if err != nil {
			glog.Infof("Failed to add policy rule `ip rule add prio 32765 from all lookup external_ip` due to " + err.Error())
			return errors.New("Failed to add policy rule `ip rule add prio 32765 from all lookup external_ip` due to " + err.Error())
		}
	}

	out, err = exec.Command("ip", "route", "list", "table", externalIPRouteTableId).Output()
	if err != nil {
		return errors.New("Failed to get routes in external_ip table due to: " + err.Error())
	}
	outStr := string(out)
	activeExternalIPs := make(map[string]bool)
	for _, svc := range serviceInfoMap {
		for _, externalIP := range svc.externalIPs {
			activeExternalIPs[externalIP] = true

			if !strings.Contains(outStr, externalIP) {
				if err = exec.Command("ip", "route", "add", externalIP, "dev", "kube-bridge", "table",
					externalIPRouteTableId).Run(); err != nil {
					glog.Error("Failed to add route for " + externalIP + " in custom route table for external IP's due to: " + err.Error())
					continue
				}
			}
		}
	}

	// check if there are any pbr in externalIPRouteTableId for external IP's
	if len(outStr) > 0 {
		// clean up stale external IPs
		for _, line := range strings.Split(strings.Trim(outStr, "\n"), "\n") {
			route := strings.Split(strings.Trim(line, " "), " ")
			ip := route[0]
			if !activeExternalIPs[ip] {
				args := []string{"route", "del", "table", externalIPRouteTableId}
				args = append(args, route...)
				if err = exec.Command("ip", args...).Run(); err != nil {
					glog.Errorf("Failed to del route for %v in custom route table for external IP's due to: %s", ip, err)
					continue
				}
			}
		}
	}

	return nil
}

func isEndpointsForLeaderElection(ep *api.Endpoints) bool {
	_, isLeaderElection := ep.Annotations[LeaderElectionRecordAnnotationKey]
	return isLeaderElection
}

// unique identifier for a load-balanced service (namespace + name + portname)
func generateServiceId(namespace, svcName, port string) string {
	return namespace + "-" + svcName + "-" + port
}

// unique identifier for a load-balanced service (namespace + name + portname)
func generateIpPortId(ip, protocol, port string) string {
	return ip + "-" + protocol + "-" + port
}

// returns all IP addresses found on any network address in the system, excluding dummy and docker interfaces
func getAllLocalIPs() ([]netlink.Addr, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, errors.New("Could not load list of net interfaces: " + err.Error())
	}

	addrs := make([]netlink.Addr, 0)
	for _, link := range links {

		// do not include IPs for any interface that calls itself "dummy"
		// or any of the docker# interfaces
		if strings.Contains(link.Attrs().Name, "dummy") ||
			strings.Contains(link.Attrs().Name, "kube") ||
			strings.Contains(link.Attrs().Name, "docker") {

			continue
		}

		linkAddrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return nil, errors.New("Failed to get IPs for interface: " + err.Error())
		}

		addrs = append(addrs, linkAddrs...)
	}

	return addrs, nil
}

func (ln *linuxNetworking) getKubeDummyInterface() (netlink.Link, error) {
	var dummyVipInterface netlink.Link
	dummyVipInterface, err := netlink.LinkByName(KUBE_DUMMY_IF)
	if err != nil && err.Error() == IFACE_NOT_FOUND {
		glog.V(1).Infof("Could not find dummy interface: " + KUBE_DUMMY_IF + " to assign cluster ip's, creating one")
		err = netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: KUBE_DUMMY_IF}})
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

	// cleanup iptable masquerad rule
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

func (nsc *NetworkServicesController) newEndpointsEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			nsc.OnEndpointsUpdate(obj)

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			nsc.OnEndpointsUpdate(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			nsc.OnEndpointsUpdate(obj)

		},
	}
}

func (nsc *NetworkServicesController) newSvcEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			nsc.OnServiceUpdate(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			nsc.OnServiceUpdate(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			nsc.OnServiceUpdate(obj)
		},
	}

}

// NewNetworkServicesController returns NetworkServicesController object
func NewNetworkServicesController(clientset kubernetes.Interface,
	config *options.KubeRouterConfig, svcInformer cache.SharedIndexInformer,
	epInformer cache.SharedIndexInformer, podInformer cache.SharedIndexInformer) (*NetworkServicesController, error) {

	var err error
	ln, err := newLinuxNetworking()
	if err != nil {
		return nil, err
	}
	nsc := NetworkServicesController{ln: ln}

	if config.MetricsEnabled {
		//Register the metrics for this controller
		prometheus.MustRegister(metrics.ControllerIpvsServices)
		prometheus.MustRegister(metrics.ControllerIpvsServicesSyncTime)
		prometheus.MustRegister(metrics.ServiceBpsIn)
		prometheus.MustRegister(metrics.ServiceBpsOut)
		prometheus.MustRegister(metrics.ServiceBytesIn)
		prometheus.MustRegister(metrics.ServiceBytesOut)
		prometheus.MustRegister(metrics.ServiceCPS)
		prometheus.MustRegister(metrics.ServicePacketsIn)
		prometheus.MustRegister(metrics.ServicePacketsOut)
		prometheus.MustRegister(metrics.ServicePpsIn)
		prometheus.MustRegister(metrics.ServicePpsOut)
		prometheus.MustRegister(metrics.ServiceTotalConn)
		nsc.MetricsEnabled = true
	}

	nsc.syncPeriod = config.IpvsSyncPeriod
	nsc.globalHairpin = config.GlobalHairpinMode

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
	NodeIP, err = utils.GetNodeIP(node)
	if err != nil {
		return nil, err
	}
	nsc.nodeIP = NodeIP

	nsc.podLister = podInformer.GetIndexer()

	nsc.svcLister = svcInformer.GetIndexer()
	nsc.ServiceEventHandler = nsc.newSvcEventHandler()

	nsc.epLister = epInformer.GetIndexer()
	nsc.EndpointsEventHandler = nsc.newEndpointsEventHandler()

	rand.Seed(time.Now().UnixNano())

	return &nsc, nil
}
