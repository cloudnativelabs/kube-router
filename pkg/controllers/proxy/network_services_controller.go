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
	KUBE_DUMMY_IF       = "kube-dummy-if"
	KUBE_TUNNEL_IF      = "kube-tunnel-if"
	IFACE_NOT_FOUND     = "Link not found"
	IFACE_HAS_ADDR      = "file exists"
	IFACE_HAS_NO_ADDR   = "cannot assign requested address"
	IPVS_SERVER_EXISTS  = "file exists"
	IPVS_MAGLEV_HASHING = "mh"
	IPVS_SVC_F_SCHED1   = "flag-1"
	IPVS_SVC_F_SCHED2   = "flag-2"
	IPVS_SVC_F_SCHED3   = "flag-3"

	svcDSRAnnotation        = "kube-router.io/service.dsr"
	svcSchedulerAnnotation  = "kube-router.io/service.scheduler"
	svcHairpinAnnotation    = "kube-router.io/service.hairpin"
	svcLocalAnnotation      = "kube-router.io/service.local"
	svcSkipLbIpsAnnotation  = "kube-router.io/service.skiplbips"
	svcSchedFlagsAnnotation = "kube-router.io/service.schedflags"

	LeaderElectionRecordAnnotationKey = "control-plane.alpha.kubernetes.io/leader"
	localIPsIPSetName                 = "kube-router-local-ips"
	ipvsServicesIPSetName             = "kube-router-ipvs-services"
	serviceIPsIPSetName               = "kube-router-service-ips"
	ipvsFirewallChainName             = "KUBE-ROUTER-SERVICES"
	synctypeAll                       = iota
	synctypeIpvs
)

var (
	h      *ipvs.Handle
	NodeIP net.IP
)

type ipvsCalls interface {
	ipvsNewService(ipvsSvc *ipvs.Service) error
	ipvsAddService(svcs []*ipvs.Service, vip net.IP, protocol, port uint16, persistent bool, scheduler string, flags schedFlags) (*ipvs.Service, error)
	ipvsDelService(ipvsSvc *ipvs.Service) error
	ipvsUpdateService(ipvsSvc *ipvs.Service) error
	ipvsGetServices() ([]*ipvs.Service, error)
	ipvsAddServer(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error
	ipvsNewDestination(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error
	ipvsUpdateDestination(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error
	ipvsGetDestinations(ipvsSvc *ipvs.Service) ([]*ipvs.Destination, error)
	ipvsDelDestination(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error
	ipvsAddFWMarkService(vip net.IP, protocol, port uint16, persistent bool, scheduler string, flags schedFlags) (*ipvs.Service, error)
}

type netlinkCalls interface {
	ipAddrAdd(iface netlink.Link, ip string, addRoute bool) error
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
	// Delete VIP addition to "local" rt table also, fail silently if not found (DSR special case)
	if err == nil {
		out, err := exec.Command("ip", "route", "delete", "local", ip, "dev", KUBE_DUMMY_IF, "table", "local", "proto", "kernel", "scope", "host", "src",
			NodeIP.String(), "table", "local").CombinedOutput()
		if err != nil && !strings.Contains(string(out), "No such process") {
			glog.Errorf("Failed to delete route to service VIP %s configured on %s. Error: %v, Output: %s", ip, KUBE_DUMMY_IF, err, out)
		}
	}
	return err
}

// utility method to assign an IP to an interface. Mainly used to assign service VIP's
// to kube-dummy-if. Also when DSR is used, used to assign VIP to dummy interface
// inside the container.
func (ln *linuxNetworking) ipAddrAdd(iface netlink.Link, ip string, addRoute bool) error {
	naddr := &netlink.Addr{IPNet: &net.IPNet{IP: net.ParseIP(ip), Mask: net.IPv4Mask(255, 255, 255, 255)}, Scope: syscall.RT_SCOPE_LINK}
	err := netlink.AddrAdd(iface, naddr)
	if err != nil && err.Error() != IFACE_HAS_ADDR {
		glog.Errorf("Failed to assign cluster ip %s to dummy interface: %s",
			naddr.IPNet.IP.String(), err.Error())
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

	// Map of ipsets that we use.
	ipsetMap map[string]*utils.Set

	svcLister cache.Indexer
	epLister  cache.Indexer
	podLister cache.Indexer

	ServiceEventHandler   cache.ResourceEventHandler
	EndpointsEventHandler cache.ResourceEventHandler

	gracefulPeriod      time.Duration
	gracefulQueue       gracefulQueue
	gracefulTermination bool
	syncChan            chan int
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
	flags                    schedFlags
}

// IPVS scheduler flags
type schedFlags struct {
	flag1 bool /* ipvs scheduler flag-1 */
	flag2 bool /* ipvs scheduler flag-2 */
	flag3 bool /* ipvs scheduler flag-3 */
}

// map of all services, with unique service id(namespace name, service name, port) as key
type serviceInfoMap map[string]*serviceInfo

// internal representation of endpoints
type endpointsInfo struct {
	ip      string
	port    int
	isLocal bool
}

// map of all endpoints, with unique service id(namespace name, service name, port) as key
type endpointsInfoMap map[string][]endpointsInfo

// Run periodically sync ipvs configuration to reflect desired state of services and endpoints
func (nsc *NetworkServicesController) Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) error {
	t := time.NewTicker(nsc.syncPeriod)
	defer t.Stop()
	defer wg.Done()
	defer close(nsc.syncChan)

	glog.Infof("Starting network services controller")

	err := ensureMasqueradeIptablesRule(nsc.masqueradeAll, nsc.podCidr)
	// enable masquerade rule
	if err != nil {
		return errors.New("Failed to do add masquerade rule in POSTROUTING chain of nat table due to: %s" + err.Error())
	}
	// https://www.kernel.org/doc/Documentation/networking/ipvs-sysctl.txt
	// enable ipvs connection tracking
	sysctlErr := utils.SetSysctl("net/ipv4/vs/conntrack", 1)
	if sysctlErr != nil {
		return errors.New(sysctlErr.Error())
	}

	// LVS failover not working with UDP packets https://access.redhat.com/solutions/58653
	sysctlErr = utils.SetSysctl("net/ipv4/vs/expire_nodest_conn", 1)
	if sysctlErr != nil {
		return errors.New(sysctlErr.Error())
	}

	// LVS failover not working with UDP packets https://access.redhat.com/solutions/58653
	sysctlErr = utils.SetSysctl("net/ipv4/vs/expire_quiescent_template", 1)
	if sysctlErr != nil {
		return errors.New(sysctlErr.Error())
	}

	// https://github.com/kubernetes/kubernetes/pull/71114
	sysctlErr = utils.SetSysctl("net/ipv4/vs/conn_reuse_mode", 0)
	if sysctlErr != nil {
		// Check if the error is fatal, on older kernels this option does not exist and the same behaviour is default
		// if option is not found just log it
		if sysctlErr.IsFatal() {
			return errors.New(sysctlErr.Error())
		}
		glog.Info(sysctlErr.Error())
	}

	// https://github.com/kubernetes/kubernetes/pull/70530/files
	sysctlErr = utils.SetSysctl("net/ipv4/conf/all/arp_ignore", 1)
	if sysctlErr != nil {
		return errors.New(sysctlErr.Error())
	}

	// https://github.com/kubernetes/kubernetes/pull/70530/files
	sysctlErr = utils.SetSysctl("net/ipv4/conf/all/arp_announce", 2)
	if sysctlErr != nil {
		return errors.New(sysctlErr.Error())
	}

	// https://github.com/cloudnativelabs/kube-router/issues/282
	err = nsc.setupIpvsFirewall()
	if err != nil {
		return errors.New("Error setting up ipvs firewall: " + err.Error())
	}

	gracefulTicker := time.NewTicker(5 * time.Second)
	defer gracefulTicker.Stop()

	select {
	case <-stopCh:
		glog.Info("Shutting down network services controller")
		return nil
	default:
		err := nsc.doSync()
		if err != nil {
			glog.Fatalf("Failed to perform initial full sync %s", err.Error())
		}
		nsc.readyForUpdates = true
	}

	// loop forever until notified to stop on stopCh
	for {
		select {
		case <-stopCh:
			glog.Info("Shutting down network services controller")
			return nil

		case <-gracefulTicker.C:
			if nsc.readyForUpdates && nsc.gracefulTermination {
				glog.V(3).Info("Performing periodic graceful destination cleanup")
				nsc.gracefulSync()
			}

		case perform := <-nsc.syncChan:
			switch perform {
			case synctypeAll:
				glog.V(1).Info("Performing requested full sync of services")
				err := nsc.doSync()
				if err != nil {
					glog.Errorf("Error during full sync in network service controller. Error: " + err.Error())
				}
			case synctypeIpvs:
				glog.V(1).Info("Performing requested sync of ipvs services")
				nsc.mu.Lock()
				err := nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
				nsc.mu.Unlock()
				if err != nil {
					glog.Errorf("Error during ipvs sync in network service controller. Error: " + err.Error())
				}
			}

		case <-t.C:
			glog.V(1).Info("Performing periodic sync of ipvs services")
			healthcheck.SendHeartBeat(healthChan, "NSC")
			err := nsc.doSync()
			if err != nil {
				glog.Errorf("Error during periodic ipvs sync in network service controller. Error: " + err.Error())
				glog.Errorf("Skipping sending heartbeat from network service controller as periodic sync failed.")
			} else {
				healthcheck.SendHeartBeat(healthChan, "NSC")
			}
		}
	}
}

func (nsc *NetworkServicesController) sync(syncType int) {
	select {
	case nsc.syncChan <- syncType:
	default:
		glog.V(2).Infof("Already pending sync, dropping request for type %d", syncType)
	}
}

func (nsc *NetworkServicesController) doSync() error {
	var err error
	nsc.mu.Lock()
	defer nsc.mu.Unlock()

	err = ensureMasqueradeIptablesRule(nsc.masqueradeAll, nsc.podCidr)
	// enable masquerade rule
	if err != nil {
		glog.Errorf("Failed to do add masquerade rule in POSTROUTING chain of nat table due to: %s", err.Error())
	}

	nsc.serviceMap = nsc.buildServicesInfo()
	nsc.endpointsMap = nsc.buildEndpointsInfo()
	err = nsc.syncHairpinIptablesRules()
	if err != nil {
		glog.Errorf("Error syncing hairpin iptables rules: %s", err.Error())
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

// Lookup service ip, protocol, port by given fwmark value (reverse of generateFwmark)
func (nsc *NetworkServicesController) lookupServiceByFWMark(FWMark uint32) (string, string, int) {
	for _, svc := range nsc.serviceMap {
		for _, externalIP := range svc.externalIPs {
			gfwmark := generateFwmark(externalIP, svc.protocol, fmt.Sprint(svc.port))
			if FWMark == gfwmark {
				return externalIP, svc.protocol, svc.port
			}
		}
	}
	return "", "", 0
}

func getIpvsFirewallInputChainRule() []string {
	// The iptables rule for use in {setup,cleanup}IpvsFirewall.
	return []string{
		"-m", "comment", "--comment", "handle traffic to IPVS service IPs in custom chain",
		"-m", "set", "--match-set", serviceIPsIPSetName, "dst",
		"-j", ipvsFirewallChainName}
}

func (nsc *NetworkServicesController) setupIpvsFirewall() error {
	/*
	   - create ipsets
	   - create firewall rules
	*/

	var err error
	var ipset *utils.Set

	ipSetHandler, err := utils.NewIPSet(false)
	if err != nil {
		return err
	}

	// Remember ipsets for use in syncIpvsFirewall
	nsc.ipsetMap = make(map[string]*utils.Set)

	// Create ipset for local addresses.
	ipset, err = ipSetHandler.Create(localIPsIPSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
	if err != nil {
		return fmt.Errorf("failed to create ipset: %s", err.Error())
	}
	nsc.ipsetMap[localIPsIPSetName] = ipset

	// Create 2 ipsets for services. One for 'ip' and one for 'ip,port'
	ipset, err = ipSetHandler.Create(serviceIPsIPSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
	if err != nil {
		return fmt.Errorf("failed to create ipset: %s", err.Error())
	}
	nsc.ipsetMap[serviceIPsIPSetName] = ipset

	ipset, err = ipSetHandler.Create(ipvsServicesIPSetName, utils.TypeHashIPPort, utils.OptionTimeout, "0")
	if err != nil {
		return fmt.Errorf("failed to create ipset: %s", err.Error())
	}
	nsc.ipsetMap[ipvsServicesIPSetName] = ipset

	// Setup a custom iptables chain to explicitly allow input traffic to
	// ipvs services only.
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed to initialize iptables executor" + err.Error())
	}

	// ClearChain either clears an existing chain or creates a new one.
	err = iptablesCmdHandler.ClearChain("filter", ipvsFirewallChainName)
	if err != nil {
		return fmt.Errorf("Failed to run iptables command: %s", err.Error())
	}

	var comment string
	var args []string

	comment = "allow input traffic to ipvs services"
	args = []string{"-m", "comment", "--comment", comment,
		"-m", "set", "--match-set", ipvsServicesIPSetName, "dst,dst",
		"-j", "ACCEPT"}
	exists, err := iptablesCmdHandler.Exists("filter", ipvsFirewallChainName, args...)
	if err != nil {
		return fmt.Errorf("Failed to run iptables command: %s", err.Error())
	}
	if !exists {
		err := iptablesCmdHandler.Insert("filter", ipvsFirewallChainName, 1, args...)
		if err != nil {
			return fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
	}

	comment = "allow icmp echo requests to service IPs"
	args = []string{"-m", "comment", "--comment", comment,
		"-p", "icmp", "--icmp-type", "echo-request",
		"-j", "ACCEPT"}
	err = iptablesCmdHandler.AppendUnique("filter", ipvsFirewallChainName, args...)
	if err != nil {
		return fmt.Errorf("Failed to run iptables command: %s", err.Error())
	}

	// We exclude the local addresses here as that would otherwise block all
	// traffic to local addresses if any NodePort service exists.
	comment = "reject all unexpected traffic to service IPs"
	args = []string{"-m", "comment", "--comment", comment,
		"-m", "set", "!", "--match-set", localIPsIPSetName, "dst",
		"-j", "REJECT", "--reject-with", "icmp-port-unreachable"}
	err = iptablesCmdHandler.AppendUnique("filter", ipvsFirewallChainName, args...)
	if err != nil {
		return fmt.Errorf("Failed to run iptables command: %s", err.Error())
	}

	// Pass incomming traffic into our custom chain.
	ipvsFirewallInputChainRule := getIpvsFirewallInputChainRule()
	exists, err = iptablesCmdHandler.Exists("filter", "INPUT", ipvsFirewallInputChainRule...)
	if err != nil {
		return fmt.Errorf("Failed to run iptables command: %s", err.Error())
	}
	if !exists {
		err = iptablesCmdHandler.Insert("filter", "INPUT", 1, ipvsFirewallInputChainRule...)
		if err != nil {
			return fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
	}

	return nil
}

func (nsc *NetworkServicesController) cleanupIpvsFirewall() {
	/*
	   - delete firewall rules
	   - delete ipsets
	*/
	var err error

	// Clear iptables rules.
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		glog.Errorf("Failed to initialize iptables executor: %s", err.Error())
	} else {
		ipvsFirewallInputChainRule := getIpvsFirewallInputChainRule()
		err = iptablesCmdHandler.Delete("filter", "INPUT", ipvsFirewallInputChainRule...)
		if err != nil {
			glog.Errorf("Failed to run iptables command: %s", err.Error())
		}

		err = iptablesCmdHandler.ClearChain("filter", ipvsFirewallChainName)
		if err != nil {
			glog.Errorf("Failed to run iptables command: %s", err.Error())
		}

		err = iptablesCmdHandler.DeleteChain("filter", ipvsFirewallChainName)
		if err != nil {
			glog.Errorf("Failed to run iptables command: %s", err.Error())
		}
	}

	// Clear ipsets.
	ipSetHandler, err := utils.NewIPSet(false)
	if err != nil {
		glog.Errorf("Failed to initialize ipset handler: %s", err.Error())
	} else {
		err = ipSetHandler.Destroy(localIPsIPSetName)
		if err != nil {
			glog.Errorf("failed to destroy ipset: %s", err.Error())
		}

		err = ipSetHandler.Destroy(serviceIPsIPSetName)
		if err != nil {
			glog.Errorf("failed to destroy ipset: %s", err.Error())
		}

		err = ipSetHandler.Destroy(ipvsServicesIPSetName)
		if err != nil {
			glog.Errorf("failed to destroy ipset: %s", err.Error())
		}
	}
}

func (nsc *NetworkServicesController) syncIpvsFirewall() error {
	/*
	   - update ipsets based on currently active IPVS services
	*/
	var err error

	localIPsIPSet := nsc.ipsetMap[localIPsIPSetName]

	// Populate local addresses ipset.
	addrs, err := getAllLocalIPs()
	localIPsSets := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		localIPsSets = append(localIPsSets, addr.IP.String())
	}
	err = localIPsIPSet.Refresh(localIPsSets, utils.OptionTimeout, "0")
	if err != nil {
		return fmt.Errorf("failed to sync ipset: %s", err.Error())
	}

	// Populate service ipsets.
	ipvsServices, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return errors.New("Failed to list IPVS services: " + err.Error())
	}

	serviceIPsSets := make([]string, 0, len(ipvsServices))
	ipvsServicesSets := make([]string, 0, len(ipvsServices))

	for _, ipvsService := range ipvsServices {
		var address, protocol string
		var port int
		if ipvsService.Address != nil {
			address = ipvsService.Address.String()
			if ipvsService.Protocol == syscall.IPPROTO_TCP {
				protocol = "tcp"
			} else {
				protocol = "udp"
			}
			port = int(ipvsService.Port)
		} else if ipvsService.FWMark != 0 {
			address, protocol, port = nsc.lookupServiceByFWMark(ipvsService.FWMark)
			if address == "" {
				continue
			}
		}

		serviceIPsSet := address
		serviceIPsSets = append(serviceIPsSets, serviceIPsSet)

		ipvsServicesSet := fmt.Sprintf("%s,%s:%d", address, protocol, port)
		ipvsServicesSets = append(ipvsServicesSets, ipvsServicesSet)

	}

	serviceIPsIPSet := nsc.ipsetMap[serviceIPsIPSetName]
	err = serviceIPsIPSet.Refresh(serviceIPsSets, utils.OptionTimeout, "0")
	if err != nil {
		return fmt.Errorf("failed to sync ipset: %s", err.Error())
	}

	ipvsServicesIPSet := nsc.ipsetMap[ipvsServicesIPSetName]
	err = ipvsServicesIPSet.Refresh(ipvsServicesSets, utils.OptionTimeout, "0")
	if err != nil {
		return fmt.Errorf("failed to sync ipset: %s", err.Error())
	}

	return nil
}

func (nsc *NetworkServicesController) publishMetrics(serviceInfoMap serviceInfoMap) error {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		glog.V(2).Infof("Publishing IPVS metrics took %v", endTime)
		if nsc.MetricsEnabled {
			metrics.ControllerIpvsMetricsExportTime.Observe(float64(endTime.Seconds()))
		}
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
				metrics.ControllerIpvsServices.Set(float64(len(ipvsSvcs)))
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
		nsc.sync(synctypeIpvs)
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
		nsc.sync(synctypeIpvs)
	} else {
		glog.V(1).Infof("Skipping syncing IPVS services for update to service: %s/%s as nothing changed", svc.Namespace, svc.Name)
	}
}

type externalIPService struct {
	ipvsSvc    *ipvs.Service
	externalIp string
}

func hasActiveEndpoints(svc *serviceInfo, endpoints []endpointsInfo) bool {
	for _, endpoint := range endpoints {
		if endpoint.isLocal {
			return true
		}
	}
	return false
}

// sync the ipvs service and server details configured to reflect the desired state of services and endpoint
// as learned from services and endpoints information from the api server
func (nsc *NetworkServicesController) syncIpvsServices(serviceInfoMap serviceInfoMap, endpointsInfoMap endpointsInfoMap) error {
	var ipvsSvcs []*ipvs.Service
	start := time.Now()

	defer func() {
		endTime := time.Since(start)
		if nsc.MetricsEnabled {
			metrics.ControllerIpvsServicesSyncTime.Observe(endTime.Seconds())
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

		endpoints := endpointsInfoMap[k]

		if svc.local && !hasActiveEndpoints(svc, endpoints) {
			glog.V(1).Infof("Skipping service %s/%s as it does not have active endpoints\n", svc.namespace, svc.name)
			continue
		}

		// assign cluster IP of the service to the dummy interface so that its routable from the pod's on the node
		err := nsc.ln.ipAddrAdd(dummyVipInterface, svc.clusterIP.String(), true)
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

			if !svc.local || (svc.local && endpoint.isLocal) {
				err := nsc.ln.ipvsAddServer(ipvsClusterVipSvc, &dst)
				if err != nil {
					glog.Errorf(err.Error())
				} else {
					activeServiceEndpointMap[clusterServiceId] = append(activeServiceEndpointMap[clusterServiceId], endpoint.ip)
				}
			}

			if svc.nodePort != 0 {
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

	err = nsc.syncIpvsFirewall()
	if err != nil {
		glog.Errorf("Error syncing ipvs svc iptables rules: %s", err.Error())
	}

	glog.V(1).Info("IPVS servers and services are synced to desired state")
	return nil
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
			time.Sleep(100 * time.Millisecond)
			tunIf, err = netlink.LinkByName(KUBE_TUNNEL_IF)
			if err == nil {
				break
			}
			if err != nil && err.Error() == IFACE_NOT_FOUND {
				continue
				glog.V(3).Infof("Waiting for tunnel interface %s to come up in the pod, retrying", KUBE_TUNNEL_IF)
			} else {
				break
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
	err = ln.ipAddrAdd(tunIf, vip, false)
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
				} else if schedulingMethod == IPVS_MAGLEV_HASHING {
					svcInfo.scheduler = IPVS_MAGLEV_HASHING
				}
			}

			flags, ok := svc.ObjectMeta.Annotations[svcSchedFlagsAnnotation]
			if ok && svcInfo.scheduler == IPVS_MAGLEV_HASHING {
				svcInfo.flags = parseSchedFlags(flags)
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

func parseSchedFlags(value string) schedFlags {
	var flag1, flag2, flag3 bool

	if len(value) < 1 {
		return schedFlags{}
	}

	flags := strings.Split(value, ",")
	for _, flag := range flags {
		switch strings.Trim(flag, " ") {
		case IPVS_SVC_F_SCHED1:
			flag1 = true
			break
		case IPVS_SVC_F_SCHED2:
			flag2 = true
			break
		case IPVS_SVC_F_SCHED3:
			flag3 = true
			break
		default:
		}
	}

	return schedFlags{flag1, flag2, flag3}
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
					isLocal := addr.NodeName != nil && *addr.NodeName == nsc.nodeHostName
					endpoints = append(endpoints, endpointsInfo{ip: addr.IP, port: int(port.Port), isLocal: isLocal})
				}
				endpointsMap[svcId] = shuffle(endpoints)
			}
		}
	}
	return endpointsMap
}

// Add an iptables rule to masquerade outbound IPVS traffic. IPVS nat requires that reverse path traffic
// to go through the director for its functioning. So the masquerade rule ensures source IP is modifed
// to node ip, so return traffic from real server (endpoint pods) hits the node/lvs director
func ensureMasqueradeIptablesRule(masqueradeAll bool, podCidr string) error {
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed to initialize iptables executor" + err.Error())
	}
	var args = []string{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ", "-m", "comment", "--comment", "", "-j", "MASQUERADE"}
	if masqueradeAll {
		err = iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", args...)
		if err != nil {
			return errors.New("Failed to create iptables rule to masquerade all outbound IPVS traffic" + err.Error())
		}
	} else {
		exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", args...)
		if err != nil {
			return errors.New("Failed to lookup iptables rule to masquerade all outbound IPVS traffic: " + err.Error())
		}
		if exists {
			err = iptablesCmdHandler.Delete("nat", "POSTROUTING", args...)
			if err != nil {
				return errors.New("Failed to delete iptables rule to masquerade all outbound IPVS traffic: " +
					err.Error() + ". Masquerade might still work...")
			}
			glog.Infof("Deleted iptables rule to masquerade all outbound IVPS traffic.")
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
	glog.V(2).Info("Successfully synced iptables masquerade rule")
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
					glog.V(1).Infof("Deleted invalid/outdated hairpin rule \"%s\" from chain %s", ruleFromNode, hairpinChain)
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
		return errors.New("Failed to search POSTROUTING iptables rules: " + err.Error())
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

func deleteMasqueradeIptablesRule() error {
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed to initialize iptables executor" + err.Error())
	}
	postRoutingChainRules, err := iptablesCmdHandler.List("nat", "POSTROUTING")
	if err != nil {
		return errors.New("Failed to list iptables rules in POSTROUTING chain in nat table" + err.Error())
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

	if s.Flags&0x0008 != 0 {
		flags = flags + "[flag-1(fallback)]"
	}

	if s.Flags&0x0010 != 0 {
		flags = flags + "[flag-2(port)]"
	}

	if s.Flags&0x0020 != 0 {
		flags = flags + "[flag-3]"
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

func ipvsSetSchedFlags(svc *ipvs.Service, s schedFlags) {
	if s.flag1 {
		svc.Flags |= 0x0008
	} else {
		svc.Flags &^= 0x0008
	}

	if s.flag2 {
		svc.Flags |= 0x0010
	} else {
		svc.Flags &^= 0x0010
	}

	if s.flag3 {
		svc.Flags |= 0x0020
	} else {
		svc.Flags &^= 0x0020
	}

	/* Keep netmask which is set by ipvsSetPersistence() before */
	if (svc.Netmask&0xFFFFFFFF != 0) || (s.flag1 || s.flag2 || s.flag3) {
		svc.Netmask |= 0xFFFFFFFF
	} else {
		svc.Netmask &^= 0xFFFFFFFF
	}
}

/* Compare service scheduler flags with ipvs service */
func changedIpvsSchedFlags(svc *ipvs.Service, s schedFlags) bool {
	if (s.flag1 && (svc.Flags&0x0008) == 0) || (!s.flag1 && (svc.Flags&0x0008) != 0) {
		return true
	}

	if (s.flag2 && (svc.Flags&0x0010) == 0) || (!s.flag2 && (svc.Flags&0x0010) != 0) {
		return true
	}

	if (s.flag3 && (svc.Flags&0x0020) == 0) || (!s.flag3 && (svc.Flags&0x0020) != 0) {
		return true
	}

	return false
}

func (ln *linuxNetworking) ipvsAddService(svcs []*ipvs.Service, vip net.IP, protocol, port uint16, persistent bool, scheduler string, flags schedFlags) (*ipvs.Service, error) {

	var err error
	for _, svc := range svcs {
		if vip.Equal(svc.Address) && protocol == svc.Protocol && port == svc.Port {
			if (persistent && (svc.Flags&0x0001) == 0) || (!persistent && (svc.Flags&0x0001) != 0) {
				ipvsSetPersistence(svc, persistent)

				if changedIpvsSchedFlags(svc, flags) {
					ipvsSetSchedFlags(svc, flags)
				}

				err = ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, err
				}
				glog.V(2).Infof("Updated persistence/session-affinity for service: %s", ipvsServiceString(svc))
			}

			if changedIpvsSchedFlags(svc, flags) {
				ipvsSetSchedFlags(svc, flags)

				err = ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, err
				}
				glog.V(2).Infof("Updated scheduler flags for service: %s", ipvsServiceString(svc))
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
	ipvsSetSchedFlags(&svc, flags)

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
func (ln *linuxNetworking) ipvsAddFWMarkService(vip net.IP, protocol, port uint16, persistent bool, scheduler string, flags schedFlags) (*ipvs.Service, error) {

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

				if changedIpvsSchedFlags(svc, flags) {
					ipvsSetSchedFlags(svc, flags)
				}

				err = ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, err
				}
				glog.V(2).Infof("Updated persistence/session-affinity for service: %s", ipvsServiceString(svc))
			}

			if changedIpvsSchedFlags(svc, flags) {
				ipvsSetSchedFlags(svc, flags)

				err = ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, err
				}
				glog.V(2).Infof("Updated scheduler flags for service: %s", ipvsServiceString(svc))
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
	ipvsSetSchedFlags(&svc, flags)

	err = ln.ipvsNewService(&svc)
	if err != nil {
		return nil, err
	}
	glog.Infof("Successfully added service: %s", ipvsServiceString(&svc))
	return &svc, nil
}

func (ln *linuxNetworking) ipvsAddServer(service *ipvs.Service, dest *ipvs.Destination) error {
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

// setupMangleTableRule: setsup iptables rule to FWMARK the traffic to exteranl IP vip
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
	err = iptablesCmdHandler.AppendUnique("mangle", "OUTPUT", args...)
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
	exists, err = iptablesCmdHandler.Exists("mangle", "OUTPUT", args...)
	if err != nil {
		return errors.New("Failed to cleanup iptables command to set up FWMARK due to " + err.Error())
	}
	if exists {
		err = iptablesCmdHandler.Delete("mangle", "OUTPUT", args...)
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

	_, err = exec.Command("ip", "route", "list", "table", externalIPRouteTableId).Output()
	if err != nil {
		return errors.New("Failed to verify required routing table for external IP's exists. " +
			"Failed to setup policy routing required for DSR due to " + err.Error())
	}

	out, err := exec.Command("ip", "rule", "list").Output()
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
			// Verify the DSR annotation exists
			if !svc.directServerReturn {
				glog.V(1).Infof("Skipping service %s/%s as it does not have DSR annotation\n", svc.namespace, svc.name)
				continue
			}

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

	// cleanup iptables masquerade rule
	err = deleteMasqueradeIptablesRule()
	if err != nil {
		glog.Errorf("Failed to cleanup iptablesmasquerade rule due to: %s", err.Error())
		return
	}

	// cleanup iptables hairpin rules
	err = deleteHairpinIptablesRules()
	if err != nil {
		glog.Errorf("Failed to cleanup iptables hairpin rules: %s", err.Error())
		return
	}

	nsc.cleanupIpvsFirewall()

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
	nsc.syncChan = make(chan int, 2)
	nsc.gracefulPeriod = config.IpvsGracefulPeriod
	nsc.gracefulTermination = config.IpvsGracefulTermination
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
