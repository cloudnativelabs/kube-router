package proxy

import (
	"errors"
	"fmt"
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

	"golang.org/x/net/context"

	"github.com/cloudnativelabs/kube-router/pkg/cri"
	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/docker/docker/client"
	"github.com/moby/ipvs"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	api "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog/v2"
)

const (
	KubeDummyIf       = "kube-dummy-if"
	KubeTunnelIf      = "kube-tunnel-if"
	IfaceNotFound     = "Link not found"
	IfaceHasAddr      = "file exists"
	IfaceHasNoAddr    = "cannot assign requested address"
	IpvsServerExists  = "file exists"
	IpvsMaglevHashing = "mh"
	IpvsSvcFSched1    = "flag-1"
	IpvsSvcFSched2    = "flag-2"
	IpvsSvcFSched3    = "flag-3"

	customDSRRouteTableID    = "78"
	customDSRRouteTableName  = "kube-router-dsr"
	externalIPRouteTableID   = "79"
	externalIPRouteTableName = "external_ip"

	// Taken from https://github.com/torvalds/linux/blob/master/include/uapi/linux/ip_vs.h#L21
	ipvsPersistentFlagHex = 0x0001
	ipvsHashedFlagHex     = 0x0002
	ipvsOnePacketFlagHex  = 0x0004
	ipvsSched1FlagHex     = 0x0008
	ipvsSched2FlagHex     = 0x0010
	ipvsSched3FlagHex     = 0x0020

	// Taken from https://www.kernel.org/doc/Documentation/networking/ipvs-sysctl.txt
	ipvsConnReuseModeDisableSpecialHandling = 0
	ipvsExpireQuiescentTemplateEnable       = 1
	ipvsExpireNodestConnEnable              = 1
	ipvsConntrackEnable                     = 1

	// Taken from https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
	arpAnnounceUseBestLocalAddress      = 2
	arpIgnoreReplyOnlyIfTargetIPIsLocal = 1

	svcDSRAnnotation                = "kube-router.io/service.dsr"
	svcSchedulerAnnotation          = "kube-router.io/service.scheduler"
	svcHairpinAnnotation            = "kube-router.io/service.hairpin"
	svcHairpinExternalIPsAnnotation = "kube-router.io/service.hairpin.externalips"
	svcLocalAnnotation              = "kube-router.io/service.local"
	svcSkipLbIpsAnnotation          = "kube-router.io/service.skiplbips"
	svcSchedFlagsAnnotation         = "kube-router.io/service.schedflags"

	localIPsIPSetName     = "kube-router-local-ips"
	ipvsServicesIPSetName = "kube-router-ipvs-services"
	serviceIPsIPSetName   = "kube-router-service-ips"
	ipvsFirewallChainName = "KUBE-ROUTER-SERVICES"
	ipvsHairpinChainName  = "KUBE-ROUTER-HAIRPIN"
	synctypeAll           = iota
	synctypeIpvs

	tcpProtocol         = "tcp"
	udpProtocol         = "udp"
	noneProtocol        = "none"
	tunnelInterfaceType = "tunnel"

	gracefulTermServiceTickTime = 5 * time.Second
)

var (
	NodeIP net.IP
)

type ipvsCalls interface {
	ipvsNewService(ipvsSvc *ipvs.Service) error
	ipvsAddService(svcs []*ipvs.Service, vip net.IP, protocol, port uint16, persistent bool,
		persistentTimeout int32, scheduler string, flags schedFlags) (*ipvs.Service, error)
	ipvsDelService(ipvsSvc *ipvs.Service) error
	ipvsUpdateService(ipvsSvc *ipvs.Service) error
	ipvsGetServices() ([]*ipvs.Service, error)
	ipvsAddServer(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error
	ipvsNewDestination(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error
	ipvsUpdateDestination(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error
	ipvsGetDestinations(ipvsSvc *ipvs.Service) ([]*ipvs.Destination, error)
	ipvsDelDestination(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error
	ipvsAddFWMarkService(svcs []*ipvs.Service, fwMark uint32, protocol, port uint16, persistent bool,
		persistentTimeout int32, scheduler string, flags schedFlags) (*ipvs.Service, error)
}

type netlinkCalls interface {
	ipAddrAdd(iface netlink.Link, ip string, addRoute bool) error
	ipAddrDel(iface netlink.Link, ip string) error
	prepareEndpointForDsrWithDocker(containerID string, endpointIP string, vip string) error
	getKubeDummyInterface() (netlink.Link, error)
	setupRoutesForExternalIPForDSR(serviceInfoMap) error
	prepareEndpointForDsrWithCRI(runtimeEndpoint, containerID, endpointIP, vip string) error
	configureContainerForDSR(vip, endpointIP, containerID string, pid int,
		hostNetworkNamespaceHandle netns.NsHandle) error
	setupPolicyRoutingForDSR() error
	cleanupMangleTableRule(ip string, protocol string, port string, fwmark string, tcpMSS int) error
}

// LinuxNetworking interface contains all linux networking subsystem calls
//
//go:generate moq -out network_services_controller_moq.go . LinuxNetworking
type LinuxNetworking interface {
	ipvsCalls
	netlinkCalls
}

type linuxNetworking struct {
	ipvsHandle *ipvs.Handle
}

func (ln *linuxNetworking) ipAddrDel(iface netlink.Link, ip string) error {
	naddr := &netlink.Addr{IPNet: &net.IPNet{
		IP: net.ParseIP(ip), Mask: net.IPv4Mask(255, 255, 255, 255),
	}, Scope: syscall.RT_SCOPE_LINK}
	err := netlink.AddrDel(iface, naddr)
	if err != nil && err.Error() != IfaceHasNoAddr {
		klog.Errorf("Failed to verify is external ip %s is assocated with dummy interface %s due to %s",
			naddr.IPNet.IP.String(), KubeDummyIf, err.Error())
	}
	// Delete VIP addition to "local" rt table also, fail silently if not found (DSR special case)
	if err == nil {
		// #nosec G204
		out, err := exec.Command("ip", "route", "delete", "local", ip, "dev", KubeDummyIf,
			"table", "local", "proto", "kernel", "scope", "host", "src",
			NodeIP.String(), "table", "local").CombinedOutput()
		if err != nil && !strings.Contains(string(out), "No such process") {
			klog.Errorf("Failed to delete route to service VIP %s configured on %s. Error: %v, Output: %s",
				ip, KubeDummyIf, err, out)
		}
	}
	return err
}

// utility method to assign an IP to an interface. Mainly used to assign service VIP's
// to kube-dummy-if. Also when DSR is used, used to assign VIP to dummy interface
// inside the container.
func (ln *linuxNetworking) ipAddrAdd(iface netlink.Link, ip string, addRoute bool) error {
	naddr := &netlink.Addr{IPNet: &net.IPNet{
		IP: net.ParseIP(ip), Mask: net.IPv4Mask(255, 255, 255, 255),
	}, Scope: syscall.RT_SCOPE_LINK}
	err := netlink.AddrAdd(iface, naddr)
	if err != nil && err.Error() != IfaceHasAddr {
		klog.Errorf("Failed to assign cluster ip %s to dummy interface: %s",
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
	// #nosec G204
	out, err := exec.Command("ip", "route", "replace", "local", ip, "dev", KubeDummyIf,
		"table", "local", "proto", "kernel", "scope", "host", "src",
		NodeIP.String(), "table", "local").CombinedOutput()
	if err != nil {
		klog.Errorf("Failed to replace route to service VIP %s configured on %s. Error: %v, Output: %s",
			ip, KubeDummyIf, err, out)
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
	excludedCidrs       []net.IPNet
	masqueradeAll       bool
	globalHairpin       bool
	ipvsPermitAll       bool
	client              kubernetes.Interface
	nodeportBindOnAllIP bool
	MetricsEnabled      bool
	metricsMap          map[string][]string
	ln                  LinuxNetworking
	readyForUpdates     bool
	ProxyFirewallSetup  *sync.Cond
	ipsetMutex          *sync.Mutex
	fwMarkMap           map[uint32]string

	// Map of ipsets that we use.
	ipsetMap map[string]*utils.Set

	svcLister cache.Indexer
	epLister  cache.Indexer
	podLister cache.Indexer

	EndpointsEventHandler cache.ResourceEventHandler
	ServiceEventHandler   cache.ResourceEventHandler

	gracefulPeriod      time.Duration
	gracefulQueue       gracefulQueue
	gracefulTermination bool
	syncChan            chan int
	dsr                 *dsrOpt
	dsrTCPMSS           int
}

// DSR related options
type dsrOpt struct {
	runtimeEndpoint string
}

// internal representation of kubernetes service
type serviceInfo struct {
	name                          string
	namespace                     string
	clusterIP                     net.IP
	port                          int
	targetPort                    string
	protocol                      string
	nodePort                      int
	sessionAffinity               bool
	sessionAffinityTimeoutSeconds int32
	directServerReturn            bool
	scheduler                     string
	directServerReturnMethod      string
	hairpin                       bool
	hairpinExternalIPs            bool
	skipLbIps                     bool
	externalIPs                   []string
	loadBalancerIPs               []string
	local                         bool
	flags                         schedFlags
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
func (nsc *NetworkServicesController) Run(healthChan chan<- *healthcheck.ControllerHeartbeat,
	stopCh <-chan struct{}, wg *sync.WaitGroup) {
	t := time.NewTicker(nsc.syncPeriod)
	defer t.Stop()
	defer wg.Done()
	defer close(nsc.syncChan)

	klog.Infof("Starting network services controller")

	klog.V(1).Info("Performing cleanup of depreciated masquerade iptables rules (if needed).")
	err := nsc.deleteBadMasqueradeIptablesRules()
	if err != nil {
		klog.Errorf("Error cleaning up old/bad masquerade rules: %s", err.Error())
	}

	// enable masquerade rule
	err = nsc.ensureMasqueradeIptablesRule()
	if err != nil {
		klog.Errorf("Failed to do add masquerade rule in POSTROUTING chain of nat table due to: %s", err.Error())
	}
	// https://www.kernel.org/doc/Documentation/networking/ipvs-sysctl.txt
	// enable ipvs connection tracking
	sysctlErr := utils.SetSysctl(utils.IPv4IPVSConntrack, ipvsConntrackEnable)
	if sysctlErr != nil {
		klog.Error(sysctlErr.Error())
	}

	// LVS failover not working with UDP packets https://access.redhat.com/solutions/58653
	sysctlErr = utils.SetSysctl(utils.IPv4IPVSExpireNodestConn, ipvsExpireNodestConnEnable)
	if sysctlErr != nil {
		klog.Error(sysctlErr.Error())
	}

	// LVS failover not working with UDP packets https://access.redhat.com/solutions/58653
	sysctlErr = utils.SetSysctl(utils.IPv4IPVSExpireQuiescent, ipvsExpireQuiescentTemplateEnable)
	if sysctlErr != nil {
		klog.Error(sysctlErr.Error())
	}

	// https://github.com/kubernetes/kubernetes/pull/71114
	sysctlErr = utils.SetSysctl(utils.IPv4IPVSConnReuseMode, ipvsConnReuseModeDisableSpecialHandling)
	if sysctlErr != nil {
		// Check if the error is fatal, on older kernels this option does not exist and the same behaviour is default
		// if option is not found just log it
		if sysctlErr.IsFatal() {
			klog.Fatal(sysctlErr.Error())
		} else {
			klog.Info(sysctlErr.Error())
		}
	}

	// https://github.com/kubernetes/kubernetes/pull/70530/files
	sysctlErr = utils.SetSysctl(utils.IPv4ConfAllArpIgnore, arpIgnoreReplyOnlyIfTargetIPIsLocal)
	if sysctlErr != nil {
		klog.Error(sysctlErr.Error())
	}

	// https://github.com/kubernetes/kubernetes/pull/70530/files
	sysctlErr = utils.SetSysctl(utils.IPv4ConfAllArpAnnounce, arpAnnounceUseBestLocalAddress)
	if sysctlErr != nil {
		klog.Error(sysctlErr.Error())
	}

	// https://github.com/cloudnativelabs/kube-router/issues/282
	err = nsc.setupIpvsFirewall()
	if err != nil {
		klog.Error("Error setting up ipvs firewall: " + err.Error())
	}
	nsc.ProxyFirewallSetup.Broadcast()

	gracefulTicker := time.NewTicker(gracefulTermServiceTickTime)
	defer gracefulTicker.Stop()

	select {
	case <-stopCh:
		klog.Info("Shutting down network services controller")
		return
	default:
		err := nsc.doSync()
		if err != nil {
			klog.Fatalf("Failed to perform initial full sync %s", err.Error())
		}
		nsc.readyForUpdates = true
	}

	// loop forever until notified to stop on stopCh
	for {
		select {
		case <-stopCh:
			nsc.mu.Lock()
			nsc.readyForUpdates = false
			nsc.mu.Unlock()
			klog.Info("Shutting down network services controller")
			return

		case <-gracefulTicker.C:
			if nsc.readyForUpdates && nsc.gracefulTermination {
				klog.V(3).Info("Performing periodic graceful destination cleanup")
				nsc.gracefulSync()
			}

		case perform := <-nsc.syncChan:
			healthcheck.SendHeartBeat(healthChan, "NSC")
			switch perform {
			case synctypeAll:
				klog.V(1).Info("Performing requested full sync of services")
				err = nsc.doSync()
				if err != nil {
					klog.Errorf("Error during full sync in network service controller. Error: " + err.Error())
				}
			case synctypeIpvs:
				// We call the component pieces of doSync() here because for methods that send this on the channel they
				// have already done expensive pieces of the doSync() method like building service and endpoint info
				// and we don't want to duplicate the effort, so this is a slimmer version of doSync()
				klog.V(1).Info("Performing requested sync of ipvs services")
				nsc.mu.Lock()
				err = nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
				if err != nil {
					klog.Errorf("Error during ipvs sync in network service controller. Error: " + err.Error())
				}
				err = nsc.syncHairpinIptablesRules()
				if err != nil {
					klog.Errorf("Error syncing hairpin iptables rules: %s", err.Error())
				}
				nsc.mu.Unlock()
			}
			if err == nil {
				healthcheck.SendHeartBeat(healthChan, "NSC")
			}

		case <-t.C:
			klog.V(1).Info("Performing periodic sync of ipvs services")
			healthcheck.SendHeartBeat(healthChan, "NSC")
			err := nsc.doSync()
			if err != nil {
				klog.Errorf("Error during periodic ipvs sync in network service controller. Error: " + err.Error())
				klog.Errorf("Skipping sending heartbeat from network service controller as periodic sync failed.")
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
		klog.V(2).Infof("Already pending sync, dropping request for type %d", syncType)
	}
}

func (nsc *NetworkServicesController) doSync() error {
	var err error
	nsc.mu.Lock()
	defer nsc.mu.Unlock()

	// enable masquerade rule
	err = nsc.ensureMasqueradeIptablesRule()
	if err != nil {
		klog.Errorf("Failed to do add masquerade rule in POSTROUTING chain of nat table due to: %s", err.Error())
	}

	nsc.serviceMap = nsc.buildServicesInfo()
	nsc.endpointsMap = nsc.buildEndpointsInfo()
	err = nsc.syncHairpinIptablesRules()
	if err != nil {
		klog.Errorf("Error syncing hairpin iptables rules: %s", err.Error())
	}

	err = nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
	if err != nil {
		klog.Errorf("Error syncing IPVS services: %s", err.Error())
		return err
	}

	if nsc.MetricsEnabled {
		err = nsc.publishMetrics(nsc.serviceMap)
		if err != nil {
			klog.Errorf("Error publishing metrics: %v", err)
			return err
		}
	}
	return nil
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
		return errors.New("failed to initialize iptables executor" + err.Error())
	}

	// ClearChain either clears an existing chain or creates a new one.
	err = iptablesCmdHandler.ClearChain("filter", ipvsFirewallChainName)
	if err != nil {
		return fmt.Errorf("failed to run iptables command: %s", err.Error())
	}

	// config.IpvsPermitAll: true then create INPUT/KUBE-ROUTER-SERVICE Chain creation else return
	if !nsc.ipvsPermitAll {
		return nil
	}

	var comment string
	var args []string
	var exists bool

	comment = "allow input traffic to ipvs services"
	args = []string{"-m", "comment", "--comment", comment,
		"-m", "set", "--match-set", ipvsServicesIPSetName, "dst,dst",
		"-j", "ACCEPT"}
	exists, err = iptablesCmdHandler.Exists("filter", ipvsFirewallChainName, args...)
	if err != nil {
		return fmt.Errorf("failed to run iptables command: %s", err.Error())
	}
	if !exists {
		err := iptablesCmdHandler.Insert("filter", ipvsFirewallChainName, 1, args...)
		if err != nil {
			return fmt.Errorf("failed to run iptables command: %s", err.Error())
		}
	}

	comment = "allow icmp echo requests to service IPs"
	args = []string{"-m", "comment", "--comment", comment,
		"-p", "icmp", "--icmp-type", "echo-request",
		"-j", "ACCEPT"}
	err = iptablesCmdHandler.AppendUnique("filter", ipvsFirewallChainName, args...)
	if err != nil {
		return fmt.Errorf("failed to run iptables command: %s", err.Error())
	}

	comment = "allow icmp destination unreachable messages to service IPs"
	args = []string{"-m", "comment", "--comment", comment,
		"-p", "icmp", "--icmp-type", "destination-unreachable",
		"-j", "ACCEPT"}
	err = iptablesCmdHandler.AppendUnique("filter", ipvsFirewallChainName, args...)
	if err != nil {
		return fmt.Errorf("failed to run iptables command: %s", err.Error())
	}

	comment = "allow icmp ttl exceeded messages to service IPs"
	args = []string{"-m", "comment", "--comment", comment,
		"-p", "icmp", "--icmp-type", "time-exceeded",
		"-j", "ACCEPT"}
	err = iptablesCmdHandler.AppendUnique("filter", ipvsFirewallChainName, args...)
	if err != nil {
		return fmt.Errorf("failed to run iptables command: %s", err.Error())
	}

	// We exclude the local addresses here as that would otherwise block all
	// traffic to local addresses if any NodePort service exists.
	comment = "reject all unexpected traffic to service IPs"
	args = []string{"-m", "comment", "--comment", comment,
		"-m", "set", "!", "--match-set", localIPsIPSetName, "dst",
		"-j", "REJECT", "--reject-with", "icmp-port-unreachable"}
	err = iptablesCmdHandler.AppendUnique("filter", ipvsFirewallChainName, args...)
	if err != nil {
		return fmt.Errorf("failed to run iptables command: %s", err.Error())
	}

	// Pass incoming traffic into our custom chain.
	ipvsFirewallInputChainRule := getIpvsFirewallInputChainRule()
	exists, err = iptablesCmdHandler.Exists("filter", "INPUT", ipvsFirewallInputChainRule...)
	if err != nil {
		return fmt.Errorf("failed to run iptables command: %s", err.Error())
	}
	if !exists {
		err = iptablesCmdHandler.Insert("filter", "INPUT", 1, ipvsFirewallInputChainRule...)
		if err != nil {
			return fmt.Errorf("failed to run iptables command: %s", err.Error())
		}
	}

	return nil
}

func (nsc *NetworkServicesController) cleanupIpvsFirewall() {
	// Clear iptables rules
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		klog.Errorf("failed to initialize iptables executor: %v", err)
	} else {
		ipvsFirewallInputChainRule := getIpvsFirewallInputChainRule()
		exists, err := iptablesCmdHandler.Exists("filter", "INPUT", ipvsFirewallInputChainRule...)
		if err != nil {
			// Changed to level 1 as errors occur when ipsets have already been cleaned and needlessly worries users
			klog.V(1).Infof("failed to check if iptables rules exists: %v", err)
		} else if exists {
			err = iptablesCmdHandler.Delete("filter", "INPUT", ipvsFirewallInputChainRule...)
			if err != nil {
				klog.Errorf("failed to run iptables command: %v", err)
			}
		}

		exists, err = iptablesCmdHandler.ChainExists("filter", ipvsFirewallChainName)
		if err != nil {
			klog.Errorf("failed to check if chain exists for deletion: %v", err)
		} else if exists {
			err = iptablesCmdHandler.ClearChain("filter", ipvsFirewallChainName)
			if err != nil {
				klog.Errorf("Failed to run iptables command: %s", err.Error())
			}

			err = iptablesCmdHandler.DeleteChain("filter", ipvsFirewallChainName)
			if err != nil {
				klog.Errorf("Failed to run iptables command: %s", err.Error())
			}
		}
	}

	// For some reason, if we go too fast into the ipset logic below it causes the system to think that the above
	// iptables rules are still referencing the ipsets below, and we get errors
	time.Sleep(1 * time.Second)

	// Clear ipsets
	// There are certain actions like Cleanup() actions that aren't working with full instantiations of the controller
	// and in these instances the mutex may not be present and may not need to be present as they are operating out of a
	// single goroutine where there is no need for locking
	if nil != nsc.ipsetMutex {
		klog.V(1).Infof("Attempting to attain ipset mutex lock")
		nsc.ipsetMutex.Lock()
		klog.V(1).Infof("Attained ipset mutex lock, continuing...")
		defer func() {
			nsc.ipsetMutex.Unlock()
			klog.V(1).Infof("Returned ipset mutex lock")
		}()
	}
	ipSetHandler, err := utils.NewIPSet(false)
	if err != nil {
		klog.Errorf("Failed to initialize ipset handler: %s", err.Error())
		return
	}
	err = ipSetHandler.Save()
	if err != nil {
		klog.Fatalf("failed to initialize ipsets command executor due to %v", err)
		return
	}

	if _, ok := ipSetHandler.Sets()[localIPsIPSetName]; ok {
		err = ipSetHandler.Destroy(localIPsIPSetName)
		if err != nil {
			klog.Errorf("failed to destroy ipset: %s", err.Error())
		}
	}

	if _, ok := ipSetHandler.Sets()[serviceIPsIPSetName]; ok {
		err = ipSetHandler.Destroy(serviceIPsIPSetName)
		if err != nil {
			klog.Errorf("failed to destroy ipset: %s", err.Error())
		}
	}

	if _, ok := ipSetHandler.Sets()[ipvsServicesIPSetName]; ok {
		err = ipSetHandler.Destroy(ipvsServicesIPSetName)
		if err != nil {
			klog.Errorf("failed to destroy ipset: %s", err.Error())
		}
	}
}

func (nsc *NetworkServicesController) syncIpvsFirewall() error {
	/*
	   - update ipsets based on currently active IPVS services
	*/
	var err error
	klog.V(1).Infof("Attempting to attain ipset mutex lock")
	nsc.ipsetMutex.Lock()
	klog.V(1).Infof("Attained ipset mutex lock, continuing...")
	defer func() {
		nsc.ipsetMutex.Unlock()
		klog.V(1).Infof("Returned ipset mutex lock")
	}()

	localIPsIPSet := nsc.ipsetMap[localIPsIPSetName]

	// Populate local addresses ipset.
	addrs, err := getAllLocalIPs()
	if err != nil {
		return fmt.Errorf("failed to get local IPs: %s", err)
	}
	localIPsSets := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		localIPsSets = append(localIPsSets, addr.IP.String())
	}
	err = localIPsIPSet.Refresh(localIPsSets)
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
			protocol = convertSysCallProtoToSvcProto(ipvsService.Protocol)
			if protocol == noneProtocol {
				klog.Warningf("failed to convert protocol %d to a valid IPVS protocol for service: %s skipping",
					ipvsService.Protocol, ipvsService.Address.String())
				continue
			}
			port = int(ipvsService.Port)
		} else if ipvsService.FWMark != 0 {
			address, protocol, port, err = nsc.lookupServiceByFWMark(ipvsService.FWMark)
			if err != nil {
				klog.Warningf("failed to lookup %d by FWMark: %s - this may not be a kube-router controlled service, "+
					"but if it is, then something's gone wrong", ipvsService.FWMark, err)
				continue
			}
		}

		serviceIPsSet := address
		serviceIPsSets = append(serviceIPsSets, serviceIPsSet)

		ipvsServicesSet := fmt.Sprintf("%s,%s:%d", address, protocol, port)
		ipvsServicesSets = append(ipvsServicesSets, ipvsServicesSet)

	}

	serviceIPsIPSet := nsc.ipsetMap[serviceIPsIPSetName]
	err = serviceIPsIPSet.Refresh(serviceIPsSets)
	if err != nil {
		return fmt.Errorf("failed to sync ipset: %s", err.Error())
	}

	ipvsServicesIPSet := nsc.ipsetMap[ipvsServicesIPSetName]
	err = ipvsServicesIPSet.Refresh(ipvsServicesSets)
	if err != nil {
		return fmt.Errorf("failed to sync ipset: %s", err.Error())
	}

	return nil
}

func (nsc *NetworkServicesController) publishMetrics(serviceInfoMap serviceInfoMap) error {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		klog.V(2).Infof("Publishing IPVS metrics took %v", endTime)
		if nsc.MetricsEnabled {
			metrics.ControllerIpvsMetricsExportTime.Observe(endTime.Seconds())
		}
	}()

	ipvsSvcs, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return errors.New("Failed to list IPVS services: " + err.Error())
	}

	klog.V(1).Info("Publishing IPVS metrics")
	for _, svc := range serviceInfoMap {
		var protocol uint16
		var pushMetric bool
		var svcVip string

		protocol = convertSvcProtoToSysCallProto(svc.protocol)
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

				klog.V(3).Infof("Publishing metrics for %s/%s (%s:%d/%s)",
					svc.namespace, svc.name, svcVip, svc.port, svc.protocol)

				labelValues := []string{
					svc.namespace,
					svc.name,
					svcVip,
					svc.protocol,
					strconv.Itoa(svc.port),
				}

				key := generateIPPortID(svcVip, svc.protocol, strconv.Itoa(svc.port))
				nsc.metricsMap[key] = labelValues
				// these same metrics should be deleted when the service is deleted.
				metrics.ServiceBpsIn.WithLabelValues(labelValues...).Set(float64(ipvsSvc.Stats.BPSIn))
				metrics.ServiceBpsOut.WithLabelValues(labelValues...).Set(float64(ipvsSvc.Stats.BPSOut))
				metrics.ServiceBytesIn.WithLabelValues(labelValues...).Set(float64(ipvsSvc.Stats.BytesIn))
				metrics.ServiceBytesOut.WithLabelValues(labelValues...).Set(float64(ipvsSvc.Stats.BytesOut))
				metrics.ServiceCPS.WithLabelValues(labelValues...).Set(float64(ipvsSvc.Stats.CPS))
				metrics.ServicePacketsIn.WithLabelValues(labelValues...).Set(float64(ipvsSvc.Stats.PacketsIn))
				metrics.ServicePacketsOut.WithLabelValues(labelValues...).Set(float64(ipvsSvc.Stats.PacketsOut))
				metrics.ServicePpsIn.WithLabelValues(labelValues...).Set(float64(ipvsSvc.Stats.PPSIn))
				metrics.ServicePpsOut.WithLabelValues(labelValues...).Set(float64(ipvsSvc.Stats.PPSOut))
				metrics.ServiceTotalConn.WithLabelValues(labelValues...).Set(float64(ipvsSvc.Stats.Connections))
				metrics.ControllerIpvsServices.Set(float64(len(ipvsSvcs)))
			}
		}
	}
	return nil
}

// OnEndpointsUpdate handle change in endpoints update from the API server
func (nsc *NetworkServicesController) OnEndpointsUpdate(ep *api.Endpoints) {

	if isEndpointsForLeaderElection(ep) {
		return
	}

	nsc.mu.Lock()
	defer nsc.mu.Unlock()
	klog.V(1).Infof("Received update to endpoint: %s/%s from watch API", ep.Namespace, ep.Name)
	if !nsc.readyForUpdates {
		klog.V(3).Infof(
			"Skipping update to endpoint: %s/%s as controller is not ready to process service and endpoints updates",
			ep.Namespace, ep.Name)
		return
	}

	// If the service is headless and the previous version of the service is either non-existent or also headless,
	// skip processing as we only work with VIPs in the next section. Since the ClusterIP field is immutable we don't
	// need to consider previous versions of the service here as we are guaranteed if is a ClusterIP now, it was a
	// ClusterIP before.
	svc, exists, err := utils.ServiceForEndpoints(&nsc.svcLister, ep)
	if err != nil {
		klog.Errorf("failed to convert endpoints resource to service: %s", err)
		return
	}
	// ignore updates to Endpoints object with no corresponding Service object
	if !exists {
		return
	}
	if utils.ServiceIsHeadless(svc) {
		klog.V(1).Infof("The service associated with endpoint: %s/%s is headless, skipping...",
			ep.Namespace, ep.Name)
		return
	}

	// build new service and endpoints map to reflect the change
	newServiceMap := nsc.buildServicesInfo()
	newEndpointsMap := nsc.buildEndpointsInfo()

	if !endpointsMapsEquivalent(newEndpointsMap, nsc.endpointsMap) {
		nsc.endpointsMap = newEndpointsMap
		nsc.serviceMap = newServiceMap
		klog.V(1).Infof("Syncing IPVS services sync for update to endpoint: %s/%s", ep.Namespace, ep.Name)
		nsc.sync(synctypeIpvs)
	} else {
		klog.V(1).Infof("Skipping IPVS services sync on endpoint: %s/%s update as nothing changed",
			ep.Namespace, ep.Name)
	}
}

// OnServiceUpdate handle change in service update from the API server
func (nsc *NetworkServicesController) OnServiceUpdate(svc *api.Service) {

	nsc.mu.Lock()
	defer nsc.mu.Unlock()

	klog.V(1).Infof("Received update to service: %s/%s from watch API", svc.Namespace, svc.Name)
	if !nsc.readyForUpdates {
		klog.V(3).Infof(
			"Skipping update to service: %s/%s as controller is not ready to process service and endpoints updates",
			svc.Namespace, svc.Name)
		return
	}

	// If the service is headless and the previous version of the service is either non-existent or also headless,
	// skip processing as we only work with VIPs in the next section. Since the ClusterIP field is immutable we don't
	// need to consider previous versions of the service here as we are guaranteed if is a ClusterIP now, it was a
	// ClusterIP before.
	if utils.ServiceIsHeadless(svc) {
		klog.V(1).Infof("%s/%s is headless, skipping...", svc.Namespace, svc.Name)
		return
	}

	// build new service and endpoints map to reflect the change
	newServiceMap := nsc.buildServicesInfo()
	newEndpointsMap := nsc.buildEndpointsInfo()

	if len(newServiceMap) != len(nsc.serviceMap) || !reflect.DeepEqual(newServiceMap, nsc.serviceMap) {
		nsc.endpointsMap = newEndpointsMap
		nsc.serviceMap = newServiceMap
		klog.V(1).Infof("Syncing IPVS services sync on update to service: %s/%s", svc.Namespace, svc.Name)
		nsc.sync(synctypeIpvs)
	} else {
		klog.V(1).Infof("Skipping syncing IPVS services for update to service: %s/%s as nothing changed",
			svc.Namespace, svc.Name)
	}
}

func hasActiveEndpoints(endpoints []endpointsInfo) bool {
	for _, endpoint := range endpoints {
		if endpoint.isLocal {
			return true
		}
	}
	return false
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

func (nsc *NetworkServicesController) buildServicesInfo() serviceInfoMap {
	serviceMap := make(serviceInfoMap)
	for _, obj := range nsc.svcLister.List() {
		svc := obj.(*api.Service)

		if utils.ClusterIPIsNoneOrBlank(svc.Spec.ClusterIP) {
			klog.V(2).Infof("Skipping service name:%s namespace:%s as there is no cluster IP",
				svc.Name, svc.Namespace)
			continue
		}

		if svc.Spec.Type == "ExternalName" {
			klog.V(2).Infof("Skipping service name:%s namespace:%s due to service Type=%s",
				svc.Name, svc.Namespace, svc.Spec.Type)
			continue
		}

		for _, port := range svc.Spec.Ports {
			svcInfo := serviceInfo{
				clusterIP:   net.ParseIP(svc.Spec.ClusterIP),
				port:        int(port.Port),
				targetPort:  port.TargetPort.String(),
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
				switch {
				case schedulingMethod == ipvs.RoundRobin:
					svcInfo.scheduler = ipvs.RoundRobin
				case schedulingMethod == ipvs.LeastConnection:
					svcInfo.scheduler = ipvs.LeastConnection
				case schedulingMethod == ipvs.DestinationHashing:
					svcInfo.scheduler = ipvs.DestinationHashing
				case schedulingMethod == ipvs.SourceHashing:
					svcInfo.scheduler = ipvs.SourceHashing
				case schedulingMethod == IpvsMaglevHashing:
					svcInfo.scheduler = IpvsMaglevHashing
				}
			}

			flags, ok := svc.ObjectMeta.Annotations[svcSchedFlagsAnnotation]
			if ok && svcInfo.scheduler == IpvsMaglevHashing {
				svcInfo.flags = parseSchedFlags(flags)
			}

			copy(svcInfo.externalIPs, svc.Spec.ExternalIPs)
			for _, lbIngress := range svc.Status.LoadBalancer.Ingress {
				if len(lbIngress.IP) > 0 {
					svcInfo.loadBalancerIPs = append(svcInfo.loadBalancerIPs, lbIngress.IP)
				}
			}
			svcInfo.sessionAffinity = svc.Spec.SessionAffinity == api.ServiceAffinityClientIP

			if svcInfo.sessionAffinity {
				// Kube-apiserver side guarantees SessionAffinityConfig won't be nil when session affinity
				// type is ClientIP
				// https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/core/v1/defaults.go#L106
				svcInfo.sessionAffinityTimeoutSeconds = *svc.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds
			}
			_, svcInfo.hairpin = svc.ObjectMeta.Annotations[svcHairpinAnnotation]
			_, svcInfo.hairpinExternalIPs = svc.ObjectMeta.Annotations[svcHairpinExternalIPsAnnotation]
			_, svcInfo.local = svc.ObjectMeta.Annotations[svcLocalAnnotation]
			_, svcInfo.skipLbIps = svc.ObjectMeta.Annotations[svcSkipLbIpsAnnotation]
			if svc.Spec.ExternalTrafficPolicy == api.ServiceExternalTrafficPolicyTypeLocal {
				svcInfo.local = true
			}

			svcID := generateServiceID(svc.Namespace, svc.Name, port.Name)
			serviceMap[svcID] = &svcInfo
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
		case IpvsSvcFSched1:
			flag1 = true
		case IpvsSvcFSched2:
			flag2 = true
		case IpvsSvcFSched3:
			flag3 = true
		default:
		}
	}

	return schedFlags{flag1, flag2, flag3}
}

func shuffle(endPoints []endpointsInfo) []endpointsInfo {
	for index1 := range endPoints {
		//nolint:gosec // we don't need cryptographic randomness here
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
				svcID := generateServiceID(ep.Namespace, ep.Name, port.Name)
				endpoints := make([]endpointsInfo, 0)
				for _, addr := range epSubset.Addresses {
					isLocal := addr.NodeName != nil && *addr.NodeName == nsc.nodeHostName
					endpoints = append(endpoints, endpointsInfo{ip: addr.IP, port: int(port.Port), isLocal: isLocal})
				}
				endpointsMap[svcID] = shuffle(endpoints)
			}
		}
	}
	return endpointsMap
}

// Add an iptables rule to masquerade outbound IPVS traffic. IPVS nat requires that reverse path traffic
// to go through the director for its functioning. So the masquerade rule ensures source IP is modified
// to node ip, so return traffic from real server (endpoint pods) hits the node/lvs director
func (nsc *NetworkServicesController) ensureMasqueradeIptablesRule() error {
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed to initialize iptables executor" + err.Error())
	}
	var args = []string{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ",
		"-m", "comment", "--comment", "", "-j", "SNAT", "--to-source", nsc.nodeIP.String()}
	if iptablesCmdHandler.HasRandomFully() {
		args = append(args, "--random-fully")
	}
	if nsc.masqueradeAll {
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
			klog.Infof("Deleted iptables rule to masquerade all outbound IVPS traffic.")
		}
	}
	if len(nsc.podCidr) > 0 {
		// TODO: ipset should be used for destination podCidr(s) match after multiple podCidr(s) per node get supported
		args = []string{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ",
			"-m", "comment", "--comment", "", "!", "-s", nsc.podCidr, "!", "-d", nsc.podCidr,
			"-j", "SNAT", "--to-source", nsc.nodeIP.String()}
		if iptablesCmdHandler.HasRandomFully() {
			args = append(args, "--random-fully")
		}

		err = iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", args...)
		if err != nil {
			return errors.New("Failed to run iptables command" + err.Error())
		}
	}
	klog.V(2).Info("Successfully synced iptables masquerade rule")
	return nil
}

// Delete old/bad iptables rules to masquerade outbound IPVS traffic.
func (nsc *NetworkServicesController) deleteBadMasqueradeIptablesRules() error {
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed create iptables handler:" + err.Error())
	}

	var argsBad = [][]string{
		{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ", "-m", "comment", "--comment", "",
			"-j", "MASQUERADE"},
		{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ", "-m", "comment", "--comment", "",
			"!", "-s", nsc.podCidr, "!", "-d", nsc.podCidr, "-j", "MASQUERADE"},
	}

	// If random fully is supported remove the original rules as well
	if iptablesCmdHandler.HasRandomFully() {
		argsBad = append(argsBad, []string{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ",
			"-m", "comment", "--comment", "", "-j", "SNAT", "--to-source", nsc.nodeIP.String()})

		if len(nsc.podCidr) > 0 {
			argsBad = append(argsBad, []string{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ",
				"-m", "comment", "--comment", "",
				"!", "-s", nsc.podCidr, "!", "-d", nsc.podCidr, "-j", "SNAT", "--to-source", nsc.nodeIP.String()})
		}
	}

	for _, args := range argsBad {
		exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", args...)
		if err != nil {
			return fmt.Errorf("failed to lookup iptables rule: %s", err.Error())
		}

		if exists {
			err = iptablesCmdHandler.Delete("nat", "POSTROUTING", args...)
			if err != nil {
				return fmt.Errorf("failed to delete old/bad iptables rule to masquerade outbound IVPS "+
					"traffic: %s. Masquerade all might still work, or bugs may persist after upgrade",
					err)
			}
			klog.Infof("Deleted old/bad iptables rule to masquerade outbound traffic.")
		}
	}

	return nil
}

// syncHairpinIptablesRules adds/removes iptables rules pertaining to traffic
// from an Endpoint (Pod) to its own service VIP. Rules are only applied if
// enabled globally via CLI argument or a service has an annotation requesting
// it.
func (nsc *NetworkServicesController) syncHairpinIptablesRules() error {
	// TODO: Use ipset?
	// TODO: Log a warning that this will not work without hairpin sysctl set on veth

	// Key is a string that will match iptables.List() rules
	// Value is a string[] with arguments that iptables transaction functions expect
	rulesNeeded := make(map[string][]string)

	// Generate the rules that we need
	for svcName, svcInfo := range nsc.serviceMap {
		if nsc.globalHairpin || svcInfo.hairpin {
			// If this service doesn't have any active & local endpoints on this node, then skip it as only local
			// endpoints matter for hairpinning
			if !hasActiveEndpoints(nsc.endpointsMap[svcName]) {
				continue
			}

			for _, ep := range nsc.endpointsMap[svcName] {
				// If this specific endpoint is not local, then skip it as only local endpoints matter for hairpinning
				if !ep.isLocal {
					continue
				}

				// Handle ClusterIP Service
				rule, ruleArgs := hairpinRuleFrom(svcInfo.clusterIP.String(), ep.ip, svcInfo.port)
				rulesNeeded[rule] = ruleArgs

				// Handle ExternalIPs if requested
				if svcInfo.hairpinExternalIPs {
					for _, extIP := range svcInfo.externalIPs {
						rule, ruleArgs := hairpinRuleFrom(extIP, ep.ip, svcInfo.port)
						rulesNeeded[rule] = ruleArgs
					}
				}

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
		klog.V(1).Info("No hairpin-mode enabled services found -- no hairpin rules created")
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

	// TODO: Factor out this code
	hasHairpinChain := false
	chains, err := iptablesCmdHandler.ListChains("nat")
	if err != nil {
		return errors.New("Failed to list iptables chains: " + err.Error())
	}
	for _, chain := range chains {
		if chain == ipvsHairpinChainName {
			hasHairpinChain = true
		}
	}
	// Create a chain for hairpin rules, if needed
	if !hasHairpinChain {
		err = iptablesCmdHandler.NewChain("nat", ipvsHairpinChainName)
		if err != nil {
			return fmt.Errorf("failed to create iptables chain \"%s\": %v", ipvsHairpinChainName, err)
		}
	}

	// Create a rule that targets our hairpin chain, if needed
	// TODO: Factor this static rule out
	jumpArgs := []string{"-m", "ipvs", "--vdir", "ORIGINAL", "-j", ipvsHairpinChainName}
	err = iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", jumpArgs...)
	if err != nil {
		return fmt.Errorf("failed to add hairpin iptables jump rule: %v", err)
	}

	rulesFromNode, err := iptablesCmdHandler.List("nat", ipvsHairpinChainName)
	if err != nil {
		return fmt.Errorf("failed to get rules from iptables chain \"%s\": %v", ipvsHairpinChainName, err)
	}

	// Apply the rules we need
	for rule, ruleArgs := range rulesNeeded {
		ruleExists := false
		for _, ruleFromNode := range rulesFromNode {
			if rule == ruleFromNode {
				ruleExists = true
				break
			}
		}
		if !ruleExists {
			err = iptablesCmdHandler.AppendUnique("nat", ipvsHairpinChainName, ruleArgs...)
			if err != nil {
				return fmt.Errorf("failed to apply hairpin iptables rule: %v", err)
			}
		}
	}

	// Delete invalid/outdated rules
	for _, ruleFromNode := range rulesFromNode {
		_, ruleIsNeeded := rulesNeeded[ruleFromNode]
		if !ruleIsNeeded {
			args := strings.Fields(ruleFromNode)
			if len(args) > 2 {
				args = args[2:] // Strip "-A CHAIN_NAME"

				err = iptablesCmdHandler.Delete("nat", ipvsHairpinChainName, args...)
				if err != nil {
					klog.Errorf("Unable to delete hairpin rule \"%s\" from chain %s: %e", ruleFromNode,
						ipvsHairpinChainName, err)
				} else {
					klog.V(1).Infof("Deleted invalid/outdated hairpin rule \"%s\" from chain %s",
						ruleFromNode, ipvsHairpinChainName)
				}
			} else {
				// Ignore the chain creation rule
				if ruleFromNode == "-N "+ipvsHairpinChainName {
					continue
				}
				klog.V(1).Infof("Not removing invalid hairpin rule \"%s\" from chain %s", ruleFromNode,
					ipvsHairpinChainName)
			}
		}
	}

	return nil
}

func hairpinRuleFrom(serviceIP string, endpointIP string, servicePort int) (string, []string) {
	ruleArgs := []string{"-s", endpointIP + "/32", "-d", endpointIP + "/32",
		"-m", "ipvs", "--vaddr", serviceIP, "--vport", strconv.Itoa(servicePort),
		"-j", "SNAT", "--to-source", serviceIP}

	// Trying to ensure this matches iptables.List()
	ruleString := "-A " + ipvsHairpinChainName + " -s " + endpointIP + "/32" + " -d " +
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
	hasHairpinChain := false

	// TODO: Factor out this code
	for _, chain := range chains {
		if chain == ipvsHairpinChainName {
			hasHairpinChain = true
			break
		}
	}

	// Nothing left to do if hairpin chain doesn't exist
	if !hasHairpinChain {
		return nil
	}

	// TODO: Factor this static jump rule out
	jumpArgs := []string{"-m", "ipvs", "--vdir", "ORIGINAL", "-j", ipvsHairpinChainName}
	hasHairpinJumpRule, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", jumpArgs...)
	if err != nil {
		return fmt.Errorf("failed to search POSTROUTING iptables rules: %v", err)
	}

	// Delete the jump rule to the hairpin chain
	if hasHairpinJumpRule {
		err = iptablesCmdHandler.Delete("nat", "POSTROUTING", jumpArgs...)
		if err != nil {
			klog.Errorf("unable to delete hairpin jump rule from chain \"POSTROUTING\": %v", err)
		} else {
			klog.V(1).Info("Deleted hairpin jump rule from chain \"POSTROUTING\"")
		}
	}

	// Flush and delete the chain for hairpin rules
	err = iptablesCmdHandler.ClearChain("nat", ipvsHairpinChainName)
	if err != nil {
		return fmt.Errorf("failed to flush iptables chain \"%s\": %v", ipvsHairpinChainName, err)
	}
	err = iptablesCmdHandler.DeleteChain("nat", ipvsHairpinChainName)
	if err != nil {
		return fmt.Errorf("failed to delete iptables chain \"%s\": %v", ipvsHairpinChainName, err)
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
		if strings.Contains(rule, "ipvs") && strings.Contains(rule, "SNAT") {
			err = iptablesCmdHandler.Delete("nat", "POSTROUTING", strconv.Itoa(i))
			if err != nil {
				return errors.New("Failed to run iptables command" + err.Error())
			}
			klog.V(2).Infof("Deleted iptables masquerade rule: %s", rule)
			break
		}
	}
	return nil
}

func ipvsServiceString(s *ipvs.Service) string {
	var flags, protocol string

	protocol = convertSysCallProtoToSvcProto(s.Protocol)

	if s.Flags&ipvsPersistentFlagHex != 0 {
		flags += "[persistent port]"
	}

	if s.Flags&ipvsHashedFlagHex != 0 {
		flags += "[hashed entry]"
	}

	if s.Flags&ipvsOnePacketFlagHex != 0 {
		flags += "[one-packet scheduling]"
	}

	if s.Flags&ipvsSched1FlagHex != 0 {
		flags += "[flag-1(fallback)]"
	}

	if s.Flags&ipvsSched2FlagHex != 0 {
		flags += "[flag-2(port)]"
	}

	if s.Flags&ipvsSched3FlagHex != 0 {
		flags += "[flag-3]"
	}

	// FWMark entries don't contain a protocol, address, or port which means that we need to log them differently so as
	// not to confuse users
	if s.FWMark != 0 {
		return fmt.Sprintf("FWMark:%d (Flags: %s)", s.FWMark, flags)
	} else {
		return fmt.Sprintf("%s:%s:%v (Flags: %s)", protocol, s.Address, s.Port, flags)
	}
}

func ipvsDestinationString(d *ipvs.Destination) string {
	return fmt.Sprintf("%s:%v (Weight: %v)", d.Address, d.Port, d.Weight)
}

func ipvsSetPersistence(svc *ipvs.Service, p bool, timeout int32) {
	if p {
		svc.Flags |= ipvsPersistentFlagHex
		svc.Netmask |= 0xFFFFFFFF
		svc.Timeout = uint32(timeout)
	} else {
		svc.Flags &^= ipvsPersistentFlagHex
		svc.Netmask &^= 0xFFFFFFFF
		svc.Timeout = 0
	}
}

func ipvsSetSchedFlags(svc *ipvs.Service, s schedFlags) {
	if s.flag1 {
		svc.Flags |= ipvsSched1FlagHex
	} else {
		svc.Flags &^= ipvsSched1FlagHex
	}

	if s.flag2 {
		svc.Flags |= ipvsSched2FlagHex
	} else {
		svc.Flags &^= ipvsSched2FlagHex
	}

	if s.flag3 {
		svc.Flags |= ipvsSched3FlagHex
	} else {
		svc.Flags &^= ipvsSched3FlagHex
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
	if (s.flag1 && (svc.Flags&ipvsSched1FlagHex) == 0) || (!s.flag1 && (svc.Flags&ipvsSched1FlagHex) != 0) {
		return true
	}

	if (s.flag2 && (svc.Flags&ipvsSched2FlagHex) == 0) || (!s.flag2 && (svc.Flags&ipvsSched2FlagHex) != 0) {
		return true
	}

	if (s.flag3 && (svc.Flags&ipvsSched3FlagHex) == 0) || (!s.flag3 && (svc.Flags&ipvsSched3FlagHex) != 0) {
		return true
	}

	return false
}

func (ln *linuxNetworking) ipvsAddService(svcs []*ipvs.Service, vip net.IP, protocol, port uint16,
	persistent bool, persistentTimeout int32, scheduler string, flags schedFlags) (*ipvs.Service, error) {

	var err error
	for _, svc := range svcs {
		if vip.Equal(svc.Address) && protocol == svc.Protocol && port == svc.Port {
			if (persistent && (svc.Flags&ipvsPersistentFlagHex) == 0) ||
				(!persistent && (svc.Flags&ipvsPersistentFlagHex) != 0) ||
				svc.Timeout != uint32(persistentTimeout) {
				ipvsSetPersistence(svc, persistent, persistentTimeout)

				err = ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, err
				}
				klog.V(2).Infof("Updated persistence/session-affinity for service: %s",
					ipvsServiceString(svc))
			}

			if changedIpvsSchedFlags(svc, flags) {
				ipvsSetSchedFlags(svc, flags)

				err = ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, err
				}
				klog.V(2).Infof("Updated scheduler flags for service: %s", ipvsServiceString(svc))
			}

			if scheduler != svc.SchedName {
				svc.SchedName = scheduler
				err = ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, errors.New("Failed to update the scheduler for the service due to " + err.Error())
				}
				klog.V(2).Infof("Updated schedule for the service: %s", ipvsServiceString(svc))
			}

			klog.V(2).Infof("ipvs service %s already exists so returning", ipvsServiceString(svc))
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

	ipvsSetPersistence(&svc, persistent, persistentTimeout)
	ipvsSetSchedFlags(&svc, flags)

	err = ln.ipvsNewService(&svc)
	if err != nil {
		return nil, err
	}
	klog.V(1).Infof("Successfully added service: %s", ipvsServiceString(&svc))
	return &svc, nil
}

// ipvsAddFWMarkService: creates an IPVS service using FWMARK
func (ln *linuxNetworking) ipvsAddFWMarkService(svcs []*ipvs.Service, fwMark uint32, protocol, port uint16,
	persistent bool, persistentTimeout int32, scheduler string, flags schedFlags) (*ipvs.Service, error) {
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
					return nil, err
				}
				klog.V(2).Infof("Updated persistence/session-affinity for service: %s",
					ipvsServiceString(svc))
			}

			if changedIpvsSchedFlags(svc, flags) {
				ipvsSetSchedFlags(svc, flags)

				err := ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, err
				}
				klog.V(2).Infof("Updated scheduler flags for service: %s", ipvsServiceString(svc))
			}

			if scheduler != svc.SchedName {
				svc.SchedName = scheduler
				err := ln.ipvsUpdateService(svc)
				if err != nil {
					return nil, errors.New("Failed to update the scheduler for the service due to " + err.Error())
				}
				klog.V(2).Infof("Updated schedule for the service: %s", ipvsServiceString(svc))
			}

			klog.V(2).Infof("ipvs service %s already exists so returning", ipvsServiceString(svc))
			return svc, nil
		}
	}

	svc := ipvs.Service{
		FWMark:        fwMark,
		AddressFamily: syscall.AF_INET,
		Protocol:      protocol,
		Port:          port,
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

// setupMangleTableRule: sets up iptables rule to FWMARK the traffic to external IP vip
func setupMangleTableRule(ip string, protocol string, port string, fwmark string, tcpMSS int) error {
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

	// setup iptables rule TCPMSS for DSR mode to fix mtu problem
	mtuArgs := []string{"-d", ip, "-m", tcpProtocol, "-p", tcpProtocol, "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS",
		"--set-mss", strconv.Itoa(tcpMSS)}
	err = iptablesCmdHandler.AppendUnique("mangle", "PREROUTING", mtuArgs...)
	if err != nil {
		return errors.New("Failed to run iptables command to set up TCPMSS due to " + err.Error())
	}
	mtuArgs[0] = "-s"
	err = iptablesCmdHandler.AppendUnique("mangle", "POSTROUTING", mtuArgs...)
	if err != nil {
		return errors.New("Failed to run iptables command to set up TCPMSS due to " + err.Error())
	}
	return nil
}

func (ln *linuxNetworking) cleanupMangleTableRule(ip string, protocol string, port string,
	fwmark string, tcpMSS int) error {
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
		klog.V(2).Infof("removing mangle rule with: iptables -D PREROUTING -t mangle %s", args)
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
		klog.V(2).Infof("removing mangle rule with: iptables -D OUTPUT -t mangle %s", args)
		err = iptablesCmdHandler.Delete("mangle", "OUTPUT", args...)
		if err != nil {
			return errors.New("Failed to cleanup iptables command to set up FWMARK due to " + err.Error())
		}
	}

	// cleanup iptables rule TCPMSS
	mtuArgs := []string{"-d", ip, "-m", tcpProtocol, "-p", tcpProtocol, "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS",
		"--set-mss", strconv.Itoa(tcpMSS)}
	exists, err = iptablesCmdHandler.Exists("mangle", "PREROUTING", mtuArgs...)
	if err != nil {
		return errors.New("Failed to cleanup iptables command to set up TCPMSS due to " + err.Error())
	}
	if exists {
		klog.V(2).Infof("removing mangle rule with: iptables -D PREROUTING -t mangle %s", args)
		err = iptablesCmdHandler.Delete("mangle", "PREROUTING", mtuArgs...)
		if err != nil {
			return errors.New("Failed to cleanup iptables command to set up TCPMSS due to " + err.Error())
		}
	}
	mtuArgs[0] = "-s"
	exists, err = iptablesCmdHandler.Exists("mangle", "POSTROUTING", mtuArgs...)
	if err != nil {
		return errors.New("Failed to cleanup iptables command to set up TCPMSS due to " + err.Error())
	}
	if exists {
		klog.V(2).Infof("removing mangle rule with: iptables -D POSTROUTING -t mangle %s", args)
		err = iptablesCmdHandler.Delete("mangle", "POSTROUTING", mtuArgs...)
		if err != nil {
			return errors.New("Failed to cleanup iptables command to set up TCPMSS due to " + err.Error())
		}
	}

	return nil
}

// For DSR it is required that we dont assign the VIP to any interface to avoid martian packets
// http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html
// routeVIPTrafficToDirector: setups policy routing so that FWMARKed packets are delivered locally
func routeVIPTrafficToDirector(fwmark string) error {
	out, err := exec.Command("ip", "rule", "list").Output()
	if err != nil {
		return errors.New("Failed to verify if `ip rule` exists due to: " + err.Error())
	}
	if !strings.Contains(string(out), fwmark+" ") {
		err = exec.Command("ip", "rule", "add", "prio", "32764", "fwmark", fwmark, "table",
			customDSRRouteTableID).Run()
		if err != nil {
			return errors.New("Failed to add policy rule to lookup traffic to VIP through the custom " +
				" routing table due to " + err.Error())
		}
	}
	return nil
}

// For DSR it is required that we dont assign the VIP to any interface to avoid martian packets
// http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html
// setupPolicyRoutingForDSR: setups policy routing so that FWMARKed packets are delivered locally
func (ln *linuxNetworking) setupPolicyRoutingForDSR() error {
	b, err := os.ReadFile("/etc/iproute2/rt_tables")
	if err != nil {
		return errors.New("Failed to setup policy routing required for DSR due to " + err.Error())
	}

	if !strings.Contains(string(b), customDSRRouteTableName) {
		f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return errors.New("Failed to setup policy routing required for DSR due to " + err.Error())
		}
		defer utils.CloseCloserDisregardError(f)
		if _, err = f.WriteString(customDSRRouteTableID + " " + customDSRRouteTableName + "\n"); err != nil {
			return errors.New("Failed to setup policy routing required for DSR due to " + err.Error())
		}
	}
	out, err := exec.Command("ip", "route", "list", "table", customDSRRouteTableID).Output()
	if err != nil || !strings.Contains(string(out), " lo ") {
		if err = exec.Command("ip", "route", "add", "local", "default", "dev", "lo", "table",
			customDSRRouteTableID).Run(); err != nil {
			return errors.New("Failed to add route in custom route table due to: " + err.Error())
		}
	}
	return nil
}

// For DSR it is required that node needs to know how to route external IP. Otherwise when endpoint
// directly responds back with source IP as external IP kernel will treat as martian packet.
// To prevent martian packets add route to external IP through the `kube-bridge` interface
// setupRoutesForExternalIPForDSR: setups routing so that kernel does not think return packets as martians

func (ln *linuxNetworking) setupRoutesForExternalIPForDSR(serviceInfoMap serviceInfoMap) error {
	b, err := os.ReadFile("/etc/iproute2/rt_tables")
	if err != nil {
		return errors.New("Failed to setup external ip routing table required for DSR due to " + err.Error())
	}

	if !strings.Contains(string(b), externalIPRouteTableName) {
		f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return errors.New("Failed setup external ip routing table required for DSR due to " + err.Error())
		}
		defer utils.CloseCloserDisregardError(f)
		if _, err = f.WriteString(externalIPRouteTableID + " " + externalIPRouteTableName + "\n"); err != nil {
			return errors.New("Failed setup external ip routing table required for DSR due to " + err.Error())
		}
	}

	out, err := exec.Command("ip", "rule", "list").Output()
	if err != nil {
		return fmt.Errorf("failed to verify if `ip rule add prio 32765 from all lookup external_ip` exists due to: %v",
			err)
	}

	if !(strings.Contains(string(out), externalIPRouteTableName) ||
		strings.Contains(string(out), externalIPRouteTableID)) {
		err = exec.Command("ip", "rule", "add", "prio", "32765", "from", "all", "lookup",
			externalIPRouteTableID).Run()
		if err != nil {
			klog.Infof("Failed to add policy rule `ip rule add prio 32765 from all lookup external_ip` due to %v",
				err.Error())
			return fmt.Errorf("failed to add policy rule `ip rule add prio 32765 from all lookup external_ip` "+
				"due to %v", err)
		}
	}

	out, _ = exec.Command("ip", "route", "list", "table", externalIPRouteTableID).Output()
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
				if err = exec.Command("ip", "route", "add", externalIP, "dev", "kube-bridge", "table",
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
				if err = exec.Command("ip", args...).Run(); err != nil {
					klog.Errorf("Failed to del route for %v in custom route table for external IP's due to: %s",
						ip, err)
					continue
				}
			}
		}
	}

	return nil
}

func isEndpointsForLeaderElection(ep *api.Endpoints) bool {
	_, isLeaderElection := ep.Annotations[resourcelock.LeaderElectionRecordAnnotationKey]
	return isLeaderElection
}

// unique identifier for a load-balanced service (namespace + name + portname)
func generateServiceID(namespace, svcName, port string) string {
	return namespace + "-" + svcName + "-" + port
}

// unique identifier for a load-balanced service (namespace + name + portname)
func generateIPPortID(ip, protocol, port string) string {
	return ip + "-" + protocol + "-" + port
}

func generateEndpointID(ip, port string) string {
	return ip + ":" + port
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
	dummyVipInterface, err := netlink.LinkByName(KubeDummyIf)
	if err != nil && err.Error() == IfaceNotFound {
		klog.V(1).Infof("Could not find dummy interface: %s to assign cluster ip's, creating one",
			KubeDummyIf)
		err = netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: KubeDummyIf}})
		if err != nil {
			return nil, errors.New("Failed to add dummy interface:  " + err.Error())
		}
		dummyVipInterface, err = netlink.LinkByName(KubeDummyIf)
		if err != nil {
			return nil, errors.New("Failed to get dummy interface: " + err.Error())
		}
		err = netlink.LinkSetUp(dummyVipInterface)
		if err != nil {
			return nil, errors.New("Failed to bring dummy interface up: " + err.Error())
		}
	}
	return dummyVipInterface, nil
}

// Cleanup cleans all the configurations (IPVS, iptables, links) done
func (nsc *NetworkServicesController) Cleanup() {
	klog.Infof("Cleaning up NetworkServiceController configurations...")

	// cleanup ipvs rules by flush
	handle, err := ipvs.New("")
	if err != nil {
		klog.Errorf("failed to get ipvs handle for cleaning ipvs definitions: %v", err)
	} else {
		klog.Infof("ipvs definitions don't have names associated with them for checking, during cleanup " +
			"we assume that we own all of them and delete all ipvs definitions")
		err = handle.Flush()
		if err != nil {
			klog.Errorf("unable to flush ipvs tables: %v", err)
		}
		handle.Close()
	}

	// cleanup iptables masquerade rule
	err = deleteMasqueradeIptablesRule()
	if err != nil {
		klog.Errorf("Failed to cleanup iptablesmasquerade rule due to: %s", err.Error())
		return
	}

	// cleanup iptables hairpin rules
	err = deleteHairpinIptablesRules()
	if err != nil {
		klog.Errorf("Failed to cleanup iptables hairpin rules: %s", err.Error())
		return
	}

	nsc.cleanupIpvsFirewall()

	// delete dummy interface used to assign cluster IP's
	dummyVipInterface, err := netlink.LinkByName(KubeDummyIf)
	if err != nil {
		if err.Error() != IfaceNotFound {
			klog.Infof("Dummy interface: " + KubeDummyIf + " does not exist")
		}
	} else {
		err = netlink.LinkDel(dummyVipInterface)
		if err != nil {
			klog.Errorf("Could not delete dummy interface " + KubeDummyIf + " due to " + err.Error())
			return
		}
	}

	klog.Infof("Successfully cleaned the NetworkServiceController configuration done by kube-router")
}

func (nsc *NetworkServicesController) newEndpointsEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			nsc.handleEndpointsAdd(obj)

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			nsc.handleEndpointsUpdate(oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			nsc.handleEndpointsDelete(obj)
		},
	}
}

func (nsc *NetworkServicesController) handleEndpointsAdd(obj interface{}) {
	endpoints, ok := obj.(*api.Endpoints)
	if !ok {
		klog.Errorf("unexpected object type: %v", obj)
		return
	}
	nsc.OnEndpointsUpdate(endpoints)
}

func (nsc *NetworkServicesController) handleEndpointsUpdate(oldObj, newObj interface{}) {
	_, ok := oldObj.(*api.Endpoints)
	if !ok {
		klog.Errorf("unexpected object type: %v", oldObj)
		return
	}
	newEndpoints, ok := newObj.(*api.Endpoints)
	if !ok {
		klog.Errorf("unexpected object type: %v", newObj)
		return
	}
	nsc.OnEndpointsUpdate(newEndpoints)
}

func (nsc *NetworkServicesController) handleEndpointsDelete(obj interface{}) {
	endpoints, ok := obj.(*api.Endpoints)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("unexpected object type: %v", obj)
			return
		}
		if endpoints, ok = tombstone.Obj.(*api.Endpoints); !ok {
			klog.Errorf("unexpected object type: %v", obj)
			return
		}
	}
	nsc.OnEndpointsUpdate(endpoints)
}

func (nsc *NetworkServicesController) newSvcEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			nsc.handleServiceAdd(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			nsc.handleServiceUpdate(oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			nsc.handleServiceDelete(obj)
		},
	}
}

func (nsc *NetworkServicesController) handleServiceAdd(obj interface{}) {
	service, ok := obj.(*api.Service)
	if !ok {
		klog.Errorf("unexpected object type: %v", obj)
		return
	}
	nsc.OnServiceUpdate(service)
}

func (nsc *NetworkServicesController) handleServiceUpdate(oldObj, newObj interface{}) {
	_, ok := oldObj.(*api.Service)
	if !ok {
		klog.Errorf("unexpected object type: %v", oldObj)
		return
	}
	newService, ok := newObj.(*api.Service)
	if !ok {
		klog.Errorf("unexpected object type: %v", newObj)
		return
	}
	nsc.OnServiceUpdate(newService)
}

func (nsc *NetworkServicesController) handleServiceDelete(obj interface{}) {
	service, ok := obj.(*api.Service)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("unexpected object type: %v", obj)
			return
		}
		if service, ok = tombstone.Obj.(*api.Service); !ok {
			klog.Errorf("unexpected object type: %v", obj)
			return
		}
	}
	nsc.OnServiceUpdate(service)
}

// NewNetworkServicesController returns NetworkServicesController object
func NewNetworkServicesController(clientset kubernetes.Interface,
	config *options.KubeRouterConfig, svcInformer cache.SharedIndexInformer,
	epInformer cache.SharedIndexInformer, podInformer cache.SharedIndexInformer,
	ipsetMutex *sync.Mutex) (*NetworkServicesController, error) {

	var err error
	ln, err := newLinuxNetworking()
	if err != nil {
		return nil, err
	}

	nsc := NetworkServicesController{ln: ln, ipsetMutex: ipsetMutex, metricsMap: make(map[string][]string),
		fwMarkMap: map[uint32]string{}}

	if config.MetricsEnabled {
		// Register the metrics for this controller
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

	nsc.ProxyFirewallSetup = sync.NewCond(&sync.Mutex{})
	nsc.dsr = &dsrOpt{runtimeEndpoint: config.RuntimeEndpoint}

	nsc.masqueradeAll = false
	if config.MasqueradeAll {
		nsc.masqueradeAll = true
	}

	if config.NodePortBindOnAllIP {
		nsc.nodeportBindOnAllIP = true
	}

	if config.RunRouter {
		cidr, err := utils.GetPodCidrFromNodeSpec(nsc.client, config.HostnameOverride)
		if err != nil {
			return nil, fmt.Errorf("failed to get pod CIDR details from Node.spec: %s", err.Error())
		}
		nsc.podCidr = cidr
	}

	nsc.excludedCidrs = make([]net.IPNet, len(config.ExcludedCidrs))
	for i, excludedCidr := range config.ExcludedCidrs {
		_, ipnet, err := net.ParseCIDR(excludedCidr)
		if err != nil {
			return nil, fmt.Errorf("failed to get excluded CIDR details: %s", err.Error())
		}
		nsc.excludedCidrs[i] = *ipnet
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
	automtu, err := utils.GetMTUFromNodeIP(nsc.nodeIP)
	if err != nil {
		return nil, err
	}
	// Sets it to 60 bytes less than the auto-detected MTU to account for additional ip-ip headers needed for DSR, above
	// method GetMTUFromNodeIP() already accounts for the overhead of ip-ip overlay networking, so we need to
	// remove 60 bytes (internet headers and additional ip-ip because MTU includes internet headers. MSS does not.)
	// This needs also a condition to deal with auto-mtu=false
	nsc.dsrTCPMSS = automtu - utils.IPInIPHeaderLength*3

	nsc.podLister = podInformer.GetIndexer()

	nsc.svcLister = svcInformer.GetIndexer()
	nsc.ServiceEventHandler = nsc.newSvcEventHandler()

	nsc.ipvsPermitAll = config.IpvsPermitAll

	nsc.epLister = epInformer.GetIndexer()
	nsc.EndpointsEventHandler = nsc.newEndpointsEventHandler()

	rand.Seed(time.Now().UnixNano())

	return &nsc, nil
}
