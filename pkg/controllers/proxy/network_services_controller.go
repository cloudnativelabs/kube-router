package proxy

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/v2/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/moby/ipvs"
	"github.com/vishvananda/netlink"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog/v2"
)

const (
	KubeDummyIf       = "kube-dummy-if"
	KubeTunnelIfv4    = "kube-tunnel-if"
	KubeTunnelIfv6    = "kube-tunnel-v6"
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

	// All IPSET names need to be less than 31 characters in order for the Kernel to accept them. Keep in mind that the
	// actual formulation for this may be inet6:<setNameBase> depending on ip family, plus when we change ipsets we use
	// a swap operation that adds a hyphen to the end, so that means that these base names actually need to be less than
	// 24 characters
	localIPsIPSetName     = "kube-router-local-ips"
	serviceIPPortsSetName = "kube-router-svip-prt"
	serviceIPsIPSetName   = "kube-router-svip"

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

// NetworkServicesController enables local node as network service proxy through IPVS/LVS.
// Support only Kubernetes network services of type NodePort, ClusterIP, and LoadBalancer. For each service a
// IPVS service is created and for each service endpoint a server is added to the IPVS service.
// As services and endpoints are updated, network service controller gets the updates from
// the kubernetes api server and syncs the ipvs configuration to reflect state of services
// and endpoints

// NetworkServicesController struct stores information needed by the controller
type NetworkServicesController struct {
	primaryIP           net.IP
	nodeHostName        string
	syncPeriod          time.Duration
	mu                  sync.Mutex
	serviceMap          serviceInfoMap
	endpointsMap        endpointSliceInfoMap
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

	svcLister    cache.Indexer
	epLister     cache.Indexer
	podLister    cache.Indexer
	nodeListener cache.Indexer

	EndpointSliceEventHandler cache.ResourceEventHandler
	ServiceEventHandler       cache.ResourceEventHandler
	NodeEventHandler          cache.ResourceEventHandler

	nodesMap             nodeInfoMap
	nodeWeightAnnotation string
	defaultNodeWeight    int

	gracefulPeriod      time.Duration
	gracefulQueue       gracefulQueue
	gracefulTermination bool
	syncChan            chan int
	dsr                 *dsrOpt
	dsrTCPMSS           int

	iptablesCmdHandlers map[v1.IPFamily]utils.IPTablesHandler
	ipSetHandlers       map[v1.IPFamily]utils.IPSetHandler
	nodeIPv4Addrs       map[v1.NodeAddressType][]net.IP
	nodeIPv6Addrs       map[v1.NodeAddressType][]net.IP
	podIPv4CIDRs        []string
	podIPv6CIDRs        []string
	isIPv4Capable       bool
	isIPv6Capable       bool
}

type ipvsCalls interface {
	ipvsNewService(ipvsSvc *ipvs.Service) error
	ipvsAddService(svcs []*ipvs.Service, vip net.IP, protocol, port uint16, persistent bool,
		persistentTimeout int32, scheduler string, flags schedFlags) ([]*ipvs.Service, *ipvs.Service, error)
	ipvsDelService(ipvsSvc *ipvs.Service) error
	ipvsUpdateService(ipvsSvc *ipvs.Service) error
	ipvsGetServices() ([]*ipvs.Service, error)
	ipvsAddServer(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error
	ipvsNewDestination(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error
	ipvsUpdateDestination(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error
	ipvsGetDestinations(ipvsSvc *ipvs.Service) ([]*ipvs.Destination, error)
	ipvsDelDestination(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error
	ipvsAddFWMarkService(svcs []*ipvs.Service, fwMark uint32, family, protocol, port uint16, persistent bool,
		persistentTimeout int32, scheduler string, flags schedFlags) (*ipvs.Service, error)
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
	clusterIPs                    []string
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
type endpointSliceInfo struct {
	ip      string
	port    int
	isLocal bool
	isIPv4  bool
	isIPv6  bool
	weight  int
}

// map of all endpoints, with unique service id(namespace name, service name, port) as key
type endpointSliceInfoMap map[string][]endpointSliceInfo

// internal representation of nodes
type nodeInfo struct {
	nodeName string
	weight   int
}

// map of all nodes by the node name
type nodeInfoMap map[string]*nodeInfo

// Run periodically sync ipvs configuration to reflect desired state of services and endpoints
func (nsc *NetworkServicesController) Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) {
	t := time.NewTicker(nsc.syncPeriod)
	defer t.Stop()
	defer wg.Done()
	defer close(nsc.syncChan)

	klog.Infof("Starting network services controller")

	klog.V(1).Info("Performing cleanup of depreciated masquerade iptables rules (if needed).")
	err := nsc.deleteBadMasqueradeIptablesRules()
	if err != nil {
		klog.Fatalf("error cleaning up old/bad masquerade rules: %s", err.Error())
	}

	// enable masquerade rule
	err = nsc.ensureMasqueradeIptablesRule()
	if err != nil {
		klog.Fatalf("failed to do add masquerade rule in POSTROUTING chain of nat table due to: %s", err.Error())
	}

	setSysCtlAndCheckError := func(path string, value int) {
		sysctlErr := utils.SetSysctl(path, value)
		if sysctlErr != nil {
			// Check if the error is fatal, on older kernels this option does not exist and the same behaviour is default
			// if option is not found just log it
			if sysctlErr.IsFatal() {
				klog.Fatal(sysctlErr.Error())
			} else {
				klog.Error(sysctlErr.Error())
			}
		}
	}

	// From what I can see there are no IPv6 equivalents for the below options, so we only consider IPv4 here
	// https://www.kernel.org/doc/Documentation/networking/ipvs-sysctl.txt
	// enable ipvs connection tracking
	setSysCtlAndCheckError(utils.IPv4IPVSConntrack, ipvsConntrackEnable)

	// LVS failover not working with UDP packets https://access.redhat.com/solutions/58653
	setSysCtlAndCheckError(utils.IPv4IPVSExpireNodestConn, ipvsExpireNodestConnEnable)

	// LVS failover not working with UDP packets https://access.redhat.com/solutions/58653
	setSysCtlAndCheckError(utils.IPv4IPVSExpireQuiescent, ipvsExpireQuiescentTemplateEnable)

	// https://github.com/kubernetes/kubernetes/pull/71114
	setSysCtlAndCheckError(utils.IPv4IPVSConnReuseMode, ipvsConnReuseModeDisableSpecialHandling)

	// https://github.com/kubernetes/kubernetes/pull/70530/files
	setSysCtlAndCheckError(utils.IPv4ConfAllArpIgnore, arpIgnoreReplyOnlyIfTargetIPIsLocal)

	// https://github.com/kubernetes/kubernetes/pull/70530/files
	setSysCtlAndCheckError(utils.IPv4ConfAllArpAnnounce, arpAnnounceUseBestLocalAddress)

	// https://github.com/cloudnativelabs/kube-router/issues/282
	err = nsc.setupIpvsFirewall()
	if err != nil {
		klog.Fatalf("error setting up ipvs firewall: %s" + err.Error())
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
			klog.Fatalf("failed to perform initial full sync %s", err.Error())
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
	nsc.nodesMap = nsc.buildNodesInfo()
	nsc.endpointsMap = nsc.buildEndpointSliceInfo()
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

func (nsc *NetworkServicesController) setupIpvsFirewall() error {
	/*
	   - create ipsets
	   - create firewall rules
	*/
	var err error

	// Initialize some blank ipsets with the correct names in order to use them in the iptables below. We don't need
	// to retain references to them, because we'll use the handler to refresh them later in syncIpvsFirewall
	for _, ipSetHandler := range nsc.ipSetHandlers {
		// Create ipset for local addresses.
		_, err = ipSetHandler.Create(localIPsIPSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
		if err != nil {
			return fmt.Errorf("failed to create ipset: %s - %v", localIPsIPSetName, err)
		}

		// Create 2 ipsets for services. One for 'ip' and one for 'ip,port'
		_, err = ipSetHandler.Create(serviceIPsIPSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
		if err != nil {
			return fmt.Errorf("failed to create ipset: %s - %v", serviceIPsIPSetName, err)
		}

		_, err = ipSetHandler.Create(serviceIPPortsSetName, utils.TypeHashIPPort, utils.OptionTimeout, "0")
		if err != nil {
			return fmt.Errorf("failed to create ipset: %s - %v", serviceIPPortsSetName, err)
		}
	}

	// Setup a custom iptables chain to explicitly allow input traffic to ipvs services only.
	for family, iptablesCmdHandler := range nsc.iptablesCmdHandlers {
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
		var icmpProto string
		var icmpType string
		var icmpRejectType string

		switch family {
		case v1.IPv4Protocol:
			icmpProto = "icmp"
			icmpType = "--icmp-type"
			icmpRejectType = "icmp-port-unreachable"
		case v1.IPv6Protocol:
			icmpProto = "ipv6-icmp"
			icmpType = "--icmpv6-type"
			icmpRejectType = "icmp6-port-unreachable"
		}

		// Allow various types of ICMP that are important for routing
		comment = "allow icmp echo requests to service IPs"
		args = []string{"-m", "comment", "--comment", comment, "-p", icmpProto, icmpType, "echo-request",
			"-j", "ACCEPT"}
		err = iptablesCmdHandler.AppendUnique("filter", ipvsFirewallChainName, args...)
		if err != nil {
			return fmt.Errorf("failed to run iptables command: %s", err.Error())
		}

		comment = "allow icmp ttl exceeded messages to service IPs"
		args = []string{"-m", "comment", "--comment", comment, "-p", icmpProto, icmpType, "time-exceeded",
			"-j", "ACCEPT"}
		err = iptablesCmdHandler.AppendUnique("filter", ipvsFirewallChainName, args...)
		if err != nil {
			return fmt.Errorf("failed to run iptables command: %s", err.Error())
		}

		// destination-unreachable here is also responsible for handling / allowing
		// PMTU (https://en.wikipedia.org/wiki/Path_MTU_Discovery) responses
		comment = "allow icmp destination unreachable messages to service IPs"
		args = []string{"-m", "comment", "--comment", comment, "-p", icmpProto, icmpType, "destination-unreachable",
			"-j", "ACCEPT"}
		err = iptablesCmdHandler.AppendUnique("filter", ipvsFirewallChainName, args...)
		if err != nil {
			return fmt.Errorf("failed to run iptables command: %s", err.Error())
		}

		// Get into specific service specific allowances
		comment = "allow input traffic to ipvs services"
		args = []string{"-m", "comment", "--comment", comment, "-m", "set",
			"--match-set", getIPSetName(serviceIPPortsSetName, family), "dst,dst", "-j", "ACCEPT"}
		err := iptablesCmdHandler.AppendUnique("filter", ipvsFirewallChainName, args...)
		if err != nil {
			return fmt.Errorf("failed to run iptables command: %s", err.Error())
		}

		// We exclude the local addresses here as that would otherwise block all traffic to local addresses if any
		// NodePort service exists.
		comment = "reject all unexpected traffic to service IPs"
		args = []string{"-m", "comment", "--comment", comment,
			"-m", "set", "!", "--match-set", getIPSetName(localIPsIPSetName, family), "dst",
			"-j", "REJECT", "--reject-with", icmpRejectType}
		err = iptablesCmdHandler.AppendUnique("filter", ipvsFirewallChainName, args...)
		if err != nil {
			return fmt.Errorf("failed to run iptables command: %s", err.Error())
		}

		// Pass incoming traffic into our custom chain.
		ipvsFirewallInputChainRule := getIPVSFirewallInputChainRule(family)
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
	}

	return nil
}

func (nsc *NetworkServicesController) cleanupIpvsFirewall() {
	// Clear iptables rules
	for family, iptablesCmdHandler := range nsc.iptablesCmdHandlers {
		ipvsFirewallInputChainRule := getIPVSFirewallInputChainRule(family)
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
	for _, ipSetHandler := range nsc.ipSetHandlers {
		err := ipSetHandler.Save()
		if err != nil {
			klog.Fatalf("failed to initialize ipsets command executor due to %v", err)
			return
		}

		for _, ipSetName := range []string{localIPsIPSetName, serviceIPsIPSetName, serviceIPPortsSetName} {
			ipSetName := ipSetName
			if _, ok := ipSetHandler.Sets()[ipSetName]; ok {
				err = ipSetHandler.Destroy(ipSetName)
				if err != nil {
					klog.Errorf("failed to destroy ipset: %s", err.Error())
				}
			}
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

	// Populate local addresses ipset.
	addrsMap, err := getAllLocalIPs()
	if err != nil {
		return fmt.Errorf("failed to get local IPs: %s", err)
	}

	for family, addrs := range addrsMap {
		// Don't run for families that we don't support
		if family == v1.IPv4Protocol && !nsc.isIPv4Capable {
			continue
		}
		if family == v1.IPv6Protocol && !nsc.isIPv6Capable {
			continue
		}

		// Convert addrs from a slice of net.IP to a slice of string
		localIPsSets := make([][]string, 0, len(addrs))
		for _, addr := range addrs {
			localIPsSets = append(localIPsSets, []string{addr.String(), utils.OptionTimeout, "0"})
		}

		// Refresh the family specific IPSet with the slice of strings
		nsc.ipSetHandlers[family].RefreshSet(localIPsIPSetName, localIPsSets, utils.TypeHashIP)
	}

	// Populate service ipsets.
	ipvsServices, err := nsc.ln.ipvsGetServices()
	if err != nil {
		return errors.New("Failed to list IPVS services: " + err.Error())
	}

	serviceIPsSets := make(map[v1.IPFamily][][]string)
	serviceIPPortsIPSets := make(map[v1.IPFamily][][]string)

	for _, ipvsService := range ipvsServices {
		var address net.IP
		var protocol string
		var port int
		if ipvsService.Address != nil {
			address = ipvsService.Address
			protocol = convertSysCallProtoToSvcProto(ipvsService.Protocol)
			if protocol == noneProtocol {
				klog.Warningf("failed to convert protocol %d to a valid IPVS protocol for service: %s skipping",
					ipvsService.Protocol, ipvsService.Address.String())
				continue
			}
			port = int(ipvsService.Port)
		} else if ipvsService.FWMark != 0 {
			var ipString string
			ipString, protocol, port, err = nsc.lookupServiceByFWMark(ipvsService.FWMark)
			if err != nil {
				klog.Warningf("failed to lookup %d by FWMark: %s - this may not be a kube-router controlled service, "+
					"but if it is, then something's gone wrong", ipvsService.FWMark, err)
				continue
			}
			address = net.ParseIP(ipString)
			if address == nil {
				klog.Warning("failed to parse IP %s returned from FWMark %s - this may not be a kube-router" +
					"controlled service, but if it is then something's gone wrong")
			}
		}
		var family v1.IPFamily
		if address.To4() != nil {
			family = v1.IPv4Protocol
		} else {
			family = v1.IPv6Protocol
		}

		serviceIPsSets[family] = append(serviceIPsSets[family], []string{address.String(), utils.OptionTimeout, "0"})

		ipvsAddressWithPort := fmt.Sprintf("%s,%s:%d", address, protocol, port)
		serviceIPPortsIPSets[family] = append(serviceIPPortsIPSets[family],
			[]string{ipvsAddressWithPort, utils.OptionTimeout, "0"})

	}

	for family, setHandler := range nsc.ipSetHandlers {
		setHandler.RefreshSet(serviceIPsIPSetName, serviceIPsSets[family], utils.TypeHashIP)

		setHandler.RefreshSet(serviceIPPortsSetName, serviceIPPortsIPSets[family], utils.TypeHashIPPort)

		err := setHandler.Restore()
		if err != nil {
			return fmt.Errorf("could not save ipset for service firewall: %v", err)
		}
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
			case nsc.primaryIP.String():
				if protocol == ipvsSvc.Protocol && uint16(svc.port) == ipvsSvc.Port {
					pushMetric = true
					svcVip = nsc.primaryIP.String()
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
func (nsc *NetworkServicesController) OnEndpointsUpdate(es *discovery.EndpointSlice) {

	nsc.mu.Lock()
	defer nsc.mu.Unlock()
	klog.V(1).Infof("Received update to EndpointSlice: %s/%s from watch API", es.Namespace, es.Name)
	if !nsc.readyForUpdates {
		klog.V(1).Infof(
			"Skipping update to EndpointSlice: %s/%s as controller is not ready to process service and endpoints "+
				"updates", es.Namespace, es.Name)
		return
	}

	// If the service is headless and the previous version of the service is either non-existent or also headless,
	// skip processing as we only work with VIPs in the next section. Since the ClusterIP field is immutable we don't
	// need to consider previous versions of the service here as we are guaranteed if is a ClusterIP now, it was a
	// ClusterIP before.
	svc, exists, err := utils.ServiceForEndpointSlice(&nsc.svcLister, es)
	if err != nil {
		klog.Errorf("failed to convert endpoints resource to service for %s/%s: %v", es.Namespace, es.Name, err)
		return
	}
	// ignore updates to Endpoints object with no corresponding Service object
	if !exists {
		klog.Warningf("failed to lookup any service as an owner for %s/%s", es.Namespace, es.Name)
		return
	}
	if utils.ServiceIsHeadless(svc) {
		klog.V(1).Infof("The service associated with endpoint: %s/%s is headless, skipping...",
			es.Namespace, es.Name)
		return
	}

	ep, err := nsc.client.CoreV1().Endpoints(es.Namespace).Get(context.TODO(), es.Name, metav1.GetOptions{})
	if err != nil {
		klog.V(1).ErrorS(err, "Error fetching endpoints for service: %s/%s", es.Namespace, es.Name)
		return
	}

	// build new service and endpoints map to reflect the change
	nsc.buildAndSyncEndpoints(ep, nil)

	// TODO(pavel): clean below comments

	// newServiceMap := nsc.buildServicesInfo()
	// newEndpointsMap := nsc.buildEndpointSliceInfo()

	// if !endpointsMapsEquivalent(newEndpointsMap, nsc.endpointsMap) {
	// 	nsc.endpointsMap = newEndpointsMap
	// 	nsc.serviceMap = newServiceMap
	// 	klog.V(1).Infof("Syncing IPVS services sync for update to endpoint: %s/%s", es.Namespace, es.Name)
	// 	nsc.sync(synctypeIpvs)
	// } else {
	// 	klog.V(1).Infof("Skipping IPVS services sync on endpoint: %s/%s update as nothing changed", es.Namespace, es.Name)
	// }
}

func (nsc *NetworkServicesController) buildAndSyncEndpoints(ep *v1.Endpoints, node *v1.Node) {
	if len(nsc.nodesMap) == 0 {
		klog.V(1).Info("Skipping building and syncing of endpoints because node info map is not populated yet")
		return
	}
	newServiceMap := nsc.buildServicesInfo()
	newEndpointsMap := nsc.buildEndpointSliceInfo()

	if len(newEndpointsMap) != len(nsc.endpointsMap) || !reflect.DeepEqual(newEndpointsMap, nsc.endpointsMap) {
		nsc.endpointsMap = newEndpointsMap
		nsc.serviceMap = newServiceMap
		if ep != nil {
			klog.V(1).Infof("Syncing IPVS services sync for update to endpoint: %s/%s", ep.Namespace, ep.Name)
		} else if node != nil {
			klog.V(1).Infof("Syncing IPVS services sync for update to node: %s", node.Name)
		}
		nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
	} else {
		if ep != nil {
			klog.V(1).Infof("Skipping IPVS services sync on endpoint: %s/%s update as nothing changed", ep.Namespace, ep.Name)
		} else if node != nil {
			klog.V(1).Infof("Skipping IPVS services sync on node: %s update as nothing changed", node.Name)
		}
	}
}

// OnNodeUpdate handle change in node update from the API server
func (nsc *NetworkServicesController) OnNodeUpdate(obj interface{}) {
	node, ok := obj.(*v1.Node)
	if !ok {
		klog.Error("could not convert node update object to *v1.Node")
		return
	}

	klog.V(1).Infof("Received update to node: %s from watch API", node.Name)
	if !nsc.readyForUpdates {
		klog.V(3).Infof("Skipping update to node: %s, controller still performing bootup full-sync", node.Name)
		return
	}
	nsc.mu.Lock()
	defer nsc.mu.Unlock()
	newNodeMap := nsc.buildNodesInfo()

	if len(newNodeMap) != len(nsc.nodesMap) || !reflect.DeepEqual(newNodeMap, nsc.nodesMap) {
		nsc.nodesMap = newNodeMap
		klog.V(2).Info("Node info has changed, rebuilding endpoints")
		nsc.buildAndSyncEndpoints(nil, node)
	} else {
		klog.V(1).Info("Skipping ipvs server sync on node update because nothing changed")
	}
}

// OnServiceUpdate handle change in service update from the API server
func (nsc *NetworkServicesController) OnServiceUpdate(svc *v1.Service) {

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
	newEndpointsMap := nsc.buildEndpointSliceInfo()

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

func hasActiveEndpoints(endpoints []endpointSliceInfo) bool {
	for _, endpoint := range endpoints {
		if endpoint.isLocal {
			return true
		}
	}
	return false
}

// func hasActiveEndpoints(svc *serviceInfo, endpoints []endpointsInfo) bool {
// 	for _, endpoint := range endpoints {
// 		if endpoint.isLocal {
// 			return true
// 		}
// 	}
// 	return false
// }

func (nsc *NetworkServicesController) getPodObjectForEndpoint(endpointIP string) (*v1.Pod, error) {
	for _, obj := range nsc.podLister.List() {
		pod := obj.(*v1.Pod)
		for _, ip := range pod.Status.PodIPs {
			if strings.Compare(ip.IP, endpointIP) == 0 {
				return pod, nil
			}
		}
	}
	return nil, errors.New("Failed to find pod with ip " + endpointIP)
}

func (nsc *NetworkServicesController) buildServicesInfo() serviceInfoMap {
	serviceMap := make(serviceInfoMap)
	for _, obj := range nsc.svcLister.List() {
		svc := obj.(*v1.Service)

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
				clusterIPs:  make([]string, len(svc.Spec.ClusterIPs)),
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
				switch schedulingMethod {
				case ipvs.RoundRobin:
					svcInfo.scheduler = ipvs.RoundRobin
				case ipvs.LeastConnection:
					svcInfo.scheduler = ipvs.LeastConnection
				case ipvs.DestinationHashing:
					svcInfo.scheduler = ipvs.DestinationHashing
				case ipvs.SourceHashing:
					svcInfo.scheduler = ipvs.SourceHashing
				case IpvsMaglevHashing:
					svcInfo.scheduler = IpvsMaglevHashing
				case WeightedRoundRobin:
					svcInfo.scheduler = WeightedRoundRobin
				case WeightedLeastConnection:
					svcInfo.scheduler = WeightedLeastConnection
				}
			}

			flags, ok := svc.ObjectMeta.Annotations[svcSchedFlagsAnnotation]
			if ok && svcInfo.scheduler == IpvsMaglevHashing {
				svcInfo.flags = parseSchedFlags(flags)
			}

			copy(svcInfo.externalIPs, svc.Spec.ExternalIPs)
			copy(svcInfo.clusterIPs, svc.Spec.ClusterIPs)
			for _, lbIngress := range svc.Status.LoadBalancer.Ingress {
				if len(lbIngress.IP) > 0 {
					svcInfo.loadBalancerIPs = append(svcInfo.loadBalancerIPs, lbIngress.IP)
				}
			}
			svcInfo.sessionAffinity = svc.Spec.SessionAffinity == v1.ServiceAffinityClientIP

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
			if svc.Spec.ExternalTrafficPolicy == v1.ServiceExternalTrafficPolicyTypeLocal {
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

func shuffle(endPoints []endpointSliceInfo) []endpointSliceInfo {
	for index1 := range endPoints {
		randBitInt, err := rand.Int(rand.Reader, big.NewInt(int64(index1+1)))
		index2 := randBitInt.Int64()
		if err != nil {
			klog.Warningf("unable to get a random int: %v", err)
		}
		endPoints[index1], endPoints[index2] = endPoints[index2], endPoints[index1]
	}
	return endPoints
}

// buildEndpointSliceInfo creates a map of EndpointSlices taken at a moment in time
func (nsc *NetworkServicesController) buildEndpointSliceInfo() endpointSliceInfoMap {
	endpointsMap := make(endpointSliceInfoMap)
	for _, obj := range nsc.epLister.List() {
		var isIPv4, isIPv6 bool
		es := obj.(*discovery.EndpointSlice)
		switch es.AddressType {
		case discovery.AddressTypeIPv4:
			isIPv4 = true
		case discovery.AddressTypeIPv6:
			isIPv6 = true
		case discovery.AddressTypeFQDN:
			// At this point we don't handle FQDN type EndpointSlices, at some point in the future this might change
			continue
		default:
			// If at some point k8s adds more AddressTypes, we'd prefer to handle them manually to ensure consistent
			// functionality within kube-router
			continue
		}

		// In order to properly link the endpoint with the service, we need the service's name
		svcName, err := utils.ServiceNameforEndpointSlice(es)
		if err != nil {
			klog.Errorf("unable to lookup service from EndpointSlice, skipping: %v", err)
			continue
		}

		// Keep in mind that ports aren't embedded in Endpoints, but we do need to make an endpointSliceInfo and a svcID
		// for each pair, so we consume them as an inter and outer loop. Actual structure of EndpointSlice looks like:
		//
		// metadata:
		//	name: ...
		//	namespace: ...
		// endpoints:
		// - addresses:
		//   - 10.0.0.1
		//   conditions:
		//     ready: (true|false)
		//   nodeName: foo
		//   targetRef:
		//     kind: Pod
		//     name: bar
		//   zone: z1
		// ports:
		//   - name: baz
		//     port: 8080
		//     protocol: TCP
		//
		for _, ep := range es.Endpoints {
			// Previously, when we used endpoints, we only looked at subsets.addresses and not subsets.notReadyAddresses
			// so here we need to limit our endpoints to only the ones that are ready. In the future, we could consider
			// changing this to .Serving which continues to include pods that are in Terminating state. For now we keep
			// it the same.
			if !*ep.Conditions.Ready {
				continue
			}

			for _, port := range es.Ports {
				var endpoints []endpointSliceInfo
				var ok bool

				svcID := generateServiceID(es.Namespace, svcName, *port.Name)

				// we may have already started to populate endpoints for this service from another EndpointSlice, if so
				// continue where we left off, otherwise create a new slice
				if endpoints, ok = endpointsMap[svcID]; !ok {
					endpoints = make([]endpointSliceInfo, 0)
				}

				for _, addr := range ep.Addresses {
					klog.V(2).Infof("Processing %+v", addr)
					nodeWeight := nsc.defaultNodeWeight
					var nodeInfo *nodeInfo
					// TODO(Pavel): confirm if this logic is correct
					if ep.NodeName != nil {
						nodeInfo = nsc.nodesMap[*ep.NodeName]
					}
					if nodeInfo == nil && len(addr) > 0 {
						nodeInfo = nsc.nodesMap[addr]
					}
					if nodeInfo != nil {
						nodeWeight = nodeInfo.weight
					}
					isLocal := ep.NodeName != nil && *ep.NodeName == nsc.nodeHostName
					endpoints = append(endpoints, endpointSliceInfo{
						ip:      addr,
						port:    int(*port.Port),
						isLocal: isLocal,
						isIPv4:  isIPv4,
						isIPv6:  isIPv6,
						weight:  nodeWeight,
					})
				}
				endpointsMap[svcID] = shuffle(endpoints)
			}
		}
	}
	return endpointsMap
}

func (nsc *NetworkServicesController) buildNodesInfo() nodeInfoMap {
	nodeMap := make(nodeInfoMap)
	for _, obj := range nsc.nodeListener.List() {
		node := obj.(*v1.Node)
		var weight int
		var err error

		if weight, err = utils.GetNodeWeight(node, nsc.nodeWeightAnnotation); err != nil {
			klog.Warningf("Failed to get node weight from annotation %s, using default weight %d: %e", nsc.nodeWeightAnnotation, nsc.defaultNodeWeight, err)
			weight = nsc.defaultNodeWeight
		}

		nodeInfo := nodeInfo{
			nodeName: node.GetName(),
			weight:   weight,
		}

		klog.V(2).Infof("Using weight '%d' for node '%s'", nodeInfo.weight, nodeInfo.nodeName)
		nodeMap[nodeInfo.nodeName] = &nodeInfo

		if ip, err := utils.GetPrimaryNodeIP(node); err != nil {
			klog.Warningf("Failed to get node IP for node '%s': %e", nodeInfo.nodeName, err)
		} else {
			nodeMap[ip.String()] = &nodeInfo
		}
	}

	return nodeMap
}

// Add an iptables rule to masquerade outbound IPVS traffic. IPVS nat requires that reverse path traffic
// to go through the director for its functioning. So the masquerade rule ensures source IP is modified
// to node ip, so return traffic from real server (endpoint pods) hits the node/lvs director
func (nsc *NetworkServicesController) ensureMasqueradeIptablesRule() error {
	for ipFamily, iptablesCmdHandler := range nsc.iptablesCmdHandlers {
		// Start off by finding our primary IP and pod CIDRs based upon our IP famiily
		primaryIP, cidrs := nsc.getPrimaryAndCIDRsByFamily(ipFamily)
		// A blank primaryIP here indicates that we are not enabled for this family or that something has gone wrong
		if primaryIP == "" {
			continue
		}

		var args = []string{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ",
			"-m", "comment", "--comment", "", "-j", "SNAT", "--to-source", primaryIP}

		if iptablesCmdHandler.HasRandomFully() {
			args = append(args, "--random-fully")
		}

		if nsc.masqueradeAll {
			err := iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", args...)
			if err != nil {
				return fmt.Errorf("failed to create iptables rule to masquerade all outbound IPVS traffic: %v", err)
			}
		} else {
			exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", args...)
			if err != nil {
				return fmt.Errorf("failed to lookup iptables rule to masquerade all outbound IPVS traffic: %v", err)
			}
			if exists {
				err = iptablesCmdHandler.Delete("nat", "POSTROUTING", args...)
				if err != nil {
					return fmt.Errorf("failed to delete iptables rule to masquerade all outbound IPVS traffic: "+
						"%v - masquerade might still work", err)
				}
				klog.Infof("Deleted iptables rule to masquerade all outbound IVPS traffic.")
			}
		}

		for _, cidr := range cidrs {
			// TODO: ipset should be used for destination podCidr(s) match after multiple podCidr(s) per node get supported
			args = []string{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ",
				"-m", "comment", "--comment", "", "!", "-s", cidr, "!", "-d", cidr,
				"-j", "SNAT", "--to-source", primaryIP}
			if iptablesCmdHandler.HasRandomFully() {
				args = append(args, "--random-fully")
			}

			err := iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", args...)
			if err != nil {
				return fmt.Errorf("failed to run iptables command: %v", err)
			}
		}
	}

	klog.V(2).Info("Successfully synced iptables masquerade rule")
	return nil
}

// Delete old/bad iptables rules to masquerade outbound IPVS traffic.
func (nsc *NetworkServicesController) deleteBadMasqueradeIptablesRules() error {
	for ipFamily, iptablesCmdHandler := range nsc.iptablesCmdHandlers {
		var argsBad = [][]string{
			{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ", "-m", "comment", "--comment", "",
				"-j", "MASQUERADE"},
		}

		// Start off by finding our primary IP and pod CIDRs based upon our IP famiily
		primaryIP, cidrs := nsc.getPrimaryAndCIDRsByFamily(ipFamily)
		// A blank primaryIP here indicates that we are not enabled for this family or that something has gone wrong
		if primaryIP == "" {
			continue
		}

		// Add CIDRs of the appropriate family to bad Args
		for _, cidr := range cidrs {
			argsBad = append(argsBad, []string{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ",
				"-m", "comment", "--comment", "", "!", "-s", cidr, "!", "-d", cidr, "-j", "MASQUERADE"})
		}

		// If random fully is supported remove the original rules as well
		if iptablesCmdHandler.HasRandomFully() {
			argsBad = append(argsBad, []string{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ",
				"-m", "comment", "--comment", "", "-j", "SNAT", "--to-source", primaryIP})

			for _, cidr := range cidrs {
				argsBad = append(argsBad, []string{"-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ",
					"-m", "comment", "--comment", "",
					"!", "-s", cidr, "!", "-d", cidr, "-j", "SNAT", "--to-source", primaryIP})
			}
		}

		for _, args := range argsBad {
			exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", args...)
			if err != nil {
				return fmt.Errorf("failed to lookup iptables rule: %v", err)
			}

			if exists {
				err = iptablesCmdHandler.Delete("nat", "POSTROUTING", args...)
				if err != nil {
					return fmt.Errorf("failed to delete old/bad iptables rule to masquerade outbound IVPS "+
						"traffic: %v. Masquerade all might still work, or bugs may persist after upgrade",
						err)
				}
				klog.Infof("Deleted old/bad iptables rule to masquerade outbound traffic.")
			}
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
	ipv4RulesNeeded := make(map[string][]string)
	ipv6RulesNeeded := make(map[string][]string)

	// Generate the rules that we need
	for svcName, svcInfo := range nsc.serviceMap {
		if nsc.globalHairpin || svcInfo.hairpin {
			// If this service doesn't have any active & local endpoints on this node, then skip it as only local
			// endpoints matter for hairpinning
			if !hasActiveEndpoints(nsc.endpointsMap[svcName]) {
				continue
			}

			clusterIPs := getAllClusterIPs(svcInfo)
			externalIPs := getAllExternalIPs(svcInfo, false)

			for _, ep := range nsc.endpointsMap[svcName] {
				var familyClusterIPs []net.IP
				var familyExternalIPs []net.IP
				var familyNodeIPs []net.IP
				var family v1.IPFamily
				var rulesMap map[string][]string

				// If this specific endpoint is not local, then skip it as only local endpoints matter for hairpinning
				if !ep.isLocal {
					continue
				}

				// Get the IP family from the endpoint and match it to an existing Cluster IP family slice and do some
				// basic sanity checking
				epIP := net.ParseIP(ep.ip)
				if epIP == nil {
					klog.Warningf("found a nil IP in our internal structures for service %s, this shouldn't happen",
						svcName)
					continue
				}
				if epIP.To4() != nil {
					family = v1.IPv4Protocol
					familyClusterIPs = clusterIPs[v1.IPv4Protocol]
					familyExternalIPs = externalIPs[v1.IPv4Protocol]
					//nolint:gocritic // we intend to append to separate maps here
					familyNodeIPs = append(nsc.nodeIPv4Addrs[v1.NodeInternalIP],
						nsc.nodeIPv4Addrs[v1.NodeExternalIP]...)
					rulesMap = ipv4RulesNeeded
				} else {
					family = v1.IPv6Protocol
					familyClusterIPs = clusterIPs[v1.IPv6Protocol]
					familyExternalIPs = externalIPs[v1.IPv6Protocol]
					//nolint:gocritic // we intend to append to separate maps here
					familyNodeIPs = append(nsc.nodeIPv6Addrs[v1.NodeInternalIP],
						nsc.nodeIPv6Addrs[v1.NodeExternalIP]...)
					rulesMap = ipv6RulesNeeded
				}
				if len(familyClusterIPs) < 1 {
					klog.Infof("service %s - endpoint %s didn't have any IPs that matched it's IP family, skipping",
						svcName, epIP)
					continue
				}

				// Handle ClusterIP Service
				hairpinRuleFrom(familyClusterIPs, ep.ip, family, svcInfo.port, rulesMap)

				// Handle ExternalIPs if requested
				if svcInfo.hairpinExternalIPs {
					hairpinRuleFrom(familyExternalIPs, ep.ip, family, svcInfo.port, rulesMap)
				}

				// Handle NodePort Service
				if svcInfo.nodePort != 0 {
					hairpinRuleFrom(familyNodeIPs, ep.ip, family, svcInfo.nodePort, rulesMap)
				}
			}
		}
	}

	// Cleanup (if needed) and return if there's no hairpin-mode Services
	if len(ipv4RulesNeeded) == 0 && nsc.isIPv4Capable {
		klog.V(1).Info("No IPv4 hairpin-mode enabled services found -- no hairpin rules created")
		err := nsc.deleteHairpinIptablesRules(v1.IPv4Protocol)
		if err != nil {
			return fmt.Errorf("error deleting hairpin rules: %v", err)
		}
	}
	if len(ipv6RulesNeeded) == 0 && nsc.isIPv6Capable {
		klog.V(1).Info("No IPv6 hairpin-mode enabled services found -- no hairpin rules created")
		err := nsc.deleteHairpinIptablesRules(v1.IPv6Protocol)
		if err != nil {
			return fmt.Errorf("error deleting hairpin rules: %v", err)
		}
	}
	// If both rulesets are blank, then return now as our work is done
	if len(ipv4RulesNeeded) == 0 && len(ipv6RulesNeeded) == 0 {
		return nil
	}

	for handlerFamily, iptablesCmdHandler := range nsc.iptablesCmdHandlers {
		var rulesNeeded map[string][]string
		switch handlerFamily {
		case v1.IPv4Protocol:
			rulesNeeded = ipv4RulesNeeded
		case v1.IPv6Protocol:
			rulesNeeded = ipv6RulesNeeded
		}

		// Ensure that the Hairpin Chain exists
		err := ensureHairpinChain(iptablesCmdHandler)
		if err != nil {
			return err
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
	}

	return nil
}

func (nsc *NetworkServicesController) deleteHairpinIptablesRules(family v1.IPFamily) error {
	iptablesCmdHandler := nsc.iptablesCmdHandlers[family]

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

func (nsc *NetworkServicesController) deleteMasqueradeIptablesRule() error {
	for _, iptablesCmdHandler := range nsc.iptablesCmdHandlers {
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
		return fmt.Sprintf("[%s]:[%d]:[%s]:[%d]:%v (Flags: %s)", protocol, s.AddressFamily, s.Address, s.Netmask,
			s.Port, flags)
	}
}

func ipvsDestinationString(d *ipvs.Destination) string {
	var family string
	switch d.AddressFamily {
	case syscall.AF_INET:
		family = "IPv4"
	case syscall.AF_INET6:
		family = "IPv6"
	}
	return fmt.Sprintf("%s:%v (Family: %s, Weight: %v)", d.Address, d.Port, family, d.Weight)
}

func ipvsSetPersistence(svc *ipvs.Service, p bool, timeout int32) {
	if p {
		svc.Flags |= ipvsPersistentFlagHex
		svc.Timeout = uint32(timeout)
	} else {
		svc.Flags &^= ipvsPersistentFlagHex
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

// setupMangleTableRule: sets up iptables rule to FWMARK the traffic to external IP vip
func (nsc *NetworkServicesController) setupMangleTableRule(ip string, protocol string, port string, fwmark string,
	tcpMSS int) error {
	var iptablesCmdHandler utils.IPTablesHandler
	parsedIP := net.ParseIP(ip)
	if parsedIP.To4() != nil {
		iptablesCmdHandler = nsc.iptablesCmdHandlers[v1.IPv4Protocol]
	} else {
		iptablesCmdHandler = nsc.iptablesCmdHandlers[v1.IPv6Protocol]
	}

	args := []string{"-d", ip, "-m", protocol, "-p", protocol, "--dport", port, "-j", "MARK", "--set-mark", fwmark}
	err := iptablesCmdHandler.AppendUnique("mangle", "PREROUTING", args...)
	if err != nil {
		return fmt.Errorf("failed to run iptables command to set up FWMARK due to %v", err)
	}
	err = iptablesCmdHandler.AppendUnique("mangle", "OUTPUT", args...)
	if err != nil {
		return fmt.Errorf("failed to run iptables command to set up FWMARK due to %v", err)
	}

	// setup iptables rule TCPMSS for DSR mode to fix mtu problem
	mtuArgs := []string{"-d", ip, "-m", tcpProtocol, "-p", tcpProtocol, "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS",
		"--set-mss", strconv.Itoa(tcpMSS)}
	err = iptablesCmdHandler.AppendUnique("mangle", "PREROUTING", mtuArgs...)
	if err != nil {
		return fmt.Errorf("failed to run iptables command to set up TCPMSS due to %v", err)
	}
	mtuArgs[0] = "-s"
	err = iptablesCmdHandler.AppendUnique("mangle", "POSTROUTING", mtuArgs...)
	if err != nil {
		return fmt.Errorf("failed to run iptables command to set up TCPMSS due to %v", err)
	}
	return nil
}

func (nsc *NetworkServicesController) cleanupMangleTableRule(ip string, protocol string, port string,
	fwmark string, tcpMSS int) error {
	var iptablesCmdHandler utils.IPTablesHandler
	parsedIP := net.ParseIP(ip)
	if parsedIP.To4() != nil {
		iptablesCmdHandler = nsc.iptablesCmdHandlers[v1.IPv4Protocol]
	} else {
		iptablesCmdHandler = nsc.iptablesCmdHandlers[v1.IPv6Protocol]
	}

	args := []string{"-d", ip, "-m", protocol, "-p", protocol, "--dport", port, "-j", "MARK", "--set-mark", fwmark}
	exists, err := iptablesCmdHandler.Exists("mangle", "PREROUTING", args...)
	if err != nil {
		return fmt.Errorf("Failed to cleanup iptables command to set up FWMARK due to " + err.Error())
	}
	if exists {
		klog.V(2).Infof("removing mangle rule with: iptables -D PREROUTING -t mangle %s", args)
		err = iptablesCmdHandler.Delete("mangle", "PREROUTING", args...)
		if err != nil {
			return fmt.Errorf("Failed to cleanup iptables command to set up FWMARK due to " + err.Error())
		}
	}
	exists, err = iptablesCmdHandler.Exists("mangle", "OUTPUT", args...)
	if err != nil {
		return fmt.Errorf("Failed to cleanup iptables command to set up FWMARK due to " + err.Error())
	}
	if exists {
		klog.V(2).Infof("removing mangle rule with: iptables -D OUTPUT -t mangle %s", args)
		err = iptablesCmdHandler.Delete("mangle", "OUTPUT", args...)
		if err != nil {
			return fmt.Errorf("Failed to cleanup iptables command to set up FWMARK due to " + err.Error())
		}
	}

	// cleanup iptables rule TCPMSS
	mtuArgs := []string{"-d", ip, "-m", tcpProtocol, "-p", tcpProtocol, "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS",
		"--set-mss", strconv.Itoa(tcpMSS)}
	exists, err = iptablesCmdHandler.Exists("mangle", "PREROUTING", mtuArgs...)
	if err != nil {
		return fmt.Errorf("failed to cleanup iptables command to set up TCPMSS due to %v", err)
	}
	if exists {
		klog.V(2).Infof("removing mangle rule with: iptables -D PREROUTING -t mangle %s", args)
		err = iptablesCmdHandler.Delete("mangle", "PREROUTING", mtuArgs...)
		if err != nil {
			return fmt.Errorf("failed to cleanup iptables command to set up TCPMSS due to %v", err)
		}
	}
	mtuArgs[0] = "-s"
	exists, err = iptablesCmdHandler.Exists("mangle", "POSTROUTING", mtuArgs...)
	if err != nil {
		return fmt.Errorf("failed to cleanup iptables command to set up TCPMSS due to %v", err)
	}
	if exists {
		klog.V(2).Infof("removing mangle rule with: iptables -D POSTROUTING -t mangle %s", args)
		err = iptablesCmdHandler.Delete("mangle", "POSTROUTING", mtuArgs...)
		if err != nil {
			return fmt.Errorf("failed to cleanup iptables command to set up TCPMSS due to %v", err)
		}
	}

	return nil
}

// For DSR it is required that we dont assign the VIP to any interface to avoid martian packets
// http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html
// routeVIPTrafficToDirector: setups policy routing so that FWMARKed packets are delivered locally
func routeVIPTrafficToDirector(fwmark string, family v1.IPFamily) error {
	ipArgs := make([]string, 0)
	if family == v1.IPv6Protocol {
		ipArgs = append(ipArgs, "-6")
	}

	out, err := runIPCommandsWithArgs(ipArgs, "rule", "list").Output()
	if err != nil {
		return errors.New("Failed to verify if `ip rule` exists due to: " + err.Error())
	}
	if !strings.Contains(string(out), fwmark+" ") {
		err = runIPCommandsWithArgs(ipArgs, "rule", "add", "prio", "32764", "fwmark", fwmark, "table",
			customDSRRouteTableID).Run()
		if err != nil {
			return errors.New("Failed to add policy rule to lookup traffic to VIP through the custom " +
				" routing table due to " + err.Error())
		}
	}
	return nil
}

// isEndpointsForLeaderElection checks to see if this change has to do with leadership elections
//
// Deprecated: this is no longer used because we use EndpointSlices instead of Endpoints in the NSC now, this is
// currently preserved for posterity, but will be removed in the future if it is no longer used
//
//nolint:unused // We understand that this function is unused, but we want to keep it for now
func isEndpointsForLeaderElection(ep *v1.Endpoints) bool {
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
	err = nsc.deleteMasqueradeIptablesRule()
	if err != nil {
		klog.Errorf("Failed to cleanup iptablesmasquerade rule due to: %s", err.Error())
		return
	}

	// cleanup iptables hairpin rules
	err = nsc.deleteHairpinIptablesRules(v1.IPv4Protocol)
	if err != nil {
		klog.Errorf("Failed to cleanup iptables hairpin rules: %s", err.Error())
		return
	}
	err = nsc.deleteHairpinIptablesRules(v1.IPv6Protocol)
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

func (nsc *NetworkServicesController) newEndpointSliceEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			nsc.handleEndpointSliceAdd(obj)

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			nsc.handleEndpointSliceUpdate(oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			nsc.handleEndpointSliceDelete(obj)
		},
	}
}

func (nsc *NetworkServicesController) handleEndpointSliceAdd(obj interface{}) {
	endpoints, ok := obj.(*discovery.EndpointSlice)
	if !ok {
		klog.Errorf("unexpected object type: %v", obj)
		return
	}
	nsc.OnEndpointsUpdate(endpoints)
}

func (nsc *NetworkServicesController) handleEndpointSliceUpdate(oldObj, newObj interface{}) {
	_, ok := oldObj.(*discovery.EndpointSlice)
	if !ok {
		klog.Errorf("unexpected object type: %v", oldObj)
		return
	}
	newEndpoints, ok := newObj.(*discovery.EndpointSlice)
	if !ok {
		klog.Errorf("unexpected object type: %v", newObj)
		return
	}
	nsc.OnEndpointsUpdate(newEndpoints)
}

func (nsc *NetworkServicesController) handleEndpointSliceDelete(obj interface{}) {
	endpoints, ok := obj.(*discovery.EndpointSlice)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("unexpected object type: %v", obj)
			return
		}
		if endpoints, ok = tombstone.Obj.(*discovery.EndpointSlice); !ok {
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
	service, ok := obj.(*v1.Service)
	if !ok {
		klog.Errorf("unexpected object type: %v", obj)
		return
	}
	nsc.OnServiceUpdate(service)
}

func (nsc *NetworkServicesController) handleServiceUpdate(oldObj, newObj interface{}) {
	_, ok := oldObj.(*v1.Service)
	if !ok {
		klog.Errorf("unexpected object type: %v", oldObj)
		return
	}
	newService, ok := newObj.(*v1.Service)
	if !ok {
		klog.Errorf("unexpected object type: %v", newObj)
		return
	}
	nsc.OnServiceUpdate(newService)
}

func (nsc *NetworkServicesController) handleServiceDelete(obj interface{}) {
	service, ok := obj.(*v1.Service)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("unexpected object type: %v", obj)
			return
		}
		if service, ok = tombstone.Obj.(*v1.Service); !ok {
			klog.Errorf("unexpected object type: %v", obj)
			return
		}
	}
	nsc.OnServiceUpdate(service)
}

// NewNetworkServicesController returns NetworkServicesController object
func NewNetworkServicesController(clientset kubernetes.Interface,
	config *options.KubeRouterConfig, svcInformer cache.SharedIndexInformer,
	epSliceInformer cache.SharedIndexInformer, podInformer cache.SharedIndexInformer,
	nodeInfomer cache.SharedIndexInformer,
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
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerIpvsServices)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerIpvsServicesSyncTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ServiceBpsIn)
		metrics.DefaultRegisterer.MustRegister(metrics.ServiceBpsOut)
		metrics.DefaultRegisterer.MustRegister(metrics.ServiceBytesIn)
		metrics.DefaultRegisterer.MustRegister(metrics.ServiceBytesOut)
		metrics.DefaultRegisterer.MustRegister(metrics.ServiceCPS)
		metrics.DefaultRegisterer.MustRegister(metrics.ServicePacketsIn)
		metrics.DefaultRegisterer.MustRegister(metrics.ServicePacketsOut)
		metrics.DefaultRegisterer.MustRegister(metrics.ServicePpsIn)
		metrics.DefaultRegisterer.MustRegister(metrics.ServicePpsOut)
		metrics.DefaultRegisterer.MustRegister(metrics.ServiceTotalConn)
		nsc.MetricsEnabled = true
	}

	nsc.syncPeriod = config.IpvsSyncPeriod
	nsc.syncChan = make(chan int, 2)
	nsc.gracefulPeriod = config.IpvsGracefulPeriod
	nsc.gracefulTermination = config.IpvsGracefulTermination
	nsc.globalHairpin = config.GlobalHairpinMode

	nsc.serviceMap = make(serviceInfoMap)
	nsc.endpointsMap = make(endpointSliceInfoMap)
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
		node, err := utils.GetNodeObject(nsc.client, config.HostnameOverride)
		if err != nil {
			return nil, fmt.Errorf("failed to get node object due to: %v", err.Error())
		}

		cidr, err := utils.GetPodCidrFromNodeSpec(node)
		if err != nil {
			return nil, fmt.Errorf("failed to get pod CIDR details from Node.spec: %v", err)
		}
		nsc.podCidr = cidr

		nsc.podIPv4CIDRs, nsc.podIPv6CIDRs, err = utils.GetPodCIDRsFromNodeSpecDualStack(node)
		if err != nil {
			return nil, fmt.Errorf("failed to get pod CIDRs detail from Node.spec: %v", err)
		}
	}

	nsc.excludedCidrs = make([]net.IPNet, len(config.ExcludedCidrs))
	for i, excludedCidr := range config.ExcludedCidrs {
		_, ipnet, err := net.ParseCIDR(excludedCidr)
		if err != nil {
			return nil, fmt.Errorf("failed to get excluded CIDR details: %v", err)
		}
		nsc.excludedCidrs[i] = *ipnet
	}

	node, err := utils.GetNodeObject(clientset, config.HostnameOverride)
	if err != nil {
		return nil, err
	}

	nsc.nodeHostName = node.Name
	// We preserve the old logic here for getting the primary IP which is set on nrc.primaryIP. This can be either IPv4
	// or IPv6
	nsc.primaryIP, err = utils.GetPrimaryNodeIP(node)
	if err != nil {
		return nil, err
	}

	// Here we test to see whether the node is IPv6 capable, if the user has enabled IPv6 (via command-line options)
	// and the node has an IPv6 address, the following method will return an IPv6 address
	nsc.nodeIPv4Addrs, nsc.nodeIPv6Addrs = utils.GetAllNodeIPs(node)
	if config.EnableIPv4 && len(nsc.nodeIPv4Addrs[v1.NodeInternalIP]) < 1 &&
		len(nsc.nodeIPv4Addrs[v1.NodeExternalIP]) < 1 {
		return nil, fmt.Errorf("IPv4 was enabled, but no IPv4 address was found on the node")
	}
	nsc.isIPv4Capable = len(nsc.nodeIPv4Addrs) > 0
	if config.EnableIPv6 && len(nsc.nodeIPv6Addrs[v1.NodeInternalIP]) < 1 &&
		len(nsc.nodeIPv6Addrs[v1.NodeExternalIP]) < 1 {
		return nil, fmt.Errorf("IPv6 was enabled, but no IPv6 address was found on the node")
	}
	nsc.isIPv6Capable = len(nsc.nodeIPv6Addrs) > 0

	nsc.ipSetHandlers = make(map[v1.IPFamily]utils.IPSetHandler)
	nsc.iptablesCmdHandlers = make(map[v1.IPFamily]utils.IPTablesHandler)
	if len(nsc.nodeIPv4Addrs) > 0 {
		iptHandler, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		if err != nil {
			klog.Fatalf("Failed to allocate IPv4 iptables handler: %v", err)
			return nil, fmt.Errorf("failed to create iptables handler: %w", err)
		}
		nsc.iptablesCmdHandlers[v1.IPv4Protocol] = iptHandler

		ipset, err := utils.NewIPSet(false)
		if err != nil {
			klog.Fatalf("Failed to allocate IPv4 ipset handler: %v", err)
			return nil, fmt.Errorf("failed to create ipset handler: %w", err)
		}
		nsc.ipSetHandlers[v1.IPv4Protocol] = ipset
	}
	if len(nsc.nodeIPv6Addrs) > 0 {
		iptHandler, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			klog.Fatalf("Failed to allocate IPv6 iptables handler: %v", err)
			return nil, fmt.Errorf("failed to create iptables handler: %w", err)
		}
		nsc.iptablesCmdHandlers[v1.IPv6Protocol] = iptHandler

		ipset, err := utils.NewIPSet(true)
		if err != nil {
			klog.Fatalf("Failed to allocate IPv6 ipset handler: %v", err)
			return nil, fmt.Errorf("failed to create ipset handler: %w", err)
		}
		nsc.ipSetHandlers[v1.IPv6Protocol] = ipset
	}

	automtu, err := utils.GetMTUFromNodeIP(nsc.primaryIP)
	if err != nil {
		return nil, err
	}
	// Sets it to 60 bytes less than the auto-detected MTU to account for additional ip-ip headers needed for DSR, above
	// method GetMTUFromNodeIP() already accounts for the overhead of ip-ip overlay networking, so we need to
	// remove 60 bytes (internet headers and additional ip-ip because MTU includes internet headers. MSS does not.)
	// This needs also a condition to deal with auto-mtu=false
	nsc.dsrTCPMSS = automtu - utils.IPInIPHeaderLength*3

	nsc.nodeWeightAnnotation = config.NodeWeightAnnotation
	klog.V(2).Infof("Network services controller using '%s' node weight annotation", nsc.nodeWeightAnnotation)
	nsc.defaultNodeWeight = int(config.NodeDefaultWeight)
	klog.V(2).Infof("Network services controller using '%d' as default node weight", nsc.defaultNodeWeight)

	nsc.podLister = podInformer.GetIndexer()

	nsc.svcLister = svcInformer.GetIndexer()
	nsc.ServiceEventHandler = nsc.newSvcEventHandler()

	nsc.ipvsPermitAll = config.IpvsPermitAll

	nsc.epLister = epSliceInformer.GetIndexer()
	nsc.EndpointSliceEventHandler = nsc.newEndpointSliceEventHandler()

	nsc.nodeListener = nodeInfomer.GetIndexer()
	nsc.NodeEventHandler = nsc.newNodeEventHandler()

	return &nsc, nil
}
