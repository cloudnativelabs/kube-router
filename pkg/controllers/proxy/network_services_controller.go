package proxy

import (
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
	kubeRouterProxyName      = "kube-router"

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

	// kube-router custom labels / annotations
	svcDSRAnnotation                = "kube-router.io/service.dsr"
	svcSchedulerAnnotation          = "kube-router.io/service.scheduler"
	svcHairpinAnnotation            = "kube-router.io/service.hairpin"
	svcHairpinExternalIPsAnnotation = "kube-router.io/service.hairpin.externalips"
	svcLocalAnnotation              = "kube-router.io/service.local"
	svcSkipLbIpsAnnotation          = "kube-router.io/service.skiplbips"
	svcSchedFlagsAnnotation         = "kube-router.io/service.schedflags"

	// kubernetes standard labels / annotations
	svcProxyNameLabel = "service.kubernetes.io/service-proxy-name"
	svcHeadlessLabel  = "service.kubernetes.io/headless"

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
	krNode              utils.NodeAware
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

	svcLister     cache.Indexer
	epSliceLister cache.Indexer
	podLister     cache.Indexer

	EndpointSliceEventHandler cache.ResourceEventHandler
	ServiceEventHandler       cache.ResourceEventHandler

	gracefulPeriod      time.Duration
	gracefulQueue       gracefulQueue
	gracefulTermination bool
	syncChan            chan int
	dsr                 *dsrOpt
	dsrTCPMSS           int

	iptablesCmdHandlers map[v1.IPFamily]utils.IPTablesHandler
	ipSetHandlers       map[v1.IPFamily]utils.IPSetHandler
	podIPv4CIDRs        []string
	podIPv6CIDRs        []string

	hpc                *hairpinController
	hpEndpointReceiver chan string

	nphc *nodePortHealthCheckController
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
	intTrafficPolicy              *v1.ServiceInternalTrafficPolicy
	extTrafficPolicy              *v1.ServiceExternalTrafficPolicy
	flags                         schedFlags
	healthCheckNodePort           int
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
	ip            string
	port          int
	isLocal       bool
	isIPv4        bool
	isIPv6        bool
	isReady       bool
	isServing     bool
	isTerminating bool
}

// map of all endpoints, with unique service id(namespace name, service name, port) as key
type endpointSliceInfoMap map[string][]endpointSliceInfo

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
		klog.Fatalf("error cleaning up old/bad masquerade rules: %s", err.Error())
	}

	// Run the hairpin controller
	if nsc.hpc != nil {
		wg.Add(1)
		go nsc.hpc.Run(stopCh, wg, healthChan)
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

	// Ensure rp_filter=2 for DSR capability, see:
	// * https://access.redhat.com/solutions/53031
	// * https://github.com/cloudnativelabs/kube-router/pull/1651#issuecomment-2072851683
	if nsc.krNode.IsIPv4Capable() {
		sysctlErr := utils.SetSysctlSingleTemplate(utils.IPv4ConfRPFilterTemplate, "all", 2)
		if sysctlErr != nil {
			if sysctlErr.IsFatal() {
				klog.Fatal(sysctlErr.Error())
			} else {
				klog.Error(sysctlErr.Error())
			}
		}
	}

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
			nsc.nphc.StopAll()
			klog.Info("Shutting down network services controller")
			return

		case <-gracefulTicker.C:
			if nsc.readyForUpdates && nsc.gracefulTermination {
				klog.V(3).Info("Performing periodic graceful destination cleanup")
				nsc.gracefulSync()
			}

		case perform := <-nsc.syncChan:
			healthcheck.SendHeartBeat(healthChan, healthcheck.NetworkServicesController)
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
				healthcheck.SendHeartBeat(healthChan, healthcheck.NetworkServicesController)
			}

		case <-t.C:
			klog.V(1).Info("Performing periodic sync of ipvs services")
			healthcheck.SendHeartBeat(healthChan, healthcheck.NetworkServicesController)
			err := nsc.doSync()
			if err != nil {
				klog.Errorf("Error during periodic ipvs sync in network service controller. Error: " + err.Error())
				klog.Errorf("Skipping sending heartbeat from network service controller as periodic sync failed.")
			} else {
				healthcheck.SendHeartBeat(healthChan, healthcheck.NetworkServicesController)
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
		var icmpRejectType string
		//nolint:exhaustive // we don't need exhaustive searching for IP Families
		switch family {
		case v1.IPv4Protocol:
			icmpRejectType = "icmp-port-unreachable"
		case v1.IPv6Protocol:
			icmpRejectType = "icmp6-port-unreachable"
		}

		// Add common IPv4/IPv6 ICMP rules to the default network policy chain to ensure that pods communicate properly
		icmpRules := utils.CommonICMPRules(family)
		for _, icmpRule := range icmpRules {
			icmpArgs := []string{"-m", "comment", "--comment", icmpRule.Comment, "-p", icmpRule.IPTablesProto,
				icmpRule.IPTablesType, icmpRule.ICMPType, "-j", "ACCEPT"}
			err = iptablesCmdHandler.AppendUnique("filter", ipvsFirewallChainName, icmpArgs...)
			if err != nil {
				return fmt.Errorf("failed to run iptables command: %v", err)
			}
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
		if family == v1.IPv4Protocol && !nsc.krNode.IsIPv4Capable() {
			continue
		}
		if family == v1.IPv6Protocol && !nsc.krNode.IsIPv6Capable() {
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
			port = int(ipvsService.Port)

			isValid, err := nsc.isValidKubeRouterServiceArtifact(address, port)
			if err != nil {
				klog.Infof("failed to lookup service by address %s: %v - this does not appear to be a kube-router "+
					"controlled service, skipping...", address, err)
				continue
			}
			if !isValid {
				klog.Infof("address %s is not a valid kube-router controlled service, skipping...", address)
				continue
			}

			protocol = convertSysCallProtoToSvcProto(ipvsService.Protocol)
			if protocol == noneProtocol {
				klog.Warningf("failed to convert protocol %d to a valid IPVS protocol for service: %s skipping",
					ipvsService.Protocol, ipvsService.Address.String())
				continue
			}
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
				klog.Warningf("failed to parse IP %s returned from FWMark %d - this may not be a kube-router"+
					"controlled service, but if it is then something's gone wrong", ipString, ipvsService.FWMark)
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
			case nsc.krNode.GetPrimaryNodeIP().String():
				if protocol == ipvsSvc.Protocol && uint16(svc.port) == ipvsSvc.Port {
					pushMetric = true
					svcVip = nsc.krNode.GetPrimaryNodeIP().String()
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
	if utils.ServiceHasNoClusterIP(svc) {
		klog.V(1).Infof("The service associated with endpoint: %s/%s is headless, skipping...",
			es.Namespace, es.Name)
		return
	}

	// build new service and endpoints map to reflect the change
	newServiceMap := nsc.buildServicesInfo()
	newEndpointsMap := nsc.buildEndpointSliceInfo()

	if !endpointsMapsEquivalent(newEndpointsMap, nsc.endpointsMap) {
		nsc.endpointsMap = newEndpointsMap
		nsc.serviceMap = newServiceMap
		klog.V(1).Infof("Syncing IPVS services sync for update to endpoint: %s/%s", es.Namespace, es.Name)
		nsc.sync(synctypeIpvs)
	} else {
		klog.V(1).Infof("Skipping IPVS services sync on endpoint: %s/%s update as nothing changed",
			es.Namespace, es.Name)
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
	if utils.ServiceHasNoClusterIP(svc) {
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

		proxyName, err := getLabelFromMap(svcProxyNameLabel, svc.Labels)
		if err == nil && proxyName != kubeRouterProxyName {
			klog.V(2).Infof("Skipping service name:%s namespace:%s due to service-proxy-name label not being one "+
				"that belongs to kube-router", svc.Name, svc.Namespace)
			continue
		}

		// We handle headless service labels differently from a "None" or blank ClusterIP because ClusterIP is
		// guaranteed to be immuteable whereas labels can be added / removed
		_, err = getLabelFromMap(svcHeadlessLabel, svc.Labels)
		if err == nil {
			klog.V(2).Infof("Skipping service name:%s namespace:%s due to headless label being set", svc.Name,
				svc.Namespace)
			continue
		}

		intClusterPolicyDefault := v1.ServiceInternalTrafficPolicyCluster
		extClusterPolicyDefault := v1.ServiceExternalTrafficPolicyCluster
		for _, port := range svc.Spec.Ports {
			svcInfo := serviceInfo{
				clusterIP:           net.ParseIP(svc.Spec.ClusterIP),
				clusterIPs:          make([]string, len(svc.Spec.ClusterIPs)),
				port:                int(port.Port),
				targetPort:          port.TargetPort.String(),
				protocol:            strings.ToLower(string(port.Protocol)),
				nodePort:            int(port.NodePort),
				name:                svc.ObjectMeta.Name,
				namespace:           svc.ObjectMeta.Namespace,
				externalIPs:         make([]string, len(svc.Spec.ExternalIPs)),
				intTrafficPolicy:    &intClusterPolicyDefault,
				extTrafficPolicy:    &extClusterPolicyDefault,
				healthCheckNodePort: int(svc.Spec.HealthCheckNodePort),
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
			_, svcInfo.skipLbIps = svc.ObjectMeta.Annotations[svcSkipLbIpsAnnotation]
			svcInfo.intTrafficPolicy = svc.Spec.InternalTrafficPolicy
			svcInfo.extTrafficPolicy = &svc.Spec.ExternalTrafficPolicy

			// The kube-router.io/service.local annotation has the ability to override the internal and external traffic
			// policy that is set in the spec. In this case we set both to local when the annotation is true so that
			// previous functionality of the annotation is best preserved.
			if svc.ObjectMeta.Annotations[svcLocalAnnotation] == "true" {
				intTrafficPolicyLocal := v1.ServiceInternalTrafficPolicyLocal
				extTrafficPolicyLocal := v1.ServiceExternalTrafficPolicyLocal
				svcInfo.intTrafficPolicy = &intTrafficPolicyLocal
				svcInfo.extTrafficPolicy = &extTrafficPolicyLocal
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
	for _, obj := range nsc.epSliceLister.List() {
		var isIPv4, isIPv6 bool
		es := obj.(*discovery.EndpointSlice)
		klog.V(2).Infof("Building endpoint info for EndpointSlice: %s/%s", es.Namespace, es.Name)
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
			// We should only look at serving or ready if we want to be compliant with the upstream expectantions of a
			// network provider
			if (ep.Conditions.Serving == nil || !*ep.Conditions.Serving) &&
				(ep.Conditions.Ready == nil || !*ep.Conditions.Ready) {
				klog.V(2).Infof("Endpoint (with addresses %s) does not have a ready or serving status, skipping...",
					ep.Addresses)
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
					isLocal := ep.NodeName != nil && *ep.NodeName == nsc.krNode.GetNodeName()
					endpoints = append(endpoints, endpointSliceInfo{
						ip:            addr,
						port:          int(*port.Port),
						isLocal:       isLocal,
						isIPv4:        isIPv4,
						isIPv6:        isIPv6,
						isReady:       ep.Conditions.Ready != nil && *ep.Conditions.Ready,
						isServing:     ep.Conditions.Serving != nil && *ep.Conditions.Serving,
						isTerminating: ep.Conditions.Terminating != nil && *ep.Conditions.Terminating,
					})
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
					familyNodeIPs = nsc.krNode.GetNodeIPv4Addrs()
					rulesMap = ipv4RulesNeeded
				} else {
					family = v1.IPv6Protocol
					familyClusterIPs = clusterIPs[v1.IPv6Protocol]
					familyExternalIPs = externalIPs[v1.IPv6Protocol]
					familyNodeIPs = nsc.krNode.GetNodeIPv6Addrs()
					rulesMap = ipv6RulesNeeded
				}
				if len(familyClusterIPs) < 1 {
					klog.Infof("service %s - endpoint %s didn't have any IPs that matched it's IP family, skipping",
						svcName, epIP)
					continue
				}

				// Ensure that hairpin mode is enabled for the virtual interface assigned to the pod behind the endpoint
				// IP.
				//
				// This used to be handled by the kubelet, and then later the functionality was moved to the docker-shim
				// but now the docker-shim has been removed, and its possible that it never existed for containerd or
				// cri-o so we now ensure that it is handled.
				//
				// Without this change, the return traffic from a client to a service within the same pod will never
				// make it back into the pod's namespace
				if nsc.hpc != nil {
					nsc.hpEndpointReceiver <- ep.ip
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
	if len(ipv4RulesNeeded) == 0 && nsc.krNode.IsIPv4Capable() {
		klog.V(1).Info("No IPv4 hairpin-mode enabled services found -- no hairpin rules created")
		err := nsc.deleteHairpinIptablesRules(v1.IPv4Protocol)
		if err != nil {
			return fmt.Errorf("error deleting hairpin rules: %v", err)
		}
	}
	if len(ipv6RulesNeeded) == 0 && nsc.krNode.IsIPv6Capable() {
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
		//nolint:exhaustive // we don't need exhaustive searching for IP Families
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
	// only reply packets from PODs are altered here
	if protocol == tcpProtocol {
		mtuArgs := []string{"-s", ip, "-m", tcpProtocol, "-p", tcpProtocol, "--sport", port, "-i", "kube-bridge",
			"--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", strconv.Itoa(tcpMSS)}
		err = iptablesCmdHandler.AppendUnique("mangle", "PREROUTING", mtuArgs...)
		if err != nil {
			return fmt.Errorf("failed to run iptables command to set up TCPMSS due to %v", err)
		}
	}

	// Previous versions of MTU args were this way, we will clean then up for the next couple of versions to ensure
	// that old mangle table rules don't stick around
	// TODO: remove after v2.4.X or above
	for firstArg, chain := range map[string]string{"-s": "POSTROUTING", "-d": "PREROUTING"} {
		prevMTUArgs := []string{firstArg, ip, "-m", tcpProtocol, "-p", tcpProtocol, "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--set-mss", strconv.Itoa(tcpMSS)}
		klog.V(2).Infof("looking for mangle rule with: %s -t mangle %s", chain, prevMTUArgs)
		exists, err := iptablesCmdHandler.Exists("mangle", chain, prevMTUArgs...)
		if err != nil {
			return fmt.Errorf("failed to cleanup iptables command to set up TCPMSS due to %v", err)
		}
		if exists {
			klog.V(2).Infof("removing mangle rule with: iptables -D %s -t mangle %s", chain, prevMTUArgs)
			err = iptablesCmdHandler.Delete("mangle", chain, prevMTUArgs...)
			if err != nil {
				return fmt.Errorf("failed to cleanup iptables command to set up TCPMSS due to %v", err)
			}
		}
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
		return fmt.Errorf("failed to cleanup iptables command to set up FWMARK due to %v", err)
	}
	if exists {
		klog.V(2).Infof("removing mangle rule with: iptables -D PREROUTING -t mangle %s", args)
		err = iptablesCmdHandler.Delete("mangle", "PREROUTING", args...)
		if err != nil {
			return fmt.Errorf("failed to cleanup iptables command to set up FWMARK due to %v", err)
		}
	}
	exists, err = iptablesCmdHandler.Exists("mangle", "OUTPUT", args...)
	if err != nil {
		return fmt.Errorf("failed to cleanup iptables command to set up FWMARK due to %v", err)
	}
	if exists {
		klog.V(2).Infof("removing mangle rule with: iptables -D OUTPUT -t mangle %s", args)
		err = iptablesCmdHandler.Delete("mangle", "OUTPUT", args...)
		if err != nil {
			return fmt.Errorf("failed to cleanup iptables command to set up FWMARK due to %v", err)
		}
	}

	// cleanup iptables rule TCPMSS
	// only reply packets from PODs are altered here
	if protocol == tcpProtocol {
		mtuArgs := []string{"-s", ip, "-m", tcpProtocol, "-p", tcpProtocol, "--sport", port, "-i", "kube-bridge",
			"--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", strconv.Itoa(tcpMSS)}
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

	// In prep for further steps make sure that ipset and iptables handlers are created
	if len(nsc.iptablesCmdHandlers) < 1 {
		// Even though we have a config at this point (via passed param), we want to send nil so that the node will
		// discover which IP address families it has and act accordingly
		err = nsc.setupHandlers(nil)
		if err != nil {
			klog.Errorf("could not cleanup because we couldn't create iptables/ipset command handlers due to: %v", err)
		}
	}

	// cleanup iptables masquerade rule
	err = nsc.deleteMasqueradeIptablesRule()
	if err != nil {
		klog.Errorf("Failed to cleanup iptablesmasquerade rule due to: %s", err.Error())
		return
	}

	// cleanup iptables hairpin rules
	if _, ok := nsc.iptablesCmdHandlers[v1.IPv4Protocol]; ok {
		klog.Info("Processing IPv4 hairpin rule cleanup")
		err = nsc.deleteHairpinIptablesRules(v1.IPv4Protocol)
		if err != nil {
			klog.Errorf("Failed to cleanup iptables hairpin rules: %s", err.Error())
			return
		}
	}
	if _, ok := nsc.iptablesCmdHandlers[v1.IPv6Protocol]; ok {
		klog.Info("Processing IPv6 hairpin rule cleanup")
		err = nsc.deleteHairpinIptablesRules(v1.IPv6Protocol)
		if err != nil {
			klog.Errorf("Failed to cleanup iptables hairpin rules: %s", err.Error())
			return
		}
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

// setupHandlers Here we test to see whether the node is IPv6 capable, if the user has enabled IPv6 (via command-line
// options) and the node has an IPv6 address, the following method will return an IPv6 address
func (nsc *NetworkServicesController) setupHandlers(node *v1.Node) error {
	nsc.ipSetHandlers = make(map[v1.IPFamily]utils.IPSetHandler)
	nsc.iptablesCmdHandlers = make(map[v1.IPFamily]utils.IPTablesHandler)

	// node being nil covers the case where this function is called by something that doesn't have a kube-apiserver
	// connection like the cleanup code. In this instance we want all possible iptables and ipset handlers
	if node == nil || nsc.krNode == nil || nsc.krNode.IsIPv4Capable() {
		iptHandler, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		if err != nil {
			klog.Fatalf("Failed to allocate IPv4 iptables handler: %v", err)
			return fmt.Errorf("failed to create iptables handler: %w", err)
		}
		nsc.iptablesCmdHandlers[v1.IPv4Protocol] = iptHandler

		ipset, err := utils.NewIPSet(false)
		if err != nil {
			klog.Fatalf("Failed to allocate IPv4 ipset handler: %v", err)
			return fmt.Errorf("failed to create ipset handler: %w", err)
		}
		nsc.ipSetHandlers[v1.IPv4Protocol] = ipset
	}
	if node == nil || nsc.krNode == nil || nsc.krNode.IsIPv6Capable() {
		iptHandler, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			klog.Fatalf("Failed to allocate IPv6 iptables handler: %v", err)
			return fmt.Errorf("failed to create iptables handler: %w", err)
		}
		nsc.iptablesCmdHandlers[v1.IPv6Protocol] = iptHandler

		ipset, err := utils.NewIPSet(true)
		if err != nil {
			klog.Fatalf("Failed to allocate IPv6 ipset handler: %v", err)
			return fmt.Errorf("failed to create ipset handler: %w", err)
		}
		nsc.ipSetHandlers[v1.IPv6Protocol] = ipset
	}

	return nil
}

// NewNetworkServicesController returns NetworkServicesController object
func NewNetworkServicesController(clientset kubernetes.Interface,
	config *options.KubeRouterConfig, svcInformer cache.SharedIndexInformer,
	epSliceInformer cache.SharedIndexInformer, podInformer cache.SharedIndexInformer,
	ipsetMutex *sync.Mutex) (*NetworkServicesController, error) {

	var err error
	ln, err := newLinuxNetworking(config.ServiceTCPTimeout, config.ServiceTCPFinTimeout, config.ServiceUDPTimeout)
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

	nsc.krNode, err = utils.NewKRNode(node, nil, config.EnableIPv4, config.EnableIPv6)
	if err != nil {
		return nil, err
	}

	// This function is responsible for quite a bit:
	// * Sets nsc.nodeIPv4Addrs & nsc.isIPv4Capable
	// * Sets nsc.nodeIPv6Addr & nsc.isIPv6Capable
	// * Creates the iptables handlers for ipv4 & ipv6
	// * Creates the ipset handlers for ipv4 & ipv6
	err = nsc.setupHandlers(node)
	if err != nil {
		return nil, err
	}

	automtu, err := nsc.krNode.GetNodeMTU()
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

	nsc.epSliceLister = epSliceInformer.GetIndexer()
	nsc.EndpointSliceEventHandler = nsc.newEndpointSliceEventHandler()

	// Not creating the hairpin controller for now because this should be handled at the CNI level. The CNI bridge
	// plugin ensures that hairpin mode is set much more reliably than we do. However, as a lot of work was put into
	// the hairpin controller, and so that it is around to reference in the future if needed, I'm leaving the code
	// for now.
	// nsc.hpEndpointReceiver = make(chan string)
	// nsc.hpc = NewHairpinController(&nsc, nsc.hpEndpointReceiver)

	nsc.nphc = NewNodePortHealthCheck()

	return &nsc, nil
}
