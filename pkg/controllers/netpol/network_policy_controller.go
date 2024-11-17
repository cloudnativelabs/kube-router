package netpol

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/v2/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
	"k8s.io/klog/v2"

	v1core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	netutils "k8s.io/utils/net"
)

const (
	kubePodFirewallChainPrefix   = "KUBE-POD-FW-"
	kubeNetworkPolicyChainPrefix = "KUBE-NWPLCY-"
	kubeSourceIPSetPrefix        = "KUBE-SRC-"
	kubeDestinationIPSetPrefix   = "KUBE-DST-"
	kubeInputChainName           = "KUBE-ROUTER-INPUT"
	kubeForwardChainName         = "KUBE-ROUTER-FORWARD"
	kubeOutputChainName          = "KUBE-ROUTER-OUTPUT"
	kubeDefaultNetpolChain       = "KUBE-NWPLCY-DEFAULT"

	kubeIngressPolicyType = "ingress"
	kubeEgressPolicyType  = "egress"
	kubeBothPolicyType    = "both"

	syncVersionBase = 10
)

var (
	defaultChains = map[string]string{
		"INPUT":   kubeInputChainName,
		"FORWARD": kubeForwardChainName,
		"OUTPUT":  kubeOutputChainName,
	}
)

// Network policy controller provides both ingress and egress filtering for the pods as per the defined network
// policies. Two different types of iptables chains are used. Each pod running on the node which either
// requires ingress or egress filtering gets a pod specific chains. Each network policy has a iptables chain, which
// has rules expressed through ipsets matching source and destination pod ip's. In the FORWARD chain of the
// filter table a rule is added to jump the traffic originating (in case of egress network policy) from the pod
// or destined (in case of ingress network policy) to the pod specific iptables chain. Each
// pod specific iptables chain has rules to jump to the network polices chains, that pod matches. So packet
// originating/destined from/to pod goes through filter table's, FORWARD chain, followed by pod specific chain,
// followed by one or more network policy chains, till there is a match which will accept the packet, or gets
// dropped by the rule in the pod chain, if there is no match.

// NetworkPolicyController struct to hold information required by NetworkPolicyController
type NetworkPolicyController struct {
	krNode                      utils.NodeIPAndFamilyAware
	serviceClusterIPRanges      []net.IPNet
	serviceExternalIPRanges     []net.IPNet
	serviceLoadBalancerIPRanges []net.IPNet
	serviceNodePortRange        string
	mu                          sync.Mutex
	syncPeriod                  time.Duration
	MetricsEnabled              bool
	healthChan                  chan<- *healthcheck.ControllerHeartbeat
	fullSyncRequestChan         chan struct{}
	ipsetMutex                  *sync.Mutex

	iptablesCmdHandlers map[v1core.IPFamily]utils.IPTablesHandler
	iptablesSaveRestore map[v1core.IPFamily]utils.IPTablesSaveRestorer
	filterTableRules    map[v1core.IPFamily]*bytes.Buffer
	ipSetHandlers       map[v1core.IPFamily]utils.IPSetHandler

	podLister cache.Indexer
	npLister  cache.Indexer
	nsLister  cache.Indexer

	PodEventHandler           cache.ResourceEventHandler
	NamespaceEventHandler     cache.ResourceEventHandler
	NetworkPolicyEventHandler cache.ResourceEventHandler
}

// internal structure to represent a network policy
type networkPolicyInfo struct {
	name        string
	namespace   string
	podSelector labels.Selector

	// set of pods matching network policy spec podselector label selector
	targetPods map[string]podInfo

	// whitelist ingress rules from the network policy spec
	ingressRules []ingressRule

	// whitelist egress rules from the network policy spec
	egressRules []egressRule

	// policy type "ingress" or "egress" or "both" as defined by PolicyType in the spec
	policyType string
}

// internal structure to represent Pod
type podInfo struct {
	ip        string
	ips       []v1core.PodIP
	name      string
	namespace string
	labels    map[string]string
}

// internal structure to represent NetworkPolicyIngressRule in the spec
type ingressRule struct {
	matchAllPorts  bool
	ports          []protocolAndPort
	namedPorts     []endPoints
	matchAllSource bool
	srcPods        []podInfo
	srcIPBlocks    map[v1core.IPFamily][][]string
}

// internal structure to represent NetworkPolicyEgressRule in the spec
type egressRule struct {
	matchAllPorts        bool
	ports                []protocolAndPort
	namedPorts           []endPoints
	matchAllDestinations bool
	dstPods              []podInfo
	dstIPBlocks          map[v1core.IPFamily][][]string
}

type protocolAndPort struct {
	protocol string
	port     string
	endport  string
}

type endPoints struct {
	ips map[v1core.IPFamily][]string
	protocolAndPort
}

type numericPort2eps map[string]*endPoints
type protocol2eps map[string]numericPort2eps
type namedPort2eps map[string]protocol2eps

// Run runs forever till we receive notification on stopCh
func (npc *NetworkPolicyController) Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{},
	wg *sync.WaitGroup) {
	t := time.NewTicker(npc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	klog.Info("Starting network policy controller")
	npc.healthChan = healthChan

	// setup kube-router specific top level custom chains (KUBE-ROUTER-INPUT, KUBE-ROUTER-FORWARD, KUBE-ROUTER-OUTPUT)
	npc.ensureTopLevelChains()

	// setup default network policy chain that is applied to traffic from/to the pods that does not match any network
	// policy
	npc.ensureDefaultNetworkPolicyChain()

	// Full syncs of the network policy controller take a lot of time and can only be processed one at a time,
	// therefore, we start it in it's own goroutine and request a sync through a single item channel
	klog.Info("Starting network policy controller full sync goroutine")
	wg.Add(1)
	go func(fullSyncRequest <-chan struct{}, stopCh <-chan struct{}, wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			// Add an additional non-blocking select to ensure that if the stopCh channel is closed it is handled first
			select {
			case <-stopCh:
				klog.Info("Shutting down network policies full sync goroutine")
				return
			default:
			}
			select {
			case <-stopCh:
				klog.Info("Shutting down network policies full sync goroutine")
				return
			case <-fullSyncRequest:
				klog.V(3).Info("Received request for a full sync, processing")
				npc.fullPolicySync() // fullPolicySync() is a blocking request here
			}
		}
	}(npc.fullSyncRequestChan, stopCh, wg)

	// loop forever till notified to stop on stopCh
	for {
		klog.V(1).Info("Requesting periodic sync of iptables to reflect network policies")
		npc.RequestFullSync()
		select {
		case <-stopCh:
			klog.Infof("Shutting down network policies controller")
			return
		case <-t.C:
		}
	}
}

// RequestFullSync allows the request of a full network policy sync without blocking the callee
func (npc *NetworkPolicyController) RequestFullSync() {
	select {
	case npc.fullSyncRequestChan <- struct{}{}:
		klog.V(3).Info("Full sync request queue was empty so a full sync request was successfully sent")
	default: // Don't block if the buffered channel is full, return quickly so that we don't block callee execution
		klog.V(1).Info("Full sync request queue was full, skipping...")
	}
}

// Sync synchronizes iptables to desired state of network policies
func (npc *NetworkPolicyController) fullPolicySync() {

	var err error
	var networkPoliciesInfo []networkPolicyInfo
	npc.mu.Lock()
	defer npc.mu.Unlock()

	for ipFamily := range npc.ipSetHandlers {
		// Ensure that we start with clean handlers that don't contain previous save data
		var err error
		//nolint:exhaustive // we don't need a default condition here because we control this ourselves
		switch ipFamily {
		case v1core.IPv4Protocol:
			npc.ipSetHandlers[ipFamily], err = utils.NewIPSet(false)
		case v1core.IPv6Protocol:
			npc.ipSetHandlers[ipFamily], err = utils.NewIPSet(true)
		}
		if err != nil {
			klog.Errorf("failed to create ipset handler: %v", err)
			return
		}
	}

	healthcheck.SendHeartBeat(npc.healthChan, healthcheck.NetworkPolicyController)
	start := time.Now()
	syncVersion := strconv.FormatInt(start.UnixNano(), syncVersionBase)
	defer func() {
		endTime := time.Since(start)
		if npc.MetricsEnabled {
			metrics.ControllerIptablesSyncTime.Observe(endTime.Seconds())
		}
		klog.V(1).Infof("sync iptables took %v", endTime)
	}()

	klog.V(1).Infof("Starting sync of iptables with version: %s", syncVersion)

	// ensure kube-router specific top level chains and corresponding rules exist
	npc.ensureTopLevelChains()

	// ensure default network policy chain that is applied to traffic from/to the pods that does not match any network
	// policy
	npc.ensureDefaultNetworkPolicyChain()

	networkPoliciesInfo, err = npc.buildNetworkPoliciesInfo()
	if err != nil {
		klog.Errorf("Aborting sync. Failed to build network policies: %v", err.Error())
		return
	}

	for ipFamily, iptablesSaveRestore := range npc.iptablesSaveRestore {
		npc.filterTableRules[ipFamily].Reset()
		saveStart := time.Now()
		err := iptablesSaveRestore.SaveInto("filter", npc.filterTableRules[ipFamily])
		saveEndTime := time.Since(saveStart)
		if npc.MetricsEnabled {
			//nolint:exhaustive // we don't need exhaustive searching for IP Families
			switch ipFamily {
			case v1core.IPv4Protocol:
				metrics.ControllerIptablesV4SaveTime.Observe(saveEndTime.Seconds())
			case v1core.IPv6Protocol:
				metrics.ControllerIptablesV6SaveTime.Observe(saveEndTime.Seconds())
			}
		}
		klog.V(1).Infof("Saving %v iptables rules took %v", ipFamily, saveEndTime)

		if err != nil {
			klog.Errorf("Aborting sync. Failed to run iptables-save: %v", err.Error())
			return
		}
	}

	activePolicyChains, activePolicyIPSets, err := npc.syncNetworkPolicyChains(networkPoliciesInfo, syncVersion)
	if err != nil {
		klog.Errorf("Aborting sync. Failed to sync network policy chains: %v", err.Error())
		return
	}

	activePodFwChains := npc.syncPodFirewallChains(networkPoliciesInfo, syncVersion)

	// Makes sure that the ACCEPT rules for packets marked with "0x20000" are added to the end of each of kube-router's
	// top level chains
	npc.ensureExplicitAccept()

	err = npc.cleanupStaleRules(activePolicyChains, activePodFwChains, false)
	if err != nil {
		klog.Errorf("Aborting sync. Failed to cleanup stale iptables rules: %v", err.Error())
		return
	}

	for ipFamily, iptablesSaveRestore := range npc.iptablesSaveRestore {
		ipFamily := ipFamily
		restoreStart := time.Now()
		err := iptablesSaveRestore.Restore("filter", npc.filterTableRules[ipFamily].Bytes())
		restoreEndTime := time.Since(restoreStart)
		if npc.MetricsEnabled {
			//nolint:exhaustive // we don't need exhaustive searching for IP Families
			switch ipFamily {
			case v1core.IPv4Protocol:
				metrics.ControllerIptablesV4RestoreTime.Observe(restoreEndTime.Seconds())
			case v1core.IPv6Protocol:
				metrics.ControllerIptablesV6RestoreTime.Observe(restoreEndTime.Seconds())
			}
		}
		klog.V(1).Infof("Restoring %v iptables rules took %v", ipFamily, restoreEndTime)

		if err != nil {
			klog.Errorf("Aborting sync. Failed to run iptables-restore: %v\n%s",
				err.Error(), npc.filterTableRules[ipFamily].String())
			return
		}
	}

	err = npc.cleanupStaleIPSets(activePolicyIPSets)
	if err != nil {
		klog.Errorf("Failed to cleanup stale ipsets: %v", err.Error())
		return
	}
}

func (npc *NetworkPolicyController) iptablesCmdHandlerForCIDR(cidr *net.IPNet) (utils.IPTablesHandler, error) {
	if netutils.IsIPv4CIDR(cidr) {
		return npc.iptablesCmdHandlers[v1core.IPv4Protocol], nil
	}
	if netutils.IsIPv6CIDR(cidr) {
		return npc.iptablesCmdHandlers[v1core.IPv6Protocol], nil
	}

	return nil, fmt.Errorf("invalid CIDR")
}

func (npc *NetworkPolicyController) allowTrafficToClusterIPRange(
	serviceVIPPosition int,
	serviceClusterIPRange *net.IPNet,
	addUUIDForRuleSpec func(chain string, ruleSpec *[]string) (string, error),
	ensureRuleAtPosition func(iptablesCmdHandler utils.IPTablesHandler,
		chain string, ruleSpec []string, uuid string, position int),
	comment string) {
	whitelistServiceVips := []string{"-m", "comment", "--comment", comment,
		"-d", serviceClusterIPRange.String(), "-j", "RETURN"}
	uuid, err := addUUIDForRuleSpec(kubeInputChainName, &whitelistServiceVips)
	if err != nil {
		klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
	}
	iptablesCmdHandler, err := npc.iptablesCmdHandlerForCIDR(serviceClusterIPRange)
	if err != nil {
		klog.Fatalf("Failed to get iptables handler: %s", err.Error())
	}
	ensureRuleAtPosition(iptablesCmdHandler,
		kubeInputChainName, whitelistServiceVips, uuid, serviceVIPPosition)
}

// Creates custom chains KUBE-ROUTER-INPUT, KUBE-ROUTER-FORWARD, KUBE-ROUTER-OUTPUT
// and following rules in the filter table to jump from builtin chain to custom chain
// -A INPUT   -m comment --comment "kube-router netpol" -j KUBE-ROUTER-INPUT
// -A FORWARD -m comment --comment "kube-router netpol" -j KUBE-ROUTER-FORWARD
// -A OUTPUT  -m comment --comment "kube-router netpol" -j KUBE-ROUTER-OUTPUT
func (npc *NetworkPolicyController) ensureTopLevelChains() {
	const serviceVIPPosition = 1
	rulePosition := map[v1core.IPFamily]int{v1core.IPv4Protocol: 1, v1core.IPv6Protocol: 1}

	addUUIDForRuleSpec := func(chain string, ruleSpec *[]string) (string, error) {
		hash := sha256.Sum256([]byte(chain + strings.Join(*ruleSpec, "")))
		encoded := base32.StdEncoding.EncodeToString(hash[:])[:16]
		for idx, part := range *ruleSpec {
			if part == "--comment" {
				(*ruleSpec)[idx+1] = (*ruleSpec)[idx+1] + " - " + encoded
				return encoded, nil
			}
		}
		return "", fmt.Errorf("could not find a comment in the ruleSpec string given: %s",
			strings.Join(*ruleSpec, " "))
	}

	ensureRuleAtPosition := func(
		iptablesCmdHandler utils.IPTablesHandler, chain string, ruleSpec []string, uuid string, position int) {
		exists, err := iptablesCmdHandler.Exists("filter", chain, ruleSpec...)
		if err != nil {
			klog.Fatalf("Failed to verify rule exists in %s chain due to %s", chain, err.Error())
		}
		if !exists {
			klog.V(2).Infof("Rule '%s' doesn't exist in chain %s, inserting at position %d",
				strings.Join(ruleSpec, " "), chain, position)
			err := iptablesCmdHandler.Insert("filter", chain, position, ruleSpec...)
			if err != nil {
				klog.Fatalf("Failed to run iptables command to insert in %s chain %s", chain, err.Error())
			}
			return
		}
		rules, err := iptablesCmdHandler.List("filter", chain)
		if err != nil {
			klog.Fatalf("failed to list rules in filter table %s chain due to %s", chain, err.Error())
		}

		var ruleNo, ruleIndexOffset int
		for i, rule := range rules {
			rule = strings.Replace(rule, "\"", "", 2) // removes quote from comment string
			if strings.HasPrefix(rule, "-P") || strings.HasPrefix(rule, "-N") {
				// if this chain has a default policy, then it will show as rule #1 from iptablesCmdHandler.List so we
				// need to account for this offset
				ruleIndexOffset++
				continue
			}
			if strings.Contains(rule, uuid) {
				// range uses a 0 index, but iptables uses a 1 index so we need to increase ruleNo by 1
				ruleNo = i + 1 - ruleIndexOffset
				break
			}
		}
		if ruleNo != position {
			klog.V(2).Infof("Rule '%s' existed in chain %s, but was in position %d instead of %d, "+
				"moving...", strings.Join(ruleSpec, " "), chain, ruleNo, position)
			err = iptablesCmdHandler.Insert("filter", chain, position, ruleSpec...)
			if err != nil {
				klog.Fatalf("Failed to run iptables command to insert in %s chain %s", chain, err.Error())
			}
			err = iptablesCmdHandler.Delete("filter", chain, strconv.Itoa(ruleNo+1))
			if err != nil {
				klog.Fatalf("Failed to delete incorrect rule in %s chain due to %s", chain, err.Error())
			}
		}
	}

	for _, handler := range npc.iptablesCmdHandlers {
		for builtinChain, customChain := range defaultChains {
			exists, err := handler.ChainExists("filter", customChain)
			if err != nil {
				klog.Fatalf("failed to run iptables command to create %s chain due to %s", customChain,
					err.Error())
			}
			if !exists {
				klog.V(2).Infof("Custom chain was missing, creating: %s in filter table", customChain)
				err = handler.NewChain("filter", customChain)
				if err != nil {
					klog.Fatalf("failed to run iptables command to create %s chain due to %s", customChain,
						err.Error())
				}
			}
			args := []string{"-m", "comment", "--comment", "kube-router netpol", "-j", customChain}
			uuid, err := addUUIDForRuleSpec(builtinChain, &args)
			if err != nil {
				klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
			}
			klog.V(2).Infof("Ensuring jump to chain %s from %s at position %d", customChain, builtinChain,
				serviceVIPPosition)
			ensureRuleAtPosition(handler, builtinChain, args, uuid, serviceVIPPosition)
		}
	}

	if len(npc.serviceClusterIPRanges) > 0 {
		for idx, serviceRange := range npc.serviceClusterIPRanges {
			var family v1core.IPFamily
			if serviceRange.IP.To4() != nil {
				family = v1core.IPv4Protocol
			} else {
				family = v1core.IPv6Protocol
			}
			klog.V(2).Infof("Allow traffic to ingress towards Cluster IP Range: %s for family: %s",
				serviceRange.String(), family)
			npc.allowTrafficToClusterIPRange(rulePosition[family], &npc.serviceClusterIPRanges[idx],
				addUUIDForRuleSpec, ensureRuleAtPosition, "allow traffic to primary/secondary cluster IP range")
			rulePosition[family]++
		}
	} else {
		klog.Fatalf("Primary service cluster IP range is not configured")
	}

	for family, handler := range npc.iptablesCmdHandlers {
		whitelistTCPNodeports := []string{"-p", "tcp", "-m", "comment", "--comment",
			"allow LOCAL TCP traffic to node ports", "-m", "addrtype", "--dst-type", "LOCAL",
			"-m", "multiport", "--dports", npc.serviceNodePortRange, "-j", "RETURN"}
		uuid, err := addUUIDForRuleSpec(kubeInputChainName, &whitelistTCPNodeports)
		if err != nil {
			klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
		}
		klog.V(2).Infof("Allow TCP traffic to ingress towards node port range: %s for family: %s",
			npc.serviceNodePortRange, family)
		ensureRuleAtPosition(handler,
			kubeInputChainName, whitelistTCPNodeports, uuid, rulePosition[family])
		rulePosition[family]++

		whitelistUDPNodeports := []string{"-p", "udp", "-m", "comment", "--comment",
			"allow LOCAL UDP traffic to node ports", "-m", "addrtype", "--dst-type", "LOCAL",
			"-m", "multiport", "--dports", npc.serviceNodePortRange, "-j", "RETURN"}
		uuid, err = addUUIDForRuleSpec(kubeInputChainName, &whitelistUDPNodeports)
		if err != nil {
			klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
		}
		klog.V(2).Infof("Allow UDP traffic to ingress towards node port range: %s for family: %s",
			npc.serviceNodePortRange, family)
		ensureRuleAtPosition(handler,
			kubeInputChainName, whitelistUDPNodeports, uuid, rulePosition[family])
		rulePosition[family]++
	}

	for idx, externalIPRange := range npc.serviceExternalIPRanges {
		var family v1core.IPFamily
		if externalIPRange.IP.To4() != nil {
			family = v1core.IPv4Protocol
		} else {
			family = v1core.IPv6Protocol
		}
		whitelistServiceVips := []string{"-m", "comment", "--comment",
			"allow traffic to external IP range: " + externalIPRange.String(), "-d", externalIPRange.String(),
			"-j", "RETURN"}
		uuid, err := addUUIDForRuleSpec(kubeInputChainName, &whitelistServiceVips)
		if err != nil {
			klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
		}
		// Access externalIPRange via index to avoid implicit memory aliasing
		cidrHandler, err := npc.iptablesCmdHandlerForCIDR(&npc.serviceExternalIPRanges[idx])
		if err != nil {
			klog.Fatalf("Failed to get iptables handler: %s", err.Error())
		}
		klog.V(2).Infof("Allow traffic to ingress towards External IP Range: %s for family: %s",
			externalIPRange.String(), family)
		ensureRuleAtPosition(cidrHandler,
			kubeInputChainName, whitelistServiceVips, uuid, rulePosition[family])
		rulePosition[family]++
	}

	for idx, loadBalancerIPRange := range npc.serviceLoadBalancerIPRanges {
		var family v1core.IPFamily
		if loadBalancerIPRange.IP.To4() != nil {
			family = v1core.IPv4Protocol
		} else {
			family = v1core.IPv6Protocol
		}
		whitelistServiceVips := []string{"-m", "comment", "--comment",
			"allow traffic to load balancer IP range: " + loadBalancerIPRange.String(), "-d", loadBalancerIPRange.String(),
			"-j", "RETURN"}
		uuid, err := addUUIDForRuleSpec(kubeInputChainName, &whitelistServiceVips)
		if err != nil {
			klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
		}
		// Access loadBalancerIPRange via index to avoid implicit memory aliasing
		cidrHandler, err := npc.iptablesCmdHandlerForCIDR(&npc.serviceLoadBalancerIPRanges[idx])
		if err != nil {
			klog.Fatalf("Failed to get iptables handler: %s", err.Error())
		}
		klog.V(2).Infof("Allow traffic to ingress towards Load Balancer IP Range: %s for family: %s",
			loadBalancerIPRange.String(), family)
		ensureRuleAtPosition(cidrHandler,
			kubeInputChainName, whitelistServiceVips, uuid, rulePosition[family])
		rulePosition[family]++
	}
}

func (npc *NetworkPolicyController) ensureExplicitAccept() {
	// for the traffic to/from the local pod's let network policy controller be
	// authoritative entity to ACCEPT the traffic if it complies to network policies
	for _, filterTableRules := range npc.filterTableRules {
		for _, chain := range defaultChains {
			comment := "\"rule to explicitly ACCEPT traffic that comply to network policies\""
			args := []string{"-m", "comment", "--comment", comment, "-m", "mark", "--mark", "0x20000/0x20000",
				"-j", "ACCEPT"}
			utils.AppendUnique(filterTableRules, chain, args)
		}
	}
}

// Creates custom chains KUBE-NWPLCY-DEFAULT
func (npc *NetworkPolicyController) ensureDefaultNetworkPolicyChain() {
	for family, iptablesCmdHandler := range npc.iptablesCmdHandlers {
		exists, err := iptablesCmdHandler.ChainExists("filter", kubeDefaultNetpolChain)
		if err != nil {
			klog.Fatalf("failed to check for the existence of chain %s, error: %v", kubeDefaultNetpolChain, err)
		}
		if !exists {
			err = iptablesCmdHandler.NewChain("filter", kubeDefaultNetpolChain)
			if err != nil {
				klog.Fatalf("failed to run iptables command to create %s chain due to %s",
					kubeDefaultNetpolChain, err.Error())
			}
		}

		// Add common IPv4/IPv6 ICMP rules to the default network policy chain to ensure that pods communicate properly
		icmpRules := utils.CommonICMPRules(family)
		for _, icmpRule := range icmpRules {
			icmpArgs := []string{"-m", "comment", "--comment", icmpRule.Comment, "-p", icmpRule.IPTablesProto,
				icmpRule.IPTablesType, icmpRule.ICMPType, "-j", "ACCEPT"}
			err = iptablesCmdHandler.AppendUnique("filter", kubeDefaultNetpolChain, icmpArgs...)
			if err != nil {
				klog.Fatalf("failed to run iptables command: %v", err)
			}
		}

		// Start off by marking traffic with an invalid mark so that we can allow list only traffic accepted by a
		// matching policy. Anything that still has 0x10000
		markArgs := make([]string, 0)
		markComment := "rule to mark traffic matching a network policy"
		markArgs = append(markArgs, "-j", "MARK", "-m", "comment", "--comment", markComment,
			"--set-xmark", "0x10000/0x10000")
		err = iptablesCmdHandler.AppendUnique("filter", kubeDefaultNetpolChain, markArgs...)
		if err != nil {
			klog.Fatalf("Failed to run iptables command: %s", err.Error())
		}
	}
}

func (npc *NetworkPolicyController) cleanupStaleRules(activePolicyChains, activePodFwChains map[string]bool,
	deleteDefaultChains bool) error {

	cleanupPodFwChains := make([]string, 0)
	cleanupPolicyChains := make([]string, 0)

	for ipFamily, iptablesCmdHandler := range npc.iptablesCmdHandlers {
		// find iptables chains and ipsets that are no longer used by comparing current to the active maps we were passed
		chains, err := iptablesCmdHandler.ListChains("filter")
		if err != nil {
			return fmt.Errorf("unable to list chains: %w", err)
		}
		for _, chain := range chains {
			if strings.HasPrefix(chain, kubeNetworkPolicyChainPrefix) {
				if chain == kubeDefaultNetpolChain {
					continue
				}
				if _, ok := activePolicyChains[chain]; !ok {
					cleanupPolicyChains = append(cleanupPolicyChains, chain)
					continue
				}
			}
			if strings.HasPrefix(chain, kubePodFirewallChainPrefix) {
				if _, ok := activePodFwChains[chain]; !ok {
					cleanupPodFwChains = append(cleanupPodFwChains, chain)
					continue
				}
			}
		}

		var newChains, newRules, desiredFilterTable bytes.Buffer
		rules := strings.Split(npc.filterTableRules[ipFamily].String(), "\n")
		if len(rules) > 0 && rules[len(rules)-1] == "" {
			rules = rules[:len(rules)-1]
		}
		for _, rule := range rules {
			skipRule := false
			for _, podFWChainName := range cleanupPodFwChains {
				if strings.Contains(rule, podFWChainName) {
					skipRule = true
					break
				}
			}
			for _, policyChainName := range cleanupPolicyChains {
				if strings.Contains(rule, policyChainName) {
					skipRule = true
					break
				}
			}
			if deleteDefaultChains {
				for _, chain := range []string{kubeInputChainName, kubeForwardChainName, kubeOutputChainName,
					kubeDefaultNetpolChain} {
					if strings.Contains(rule, chain) {
						skipRule = true
						break
					}
				}
			}
			if strings.Contains(rule, "COMMIT") || strings.HasPrefix(rule, "# ") {
				skipRule = true
			}
			if skipRule {
				continue
			}
			if strings.HasPrefix(rule, ":") {
				newChains.WriteString(rule + " - [0:0]\n")
			}
			if strings.HasPrefix(rule, "-") {
				newRules.WriteString(rule + "\n")
			}
		}
		desiredFilterTable.WriteString("*filter" + "\n")
		desiredFilterTable.Write(newChains.Bytes())
		desiredFilterTable.Write(newRules.Bytes())
		desiredFilterTable.WriteString("COMMIT" + "\n")
		npc.filterTableRules[ipFamily] = &desiredFilterTable
	}

	return nil
}

func (npc *NetworkPolicyController) cleanupStaleIPSets(activePolicyIPSets map[string]bool) error {
	// There are certain actions like Cleanup() actions that aren't working with full instantiations of the controller
	// and in these instances the mutex may not be present and may not need to be present as they are operating out of a
	// single goroutine where there is no need for locking
	if nil != npc.ipsetMutex {
		klog.V(1).Infof("Attempting to attain ipset mutex lock")
		npc.ipsetMutex.Lock()
		klog.V(1).Infof("Attained ipset mutex lock, continuing...")
		defer func() {
			npc.ipsetMutex.Unlock()
			klog.V(1).Infof("Returned ipset mutex lock")
		}()
	}

	for _, ipsets := range npc.ipSetHandlers {
		cleanupPolicyIPSets := make([]*utils.Set, 0)
		if err := ipsets.Save(); err != nil {
			klog.Fatalf("failed to initialize ipsets command executor due to %s", err.Error())
		}
		for _, set := range ipsets.Sets() {
			if set.HasPrefix(kubeSourceIPSetPrefix) ||
				set.HasPrefix(kubeDestinationIPSetPrefix) {
				if _, ok := activePolicyIPSets[set.Name]; !ok {
					cleanupPolicyIPSets = append(cleanupPolicyIPSets, set)
				}
			}
		}
		// cleanup network policy ipsets
		for _, set := range cleanupPolicyIPSets {
			if err := set.Destroy(); err != nil {
				return fmt.Errorf("failed to delete ipset %s due to %s", set.Name, err)
			}
		}
	}
	return nil
}

// Cleanup cleanup configurations done
func (npc *NetworkPolicyController) Cleanup() {
	klog.Info("Cleaning up NetworkPolicyController configurations...")

	if len(npc.iptablesCmdHandlers) < 1 {
		iptablesCmdHandlers, ipSetHandlers, err := NewIPTablesHandlers(nil)
		if err != nil {
			klog.Errorf("unable to get iptables and ipset handlers: %v", err)
			return
		}
		npc.iptablesCmdHandlers = iptablesCmdHandlers
		npc.ipSetHandlers = ipSetHandlers

		// Make other structures that we rely on
		npc.iptablesSaveRestore = make(map[v1core.IPFamily]utils.IPTablesSaveRestorer, 2)
		npc.iptablesSaveRestore[v1core.IPv4Protocol] = utils.NewIPTablesSaveRestore(v1core.IPv4Protocol)
		npc.iptablesSaveRestore[v1core.IPv6Protocol] = utils.NewIPTablesSaveRestore(v1core.IPv6Protocol)
		npc.filterTableRules = make(map[v1core.IPFamily]*bytes.Buffer, 2)
		var buf bytes.Buffer
		npc.filterTableRules[v1core.IPv4Protocol] = &buf
		var buf2 bytes.Buffer
		npc.filterTableRules[v1core.IPv6Protocol] = &buf2
	}

	var emptySet map[string]bool
	// Take a dump (iptables-save) of the current filter table for cleanupStaleRules() to work on
	for ipFamily, iptablesSaveRestore := range npc.iptablesSaveRestore {
		if err := iptablesSaveRestore.SaveInto("filter", npc.filterTableRules[ipFamily]); err != nil {
			klog.Errorf("error encountered attempting to list iptables rules for cleanup: %v", err)
			return
		}
	}
	// Run cleanupStaleRules() to get rid of most of the kube-router rules (this is the same logic that runs as
	// part NPC's runtime loop). Setting the last parameter to true causes even the default chains are removed.
	err := npc.cleanupStaleRules(emptySet, emptySet, true)
	if err != nil {
		klog.Errorf("error encountered attempting to cleanup iptables rules: %v", err)
		return
	}
	// Restore (iptables-restore) npc's cleaned up version of the iptables filter chain
	for ipFamily, iptablesSaveRestore := range npc.iptablesSaveRestore {
		if err = iptablesSaveRestore.Restore("filter", npc.filterTableRules[ipFamily].Bytes()); err != nil {
			klog.Errorf(
				"error encountered while loading running iptables-restore: %v\n%s", err,
				npc.filterTableRules[ipFamily].String())
		}
	}

	// Cleanup ipsets
	err = npc.cleanupStaleIPSets(emptySet)
	if err != nil {
		klog.Errorf("error encountered while cleaning ipsets: %v", err)
		return
	}

	klog.Infof("Successfully cleaned the NetworkPolicyController configurations done by kube-router")
}

func NewIPTablesHandlers(config *options.KubeRouterConfig) (
	map[v1core.IPFamily]utils.IPTablesHandler, map[v1core.IPFamily]utils.IPSetHandler, error) {
	iptablesCmdHandlers := make(map[v1core.IPFamily]utils.IPTablesHandler, 2)
	ipSetHandlers := make(map[v1core.IPFamily]utils.IPSetHandler, 2)

	if config == nil || config.EnableIPv4 {
		iptHandler, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create iptables handler: %w", err)
		}
		iptablesCmdHandlers[v1core.IPv4Protocol] = iptHandler

		ipset, err := utils.NewIPSet(false)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create ipset handler: %w", err)
		}
		ipSetHandlers[v1core.IPv4Protocol] = ipset
	}
	if config == nil || config.EnableIPv6 {
		iptHandler, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create iptables handler: %w", err)
		}
		iptablesCmdHandlers[v1core.IPv6Protocol] = iptHandler

		ipset, err := utils.NewIPSet(true)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create ipset handler: %w", err)
		}
		ipSetHandlers[v1core.IPv6Protocol] = ipset
	}
	return iptablesCmdHandlers, ipSetHandlers, nil
}

// NewNetworkPolicyController returns new NetworkPolicyController object
func NewNetworkPolicyController(clientset kubernetes.Interface,
	config *options.KubeRouterConfig, podInformer cache.SharedIndexInformer,
	npInformer cache.SharedIndexInformer, nsInformer cache.SharedIndexInformer,
	ipsetMutex *sync.Mutex, linkQ utils.LocalLinkQuerier,
	iptablesCmdHandlers map[v1core.IPFamily]utils.IPTablesHandler,
	ipSetHandlers map[v1core.IPFamily]utils.IPSetHandler) (*NetworkPolicyController, error) {
	npc := NetworkPolicyController{ipsetMutex: ipsetMutex}

	// Creating a single-item buffered channel to ensure that we only keep a single full sync request at a time,
	// additional requests would be pointless to queue since after the first one was processed the system would already
	// be up to date with all of the policy changes from any enqueued request after that
	npc.fullSyncRequestChan = make(chan struct{}, 1)

	// Validate and parse ClusterIP service range
	if len(config.ClusterIPCIDRs) == 0 {
		return nil, fmt.Errorf("failed to get parse --service-cluster-ip-range parameter, the list is empty")
	}

	_, primaryIpnet, err := net.ParseCIDR(strings.TrimSpace(config.ClusterIPCIDRs[0]))
	if err != nil {
		return nil, fmt.Errorf("failed to get parse --service-cluster-ip-range parameter: %w", err)
	}
	npc.serviceClusterIPRanges = append(npc.serviceClusterIPRanges, *primaryIpnet)

	// Validate that ClusterIP service range type matches the configuration
	if config.EnableIPv4 && !config.EnableIPv6 {
		if !netutils.IsIPv4CIDR(&npc.serviceClusterIPRanges[0]) {
			//nolint:goconst // we don't care about abstracting an error message
			return nil, fmt.Errorf("failed to get parse --service-cluster-ip-range parameter: " +
				"IPv4 is enabled but only IPv6 address is provided")
		}
	}
	if !config.EnableIPv4 && config.EnableIPv6 {
		if !netutils.IsIPv6CIDR(&npc.serviceClusterIPRanges[0]) {
			return nil, fmt.Errorf("failed to get parse --service-cluster-ip-range parameter: " +
				"IPv6 is enabled but only IPv4 address is provided")
		}
	}

	if len(config.ClusterIPCIDRs) > 1 {
		if config.EnableIPv4 && config.EnableIPv6 {
			_, secondaryIpnet, err := net.ParseCIDR(strings.TrimSpace(config.ClusterIPCIDRs[1]))
			if err != nil {
				return nil, fmt.Errorf("failed to get parse --service-cluster-ip-range parameter: %v", err)
			}
			npc.serviceClusterIPRanges = append(npc.serviceClusterIPRanges, *secondaryIpnet)

			ipv4Provided := netutils.IsIPv4CIDR(&npc.serviceClusterIPRanges[0]) ||
				netutils.IsIPv4CIDR(&npc.serviceClusterIPRanges[1])
			ipv6Provided := netutils.IsIPv6CIDR(&npc.serviceClusterIPRanges[0]) ||
				netutils.IsIPv6CIDR(&npc.serviceClusterIPRanges[1])
			if !(ipv4Provided && ipv6Provided) {
				return nil, fmt.Errorf("failed to get parse --service-cluster-ip-range parameter: " +
					"dual-stack is enabled, both IPv4 and IPv6 addresses should be provided")
			}
		} else {
			return nil, fmt.Errorf("too many CIDRs provided in --service-cluster-ip-range parameter: " +
				"dual-stack must be enabled to provide two addresses")
		}
	}
	if len(config.ClusterIPCIDRs) > 2 {
		return nil, fmt.Errorf("too many CIDRs provided in --service-cluster-ip-range parameter, only two " +
			"addresses are allowed at once for dual-stack")
	}

	// Validate and parse NodePort range
	if npc.serviceNodePortRange, err = validateNodePortRange(config.NodePortRange); err != nil {
		return nil, err
	}

	// Validate and parse ExternalIP service range
	for _, externalIPRange := range config.ExternalIPCIDRs {
		_, ipnet, err := net.ParseCIDR(externalIPRange)
		if err != nil {
			return nil, fmt.Errorf("failed to get parse --service-external-ip-range parameter: '%s'. Error: %s",
				externalIPRange, err.Error())
		}
		npc.serviceExternalIPRanges = append(npc.serviceExternalIPRanges, *ipnet)
	}

	// Validate and parse LoadBalancerIP service range
	for _, loadBalancerIPRange := range config.LoadBalancerCIDRs {
		_, ipnet, err := net.ParseCIDR(loadBalancerIPRange)
		if err != nil {
			return nil, fmt.Errorf("failed to get parse --loadbalancer-ip-range parameter: '%s'. Error: %s",
				loadBalancerIPRange, err.Error())
		}
		npc.serviceLoadBalancerIPRanges = append(npc.serviceLoadBalancerIPRanges, *ipnet)
	}

	if config.MetricsEnabled {
		// Register the metrics for this controller
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerIptablesSyncTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerIptablesV4SaveTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerIptablesV6SaveTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerIptablesV4RestoreTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerIptablesV6RestoreTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerPolicyChainsSyncTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerPolicyIpsetV4RestoreTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerPolicyIpsetV6RestoreTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerPolicyChains)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerPolicyIpsets)
		npc.MetricsEnabled = true
	}

	npc.syncPeriod = config.IPTablesSyncPeriod

	node, err := utils.GetNodeObject(clientset, config.HostnameOverride)
	if err != nil {
		return nil, err
	}

	npc.krNode, err = utils.NewKRNode(node, linkQ, config.EnableIPv4, config.EnableIPv6)
	if err != nil {
		return nil, err
	}

	npc.iptablesCmdHandlers = iptablesCmdHandlers
	npc.iptablesSaveRestore = make(map[v1core.IPFamily]utils.IPTablesSaveRestorer, 2)
	npc.filterTableRules = make(map[v1core.IPFamily]*bytes.Buffer, 2)
	npc.ipSetHandlers = ipSetHandlers

	if config.EnableIPv4 {
		if !npc.krNode.IsIPv4Capable() {
			return nil, fmt.Errorf("IPv4 was enabled but no IPv4 address was found on node")
		}
		klog.V(2).Infof("IPv4 is enabled")
		npc.iptablesSaveRestore[v1core.IPv4Protocol] = utils.NewIPTablesSaveRestore(v1core.IPv4Protocol)
		var buf bytes.Buffer
		npc.filterTableRules[v1core.IPv4Protocol] = &buf
	}
	if config.EnableIPv6 {
		if !npc.krNode.IsIPv6Capable() {
			return nil, fmt.Errorf("IPv6 was enabled but no IPv6 address was found on node")
		}
		klog.V(2).Infof("IPv6 is enabled")
		npc.iptablesSaveRestore[v1core.IPv6Protocol] = utils.NewIPTablesSaveRestore(v1core.IPv6Protocol)
		var buf bytes.Buffer
		npc.filterTableRules[v1core.IPv6Protocol] = &buf
	}

	npc.podLister = podInformer.GetIndexer()
	npc.PodEventHandler = npc.newPodEventHandler()

	npc.nsLister = nsInformer.GetIndexer()
	npc.NamespaceEventHandler = npc.newNamespaceEventHandler()

	npc.npLister = npInformer.GetIndexer()
	npc.NetworkPolicyEventHandler = npc.newNetworkPolicyEventHandler()

	return &npc, nil
}
