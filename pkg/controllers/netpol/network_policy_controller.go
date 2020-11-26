package netpol

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"

	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	kubePodFirewallChainPrefix   = "KUBE-POD-FW-"
	kubeNetworkPolicyChainPrefix = "KUBE-NWPLCY-"
	kubeSourceIPSetPrefix        = "KUBE-SRC-"
	kubeDestinationIPSetPrefix   = "KUBE-DST-"
	kubeInputChainName           = "KUBE-ROUTER-INPUT"
	kubeForwardChainName         = "KUBE-ROUTER-FORWARD"
	kubeOutputChainName          = "KUBE-ROUTER-OUTPUT"
)

// Network policy controller provides both ingress and egress filtering for the pods as per the defined network
// policies. Two different types of iptables chains are used. Each pod running on the node which either
// requires ingress or egress filtering gets a pod specific chains. Each network policy has a iptables chain, which
// has rules expressed through ipsets matching source and destination pod ip's. In the FORWARD chain of the
// filter table a rule is added to jump the traffic originating (in case of egress network policy) from the pod
// or destined (in case of ingress network policy) to the pod specific iptables chain. Each
// pod specific iptables chain has rules to jump to the network polices chains, that pod matches. So packet
// originating/destined from/to pod goes through fitler table's, FORWARD chain, followed by pod specific chain,
// followed by one or more network policy chains, till there is a match which will accept the packet, or gets
// dropped by the rule in the pod chain, if there is no match.

// NetworkPolicyController strcut to hold information required by NetworkPolicyController
type NetworkPolicyController struct {
	nodeIP                  net.IP
	nodeHostName            string
	serviceClusterIPRange   net.IPNet
	serviceExternalIPRanges []net.IPNet
	serviceNodePortRange    string
	mu                      sync.Mutex
	syncPeriod              time.Duration
	MetricsEnabled          bool
	healthChan              chan<- *healthcheck.ControllerHeartbeat
	fullSyncRequestChan     chan struct{}

	ipSetHandler *utils.IPSet

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
	srcIPBlocks    [][]string
}

// internal structure to represent NetworkPolicyEgressRule in the spec
type egressRule struct {
	matchAllPorts        bool
	ports                []protocolAndPort
	namedPorts           []endPoints
	matchAllDestinations bool
	dstPods              []podInfo
	dstIPBlocks          [][]string
}

type protocolAndPort struct {
	protocol string
	port     string
}

type endPoints struct {
	ips []string
	protocolAndPort
}

type numericPort2eps map[string]*endPoints
type protocol2eps map[string]numericPort2eps
type namedPort2eps map[string]protocol2eps

// Run runs forver till we receive notification on stopCh
func (npc *NetworkPolicyController) Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) {
	t := time.NewTicker(npc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	glog.Info("Starting network policy controller")
	npc.healthChan = healthChan

	// setup kube-router specific top level cutoms chains
	npc.ensureTopLevelChains()

	// Full syncs of the network policy controller take a lot of time and can only be processed one at a time,
	// therefore, we start it in it's own goroutine and request a sync through a single item channel
	glog.Info("Starting network policy controller full sync goroutine")
	wg.Add(1)
	go func(fullSyncRequest <-chan struct{}, stopCh <-chan struct{}, wg *sync.WaitGroup) {
		defer wg.Done()
		for {
			// Add an additional non-blocking select to ensure that if the stopCh channel is closed it is handled first
			select {
			case <-stopCh:
				glog.Info("Shutting down network policies full sync goroutine")
				return
			default:
			}
			select {
			case <-stopCh:
				glog.Info("Shutting down network policies full sync goroutine")
				return
			case <-fullSyncRequest:
				glog.V(3).Info("Received request for a full sync, processing")
				npc.fullPolicySync() // fullPolicySync() is a blocking request here
			}
		}
	}(npc.fullSyncRequestChan, stopCh, wg)

	// loop forever till notified to stop on stopCh
	for {
		glog.V(1).Info("Requesting periodic sync of iptables to reflect network policies")
		npc.RequestFullSync()
		select {
		case <-stopCh:
			glog.Infof("Shutting down network policies controller")
			return
		case <-t.C:
		}
	}
}

// Creates custom chains KUBE-ROUTER-INPUT, KUBE-ROUTER-FORWARD, KUBE-ROUTER-OUTPUT
// and following rules in the filter table to jump from builtin chain to custom chain
// -A INPUT   -m comment --comment "kube-router netpol" -j KUBE-ROUTER-INPUT
// -A FORWARD -m comment --comment "kube-router netpol" -j KUBE-ROUTER-FORWARD
// -A OUTPUT  -m comment --comment "kube-router netpol" -j KUBE-ROUTER-OUTPUT
func (npc *NetworkPolicyController) ensureTopLevelChains() {

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		glog.Fatalf("Failed to initialize iptables executor due to %s", err.Error())
	}

	addUUIDForRuleSpec := func(chain string, ruleSpec *[]string) (string, error) {
		hash := sha256.Sum256([]byte(chain + strings.Join(*ruleSpec, "")))
		encoded := base32.StdEncoding.EncodeToString(hash[:])[:16]
		for idx, part := range *ruleSpec {
			if "--comment" == part {
				(*ruleSpec)[idx+1] = (*ruleSpec)[idx+1] + " - " + encoded
				return encoded, nil
			}
		}
		return "", fmt.Errorf("could not find a comment in the ruleSpec string given: %s", strings.Join(*ruleSpec, " "))
	}

	ensureRuleAtPosition := func(chain string, ruleSpec []string, uuid string, position int) {
		exists, err := iptablesCmdHandler.Exists("filter", chain, ruleSpec...)
		if err != nil {
			glog.Fatalf("Failed to verify rule exists in %s chain due to %s", chain, err.Error())
		}
		if !exists {
			err := iptablesCmdHandler.Insert("filter", chain, position, ruleSpec...)
			if err != nil {
				glog.Fatalf("Failed to run iptables command to insert in %s chain %s", chain, err.Error())
			}
			return
		}
		rules, err := iptablesCmdHandler.List("filter", chain)
		if err != nil {
			glog.Fatalf("failed to list rules in filter table %s chain due to %s", chain, err.Error())
		}

		var ruleNo, ruleIndexOffset int
		for i, rule := range rules {
			rule = strings.Replace(rule, "\"", "", 2) //removes quote from comment string
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
			err = iptablesCmdHandler.Insert("filter", chain, position, ruleSpec...)
			if err != nil {
				glog.Fatalf("Failed to run iptables command to insert in %s chain %s", chain, err.Error())
			}
			err = iptablesCmdHandler.Delete("filter", chain, strconv.Itoa(ruleNo+1))
			if err != nil {
				glog.Fatalf("Failed to delete incorrect rule in %s chain due to %s", chain, err.Error())
			}
		}
	}

	chains := map[string]string{"INPUT": kubeInputChainName, "FORWARD": kubeForwardChainName, "OUTPUT": kubeOutputChainName}

	for builtinChain, customChain := range chains {
		err = iptablesCmdHandler.NewChain("filter", customChain)
		if err != nil && err.(*iptables.Error).ExitStatus() != 1 {
			glog.Fatalf("Failed to run iptables command to create %s chain due to %s", customChain, err.Error())
		}
		args := []string{"-m", "comment", "--comment", "kube-router netpol", "-j", customChain}
		uuid, err := addUUIDForRuleSpec(builtinChain, &args)
		if err != nil {
			glog.Fatalf("Failed to get uuid for rule: %s", err.Error())
		}
		ensureRuleAtPosition(builtinChain, args, uuid, 1)
	}

	whitelistServiceVips := []string{"-m", "comment", "--comment", "allow traffic to cluster IP", "-d", npc.serviceClusterIPRange.String(), "-j", "RETURN"}
	uuid, err := addUUIDForRuleSpec(kubeInputChainName, &whitelistServiceVips)
	if err != nil {
		glog.Fatalf("Failed to get uuid for rule: %s", err.Error())
	}
	ensureRuleAtPosition(kubeInputChainName, whitelistServiceVips, uuid, 1)

	whitelistTCPNodeports := []string{"-p", "tcp", "-m", "comment", "--comment", "allow LOCAL TCP traffic to node ports", "-m", "addrtype", "--dst-type", "LOCAL",
		"-m", "multiport", "--dports", npc.serviceNodePortRange, "-j", "RETURN"}
	uuid, err = addUUIDForRuleSpec(kubeInputChainName, &whitelistTCPNodeports)
	if err != nil {
		glog.Fatalf("Failed to get uuid for rule: %s", err.Error())
	}
	ensureRuleAtPosition(kubeInputChainName, whitelistTCPNodeports, uuid, 2)

	whitelistUDPNodeports := []string{"-p", "udp", "-m", "comment", "--comment", "allow LOCAL UDP traffic to node ports", "-m", "addrtype", "--dst-type", "LOCAL",
		"-m", "multiport", "--dports", npc.serviceNodePortRange, "-j", "RETURN"}
	uuid, err = addUUIDForRuleSpec(kubeInputChainName, &whitelistUDPNodeports)
	if err != nil {
		glog.Fatalf("Failed to get uuid for rule: %s", err.Error())
	}
	ensureRuleAtPosition(kubeInputChainName, whitelistUDPNodeports, uuid, 3)

	for externalIPIndex, externalIPRange := range npc.serviceExternalIPRanges {
		whitelistServiceVips := []string{"-m", "comment", "--comment", "allow traffic to external IP range: " + externalIPRange.String(), "-d", externalIPRange.String(), "-j", "RETURN"}
		uuid, err = addUUIDForRuleSpec(kubeInputChainName, &whitelistServiceVips)
		if err != nil {
			glog.Fatalf("Failed to get uuid for rule: %s", err.Error())
		}
		ensureRuleAtPosition(kubeInputChainName, whitelistServiceVips, uuid, externalIPIndex+4)
	}

}

// OnPodUpdate handles updates to pods from the Kubernetes api server
func (npc *NetworkPolicyController) OnPodUpdate(obj interface{}) {
	pod := obj.(*api.Pod)
	glog.V(2).Infof("Received update to pod: %s/%s", pod.Namespace, pod.Name)

	npc.RequestFullSync()
}

// OnNetworkPolicyUpdate handles updates to network policy from the kubernetes api server
func (npc *NetworkPolicyController) OnNetworkPolicyUpdate(obj interface{}) {
	netpol := obj.(*networking.NetworkPolicy)
	glog.V(2).Infof("Received update for network policy: %s/%s", netpol.Namespace, netpol.Name)

	npc.RequestFullSync()
}

// RequestFullSync allows the request of a full network policy sync without blocking the callee
func (npc *NetworkPolicyController) RequestFullSync() {
	select {
	case npc.fullSyncRequestChan <- struct{}{}:
		glog.V(3).Info("Full sync request queue was empty so a full sync request was successfully sent")
	default: // Don't block if the buffered channel is full, return quickly so that we don't block callee execution
		glog.V(1).Info("Full sync request queue was full, skipping...")
	}
}

// Sync synchronizes iptables to desired state of network policies
func (npc *NetworkPolicyController) fullPolicySync() {

	var err error
	var networkPoliciesInfo []networkPolicyInfo
	npc.mu.Lock()
	defer npc.mu.Unlock()

	healthcheck.SendHeartBeat(npc.healthChan, "NPC")
	start := time.Now()
	syncVersion := strconv.FormatInt(start.UnixNano(), 10)
	defer func() {
		endTime := time.Since(start)
		if npc.MetricsEnabled {
			metrics.ControllerIptablesSyncTime.Observe(endTime.Seconds())
		}
		glog.V(1).Infof("sync iptables took %v", endTime)
	}()

	glog.V(1).Infof("Starting sync of iptables with version: %s", syncVersion)

	// ensure kube-router specific top level chains and corresponding rules exist
	npc.ensureTopLevelChains()

	networkPoliciesInfo, err = npc.buildNetworkPoliciesInfo()
	if err != nil {
		glog.Errorf("Aborting sync. Failed to build network policies: %v", err.Error())
		return
	}

	activePolicyChains, activePolicyIPSets, err := npc.syncNetworkPolicyChains(networkPoliciesInfo, syncVersion)
	if err != nil {
		glog.Errorf("Aborting sync. Failed to sync network policy chains: %v" + err.Error())
		return
	}

	activePodFwChains, err := npc.syncPodFirewallChains(networkPoliciesInfo, syncVersion)
	if err != nil {
		glog.Errorf("Aborting sync. Failed to sync pod firewalls: %v", err.Error())
		return
	}

	err = cleanupStaleRules(activePolicyChains, activePodFwChains, activePolicyIPSets)
	if err != nil {
		glog.Errorf("Aborting sync. Failed to cleanup stale iptables rules: %v", err.Error())
		return
	}
}

// Configure iptables rules representing each network policy. All pod's matched by
// network policy spec podselector labels are grouped together in one ipset which
// is used for matching destination ip address. Each ingress rule in the network
// policyspec is evaluated to set of matching pods, which are grouped in to a
// ipset used for source ip addr matching.
func (npc *NetworkPolicyController) syncNetworkPolicyChains(networkPoliciesInfo []networkPolicyInfo, version string) (map[string]bool, map[string]bool, error) {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		metrics.ControllerPolicyChainsSyncTime.Observe(endTime.Seconds())
		glog.V(2).Infof("Syncing network policy chains took %v", endTime)
	}()
	activePolicyChains := make(map[string]bool)
	activePolicyIPSets := make(map[string]bool)

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		glog.Fatalf("Failed to initialize iptables executor due to: %s", err.Error())
	}

	// run through all network policies
	for _, policy := range networkPoliciesInfo {

		// ensure there is a unique chain per network policy in filter table
		policyChainName := networkPolicyChainName(policy.namespace, policy.name, version)
		err := iptablesCmdHandler.NewChain("filter", policyChainName)
		if err != nil && err.(*iptables.Error).ExitStatus() != 1 {
			return nil, nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}

		activePolicyChains[policyChainName] = true

		currnetPodIps := make([]string, 0, len(policy.targetPods))
		for ip := range policy.targetPods {
			currnetPodIps = append(currnetPodIps, ip)
		}

		if policy.policyType == "both" || policy.policyType == "ingress" {
			// create a ipset for all destination pod ip's matched by the policy spec PodSelector
			targetDestPodIPSetName := policyDestinationPodIPSetName(policy.namespace, policy.name)
			targetDestPodIPSet, err := npc.ipSetHandler.Create(targetDestPodIPSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create ipset: %s", err.Error())
			}
			err = targetDestPodIPSet.Refresh(currnetPodIps, utils.OptionTimeout, "0")
			if err != nil {
				glog.Errorf("failed to refresh targetDestPodIPSet,: " + err.Error())
			}
			err = npc.processIngressRules(policy, targetDestPodIPSetName, activePolicyIPSets, version)
			if err != nil {
				return nil, nil, err
			}
			activePolicyIPSets[targetDestPodIPSet.Name] = true
		}

		if policy.policyType == "both" || policy.policyType == "egress" {
			// create a ipset for all source pod ip's matched by the policy spec PodSelector
			targetSourcePodIPSetName := policySourcePodIPSetName(policy.namespace, policy.name)
			targetSourcePodIPSet, err := npc.ipSetHandler.Create(targetSourcePodIPSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create ipset: %s", err.Error())
			}
			err = targetSourcePodIPSet.Refresh(currnetPodIps, utils.OptionTimeout, "0")
			if err != nil {
				glog.Errorf("failed to refresh targetSourcePodIPSet: " + err.Error())
			}
			err = npc.processEgressRules(policy, targetSourcePodIPSetName, activePolicyIPSets, version)
			if err != nil {
				return nil, nil, err
			}
			activePolicyIPSets[targetSourcePodIPSet.Name] = true
		}

	}

	glog.V(2).Infof("Iptables chains in the filter table are synchronized with the network policies.")

	return activePolicyChains, activePolicyIPSets, nil
}

func (npc *NetworkPolicyController) processIngressRules(policy networkPolicyInfo,
	targetDestPodIPSetName string, activePolicyIPSets map[string]bool, version string) error {

	// From network policy spec: "If field 'Ingress' is empty then this NetworkPolicy does not allow any traffic "
	// so no whitelist rules to be added to the network policy
	if policy.ingressRules == nil {
		return nil
	}

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return fmt.Errorf("Failed to initialize iptables executor due to: %s", err.Error())
	}

	policyChainName := networkPolicyChainName(policy.namespace, policy.name, version)

	// run through all the ingress rules in the spec and create iptables rules
	// in the chain for the network policy
	for i, ingressRule := range policy.ingressRules {

		if len(ingressRule.srcPods) != 0 {
			srcPodIPSetName := policyIndexedSourcePodIPSetName(policy.namespace, policy.name, i)
			srcPodIPSet, err := npc.ipSetHandler.Create(srcPodIPSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
			if err != nil {
				return fmt.Errorf("failed to create ipset: %s", err.Error())
			}

			activePolicyIPSets[srcPodIPSet.Name] = true

			ingressRuleSrcPodIPs := make([]string, 0, len(ingressRule.srcPods))
			for _, pod := range ingressRule.srcPods {
				ingressRuleSrcPodIPs = append(ingressRuleSrcPodIPs, pod.ip)
			}
			err = srcPodIPSet.Refresh(ingressRuleSrcPodIPs, utils.OptionTimeout, "0")
			if err != nil {
				glog.Errorf("failed to refresh srcPodIPSet: " + err.Error())
			}

			if len(ingressRule.ports) != 0 {
				// case where 'ports' details and 'from' details specified in the ingress rule
				// so match on specified source and destination ip's and specified port (if any) and protocol
				for _, portProtocol := range ingressRule.ports {
					comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
						policy.name + " namespace " + policy.namespace
					if err := npc.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, srcPodIPSetName, targetDestPodIPSetName, portProtocol.protocol, portProtocol.port); err != nil {
						return err
					}
				}
			}

			if len(ingressRule.namedPorts) != 0 {
				for j, endPoints := range ingressRule.namedPorts {
					namedPortIPSetName := policyIndexedIngressNamedPortIPSetName(policy.namespace, policy.name, i, j)
					namedPortIPSet, err := npc.ipSetHandler.Create(namedPortIPSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
					if err != nil {
						return fmt.Errorf("failed to create ipset: %s", err.Error())
					}
					activePolicyIPSets[namedPortIPSet.Name] = true
					err = namedPortIPSet.Refresh(endPoints.ips, utils.OptionTimeout, "0")
					if err != nil {
						glog.Errorf("failed to refresh namedPortIPSet: " + err.Error())
					}
					comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
						policy.name + " namespace " + policy.namespace
					if err := npc.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, srcPodIPSetName, namedPortIPSetName, endPoints.protocol, endPoints.port); err != nil {
						return err
					}
				}
			}

			if len(ingressRule.ports) == 0 && len(ingressRule.namedPorts) == 0 {
				// case where no 'ports' details specified in the ingress rule but 'from' details specified
				// so match on specified source and destination ip with all port and protocol
				comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
					policy.name + " namespace " + policy.namespace
				if err := npc.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, srcPodIPSetName, targetDestPodIPSetName, "", ""); err != nil {
					return err
				}
			}
		}

		// case where only 'ports' details specified but no 'from' details in the ingress rule
		// so match on all sources, with specified port (if any) and protocol
		if ingressRule.matchAllSource && !ingressRule.matchAllPorts {
			for _, portProtocol := range ingressRule.ports {
				comment := "rule to ACCEPT traffic from all sources to dest pods selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				if err := npc.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, "", targetDestPodIPSetName, portProtocol.protocol, portProtocol.port); err != nil {
					return err
				}
			}

			for j, endPoints := range ingressRule.namedPorts {
				namedPortIPSetName := policyIndexedIngressNamedPortIPSetName(policy.namespace, policy.name, i, j)
				namedPortIPSet, err := npc.ipSetHandler.Create(namedPortIPSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
				if err != nil {
					return fmt.Errorf("failed to create ipset: %s", err.Error())
				}

				activePolicyIPSets[namedPortIPSet.Name] = true

				err = namedPortIPSet.Refresh(endPoints.ips, utils.OptionTimeout, "0")
				if err != nil {
					glog.Errorf("failed to refresh namedPortIPSet: " + err.Error())
				}
				comment := "rule to ACCEPT traffic from all sources to dest pods selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				if err := npc.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, "", namedPortIPSetName, endPoints.protocol, endPoints.port); err != nil {
					return err
				}
			}
		}

		// case where nether ports nor from details are speified in the ingress rule
		// so match on all ports, protocol, source IP's
		if ingressRule.matchAllSource && ingressRule.matchAllPorts {
			comment := "rule to ACCEPT traffic from all sources to dest pods selected by policy name: " +
				policy.name + " namespace " + policy.namespace
			if err := npc.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, "", targetDestPodIPSetName, "", ""); err != nil {
				return err
			}
		}

		if len(ingressRule.srcIPBlocks) != 0 {
			srcIPBlockIPSetName := policyIndexedSourceIPBlockIPSetName(policy.namespace, policy.name, i)
			srcIPBlockIPSet, err := npc.ipSetHandler.Create(srcIPBlockIPSetName, utils.TypeHashNet, utils.OptionTimeout, "0")
			if err != nil {
				return fmt.Errorf("failed to create ipset: %s", err.Error())
			}
			activePolicyIPSets[srcIPBlockIPSet.Name] = true
			err = srcIPBlockIPSet.RefreshWithBuiltinOptions(ingressRule.srcIPBlocks)
			if err != nil {
				glog.Errorf("failed to refresh srcIPBlockIPSet: " + err.Error())
			}
			if !ingressRule.matchAllPorts {
				for _, portProtocol := range ingressRule.ports {
					comment := "rule to ACCEPT traffic from specified ipBlocks to dest pods selected by policy name: " +
						policy.name + " namespace " + policy.namespace
					if err := npc.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, srcIPBlockIPSetName, targetDestPodIPSetName, portProtocol.protocol, portProtocol.port); err != nil {
						return err
					}
				}

				for j, endPoints := range ingressRule.namedPorts {
					namedPortIPSetName := policyIndexedIngressNamedPortIPSetName(policy.namespace, policy.name, i, j)
					namedPortIPSet, err := npc.ipSetHandler.Create(namedPortIPSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
					if err != nil {
						return fmt.Errorf("failed to create ipset: %s", err.Error())
					}

					activePolicyIPSets[namedPortIPSet.Name] = true

					err = namedPortIPSet.Refresh(endPoints.ips, utils.OptionTimeout, "0")
					if err != nil {
						glog.Errorf("failed to refresh namedPortIPSet: " + err.Error())
					}
					comment := "rule to ACCEPT traffic from specified ipBlocks to dest pods selected by policy name: " +
						policy.name + " namespace " + policy.namespace
					if err := npc.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, srcIPBlockIPSetName, namedPortIPSetName, endPoints.protocol, endPoints.port); err != nil {
						return err
					}
				}
			}
			if ingressRule.matchAllPorts {
				comment := "rule to ACCEPT traffic from specified ipBlocks to dest pods selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				if err := npc.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, srcIPBlockIPSetName, targetDestPodIPSetName, "", ""); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (npc *NetworkPolicyController) processEgressRules(policy networkPolicyInfo,
	targetSourcePodIPSetName string, activePolicyIPSets map[string]bool, version string) error {

	// From network policy spec: "If field 'Ingress' is empty then this NetworkPolicy does not allow any traffic "
	// so no whitelist rules to be added to the network policy
	if policy.egressRules == nil {
		return nil
	}

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return fmt.Errorf("Failed to initialize iptables executor due to: %s", err.Error())
	}

	policyChainName := networkPolicyChainName(policy.namespace, policy.name, version)

	// run through all the egress rules in the spec and create iptables rules
	// in the chain for the network policy
	for i, egressRule := range policy.egressRules {

		if len(egressRule.dstPods) != 0 {
			dstPodIPSetName := policyIndexedDestinationPodIPSetName(policy.namespace, policy.name, i)
			dstPodIPSet, err := npc.ipSetHandler.Create(dstPodIPSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
			if err != nil {
				return fmt.Errorf("failed to create ipset: %s", err.Error())
			}

			activePolicyIPSets[dstPodIPSet.Name] = true

			egressRuleDstPodIps := make([]string, 0, len(egressRule.dstPods))
			for _, pod := range egressRule.dstPods {
				egressRuleDstPodIps = append(egressRuleDstPodIps, pod.ip)
			}
			err = dstPodIPSet.Refresh(egressRuleDstPodIps, utils.OptionTimeout, "0")
			if err != nil {
				glog.Errorf("failed to refresh dstPodIPSet: " + err.Error())
			}
			if len(egressRule.ports) != 0 {
				// case where 'ports' details and 'from' details specified in the egress rule
				// so match on specified source and destination ip's and specified port (if any) and protocol
				for _, portProtocol := range egressRule.ports {
					comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
						policy.name + " namespace " + policy.namespace
					if err := npc.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, targetSourcePodIPSetName, dstPodIPSetName, portProtocol.protocol, portProtocol.port); err != nil {
						return err
					}
				}
			}

			if len(egressRule.namedPorts) != 0 {
				for j, endPoints := range egressRule.namedPorts {
					namedPortIPSetName := policyIndexedEgressNamedPortIPSetName(policy.namespace, policy.name, i, j)
					namedPortIPSet, err := npc.ipSetHandler.Create(namedPortIPSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
					if err != nil {
						return fmt.Errorf("failed to create ipset: %s", err.Error())
					}

					activePolicyIPSets[namedPortIPSet.Name] = true

					err = namedPortIPSet.Refresh(endPoints.ips, utils.OptionTimeout, "0")
					if err != nil {
						glog.Errorf("failed to refresh namedPortIPSet: " + err.Error())
					}
					comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
						policy.name + " namespace " + policy.namespace
					if err := npc.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, targetSourcePodIPSetName, namedPortIPSetName, endPoints.protocol, endPoints.port); err != nil {
						return err
					}
				}

			}

			if len(egressRule.ports) == 0 && len(egressRule.namedPorts) == 0 {
				// case where no 'ports' details specified in the ingress rule but 'from' details specified
				// so match on specified source and destination ip with all port and protocol
				comment := "rule to ACCEPT traffic from source pods to dest pods selected by policy name " +
					policy.name + " namespace " + policy.namespace
				if err := npc.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, targetSourcePodIPSetName, dstPodIPSetName, "", ""); err != nil {
					return err
				}
			}
		}

		// case where only 'ports' details specified but no 'to' details in the egress rule
		// so match on all sources, with specified port (if any) and protocol
		if egressRule.matchAllDestinations && !egressRule.matchAllPorts {
			for _, portProtocol := range egressRule.ports {
				comment := "rule to ACCEPT traffic from source pods to all destinations selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				if err := npc.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, targetSourcePodIPSetName, "", portProtocol.protocol, portProtocol.port); err != nil {
					return err
				}
			}
		}

		// case where nether ports nor from details are speified in the egress rule
		// so match on all ports, protocol, source IP's
		if egressRule.matchAllDestinations && egressRule.matchAllPorts {
			comment := "rule to ACCEPT traffic from source pods to all destinations selected by policy name: " +
				policy.name + " namespace " + policy.namespace
			if err := npc.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, targetSourcePodIPSetName, "", "", ""); err != nil {
				return err
			}
		}
		if len(egressRule.dstIPBlocks) != 0 {
			dstIPBlockIPSetName := policyIndexedDestinationIPBlockIPSetName(policy.namespace, policy.name, i)
			dstIPBlockIPSet, err := npc.ipSetHandler.Create(dstIPBlockIPSetName, utils.TypeHashNet, utils.OptionTimeout, "0")
			if err != nil {
				return fmt.Errorf("failed to create ipset: %s", err.Error())
			}
			activePolicyIPSets[dstIPBlockIPSet.Name] = true
			err = dstIPBlockIPSet.RefreshWithBuiltinOptions(egressRule.dstIPBlocks)
			if err != nil {
				glog.Errorf("failed to refresh dstIPBlockIPSet: " + err.Error())
			}
			if !egressRule.matchAllPorts {
				for _, portProtocol := range egressRule.ports {
					comment := "rule to ACCEPT traffic from source pods to specified ipBlocks selected by policy name: " +
						policy.name + " namespace " + policy.namespace
					if err := npc.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, targetSourcePodIPSetName, dstIPBlockIPSetName, portProtocol.protocol, portProtocol.port); err != nil {
						return err
					}
				}
			}
			if egressRule.matchAllPorts {
				comment := "rule to ACCEPT traffic from source pods to specified ipBlocks selected by policy name: " +
					policy.name + " namespace " + policy.namespace
				if err := npc.appendRuleToPolicyChain(iptablesCmdHandler, policyChainName, comment, targetSourcePodIPSetName, dstIPBlockIPSetName, "", ""); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (npc *NetworkPolicyController) appendRuleToPolicyChain(iptablesCmdHandler *iptables.IPTables, policyChainName, comment, srcIPSetName, dstIPSetName, protocol, dPort string) error {
	if iptablesCmdHandler == nil {
		return fmt.Errorf("Failed to run iptables command: iptablesCmdHandler is nil")
	}
	args := make([]string, 0)
	if comment != "" {
		args = append(args, "-m", "comment", "--comment", comment)
	}
	if srcIPSetName != "" {
		args = append(args, "-m", "set", "--match-set", srcIPSetName, "src")
	}
	if dstIPSetName != "" {
		args = append(args, "-m", "set", "--match-set", dstIPSetName, "dst")
	}
	if protocol != "" {
		args = append(args, "-p", protocol)
	}
	if dPort != "" {
		args = append(args, "--dport", dPort)
	}

	markComment := "rule to mark traffic matching a network policy"
	markArgs := append(args, "-j", "MARK", "-m", "comment", "--comment", markComment, "--set-xmark", "0x10000/0x10000")
	err := iptablesCmdHandler.AppendUnique("filter", policyChainName, markArgs...)
	if err != nil {
		return fmt.Errorf("Failed to run iptables command: %s", err.Error())
	}

	returnComment := "rule to RETURN traffic matching a network policy"
	returnArgs := append(args, "-m", "comment", "--comment", returnComment, "-m", "mark", "--mark", "0x10000/0x10000", "-j", "RETURN")
	err = iptablesCmdHandler.AppendUnique("filter", policyChainName, returnArgs...)
	if err != nil {
		return fmt.Errorf("Failed to run iptables command: %s", err.Error())
	}

	return nil
}

func (npc *NetworkPolicyController) syncPodFirewallChains(networkPoliciesInfo []networkPolicyInfo, version string) (map[string]bool, error) {

	activePodFwChains := make(map[string]bool)

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		glog.Fatalf("Failed to initialize iptables executor: %s", err.Error())
	}

	dropUnmarkedTrafficRules := func(podName, podNamespace, podFwChainName string) error {
		// add rule to log the packets that will be dropped due to network policy enforcement
		comment := "rule to log dropped traffic POD name:" + podName + " namespace: " + podNamespace
		args := []string{"-m", "comment", "--comment", comment, "-m", "mark", "!", "--mark", "0x10000/0x10000", "-j", "NFLOG", "--nflog-group", "100", "-m", "limit", "--limit", "10/minute", "--limit-burst", "10"}
		err = iptablesCmdHandler.AppendUnique("filter", podFwChainName, args...)
		if err != nil {
			return fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}

		// add rule to DROP if no applicable network policy permits the traffic
		comment = "rule to REJECT traffic destined for POD name:" + podName + " namespace: " + podNamespace
		args = []string{"-m", "comment", "--comment", comment, "-m", "mark", "!", "--mark", "0x10000/0x10000", "-j", "REJECT"}
		err = iptablesCmdHandler.AppendUnique("filter", podFwChainName, args...)
		if err != nil {
			return fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}

		// reset mark to let traffic pass through rest of the chains
		args = []string{"-j", "MARK", "--set-mark", "0/0x10000"}
		err = iptablesCmdHandler.AppendUnique("filter", podFwChainName, args...)
		if err != nil {
			return fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}

		return nil
	}

	// loop through the pods running on the node which to which ingress network policies to be applied
	ingressNetworkPolicyEnabledPods, err := npc.getIngressNetworkPolicyEnabledPods(networkPoliciesInfo, npc.nodeIP.String())
	if err != nil {
		return nil, err
	}
	for _, pod := range *ingressNetworkPolicyEnabledPods {

		// below condition occurs when we get trasient update while removing or adding pod
		// subseqent update will do the correct action
		if len(pod.ip) == 0 || pod.ip == "" {
			continue
		}

		// ensure pod specific firewall chain exist for all the pods that need ingress firewall
		podFwChainName := podFirewallChainName(pod.namespace, pod.name, version)
		err = iptablesCmdHandler.NewChain("filter", podFwChainName)
		if err != nil && err.(*iptables.Error).ExitStatus() != 1 {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		activePodFwChains[podFwChainName] = true

		// add entries in pod firewall to run through required network policies
		for _, policy := range networkPoliciesInfo {
			if _, ok := policy.targetPods[pod.ip]; ok {
				comment := "run through nw policy " + policy.name
				policyChainName := networkPolicyChainName(policy.namespace, policy.name, version)
				args := []string{"-m", "comment", "--comment", comment, "-j", policyChainName}
				exists, err := iptablesCmdHandler.Exists("filter", podFwChainName, args...)
				if err != nil {
					return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
				}
				if !exists {
					err := iptablesCmdHandler.Insert("filter", podFwChainName, 1, args...)
					if err != nil && err.(*iptables.Error).ExitStatus() != 1 {
						return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
					}
				}
			}
		}

		comment := "rule to permit the traffic traffic to pods when source is the pod's local node"
		args := []string{"-m", "comment", "--comment", comment, "-m", "addrtype", "--src-type", "LOCAL", "-d", pod.ip, "-j", "ACCEPT"}
		exists, err := iptablesCmdHandler.Exists("filter", podFwChainName, args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err := iptablesCmdHandler.Insert("filter", podFwChainName, 1, args...)
			if err != nil {
				return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
			}
		}

		// ensure statefull firewall, that permits return traffic for the traffic originated by the pod
		comment = "rule for stateful firewall for pod"
		args = []string{"-m", "comment", "--comment", comment, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
		exists, err = iptablesCmdHandler.Exists("filter", podFwChainName, args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err := iptablesCmdHandler.Insert("filter", podFwChainName, 1, args...)
			if err != nil {
				return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
			}
		}

		// ensure there is rule in filter table and FORWARD chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting routed (coming for other node pods)
		comment = "rule to jump traffic destined to POD name:" + pod.name + " namespace: " + pod.namespace +
			" to chain " + podFwChainName
		args = []string{"-m", "comment", "--comment", comment, "-d", pod.ip, "-j", podFwChainName}
		exists, err = iptablesCmdHandler.Exists("filter", kubeForwardChainName, args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err := iptablesCmdHandler.Insert("filter", kubeForwardChainName, 1, args...)
			if err != nil {
				return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
			}
		}

		// ensure there is rule in filter table and OUTPUT chain to jump to pod specific firewall chain
		// this rule applies to the traffic from a pod getting routed back to another pod on same node by service proxy
		exists, err = iptablesCmdHandler.Exists("filter", kubeOutputChainName, args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err := iptablesCmdHandler.Insert("filter", kubeOutputChainName, 1, args...)
			if err != nil {
				return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
			}
		}

		// ensure there is rule in filter table and forward chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting switched (coming for same node pods)
		comment = "rule to jump traffic destined to POD name:" + pod.name + " namespace: " + pod.namespace +
			" to chain " + podFwChainName
		args = []string{"-m", "physdev", "--physdev-is-bridged",
			"-m", "comment", "--comment", comment,
			"-d", pod.ip,
			"-j", podFwChainName}
		exists, err = iptablesCmdHandler.Exists("filter", kubeForwardChainName, args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err = iptablesCmdHandler.Insert("filter", kubeForwardChainName, 1, args...)
			if err != nil {
				return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
			}
		}

		err = dropUnmarkedTrafficRules(pod.name, pod.namespace, podFwChainName)
		if err != nil {
			return nil, err
		}
	}

	// loop through the pods running on the node which egress network policies to be applied
	egressNetworkPolicyEnabledPods, err := npc.getEgressNetworkPolicyEnabledPods(networkPoliciesInfo, npc.nodeIP.String())
	if err != nil {
		return nil, err
	}
	for _, pod := range *egressNetworkPolicyEnabledPods {

		// below condition occurs when we get trasient update while removing or adding pod
		// subseqent update will do the correct action
		if len(pod.ip) == 0 || pod.ip == "" {
			continue
		}

		// ensure pod specific firewall chain exist for all the pods that need egress firewall
		podFwChainName := podFirewallChainName(pod.namespace, pod.name, version)
		err = iptablesCmdHandler.NewChain("filter", podFwChainName)
		if err != nil && err.(*iptables.Error).ExitStatus() != 1 {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		activePodFwChains[podFwChainName] = true

		// add entries in pod firewall to run through required network policies
		for _, policy := range networkPoliciesInfo {
			if _, ok := policy.targetPods[pod.ip]; ok {
				comment := "run through nw policy " + policy.name
				policyChainName := networkPolicyChainName(policy.namespace, policy.name, version)
				args := []string{"-m", "comment", "--comment", comment, "-j", policyChainName}
				exists, err := iptablesCmdHandler.Exists("filter", podFwChainName, args...)
				if err != nil {
					return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
				}
				if !exists {
					err := iptablesCmdHandler.Insert("filter", podFwChainName, 1, args...)
					if err != nil && err.(*iptables.Error).ExitStatus() != 1 {
						return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
					}
				}
			}
		}

		// ensure statefull firewall, that permits return traffic for the traffic originated by the pod
		comment := "rule for stateful firewall for pod"
		args := []string{"-m", "comment", "--comment", comment, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
		exists, err := iptablesCmdHandler.Exists("filter", podFwChainName, args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err := iptablesCmdHandler.Insert("filter", podFwChainName, 1, args...)
			if err != nil {
				return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
			}
		}

		egressFilterChains := []string{kubeInputChainName, kubeForwardChainName, kubeOutputChainName}
		for _, chain := range egressFilterChains {
			// ensure there is rule in filter table and FORWARD chain to jump to pod specific firewall chain
			// this rule applies to the traffic getting forwarded/routed (traffic from the pod destinted
			// to pod on a different node)
			comment = "rule to jump traffic from POD name:" + pod.name + " namespace: " + pod.namespace +
				" to chain " + podFwChainName
			args = []string{"-m", "comment", "--comment", comment, "-s", pod.ip, "-j", podFwChainName}
			exists, err = iptablesCmdHandler.Exists("filter", chain, args...)
			if err != nil {
				return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
			}
			if !exists {
				err := iptablesCmdHandler.AppendUnique("filter", chain, args...)
				if err != nil {
					return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
				}
			}
		}

		// ensure there is rule in filter table and forward chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting switched (coming for same node pods)
		comment = "rule to jump traffic from POD name:" + pod.name + " namespace: " + pod.namespace +
			" to chain " + podFwChainName
		args = []string{"-m", "physdev", "--physdev-is-bridged",
			"-m", "comment", "--comment", comment,
			"-s", pod.ip,
			"-j", podFwChainName}
		exists, err = iptablesCmdHandler.Exists("filter", kubeForwardChainName, args...)
		if err != nil {
			return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err = iptablesCmdHandler.Insert("filter", kubeForwardChainName, 1, args...)
			if err != nil {
				return nil, fmt.Errorf("Failed to run iptables command: %s", err.Error())
			}
		}

		err = dropUnmarkedTrafficRules(pod.name, pod.namespace, podFwChainName)
		if err != nil {
			return nil, err
		}
	}

	return activePodFwChains, nil
}

func cleanupStaleRules(activePolicyChains, activePodFwChains, activePolicyIPSets map[string]bool) error {

	cleanupPodFwChains := make([]string, 0)
	cleanupPolicyChains := make([]string, 0)
	cleanupPolicyIPSets := make([]*utils.Set, 0)

	// initialize tool sets for working with iptables and ipset
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		glog.Fatalf("failed to initialize iptables command executor due to %s", err.Error())
	}
	ipsets, err := utils.NewIPSet(false)
	if err != nil {
		glog.Fatalf("failed to create ipsets command executor due to %s", err.Error())
	}
	err = ipsets.Save()
	if err != nil {
		glog.Fatalf("failed to initialize ipsets command executor due to %s", err.Error())
	}

	// find iptables chains and ipsets that are no longer used by comparing current to the active maps we were passed
	chains, err := iptablesCmdHandler.ListChains("filter")
	if err != nil {
		return fmt.Errorf("Unable to list chains: %s", err)
	}
	for _, chain := range chains {
		if strings.HasPrefix(chain, kubeNetworkPolicyChainPrefix) {
			if _, ok := activePolicyChains[chain]; !ok {
				cleanupPolicyChains = append(cleanupPolicyChains, chain)
			}
		}
		if strings.HasPrefix(chain, kubePodFirewallChainPrefix) {
			if _, ok := activePodFwChains[chain]; !ok {
				cleanupPodFwChains = append(cleanupPodFwChains, chain)
			}
		}
	}
	for _, set := range ipsets.Sets {
		if strings.HasPrefix(set.Name, kubeSourceIPSetPrefix) ||
			strings.HasPrefix(set.Name, kubeDestinationIPSetPrefix) {
			if _, ok := activePolicyIPSets[set.Name]; !ok {
				cleanupPolicyIPSets = append(cleanupPolicyIPSets, set)
			}
		}
	}

	// remove stale iptables podFwChain references from the filter table chains
	for _, podFwChain := range cleanupPodFwChains {

		primaryChains := []string{kubeInputChainName, kubeForwardChainName, kubeOutputChainName}
		for _, egressChain := range primaryChains {
			forwardChainRules, err := iptablesCmdHandler.List("filter", egressChain)
			if err != nil {
				return fmt.Errorf("failed to list rules in filter table, %s podFwChain due to %s", egressChain, err.Error())
			}

			// TODO delete rule by spec, than rule number to avoid extra loop
			var realRuleNo int
			for i, rule := range forwardChainRules {
				if strings.Contains(rule, podFwChain) {
					err = iptablesCmdHandler.Delete("filter", egressChain, strconv.Itoa(i-realRuleNo))
					if err != nil {
						return fmt.Errorf("failed to delete rule: %s from the %s podFwChain of filter table due to %s", rule, egressChain, err.Error())
					}
					realRuleNo++
				}
			}
		}
	}

	// cleanup pod firewall chain
	for _, chain := range cleanupPodFwChains {
		glog.V(2).Infof("Found pod fw chain to cleanup: %s", chain)
		err = iptablesCmdHandler.ClearChain("filter", chain)
		if err != nil {
			return fmt.Errorf("Failed to flush the rules in chain %s due to %s", chain, err.Error())
		}
		err = iptablesCmdHandler.DeleteChain("filter", chain)
		if err != nil {
			return fmt.Errorf("Failed to delete the chain %s due to %s", chain, err.Error())
		}
		glog.V(2).Infof("Deleted pod specific firewall chain: %s from the filter table", chain)
	}

	// cleanup network policy chains
	for _, policyChain := range cleanupPolicyChains {
		glog.V(2).Infof("Found policy chain to cleanup %s", policyChain)

		// first clean up any references from active pod firewall chains
		for podFwChain := range activePodFwChains {
			podFwChainRules, err := iptablesCmdHandler.List("filter", podFwChain)
			if err != nil {
				return fmt.Errorf("Unable to list rules from the chain %s: %s", podFwChain, err)
			}
			for i, rule := range podFwChainRules {
				if strings.Contains(rule, policyChain) {
					err = iptablesCmdHandler.Delete("filter", podFwChain, strconv.Itoa(i))
					if err != nil {
						return fmt.Errorf("Failed to delete rule %s from the chain %s", rule, podFwChain)
					}
					break
				}
			}
		}

		// now that all stale and active references to the network policy chain have been removed, delete the chain
		err = iptablesCmdHandler.ClearChain("filter", policyChain)
		if err != nil {
			return fmt.Errorf("Failed to flush the rules in chain %s due to  %s", policyChain, err)
		}
		err = iptablesCmdHandler.DeleteChain("filter", policyChain)
		if err != nil {
			return fmt.Errorf("Failed to flush the rules in chain %s due to %s", policyChain, err)
		}
		glog.V(2).Infof("Deleted network policy chain: %s from the filter table", policyChain)
	}

	// cleanup network policy ipsets
	for _, set := range cleanupPolicyIPSets {
		err = set.Destroy()
		if err != nil {
			return fmt.Errorf("Failed to delete ipset %s due to %s", set.Name, err)
		}
	}
	return nil
}

func (npc *NetworkPolicyController) getIngressNetworkPolicyEnabledPods(networkPoliciesInfo []networkPolicyInfo, nodeIP string) (*map[string]podInfo, error) {
	nodePods := make(map[string]podInfo)

	for _, obj := range npc.podLister.List() {
		pod := obj.(*api.Pod)

		if strings.Compare(pod.Status.HostIP, nodeIP) != 0 {
			continue
		}
		for _, policy := range networkPoliciesInfo {
			if policy.namespace != pod.ObjectMeta.Namespace {
				continue
			}
			_, ok := policy.targetPods[pod.Status.PodIP]
			if ok && (policy.policyType == "both" || policy.policyType == "ingress") {
				glog.V(2).Infof("Found pod name: " + pod.ObjectMeta.Name + " namespace: " + pod.ObjectMeta.Namespace + " for which network policies need to be applied.")
				nodePods[pod.Status.PodIP] = podInfo{ip: pod.Status.PodIP,
					name:      pod.ObjectMeta.Name,
					namespace: pod.ObjectMeta.Namespace,
					labels:    pod.ObjectMeta.Labels}
				break
			}
		}
	}
	return &nodePods, nil

}

func (npc *NetworkPolicyController) getEgressNetworkPolicyEnabledPods(networkPoliciesInfo []networkPolicyInfo, nodeIP string) (*map[string]podInfo, error) {

	nodePods := make(map[string]podInfo)

	for _, obj := range npc.podLister.List() {
		pod := obj.(*api.Pod)

		if strings.Compare(pod.Status.HostIP, nodeIP) != 0 {
			continue
		}
		for _, policy := range networkPoliciesInfo {
			if policy.namespace != pod.ObjectMeta.Namespace {
				continue
			}
			_, ok := policy.targetPods[pod.Status.PodIP]
			if ok && (policy.policyType == "both" || policy.policyType == "egress") {
				glog.V(2).Infof("Found pod name: " + pod.ObjectMeta.Name + " namespace: " + pod.ObjectMeta.Namespace + " for which network policies need to be applied.")
				nodePods[pod.Status.PodIP] = podInfo{ip: pod.Status.PodIP,
					name:      pod.ObjectMeta.Name,
					namespace: pod.ObjectMeta.Namespace,
					labels:    pod.ObjectMeta.Labels}
				break
			}
		}
	}
	return &nodePods, nil
}

func (npc *NetworkPolicyController) processNetworkPolicyPorts(npPorts []networking.NetworkPolicyPort, namedPort2eps namedPort2eps) (numericPorts []protocolAndPort, namedPorts []endPoints) {
	numericPorts, namedPorts = make([]protocolAndPort, 0), make([]endPoints, 0)
	for _, npPort := range npPorts {
		if npPort.Port == nil {
			numericPorts = append(numericPorts, protocolAndPort{port: "", protocol: string(*npPort.Protocol)})
		} else if npPort.Port.Type == intstr.Int {
			numericPorts = append(numericPorts, protocolAndPort{port: npPort.Port.String(), protocol: string(*npPort.Protocol)})
		} else {
			if protocol2eps, ok := namedPort2eps[npPort.Port.String()]; ok {
				if numericPort2eps, ok := protocol2eps[string(*npPort.Protocol)]; ok {
					for _, eps := range numericPort2eps {
						namedPorts = append(namedPorts, *eps)
					}
				}
			}
		}
	}
	return
}

func (npc *NetworkPolicyController) buildNetworkPoliciesInfo() ([]networkPolicyInfo, error) {

	NetworkPolicies := make([]networkPolicyInfo, 0)

	for _, policyObj := range npc.npLister.List() {

		policy, ok := policyObj.(*networking.NetworkPolicy)
		podSelector, _ := v1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		if !ok {
			return nil, fmt.Errorf("Failed to convert")
		}
		newPolicy := networkPolicyInfo{
			name:        policy.Name,
			namespace:   policy.Namespace,
			podSelector: podSelector,
			policyType:  "ingress",
		}

		ingressType, egressType := false, false
		for _, policyType := range policy.Spec.PolicyTypes {
			if policyType == networking.PolicyTypeIngress {
				ingressType = true
			}
			if policyType == networking.PolicyTypeEgress {
				egressType = true
			}
		}
		if ingressType && egressType {
			newPolicy.policyType = "both"
		} else if egressType {
			newPolicy.policyType = "egress"
		} else if ingressType {
			newPolicy.policyType = "ingress"
		}

		matchingPods, err := npc.ListPodsByNamespaceAndLabels(policy.Namespace, podSelector)
		newPolicy.targetPods = make(map[string]podInfo)
		namedPort2IngressEps := make(namedPort2eps)
		if err == nil {
			for _, matchingPod := range matchingPods {
				if matchingPod.Status.PodIP == "" {
					continue
				}
				newPolicy.targetPods[matchingPod.Status.PodIP] = podInfo{ip: matchingPod.Status.PodIP,
					name:      matchingPod.ObjectMeta.Name,
					namespace: matchingPod.ObjectMeta.Namespace,
					labels:    matchingPod.ObjectMeta.Labels}
				npc.grabNamedPortFromPod(matchingPod, &namedPort2IngressEps)
			}
		}

		if policy.Spec.Ingress == nil {
			newPolicy.ingressRules = nil
		} else {
			newPolicy.ingressRules = make([]ingressRule, 0)
		}

		if policy.Spec.Egress == nil {
			newPolicy.egressRules = nil
		} else {
			newPolicy.egressRules = make([]egressRule, 0)
		}

		for _, specIngressRule := range policy.Spec.Ingress {
			ingressRule := ingressRule{}
			ingressRule.srcPods = make([]podInfo, 0)
			ingressRule.srcIPBlocks = make([][]string, 0)

			// If this field is empty or missing in the spec, this rule matches all sources
			if len(specIngressRule.From) == 0 {
				ingressRule.matchAllSource = true
			} else {
				ingressRule.matchAllSource = false
				for _, peer := range specIngressRule.From {
					if peerPods, err := npc.evalPodPeer(policy, peer); err == nil {
						for _, peerPod := range peerPods {
							if peerPod.Status.PodIP == "" {
								continue
							}
							ingressRule.srcPods = append(ingressRule.srcPods,
								podInfo{ip: peerPod.Status.PodIP,
									name:      peerPod.ObjectMeta.Name,
									namespace: peerPod.ObjectMeta.Namespace,
									labels:    peerPod.ObjectMeta.Labels})
						}
					}
					ingressRule.srcIPBlocks = append(ingressRule.srcIPBlocks, npc.evalIPBlockPeer(peer)...)
				}
			}

			ingressRule.ports = make([]protocolAndPort, 0)
			ingressRule.namedPorts = make([]endPoints, 0)
			// If this field is empty or missing in the spec, this rule matches all ports
			if len(specIngressRule.Ports) == 0 {
				ingressRule.matchAllPorts = true
			} else {
				ingressRule.matchAllPorts = false
				ingressRule.ports, ingressRule.namedPorts = npc.processNetworkPolicyPorts(specIngressRule.Ports, namedPort2IngressEps)
			}

			newPolicy.ingressRules = append(newPolicy.ingressRules, ingressRule)
		}

		for _, specEgressRule := range policy.Spec.Egress {
			egressRule := egressRule{}
			egressRule.dstPods = make([]podInfo, 0)
			egressRule.dstIPBlocks = make([][]string, 0)
			namedPort2EgressEps := make(namedPort2eps)

			// If this field is empty or missing in the spec, this rule matches all sources
			if len(specEgressRule.To) == 0 {
				egressRule.matchAllDestinations = true
			} else {
				egressRule.matchAllDestinations = false
				for _, peer := range specEgressRule.To {
					if peerPods, err := npc.evalPodPeer(policy, peer); err == nil {
						for _, peerPod := range peerPods {
							if peerPod.Status.PodIP == "" {
								continue
							}
							egressRule.dstPods = append(egressRule.dstPods,
								podInfo{ip: peerPod.Status.PodIP,
									name:      peerPod.ObjectMeta.Name,
									namespace: peerPod.ObjectMeta.Namespace,
									labels:    peerPod.ObjectMeta.Labels})
							npc.grabNamedPortFromPod(peerPod, &namedPort2EgressEps)
						}

					}
					egressRule.dstIPBlocks = append(egressRule.dstIPBlocks, npc.evalIPBlockPeer(peer)...)
				}
			}

			egressRule.ports = make([]protocolAndPort, 0)
			egressRule.namedPorts = make([]endPoints, 0)
			// If this field is empty or missing in the spec, this rule matches all ports
			if len(specEgressRule.Ports) == 0 {
				egressRule.matchAllPorts = true
			} else {
				egressRule.matchAllPorts = false
				egressRule.ports, egressRule.namedPorts = npc.processNetworkPolicyPorts(specEgressRule.Ports, namedPort2EgressEps)
			}

			newPolicy.egressRules = append(newPolicy.egressRules, egressRule)
		}
		NetworkPolicies = append(NetworkPolicies, newPolicy)
	}

	return NetworkPolicies, nil
}

func (npc *NetworkPolicyController) evalPodPeer(policy *networking.NetworkPolicy, peer networking.NetworkPolicyPeer) ([]*api.Pod, error) {

	var matchingPods []*api.Pod
	matchingPods = make([]*api.Pod, 0)
	var err error
	// spec can have both PodSelector AND NamespaceSelector
	if peer.NamespaceSelector != nil {
		namespaceSelector, _ := v1.LabelSelectorAsSelector(peer.NamespaceSelector)
		namespaces, err := npc.ListNamespaceByLabels(namespaceSelector)
		if err != nil {
			return nil, errors.New("Failed to build network policies info due to " + err.Error())
		}

		podSelector := labels.Everything()
		if peer.PodSelector != nil {
			podSelector, _ = v1.LabelSelectorAsSelector(peer.PodSelector)
		}
		for _, namespace := range namespaces {
			namespacePods, err := npc.ListPodsByNamespaceAndLabels(namespace.Name, podSelector)
			if err != nil {
				return nil, errors.New("Failed to build network policies info due to " + err.Error())
			}
			matchingPods = append(matchingPods, namespacePods...)
		}
	} else if peer.PodSelector != nil {
		podSelector, _ := v1.LabelSelectorAsSelector(peer.PodSelector)
		matchingPods, err = npc.ListPodsByNamespaceAndLabels(policy.Namespace, podSelector)
	}

	return matchingPods, err
}

func (npc *NetworkPolicyController) ListPodsByNamespaceAndLabels(namespace string, podSelector labels.Selector) (ret []*api.Pod, err error) {
	podLister := listers.NewPodLister(npc.podLister)
	allMatchedNameSpacePods, err := podLister.Pods(namespace).List(podSelector)
	if err != nil {
		return nil, err
	}
	return allMatchedNameSpacePods, nil
}

func (npc *NetworkPolicyController) ListNamespaceByLabels(namespaceSelector labels.Selector) ([]*api.Namespace, error) {
	namespaceLister := listers.NewNamespaceLister(npc.nsLister)
	matchedNamespaces, err := namespaceLister.List(namespaceSelector)
	if err != nil {
		return nil, err
	}
	return matchedNamespaces, nil
}

func (npc *NetworkPolicyController) evalIPBlockPeer(peer networking.NetworkPolicyPeer) [][]string {
	ipBlock := make([][]string, 0)
	if peer.PodSelector == nil && peer.NamespaceSelector == nil && peer.IPBlock != nil {
		if cidr := peer.IPBlock.CIDR; strings.HasSuffix(cidr, "/0") {
			ipBlock = append(ipBlock, []string{"0.0.0.0/1", utils.OptionTimeout, "0"}, []string{"128.0.0.0/1", utils.OptionTimeout, "0"})
		} else {
			ipBlock = append(ipBlock, []string{cidr, utils.OptionTimeout, "0"})
		}
		for _, except := range peer.IPBlock.Except {
			if strings.HasSuffix(except, "/0") {
				ipBlock = append(ipBlock, []string{"0.0.0.0/1", utils.OptionTimeout, "0", utils.OptionNoMatch}, []string{"128.0.0.0/1", utils.OptionTimeout, "0", utils.OptionNoMatch})
			} else {
				ipBlock = append(ipBlock, []string{except, utils.OptionTimeout, "0", utils.OptionNoMatch})
			}
		}
	}
	return ipBlock
}

func (npc *NetworkPolicyController) grabNamedPortFromPod(pod *api.Pod, namedPort2eps *namedPort2eps) {
	if pod == nil || namedPort2eps == nil {
		return
	}
	for k := range pod.Spec.Containers {
		for _, port := range pod.Spec.Containers[k].Ports {
			name := port.Name
			protocol := string(port.Protocol)
			containerPort := strconv.Itoa(int(port.ContainerPort))

			if (*namedPort2eps)[name] == nil {
				(*namedPort2eps)[name] = make(protocol2eps)
			}
			if (*namedPort2eps)[name][protocol] == nil {
				(*namedPort2eps)[name][protocol] = make(numericPort2eps)
			}
			if eps, ok := (*namedPort2eps)[name][protocol][containerPort]; !ok {
				(*namedPort2eps)[name][protocol][containerPort] = &endPoints{
					ips:             []string{pod.Status.PodIP},
					protocolAndPort: protocolAndPort{port: containerPort, protocol: protocol},
				}
			} else {
				eps.ips = append(eps.ips, pod.Status.PodIP)
			}
		}
	}
}

func podFirewallChainName(namespace, podName string, version string) string {
	hash := sha256.Sum256([]byte(namespace + podName + version))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubePodFirewallChainPrefix + encoded[:16]
}

func networkPolicyChainName(namespace, policyName string, version string) string {
	hash := sha256.Sum256([]byte(namespace + policyName + version))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeNetworkPolicyChainPrefix + encoded[:16]
}

func policySourcePodIPSetName(namespace, policyName string) string {
	hash := sha256.Sum256([]byte(namespace + policyName))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeSourceIPSetPrefix + encoded[:16]
}

func policyDestinationPodIPSetName(namespace, policyName string) string {
	hash := sha256.Sum256([]byte(namespace + policyName))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func policyIndexedSourcePodIPSetName(namespace, policyName string, ingressRuleNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) + "pod"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeSourceIPSetPrefix + encoded[:16]
}

func policyIndexedDestinationPodIPSetName(namespace, policyName string, egressRuleNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) + "pod"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func policyIndexedSourceIPBlockIPSetName(namespace, policyName string, ingressRuleNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) + "ipblock"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeSourceIPSetPrefix + encoded[:16]
}

func policyIndexedDestinationIPBlockIPSetName(namespace, policyName string, egressRuleNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) + "ipblock"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func policyIndexedIngressNamedPortIPSetName(namespace, policyName string, ingressRuleNo, namedPortNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) + strconv.Itoa(namedPortNo) + "namedport"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func policyIndexedEgressNamedPortIPSetName(namespace, policyName string, egressRuleNo, namedPortNo int) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) + strconv.Itoa(namedPortNo) + "namedport"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

// Cleanup cleanup configurations done
func (npc *NetworkPolicyController) Cleanup() {

	glog.Info("Cleaning up iptables configuration permanently done by kube-router")

	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		glog.Errorf("Failed to initialize iptables executor: %s", err.Error())
	}

	// delete jump rules in FORWARD chain to pod specific firewall chain
	forwardChainRules, err := iptablesCmdHandler.List("filter", kubeForwardChainName)
	if err != nil {
		glog.Errorf("Failed to delete iptables rules as part of cleanup")
		return
	}

	// TODO: need a better way to delte rule with out using number
	var realRuleNo int
	for i, rule := range forwardChainRules {
		if strings.Contains(rule, kubePodFirewallChainPrefix) {
			err = iptablesCmdHandler.Delete("filter", kubeForwardChainName, strconv.Itoa(i-realRuleNo))
			if err != nil {
				glog.Errorf("Failed to delete iptables rule as part of cleanup: %s", err)
			}
			realRuleNo++
		}
	}

	// delete jump rules in OUTPUT chain to pod specific firewall chain
	forwardChainRules, err = iptablesCmdHandler.List("filter", kubeOutputChainName)
	if err != nil {
		glog.Errorf("Failed to delete iptables rules as part of cleanup")
		return
	}

	// TODO: need a better way to delte rule with out using number
	realRuleNo = 0
	for i, rule := range forwardChainRules {
		if strings.Contains(rule, kubePodFirewallChainPrefix) {
			err = iptablesCmdHandler.Delete("filter", kubeOutputChainName, strconv.Itoa(i-realRuleNo))
			if err != nil {
				glog.Errorf("Failed to delete iptables rule as part of cleanup: %s", err)
			}
			realRuleNo++
		}
	}

	// flush and delete pod specific firewall chain
	chains, err := iptablesCmdHandler.ListChains("filter")
	if err != nil {
		glog.Errorf("Unable to list chains: %s", err)
		return
	}
	for _, chain := range chains {
		if strings.HasPrefix(chain, kubePodFirewallChainPrefix) {
			err = iptablesCmdHandler.ClearChain("filter", chain)
			if err != nil {
				glog.Errorf("Failed to cleanup iptables rules: " + err.Error())
				return
			}
			err = iptablesCmdHandler.DeleteChain("filter", chain)
			if err != nil {
				glog.Errorf("Failed to cleanup iptables rules: " + err.Error())
				return
			}
		}
	}

	// flush and delete per network policy specific chain
	chains, err = iptablesCmdHandler.ListChains("filter")
	if err != nil {
		glog.Errorf("Unable to list chains: %s", err)
		return
	}
	for _, chain := range chains {
		if strings.HasPrefix(chain, kubeNetworkPolicyChainPrefix) {
			err = iptablesCmdHandler.ClearChain("filter", chain)
			if err != nil {
				glog.Errorf("Failed to cleanup iptables rules: " + err.Error())
				return
			}
			err = iptablesCmdHandler.DeleteChain("filter", chain)
			if err != nil {
				glog.Errorf("Failed to cleanup iptables rules: " + err.Error())
				return
			}
		}
	}

	// delete all ipsets
	ipset, err := utils.NewIPSet(false)
	if err != nil {
		glog.Errorf("Failed to clean up ipsets: " + err.Error())
	}
	err = ipset.Save()
	if err != nil {
		glog.Errorf("Failed to clean up ipsets: " + err.Error())
	}
	err = ipset.DestroyAllWithin()
	if err != nil {
		glog.Errorf("Failed to clean up ipsets: " + err.Error())
	}
	glog.Infof("Successfully cleaned the iptables configuration done by kube-router")
}

func (npc *NetworkPolicyController) newPodEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			npc.OnPodUpdate(obj)

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newPoObj := newObj.(*api.Pod)
			oldPoObj := oldObj.(*api.Pod)
			if newPoObj.Status.Phase != oldPoObj.Status.Phase || newPoObj.Status.PodIP != oldPoObj.Status.PodIP {
				// for the network policies, we are only interested in pod status phase change or IP change
				npc.OnPodUpdate(newObj)
			}
		},
		DeleteFunc: func(obj interface{}) {
			npc.handlePodDelete(obj)
		},
	}
}

func (npc *NetworkPolicyController) newNetworkPolicyEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			npc.OnNetworkPolicyUpdate(obj)

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			npc.OnNetworkPolicyUpdate(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			npc.handleNetworkPolicyDelete(obj)

		},
	}
}

func (npc *NetworkPolicyController) handlePodDelete(obj interface{}) {
	pod, ok := obj.(*api.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			glog.Errorf("unexpected object type: %v", obj)
			return
		}
		if pod, ok = tombstone.Obj.(*api.Pod); !ok {
			glog.Errorf("unexpected object type: %v", obj)
			return
		}
	}
	glog.V(2).Infof("Received pod: %s/%s delete event", pod.Namespace, pod.Name)

	npc.RequestFullSync()
}

func (npc *NetworkPolicyController) handleNetworkPolicyDelete(obj interface{}) {
	netpol, ok := obj.(*networking.NetworkPolicy)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			glog.Errorf("unexpected object type: %v", obj)
			return
		}
		if netpol, ok = tombstone.Obj.(*networking.NetworkPolicy); !ok {
			glog.Errorf("unexpected object type: %v", obj)
			return
		}
	}
	glog.V(2).Infof("Received network policy: %s/%s delete event", netpol.Namespace, netpol.Name)

	npc.RequestFullSync()
}

// NewNetworkPolicyController returns new NetworkPolicyController object
func NewNetworkPolicyController(clientset kubernetes.Interface,
	config *options.KubeRouterConfig, podInformer cache.SharedIndexInformer,
	npInformer cache.SharedIndexInformer, nsInformer cache.SharedIndexInformer) (*NetworkPolicyController, error) {
	npc := NetworkPolicyController{}

	// Creating a single-item buffered channel to ensure that we only keep a single full sync request at a time,
	// additional requests would be pointless to queue since after the first one was processed the system would already
	// be up to date with all of the policy changes from any enqueued request after that
	npc.fullSyncRequestChan = make(chan struct{}, 1)

	// Validate and parse ClusterIP service range
	_, ipnet, err := net.ParseCIDR(config.ClusterIPCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to get parse --service-cluster-ip-range parameter: %s", err.Error())
	}
	npc.serviceClusterIPRange = *ipnet

	// Validate and parse NodePort range
	nodePortValidator := regexp.MustCompile(`^([0-9]+)[:-]{1}([0-9]+)$`)
	if matched := nodePortValidator.MatchString(config.NodePortRange); !matched {
		return nil, fmt.Errorf("failed to parse node port range given: '%s' please see specification in help text", config.NodePortRange)
	}
	matches := nodePortValidator.FindStringSubmatch(config.NodePortRange)
	if len(matches) != 3 {
		return nil, fmt.Errorf("could not parse port number from range given: '%s'", config.NodePortRange)
	}
	port1, err := strconv.ParseInt(matches[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("could not parse first port number from range given: '%s'", config.NodePortRange)
	}
	port2, err := strconv.ParseInt(matches[2], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("could not parse second port number from range given: '%s'", config.NodePortRange)
	}
	if port1 >= port2 {
		return nil, fmt.Errorf("port 1 is greater than or equal to port 2 in range given: '%s'", config.NodePortRange)
	}
	npc.serviceNodePortRange = fmt.Sprintf("%d:%d", port1, port2)

	// Validate and parse ExternalIP service range
	for _, externalIPRange := range config.ExternalIPCIDRs {
		_, ipnet, err := net.ParseCIDR(externalIPRange)
		if err != nil {
			return nil, fmt.Errorf("failed to get parse --service-external-ip-range parameter: '%s'. Error: %s", externalIPRange, err.Error())
		}
		npc.serviceExternalIPRanges = append(npc.serviceExternalIPRanges, *ipnet)
	}

	if config.MetricsEnabled {
		//Register the metrics for this controller
		prometheus.MustRegister(metrics.ControllerIptablesSyncTime)
		prometheus.MustRegister(metrics.ControllerPolicyChainsSyncTime)
		npc.MetricsEnabled = true
	}

	npc.syncPeriod = config.IPTablesSyncPeriod

	node, err := utils.GetNodeObject(clientset, config.HostnameOverride)
	if err != nil {
		return nil, err
	}

	npc.nodeHostName = node.Name

	nodeIP, err := utils.GetNodeIP(node)
	if err != nil {
		return nil, err
	}
	npc.nodeIP = nodeIP

	ipset, err := utils.NewIPSet(false)
	if err != nil {
		return nil, err
	}
	err = ipset.Save()
	if err != nil {
		return nil, err
	}
	npc.ipSetHandler = ipset

	npc.podLister = podInformer.GetIndexer()
	npc.PodEventHandler = npc.newPodEventHandler()

	npc.nsLister = nsInformer.GetIndexer()
	npc.NamespaceEventHandler = npc.newNamespaceEventHandler()

	npc.npLister = npInformer.GetIndexer()
	npc.NetworkPolicyEventHandler = npc.newNetworkPolicyEventHandler()

	return &npc, nil
}
