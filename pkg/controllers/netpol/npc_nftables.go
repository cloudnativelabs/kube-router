package netpol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/v2/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	v1core "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
	"sigs.k8s.io/knftables"
)

const (
	ipv4Table = "kube-router-filter-ipv4"
	ipv6Table = "kube-router-filter-ipv6"

	// nftMarkAcceptRule accepts traffic that a pod firewall chain marked as compliant with
	// network policies (bit 0x20000)
	nftMarkAcceptRule = "meta mark and 0x20000 == 0x20000 counter accept"
)

var chainToHook = map[string]knftables.BaseChainHook{
	kubeInputChainName:   knftables.InputHook,
	kubeOutputChainName:  knftables.OutputHook,
	kubeForwardChainName: knftables.ForwardHook,
}

// podFwJump holds the data needed to add a per-pod jump rule to the top-level chains.
// It is collected by syncPodFirewallChains and consumed by syncTopLevelChainsAtomic.
type podFwJump struct {
	podIP      string
	podFwChain string
	podName    string
	podNS      string
}

// NetworkPolicyControllerNftables is the nftables-based implementation of NetworkPolicyController.
// It uses nftables chains and named sets (instead of iptables chains and ipsets) to enforce
// Kubernetes network policies. This implementation is enabled via the UseNftablesForNetpol configuration
// option and provides the same network policy functionality as the iptables implementation.
type NetworkPolicyControllerNftables struct {
	*NetworkPolicyControllerBase

	knftInterfaces map[v1core.IPFamily]knftables.Interface
	ctx            context.Context
}

func NewKnftablesInterfaces(
	ctx context.Context, config *options.KubeRouterConfig) (map[v1core.IPFamily]knftables.Interface, error) {
	if config == nil || !config.UseNftablesForNetpol {
		return nil, nil
	}
	nftInterfaces := make(map[v1core.IPFamily]knftables.Interface, 2)
	var err error
	if config.EnableIPv4 {
		nftInterfaces[v1core.IPv4Protocol], err = initTable(ctx, knftables.IPv4Family, ipv4Table)
		if err != nil {
			return nil, err
		}
	}
	if config.EnableIPv6 {
		nftInterfaces[v1core.IPv6Protocol], err = initTable(ctx, knftables.IPv6Family, ipv6Table)
		if err != nil {
			return nil, err
		}
	}
	return nftInterfaces, nil
}

// create a new table and returns the interface to interact with it
func initTable(ctx context.Context, ipFamily knftables.Family, name string) (knftables.Interface, error) {
	nft, err := knftables.New(ipFamily, name)
	if err != nil {
		return nil, fmt.Errorf("no nftables support: %v", err)
	}
	tx := nft.NewTransaction()

	tx.Add(&knftables.Table{
		Comment: new("rules for " + name),
	})
	err = nft.Run(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("nftables: couldn't initialise table %s: %v", name, err)
	}
	return nft, nil
}

// Run runs forever till we receive notification on stopCh
func (npc *NetworkPolicyControllerNftables) Run(
	healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) {
	t := time.NewTicker(npc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	klog.Info("Starting network policy controller")
	npc.healthChan = healthChan

	var cancel context.CancelFunc
	npc.ctx, cancel = context.WithCancel(context.Background())

	// Ensure cancel is only called once to prevent race condition
	var cancelOnce sync.Once
	safeCancel := func() {
		cancelOnce.Do(func() {
			cancel()
		})
	}

	// setup kube-router specific top level custom chains (KUBE-ROUTER-INPUT, KUBE-ROUTER-FORWARD, KUBE-ROUTER-OUTPUT)
	if err := npc.ensureTopLevelChains(); err != nil {
		klog.Fatalf("Failed to setup top level chains: %v", err)
	}

	// setup default network policy chain that is applied to traffic from/to the pods that does not match any network
	// policy
	npc.ensureDefaultNetworkPolicyChain()

	// setup common network policy chain that is applied to all bi-directional traffic
	npc.ensureCommonPolicyChain()

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
				safeCancel()
				return
			default:
			}
			select {
			case <-stopCh:
				klog.Info("Shutting down network policies full sync goroutine")
				safeCancel()
				return
			case <-fullSyncRequest:
				klog.V(3).Info("Received request for a full sync, processing")
				npc.fullPolicySync() // fullPolicySync() is a blocking request here
			}
		}
	}(npc.fullSyncRequestChan, stopCh, wg)

	// loop forever till notified to stop on stopCh
	for {
		klog.V(1).Info("Requesting periodic sync of nftables to reflect network policies")
		npc.RequestFullSync()
		select {
		case <-stopCh:
			klog.Infof("Shutting down network policies controller")
			safeCancel()
			return
		case <-t.C:
		}
	}
}

func (npc *NetworkPolicyControllerNftables) fullPolicySync() {
	npc.mu.Lock()
	defer npc.mu.Unlock()

	healthcheck.SendHeartBeat(npc.healthChan, healthcheck.NetworkPolicyController)
	start := time.Now()
	syncVersion := strconv.FormatInt(start.UnixNano(), syncVersionBase)
	defer func() {
		endTime := time.Since(start)
		if npc.MetricsEnabled {
			metrics.ControllerIptablesSyncTime.Observe(endTime.Seconds())
		}
		klog.V(1).Infof("sync nftables took %v", endTime)
	}()

	klog.V(1).Infof("Starting sync of nftables with version: %s", syncVersion)

	// ensure default network policy chain that is applied to traffic from/to the pods that does not match any network
	// policy
	npc.ensureDefaultNetworkPolicyChain()

	// ensure common network policy chain that is applied to all bi-directional traffic
	npc.ensureCommonPolicyChain()

	// (re)create KUBE-NWPLCY-TAIL chain + kube-router-local-pods named set. Rebuild every sync so the
	// per-CIDR REJECT rules track --netpol-default-deny / pod CIDR changes without a controller restart.
	npc.ensureDefaultTailChain()

	networkPoliciesInfo, err := npc.buildNetworkPoliciesInfo()
	if err != nil {
		klog.Errorf("Aborting sync. Failed to build network policies: %v", err.Error())
		return
	}

	activePolicyChains, activePolicyIPSets, err := npc.syncNetworkPolicyChains(networkPoliciesInfo, syncVersion)
	if err != nil {
		klog.Errorf("Aborting sync. Failed to sync network policy chains: %v", err.Error())
		return
	}

	activePodFwChains, activePodIPs, podJumps, err := npc.syncPodFirewallChains(networkPoliciesInfo, syncVersion)
	if err != nil {
		klog.Errorf("Aborting sync. Failed to sync pod firewall chains: %v", err.Error())
		return
	}
	klog.V(3).Infof("Active pod firewall chains: %d", len(activePodFwChains))

	// Refresh the kube-router-local-pods named set before the top-level chains are rebuilt,
	// so the TAIL chain's set-gated REJECT rules reference current pod IPs.
	// No-op when --netpol-default-deny is disabled.
	npc.populateProtectedPodsIPSet(activePodIPs)

	// Atomically rebuild every top-level chain in one transaction per family:
	// flush → static exemptions → per-pod jumps → TAIL jump → explicit ACCEPT.
	// This eliminates the enforcement gap that existed when those writes happened
	// across several separate transactions.
	if err := npc.syncTopLevelChainsAtomic(podJumps); err != nil {
		klog.Errorf("Aborting sync. Failed to atomically rebuild top-level chains: %v", err)
		return
	}

	// GC must run last, and pod-fw chains before policy objects: only after the atomic top-level
	// rebuild do the previous sync's pod-fw chains lose their inbound jump references, and only
	// after those chains are deleted do the stale policy chains and sets they referenced become
	// deletable in turn.
	npc.gcPodFwChainsNft(activePodFwChains)
	npc.gcPolicyObjectsNft(activePolicyChains, activePolicyIPSets)
}

// nftablesNodePortRange converts the stored colon-separated port range (e.g. "30000:32767")
// to the hyphen-separated form required by nftables (e.g. "30000-32767").
func (npc *NetworkPolicyControllerNftables) nftablesNodePortRange() string {
	return strings.ReplaceAll(npc.serviceNodePortRange, ":", "-")
}

// ensureTopLevelChains creates the top-level hook chains if they are missing, WITHOUT flushing
// them or installing any rules. We deliberately preserve whatever ruleset the previous controller
// instance left in the kernel so that policies stay enforced across a restart; the first
// fullPolicySync atomically replaces the chain contents via syncTopLevelChainsAtomic. Flushing
// here would open an allow-all window between startup and the end of the first sync.
func (npc *NetworkPolicyControllerNftables) ensureTopLevelChains() error {
	ctx := npc.ctx
	klog.V(2).Infof("Ensuring top level chains exist")

	// Validate early that a cluster IP range is configured, because syncTopLevelChainsAtomic
	// depends on it for the service CIDR exemption rules.
	if len(npc.ipRanges.ClusterIPRanges()) == 0 {
		return errors.New("primary service cluster IP range is not configured")
	}

	for _, nft := range npc.knftInterfaces {
		tx := nft.NewTransaction()
		for chain, hook := range chainToHook {
			tx.Add(&knftables.Chain{
				Name:     chain,
				Comment:  new("top level " + chain + " chain for kube-router"),
				Type:     knftables.PtrTo(knftables.FilterType),
				Hook:     new(hook),
				Priority: knftables.PtrTo(knftables.FilterPriority),
			})
		}
		if err := nft.Run(ctx, tx); err != nil {
			klog.ErrorS(err, "nftables: couldn't ensure top level chains")
			return fmt.Errorf("failed to ensure top level chains: %w", err)
		}
	}
	return nil
}

// Creates custom chains KUBE-NWPLCY-DEFAULT which holds rules for the default network policy. This is applied to
// traffic which is not selected by any network policy and is primarily used to allow traffic that is accepted by
// default.
//
// NOTE: This chain is only targeted by unidirectional network traffic selectors.
func (npc *NetworkPolicyControllerNftables) ensureDefaultNetworkPolicyChain() {
	ctx := npc.ctx
	klog.V(2).Infof("Creating default network policy chain")

	for _, nft := range npc.knftInterfaces {
		tx := nft.NewTransaction()
		tx.Add(&knftables.Chain{
			Name:    kubeDefaultNetpolChain,
			Comment: new(kubeDefaultNetpolChain + " chain for kube-router"),
		})
		tx.Flush(&knftables.Chain{
			Name: kubeDefaultNetpolChain,
		})
		// Start off by marking traffic with an invalid mark so that we can allow list only traffic accepted by a
		// matching policy. Anything that still has 0x10000
		tx.Add(&knftables.Rule{
			Chain: kubeDefaultNetpolChain,
			Rule: knftables.Concat(
				"counter", "meta mark", "set mark", "or", "0x10000",
			),
			Comment: new("mark netpol match"),
		})
		err := nft.Run(ctx, tx)
		if err != nil {
			klog.V(2).ErrorS(err, "nftables: couldn't setup chain %s", kubeDefaultNetpolChain)
			continue
		}
	}
}

func (npc *NetworkPolicyControllerNftables) ensureCommonPolicyChain() {
	ctx := npc.ctx
	klog.V(2).Infof("Creating common policy chains")

	for family, nft := range npc.knftInterfaces {
		tx := nft.NewTransaction()
		tx.Add(&knftables.Chain{
			Name:    kubeCommonNetpolChain,
			Comment: new(kubeCommonNetpolChain + " chain for kube-router"),
		})
		tx.Flush(&knftables.Chain{
			Name: kubeCommonNetpolChain,
		})
		// ensure stateful firewall drops INVALID state traffic from/to the pod
		// For full context see: https://bugzilla.netfilter.org/show_bug.cgi?id=693
		// The NAT engine ignores any packet with state INVALID, because there's no reliable way to determine what kind of
		// NAT should be performed. So the proper way to prevent the leakage is to drop INVALID packets.
		// In the future, if we ever allow services or nodes to disable conntrack checking, we may need to make this
		// conditional so that non-tracked traffic doesn't get dropped as invalid.
		tx.Add(&knftables.Rule{
			Chain: kubeCommonNetpolChain,
			Rule: knftables.Concat(
				"ct state invalid", "counter", "drop",
			),
			Comment: new("drop invalid state"),
		})
		// ensure stateful firewall that permits RELATED,ESTABLISHED traffic from/to the pod
		tx.Add(&knftables.Rule{
			Chain: kubeCommonNetpolChain,
			Rule: knftables.Concat(
				"ct state established,related", "counter", "accept",
			),
			Comment: new("accept established/related"),
		})

		icmpRules := utils.CommonICMPRules(family)
		for _, icmpRule := range icmpRules {
			tx.Add(&knftables.Rule{
				Chain: kubeCommonNetpolChain,
				Rule: knftables.Concat(
					icmpRule.NftablesProto,
					"type", icmpRule.NftablesICMPType,
					"counter", "accept"),
				Comment: new("allow icmp " + icmpRule.NftablesICMPType + " messages"),
			})
		}
		err := nft.Run(ctx, tx)
		if err != nil {
			klog.V(2).ErrorS(err, "nftables: couldn't setup chain %s", kubeCommonNetpolChain)
			continue
		}
	}
}

func NewNetworkPolicyControllerNftables(
	npcBase *NetworkPolicyControllerBase, clientset kubernetes.Interface,
	config *options.KubeRouterConfig, podInformer cache.SharedIndexInformer,
	npInformer cache.SharedIndexInformer, nsInformer cache.SharedIndexInformer,
	linkQ utils.LocalLinkQuerier,
	knftInterfaces map[v1core.IPFamily]knftables.Interface) (*NetworkPolicyControllerNftables, error) {

	npc := NetworkPolicyControllerNftables{NetworkPolicyControllerBase: npcBase, knftInterfaces: knftInterfaces}

	if config.EnableIPv4 {
		if !npc.krNode.IsIPv4Capable() {
			return nil, errors.New("IPv4 was enabled but no IPv4 address was found on node")
		}
		klog.V(2).Infof("IPv4 is enabled")
		nft, ok := npc.knftInterfaces[v1core.IPv4Protocol]
		if !ok || nft == nil {
			return nil, errors.New("IPv4 is enabled but nftables interface for IPv4 is not initialized")
		}
		var buf bytes.Buffer
		npc.filterTableRules[v1core.IPv4Protocol] = &buf
	}
	if config.EnableIPv6 {
		if !npc.krNode.IsIPv6Capable() {
			return nil, errors.New("IPv6 was enabled but no IPv6 address was found on node")
		}
		klog.V(2).Infof("IPv6 is enabled")
		nft, ok := npc.knftInterfaces[v1core.IPv6Protocol]
		if !ok || nft == nil {
			return nil, errors.New("IPv6 is enabled but nftables interface for IPv6 is not initialized")
		}
		var buf bytes.Buffer
		npc.filterTableRules[v1core.IPv6Protocol] = &buf
	}
	return &npc, nil
}

// ---------------------------------------------------------------------------
// nftables set naming helpers
// ---------------------------------------------------------------------------
// These produce bare names (no "6:" family prefix) because the sets live inside
// a per-IP-family nftables table.

func nftDestinationPodSetName(namespace, policyName string, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + string(ipFamily)))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func nftSourcePodSetName(namespace, policyName string, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + string(ipFamily)))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeSourceIPSetPrefix + encoded[:16]
}

func nftIndexedSourcePodSetName(namespace, policyName string, ingressRuleNo int, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) +
		string(ipFamily) + "pod"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeSourceIPSetPrefix + encoded[:16]
}

func nftIndexedDestinationPodSetName(namespace, policyName string, egressRuleNo int, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) +
		string(ipFamily) + "pod"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func nftIndexedSourceIPBlockSetName(namespace, policyName string, ingressRuleNo int, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) +
		string(ipFamily) + "ipblock"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeSourceIPSetPrefix + encoded[:16]
}

func nftIndexedSourceIPBlockExceptSetName(
	namespace, policyName string, ingressRuleNo int, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) +
		string(ipFamily) + "ipblockexcept"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeSourceIPSetPrefix + encoded[:16]
}

func nftIndexedDestinationIPBlockSetName(
	namespace, policyName string, egressRuleNo int, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) +
		string(ipFamily) + "ipblock"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func nftIndexedDestinationIPBlockExceptSetName(
	namespace, policyName string, egressRuleNo int, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) +
		string(ipFamily) + "ipblockexcept"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

// nftIndexedSourceIPBlockChainName returns the name of a per-rule sub-chain used when an ingress
// ipBlock rule has except CIDRs. Isolating the except-return inside a sub-chain ensures that the
// return only exits back to the policy chain, not past all remaining policy rules.
func nftIndexedSourceIPBlockChainName(
	namespace, policyName string, ingressRuleNo int, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) +
		string(ipFamily) + "ipblockchain"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeNetworkPolicyChainPrefix + encoded[:16]
}

// nftIndexedDestinationIPBlockChainName returns the name of a per-rule sub-chain used when an egress
// ipBlock rule has except CIDRs. See nftIndexedSourceIPBlockChainName for rationale.
func nftIndexedDestinationIPBlockChainName(
	namespace, policyName string, egressRuleNo int, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) +
		string(ipFamily) + "ipblockchain"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeNetworkPolicyChainPrefix + encoded[:16]
}

func nftIndexedIngressNamedPortSetName(
	namespace, policyName string, ingressRuleNo, namedPortNo int, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "ingressrule" + strconv.Itoa(ingressRuleNo) +
		strconv.Itoa(namedPortNo) + string(ipFamily) + "namedport"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

func nftIndexedEgressNamedPortSetName(
	namespace, policyName string, egressRuleNo, namedPortNo int, ipFamily v1core.IPFamily) string {
	hash := sha256.Sum256([]byte(namespace + policyName + "egressrule" + strconv.Itoa(egressRuleNo) +
		strconv.Itoa(namedPortNo) + string(ipFamily) + "namedport"))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return kubeDestinationIPSetPrefix + encoded[:16]
}

// ---------------------------------------------------------------------------
// nftables set helpers
// ---------------------------------------------------------------------------

// nftAddOrReplaceIPSet declares a named nftables set and flushes+repopulates its elements
// within the given transaction.
func (npc *NetworkPolicyControllerNftables) nftAddOrReplaceIPSet(
	tx *knftables.Transaction, setName string, entries []string, ipFamily v1core.IPFamily) {

	setType := "ipv4_addr"
	if ipFamily == v1core.IPv6Protocol {
		setType = "ipv6_addr"
	}
	set := &knftables.Set{
		Name:    setName,
		Type:    setType,
		Comment: new("netpol set"),
	}
	tx.Add(set)
	tx.Flush(&knftables.Set{Name: setName})
	for _, entry := range entries {
		tx.Add(&knftables.Element{
			Set: setName,
			Key: []string{entry},
		})
	}
}

// nftAddOrReplaceIPBlockSet declares a named interval nftables set for CIDR ipblock rules.
// entries is the 2-D slice produced by evalIPBlockPeer where each inner slice is one of:
//
//	[cidr, "timeout", "0"]              – include this CIDR
//	[cidr, "timeout", "0", "nomatch"]   – exclude this CIDR (populated into exceptSetName)
//
// If any exclude entries are present they are written into a second interval set named
// exceptSetName so that the caller can prepend a return rule for them.  The function
// returns true when at least one exclude entry was found (i.e. an except set was created).
func (npc *NetworkPolicyControllerNftables) nftAddOrReplaceIPBlockSet(
	tx *knftables.Transaction, setName, exceptSetName string, entries [][]string, ipFamily v1core.IPFamily) bool {

	setType := "ipv4_addr"
	if ipFamily == v1core.IPv6Protocol {
		setType = "ipv6_addr"
	}
	tx.Add(&knftables.Set{
		Name:    setName,
		Type:    setType,
		Flags:   []knftables.SetFlag{knftables.IntervalFlag},
		Comment: new("netpol ipblock set"),
	})
	tx.Flush(&knftables.Set{Name: setName})

	var exceptCIDRs []string
	for _, entry := range entries {
		if len(entry) == 0 {
			continue
		}
		if len(entry) >= 4 && entry[3] == utils.OptionNoMatch {
			exceptCIDRs = append(exceptCIDRs, entry[0])
			continue
		}
		tx.Add(&knftables.Element{
			Set: setName,
			Key: []string{entry[0]},
		})
	}

	if len(exceptCIDRs) == 0 {
		return false
	}

	// Populate the except set with the excluded CIDRs.
	tx.Add(&knftables.Set{
		Name:    exceptSetName,
		Type:    setType,
		Flags:   []knftables.SetFlag{knftables.IntervalFlag},
		Comment: new("netpol ipblock except set"),
	})
	tx.Flush(&knftables.Set{Name: exceptSetName})
	for _, cidr := range exceptCIDRs {
		tx.Add(&knftables.Element{
			Set: exceptSetName,
			Key: []string{cidr},
		})
	}
	return true
}

// ---------------------------------------------------------------------------
// rule builder
// ---------------------------------------------------------------------------

// appendRuleToPolicyChainNft adds an nftables policyChainName that marks
// matching traffic with 0x10000 and returns, mirroring the iptables MARK+RETURN pair.
func (npc *NetworkPolicyControllerNftables) appendRuleToPolicyChainNft(
	tx *knftables.Transaction, policyChainName, comment,
	srcSetName, dstSetName, protocol, dPort, endDport string, ipFamily v1core.IPFamily) {

	parts := make([]any, 0)

	addrKeyword := "ip"
	if ipFamily == v1core.IPv6Protocol {
		addrKeyword = "ip6"
	}
	if srcSetName != "" {
		parts = append(parts, addrKeyword, "saddr", "@"+srcSetName)
	}
	if dstSetName != "" {
		parts = append(parts, addrKeyword, "daddr", "@"+dstSetName)
	}
	// Determine the effective L4 protocol for this rule.
	// nftables requires an explicit protocol keyword before any port match (e.g. "tcp dport 80").
	// Kubernetes allows omitting Protocol on a NetworkPolicyPort, which the K8s spec says
	// defaults to TCP. Normalise to lowercase to match nftables expectations.
	effectiveProtocol := strings.ToLower(protocol)
	if effectiveProtocol == "" && dPort != "" {
		// No protocol specified but a port is present — default to TCP per the Kubernetes spec
		// (https://kubernetes.io/docs/concepts/services-networking/network-policies/#behavior-of-to-and-from-selectors).
		effectiveProtocol = "tcp"
	}
	if effectiveProtocol != "" {
		parts = append(parts, effectiveProtocol)
	}
	if dPort != "" {
		if endDport != "" {
			parts = append(parts, "dport", dPort+"-"+endDport)
		} else {
			parts = append(parts, "dport", dPort)
		}
	}
	// Mark and return in a single step (equivalent to iptables MARK --set-xmark + RETURN).
	parts = append(parts, "counter")
	parts = append(parts, "meta mark set meta mark or 0x10000")
	parts = append(parts, "return")

	var commentPtr *string
	if comment != "" {
		commentPtr = new(comment)
	}
	tx.Add(&knftables.Rule{
		Chain:   policyChainName,
		Rule:    knftables.Concat(parts...),
		Comment: commentPtr,
	})
}

// ---------------------------------------------------------------------------
// ingress / egress rule processors
// ---------------------------------------------------------------------------

// nftAddPodMatchRules appends the pod-selector match rules shared by ingress and egress processing.
// podSetName is the matched pods, counterSetName the opposite set; podIsSource picks which is the
// source (true for ingress, false for egress) and drives the rule comment's direction.
func (npc *NetworkPolicyControllerNftables) nftAddPodMatchRules(
	tx *knftables.Transaction, policyChainName string, policy networkPolicyInfo,
	activePolicyIPSets map[string]bool, ruleIdx int, ipFamily v1core.IPFamily,
	podSetName, counterSetName string,
	ports []protocolAndPort, namedPorts []endPoints,
	namedPortSetNameFn func(string, string, int, int, v1core.IPFamily) string,
	podIsSource bool) {

	srcSet, dstSet := podSetName, counterSetName
	if !podIsSource {
		srcSet, dstSet = counterSetName, podSetName
	}

	kind := cmtIngressPods
	if !podIsSource {
		kind = cmtEgressPods
	}

	for _, portProtocol := range ports {
		comment := polRuleComment(policy, kind)
		npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
			srcSet, dstSet,
			portProtocol.protocol, portProtocol.port, portProtocol.endport, ipFamily)
	}

	for epIdx, ep := range namedPorts {
		namedPortSetName := namedPortSetNameFn(policy.namespace, policy.name, ruleIdx, epIdx, ipFamily)
		activePolicyIPSets[namedPortSetName] = true
		npc.nftAddOrReplaceIPSet(tx, namedPortSetName, ep.ips[ipFamily], ipFamily)
		comment := polRuleComment(policy, kind+cmtNamedPort)
		npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
			srcSet, namedPortSetName,
			ep.protocol, ep.port, ep.endport, ipFamily)
	}

	if len(ports) == 0 && len(namedPorts) == 0 {
		comment := polRuleComment(policy, kind)
		npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
			srcSet, dstSet, "", "", "", ipFamily)
	}
}

func (npc *NetworkPolicyControllerNftables) processIngressRulesNft(
	tx *knftables.Transaction, policy networkPolicyInfo,
	targetDestPodSetName string, activePolicyIPSets map[string]bool,
	activePolicyChains map[string]bool,
	version string, ipFamily v1core.IPFamily) {

	if policy.ingressRules == nil {
		return
	}

	policyChainName := networkPolicyChainName(policy.namespace, policy.name, version, ipFamily)

	for ruleIdx, ingressRule := range policy.ingressRules {

		if len(ingressRule.srcPods) != 0 {
			srcPodSetName := nftIndexedSourcePodSetName(policy.namespace, policy.name, ruleIdx, ipFamily)
			activePolicyIPSets[srcPodSetName] = true
			npc.nftAddOrReplaceIPSet(tx, srcPodSetName,
				getIPsFromPods(ingressRule.srcPods, ipFamily), ipFamily)
			npc.nftAddPodMatchRules(tx, policyChainName, policy, activePolicyIPSets, ruleIdx, ipFamily,
				srcPodSetName, targetDestPodSetName,
				ingressRule.ports, ingressRule.namedPorts, nftIndexedIngressNamedPortSetName, true)
		}

		if ingressRule.matchAllSource && !ingressRule.matchAllPorts {
			for _, portProtocol := range ingressRule.ports {
				comment := polRuleComment(policy, cmtIngressAny)
				npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
					"", targetDestPodSetName,
					portProtocol.protocol, portProtocol.port, portProtocol.endport, ipFamily)
			}
			for epIdx, endPoints := range ingressRule.namedPorts {
				namedPortSetName := nftIndexedIngressNamedPortSetName(policy.namespace,
					policy.name, ruleIdx, epIdx, ipFamily)
				activePolicyIPSets[namedPortSetName] = true
				npc.nftAddOrReplaceIPSet(tx, namedPortSetName,
					endPoints.ips[ipFamily], ipFamily)
				comment := polRuleComment(policy, cmtIngressAny+cmtNamedPort)
				npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
					"", namedPortSetName,
					endPoints.protocol, endPoints.port, endPoints.endport, ipFamily)
			}
		}

		if ingressRule.matchAllSource && ingressRule.matchAllPorts {
			comment := polRuleComment(policy, cmtIngressAny)
			npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
				"", targetDestPodSetName, "", "", "", ipFamily)
		}

		if len(ingressRule.srcIPBlocks[ipFamily]) != 0 {
			srcIPBlockSetName := nftIndexedSourceIPBlockSetName(policy.namespace, policy.name, ruleIdx, ipFamily)
			srcIPBlockExceptSetName := nftIndexedSourceIPBlockExceptSetName(policy.namespace, policy.name, ruleIdx, ipFamily)
			activePolicyIPSets[srcIPBlockSetName] = true
			hasExcepts := npc.nftAddOrReplaceIPBlockSet(tx, srcIPBlockSetName, srcIPBlockExceptSetName,
				ingressRule.srcIPBlocks[ipFamily], ipFamily)

			// ipBlockChain is where the ipBlock accept rules land. When there are except CIDRs,
			// a per-rule sub-chain is used so that "return" for excepted IPs only exits that
			// sub-chain; the policy chain continues to evaluate later rules (Kubernetes ORs all rules).
			ipBlockChain := policyChainName
			if hasExcepts {
				activePolicyIPSets[srcIPBlockExceptSetName] = true
				addrKeyword := "ip"
				if ipFamily == v1core.IPv6Protocol {
					addrKeyword = "ip6"
				}
				subChainName := nftIndexedSourceIPBlockChainName(policy.namespace, policy.name, ruleIdx, ipFamily)
				activePolicyChains[subChainName] = true
				tx.Add(&knftables.Chain{Name: subChainName})
				tx.Flush(&knftables.Chain{Name: subChainName})
				tx.Add(&knftables.Rule{
					Chain:   subChainName,
					Rule:    knftables.Concat(addrKeyword, "saddr", "@"+srcIPBlockExceptSetName, "counter return"),
					Comment: new(idComment(policy.namespace, policy.name, cmtExceptSrc)),
				})
				tx.Add(&knftables.Rule{
					Chain:   policyChainName,
					Rule:    knftables.Concat("counter jump", subChainName),
					Comment: new(idComment(policy.namespace, policy.name, cmtIPBlock)),
				})
				ipBlockChain = subChainName
			}

			if !ingressRule.matchAllPorts {
				for _, portProtocol := range ingressRule.ports {
					comment := polRuleComment(policy, cmtIngressCIDR)
					npc.appendRuleToPolicyChainNft(tx, ipBlockChain, comment,
						srcIPBlockSetName, targetDestPodSetName,
						portProtocol.protocol, portProtocol.port, portProtocol.endport, ipFamily)
				}
				for epIdx, endPoints := range ingressRule.namedPorts {
					namedPortSetName := nftIndexedIngressNamedPortSetName(policy.namespace,
						policy.name, ruleIdx, epIdx, ipFamily)
					activePolicyIPSets[namedPortSetName] = true
					npc.nftAddOrReplaceIPSet(tx, namedPortSetName,
						endPoints.ips[ipFamily], ipFamily)
					comment := polRuleComment(policy, cmtIngressCIDR+cmtNamedPort)
					npc.appendRuleToPolicyChainNft(tx, ipBlockChain, comment,
						srcIPBlockSetName, namedPortSetName,
						endPoints.protocol, endPoints.port, endPoints.endport, ipFamily)
				}
			}
			if ingressRule.matchAllPorts {
				comment := polRuleComment(policy, cmtIngressCIDR)
				npc.appendRuleToPolicyChainNft(tx, ipBlockChain, comment,
					srcIPBlockSetName, targetDestPodSetName, "", "", "", ipFamily)
			}
		}
	}
}

func (npc *NetworkPolicyControllerNftables) processEgressRulesNft(
	tx *knftables.Transaction, policy networkPolicyInfo,
	targetSourcePodSetName string, activePolicyIPSets map[string]bool,
	activePolicyChains map[string]bool,
	version string, ipFamily v1core.IPFamily) {

	if policy.egressRules == nil {
		return
	}

	policyChainName := networkPolicyChainName(policy.namespace, policy.name, version, ipFamily)

	for ruleIdx, egressRule := range policy.egressRules {

		if len(egressRule.dstPods) != 0 {
			dstPodSetName := nftIndexedDestinationPodSetName(policy.namespace, policy.name, ruleIdx, ipFamily)
			activePolicyIPSets[dstPodSetName] = true
			npc.nftAddOrReplaceIPSet(tx, dstPodSetName,
				getIPsFromPods(egressRule.dstPods, ipFamily), ipFamily)
			npc.nftAddPodMatchRules(tx, policyChainName, policy, activePolicyIPSets, ruleIdx, ipFamily,
				dstPodSetName, targetSourcePodSetName,
				egressRule.ports, egressRule.namedPorts, nftIndexedEgressNamedPortSetName, false)
		}

		if egressRule.matchAllDestinations && !egressRule.matchAllPorts {
			for _, portProtocol := range egressRule.ports {
				comment := polRuleComment(policy, cmtEgressAny)
				npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
					targetSourcePodSetName, "",
					portProtocol.protocol, portProtocol.port, portProtocol.endport, ipFamily)
			}
			for _, portProtocol := range egressRule.namedPorts {
				comment := polRuleComment(policy, cmtEgressAny+cmtNamedPort)
				npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
					targetSourcePodSetName, "",
					portProtocol.protocol, portProtocol.port, portProtocol.endport, ipFamily)
			}
		}

		if egressRule.matchAllDestinations && egressRule.matchAllPorts {
			comment := polRuleComment(policy, cmtEgressAny)
			npc.appendRuleToPolicyChainNft(tx, policyChainName, comment,
				targetSourcePodSetName, "", "", "", "", ipFamily)
		}

		if len(egressRule.dstIPBlocks[ipFamily]) != 0 {
			dstIPBlockSetName := nftIndexedDestinationIPBlockSetName(policy.namespace, policy.name, ruleIdx, ipFamily)
			dstIPBlockExceptSetName := nftIndexedDestinationIPBlockExceptSetName(
				policy.namespace, policy.name, ruleIdx, ipFamily)
			activePolicyIPSets[dstIPBlockSetName] = true
			hasExcepts := npc.nftAddOrReplaceIPBlockSet(tx, dstIPBlockSetName, dstIPBlockExceptSetName,
				egressRule.dstIPBlocks[ipFamily], ipFamily)

			// ipBlockChain is where the ipBlock accept rules land. When there are except CIDRs,
			// a per-rule sub-chain is used so that "return" for excepted IPs only exits that
			// sub-chain; the policy chain continues to evaluate later rules (Kubernetes ORs all rules).
			ipBlockChain := policyChainName
			if hasExcepts {
				activePolicyIPSets[dstIPBlockExceptSetName] = true
				addrKeyword := "ip"
				if ipFamily == v1core.IPv6Protocol {
					addrKeyword = "ip6"
				}
				subChainName := nftIndexedDestinationIPBlockChainName(policy.namespace, policy.name, ruleIdx, ipFamily)
				activePolicyChains[subChainName] = true
				tx.Add(&knftables.Chain{Name: subChainName})
				tx.Flush(&knftables.Chain{Name: subChainName})
				tx.Add(&knftables.Rule{
					Chain:   subChainName,
					Rule:    knftables.Concat(addrKeyword, "daddr", "@"+dstIPBlockExceptSetName, "counter return"),
					Comment: new(idComment(policy.namespace, policy.name, cmtExceptDst)),
				})
				tx.Add(&knftables.Rule{
					Chain:   policyChainName,
					Rule:    knftables.Concat("counter jump", subChainName),
					Comment: new(idComment(policy.namespace, policy.name, cmtIPBlock)),
				})
				ipBlockChain = subChainName
			}

			if !egressRule.matchAllPorts {
				for _, portProtocol := range egressRule.ports {
					comment := polRuleComment(policy, cmtEgressCIDR)
					npc.appendRuleToPolicyChainNft(tx, ipBlockChain, comment,
						targetSourcePodSetName, dstIPBlockSetName,
						portProtocol.protocol, portProtocol.port, portProtocol.endport, ipFamily)
				}
			}
			if egressRule.matchAllPorts {
				comment := polRuleComment(policy, cmtEgressCIDR)
				npc.appendRuleToPolicyChainNft(tx, ipBlockChain, comment,
					targetSourcePodSetName, dstIPBlockSetName, "", "", "", ipFamily)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// syncNetworkPolicyChains
// ---------------------------------------------------------------------------

// syncNetworkPolicyChains is the nftables equivalent of the iptables/ipset implementation.
// For each network policy it creates one nftables chain per IP family, plus named sets
// that hold the matched pod IPs (replacing iptables ipsets).  It returns maps of all
// active chain and set names so the caller can garbage-collect stale objects.
func (npc *NetworkPolicyControllerNftables) syncNetworkPolicyChains(
	networkPoliciesInfo []networkPolicyInfo, version string) (map[string]bool, map[string]bool, error) {

	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		if npc.MetricsEnabled {
			metrics.ControllerPolicyChainsSyncTime.Observe(endTime.Seconds())
		}
		klog.V(2).Infof("Syncing network policy chains took %v", endTime)
	}()

	ctx := npc.ctx
	activePolicyChains := make(map[string]bool)
	activePolicyIPSets := make(map[string]bool)

	defer func() {
		if npc.MetricsEnabled {
			metrics.ControllerPolicyChains.Set(float64(len(activePolicyChains)))
			metrics.ControllerPolicyIpsets.Set(float64(len(activePolicyIPSets)))
		}
	}()

	for _, policy := range networkPoliciesInfo {
		// Gather current pod IPs for this policy split by IP family.
		currentPodIPs := make(map[v1core.IPFamily][]string)
		for _, pod := range policy.targetPods {
			for _, ip := range pod.ips {
				if netutils.IsIPv4String(ip.IP) {
					currentPodIPs[v1core.IPv4Protocol] = append(currentPodIPs[v1core.IPv4Protocol], ip.IP)
				}
				if netutils.IsIPv6String(ip.IP) {
					currentPodIPs[v1core.IPv6Protocol] = append(currentPodIPs[v1core.IPv6Protocol], ip.IP)
				}
			}
		}

		for ipFamily, nft := range npc.knftInterfaces {
			// One chain per policy per IP family – name is a hash of namespace+name+version+family.
			policyChainName := networkPolicyChainName(policy.namespace, policy.name, version, ipFamily)
			activePolicyChains[policyChainName] = true

			tx := nft.NewTransaction()

			// Declare (or reset) the policy chain.
			tx.Add(&knftables.Chain{
				Name:    policyChainName,
				Comment: new(clampComment("netpol " + policy.namespace + "/" + policy.name)),
			})
			tx.Flush(&knftables.Chain{Name: policyChainName})

			if policy.policyType == kubeBothPolicyType || policy.policyType == kubeIngressPolicyType {
				// Destination-pod set – all pods targeted by this policy (used for ingress matching).
				targetDestPodSetName := nftDestinationPodSetName(policy.namespace, policy.name, ipFamily)
				activePolicyIPSets[targetDestPodSetName] = true
				npc.nftAddOrReplaceIPSet(tx, targetDestPodSetName, currentPodIPs[ipFamily], ipFamily)

				npc.processIngressRulesNft(tx, policy, targetDestPodSetName,
					activePolicyIPSets, activePolicyChains, version, ipFamily)
			}

			if policy.policyType == kubeBothPolicyType || policy.policyType == kubeEgressPolicyType {
				// Source-pod set – all pods targeted by this policy (used for egress matching).
				targetSourcePodSetName := nftSourcePodSetName(policy.namespace, policy.name, ipFamily)
				activePolicyIPSets[targetSourcePodSetName] = true
				npc.nftAddOrReplaceIPSet(tx, targetSourcePodSetName, currentPodIPs[ipFamily], ipFamily)

				npc.processEgressRulesNft(tx, policy, targetSourcePodSetName,
					activePolicyIPSets, activePolicyChains, version, ipFamily)
			}

			if err := nft.Run(ctx, tx); err != nil {
				return nil, nil, fmt.Errorf("nftables: failed to sync policy chain %s: %w", policyChainName, err)
			}
		}
	}

	klog.V(2).Infof("nftables chains are synchronized with the network policies.")
	return activePolicyChains, activePolicyIPSets, nil
}

// gcStaleChainsNft deletes the given stale chains from one family's table. All stale chains are
// flushed first in a single transaction, which removes any jump rules they hold into OTHER stale
// chains (e.g. stale pod-fw chains jumping into stale policy chains), so the per-chain deletes
// that follow succeed regardless of ordering. Each delete then runs in its own transaction so
// that one unexpected "Resource busy" failure doesn't block removal of unrelated chains.
func (npc *NetworkPolicyControllerNftables) gcStaleChainsNft(nft knftables.Interface, staleChains []string) {
	if len(staleChains) == 0 {
		return
	}
	ctx := npc.ctx

	flushTx := nft.NewTransaction()
	for _, chain := range staleChains {
		flushTx.Flush(&knftables.Chain{Name: chain})
	}
	if err := nft.Run(ctx, flushTx); err != nil {
		klog.Warningf("nftables: failed to flush stale chains (will retry next sync): %v", err)
	}

	for _, chain := range staleChains {
		tx := nft.NewTransaction()
		tx.Delete(&knftables.Chain{Name: chain})
		if err := nft.Run(ctx, tx); err != nil {
			klog.Warningf("nftables: failed to delete stale chain %s (will retry next sync): %v", chain, err)
		}
	}
}

// gcPodFwChainsNft deletes stale KUBE-POD-FW-* chains. It must run AFTER syncTopLevelChainsAtomic:
// only once the top-level chains have been atomically rebuilt do the previous sync's pod-fw chains
// lose their inbound jump references and become deletable. Running this GC earlier in the sync is
// what caused the unbounded pod-fw chain leak.
func (npc *NetworkPolicyControllerNftables) gcPodFwChainsNft(activePodFwChains map[string]bool) {
	for _, nft := range npc.knftInterfaces {
		existingChains, err := nft.List(npc.ctx, "chains")
		if err != nil {
			klog.Warningf("nftables: could not list chains for pod fw cleanup (will retry next sync): %v", err)
			continue
		}
		staleChains := make([]string, 0)
		for _, chain := range existingChains {
			if strings.HasPrefix(chain, kubePodFirewallChainPrefix) && !activePodFwChains[chain] {
				staleChains = append(staleChains, chain)
			}
		}
		npc.gcStaleChainsNft(nft, staleChains)
	}
}

// gcPolicyObjectsNft deletes stale policy chains and sets that are no longer referenced by any
// active policy. It must run AFTER gcPodFwChainsNft: stale policy chains are referenced by the
// stale pod-fw chains from the same sync version, so those have to be flushed and deleted before
// the policy chains (and then the sets referenced by their rules) become deletable.
func (npc *NetworkPolicyControllerNftables) gcPolicyObjectsNft(
	activePolicyChains, activePolicyIPSets map[string]bool) {

	ctx := npc.ctx

	for _, nft := range npc.knftInterfaces {
		existingChains, err := nft.List(ctx, "chains")
		if err != nil {
			klog.Warningf("nftables: could not list chains for cleanup: %v", err)
			continue
		}
		staleChains := make([]string, 0)
		for _, chain := range existingChains {
			if strings.HasPrefix(chain, kubeNetworkPolicyChainPrefix) &&
				chain != kubeDefaultNetpolChain &&
				chain != kubeCommonNetpolChain &&
				chain != kubeTailNetpolChain &&
				!activePolicyChains[chain] {
				staleChains = append(staleChains, chain)
			}
		}
		npc.gcStaleChainsNft(nft, staleChains)
	}

	for _, nft := range npc.knftInterfaces {
		existingSets, err := nft.List(ctx, "sets")
		if err != nil {
			klog.Warningf("nftables: could not list sets for cleanup: %v", err)
			continue
		}
		for _, set := range existingSets {
			if (strings.HasPrefix(set, kubeSourceIPSetPrefix) ||
				strings.HasPrefix(set, kubeDestinationIPSetPrefix)) &&
				!activePolicyIPSets[set] {
				tx := nft.NewTransaction()
				tx.Delete(&knftables.Set{Name: set})
				if err := nft.Run(ctx, tx); err != nil {
					klog.Warningf("nftables: failed to cleanup stale set %s (will retry next sync): %v", set, err)
				}
			}
		}
	}
}

// syncPodFirewallChains is the nftables equivalent of the iptables syncPodFirewallChains.
// For each local pod it creates a per-pod nftables chain that enforces network policies, and
// records the jump entries that syncTopLevelChainsAtomic later writes into the top-level chains.
// Returns the set of active pod firewall chain names (consumed by gcPodFwChainsNft), a per-family
// map of pod IPs whose chain was programmed this sync (consumed by populateProtectedPodsIPSet),
// and the collected jump entries.
func (npc *NetworkPolicyControllerNftables) syncPodFirewallChains(
	networkPoliciesInfo []networkPolicyInfo, version string) (
	map[string]bool, map[v1core.IPFamily][]string, map[v1core.IPFamily][]podFwJump, error) {

	ctx := npc.ctx
	activePodFwChains := make(map[string]bool)
	activePodIPs := make(map[v1core.IPFamily][]string)
	podJumps := make(map[v1core.IPFamily][]podFwJump)
	var errs []error

	// Collect all local pods across all node IPs.
	allLocalPods := make(map[string]podInfo)
	for _, nodeIP := range npc.krNode.GetNodeIPAddrs() {
		npc.getLocalPods(allLocalPods, nodeIP.String())
	}

	for _, pod := range allLocalPods {
		podFwChainName := podFirewallChainName(pod.namespace, pod.name, version)
		activePodFwChains[podFwChainName] = true

		for ipFamily, nft := range npc.knftInterfaces {
			ip, err := getPodIPForFamily(pod, ipFamily)
			if err != nil {
				klog.Infof("unable to get address for pod: %s -- skipping pod chain for pod "+
					"(this is normal for pods that are not dual-stack)", err.Error())
				continue
			}

			// Record for populateProtectedPodsIPSet: only IPs whose chain we just programmed are "protected".
			activePodIPs[ipFamily] = append(activePodIPs[ipFamily], ip)

			addrKeyword := "ip"
			if ipFamily == v1core.IPv6Protocol {
				addrKeyword = "ip6"
			}

			tx := nft.NewTransaction()

			// Create (or reset) the per-pod firewall chain.
			tx.Add(&knftables.Chain{
				Name:    podFwChainName,
				Comment: new(clampComment("podfw " + pod.namespace + "/" + pod.name)),
			})
			tx.Flush(&knftables.Chain{Name: podFwChainName})

			// 1. Jump to the common policy chain (stateful INVALID drop, RELATED/ESTABLISHED accept, ICMP).
			tx.Add(&knftables.Rule{
				Chain:   podFwChainName,
				Rule:    knftables.Concat("counter jump", kubeCommonNetpolChain),
				Comment: new("common netpol rules"),
			})

			// 2. Allow traffic whose source is the local node itself.
			tx.Add(&knftables.Rule{
				Chain: podFwChainName,
				Rule: knftables.Concat(
					"fib saddr type local", addrKeyword, "daddr", ip,
					"counter accept",
				),
				Comment: new("from local node"),
			})

			// 3. Jump to every applicable network-policy chain; track whether ingress/egress is covered.
			hasIngressPolicy := false
			hasEgressPolicy := false
			for _, policy := range networkPoliciesInfo {
				if _, ok := policy.targetPods[pod.ip]; !ok {
					continue
				}
				policyChainName := networkPolicyChainName(policy.namespace, policy.name, version, ipFamily)
				comment := idComment(policy.namespace, policy.name, cmtJumpPolicy)
				switch policy.policyType {
				case kubeBothPolicyType:
					hasIngressPolicy = true
					hasEgressPolicy = true
					tx.Add(&knftables.Rule{
						Chain:   podFwChainName,
						Rule:    knftables.Concat("counter jump", policyChainName),
						Comment: new(comment),
					})
				case kubeIngressPolicyType:
					hasIngressPolicy = true
					tx.Add(&knftables.Rule{
						Chain:   podFwChainName,
						Rule:    knftables.Concat(addrKeyword, "daddr", ip, "counter jump", policyChainName),
						Comment: new(comment),
					})
				case kubeEgressPolicyType:
					hasEgressPolicy = true
					tx.Add(&knftables.Rule{
						Chain:   podFwChainName,
						Rule:    knftables.Concat(addrKeyword, "saddr", ip, "counter jump", policyChainName),
						Comment: new(comment),
					})
				}
			}

			// 4. Fall back to the default netpol chain for directions not covered by a specific policy.
			// Egress (saddr) is evaluated before ingress (daddr) to match iptables reference behaviour.
			if !hasEgressPolicy {
				tx.Add(&knftables.Rule{
					Chain:   podFwChainName,
					Rule:    knftables.Concat(addrKeyword, "saddr", ip, "counter jump", kubeDefaultNetpolChain),
					Comment: new("default egress"),
				})
			}
			if !hasIngressPolicy {
				tx.Add(&knftables.Rule{
					Chain:   podFwChainName,
					Rule:    knftables.Concat(addrKeyword, "daddr", ip, "counter jump", kubeDefaultNetpolChain),
					Comment: new("default ingress"),
				})
			}

			// 5. Log then reject traffic not approved by any policy (bit 0x10000 still clear).
			tx.Add(&knftables.Rule{
				Chain:   podFwChainName,
				Rule:    "meta mark and 0x10000 == 0x0 limit rate 10/minute burst 10 packets log group 100",
				Comment: new(idComment(pod.namespace, pod.name, cmtLogDrop)),
			})
			tx.Add(&knftables.Rule{
				Chain:   podFwChainName,
				Rule:    "meta mark and 0x10000 == 0x0 counter reject",
				Comment: new(idComment(pod.namespace, pod.name, cmtReject)),
			})

			// 6. Clear bit 0x10000 so subsequent chains start with a clean slate.
			tx.Add(&knftables.Rule{
				Chain:   podFwChainName,
				Rule:    "meta mark set meta mark and 0xfffeffff",
				Comment: new("clear netpol mark"),
			})

			// 7. Set bit 0x20000 to signal to the top-level ACCEPT rule that policy was satisfied.
			tx.Add(&knftables.Rule{
				Chain:   podFwChainName,
				Rule:    "meta mark set meta mark or 0x20000",
				Comment: new("set netpol-ok mark"),
			})

			// Record the jump entries; syncTopLevelChainsAtomic writes them into the top-level
			// chains atomically after all pod-fw chains are ready.
			podJumps[ipFamily] = append(podJumps[ipFamily], podFwJump{
				podIP:      ip,
				podFwChain: podFwChainName,
				podName:    pod.name,
				podNS:      pod.namespace,
			})

			if err := nft.Run(ctx, tx); err != nil {
				klog.Errorf("nftables: failed to sync pod firewall chain for pod %s/%s family %s: %v",
					pod.namespace, pod.name, ipFamily, err)
				errs = append(errs, fmt.Errorf("failed to sync pod firewall chain for %s/%s (family %s): %w",
					pod.namespace, pod.name, ipFamily, err))
			}
		}
	}

	if len(errs) > 0 {
		return activePodFwChains, activePodIPs, podJumps,
			fmt.Errorf("encountered %d errors during pod firewall chain sync: %v", len(errs), errs)
	}
	return activePodFwChains, activePodIPs, podJumps, nil
}

// syncTopLevelChainsAtomic atomically rebuilds every top-level netfilter chain (INPUT, FORWARD, OUTPUT)
// in a single nftables transaction per IP family. By folding the flush, static exemption rules,
// per-pod jump rules, the TAIL jump, and the explicit ACCEPT into one transaction we eliminate the
// enforcement gap that existed when those writes happened across several separate transactions.
//
// Call this AFTER syncPodFirewallChains so that all pod-fw chains exist before the top-level
// chains jump into them.
func (npc *NetworkPolicyControllerNftables) syncTopLevelChainsAtomic(
	podJumps map[v1core.IPFamily][]podFwJump) error {

	ctx := npc.ctx

	for family, nft := range npc.knftInterfaces {
		tx := nft.NewTransaction()

		addrKeyword := "ip"
		if family == v1core.IPv6Protocol {
			addrKeyword = "ip6"
		}

		// 1. Atomically create (if missing) and flush every top-level hook chain.
		for chain, hook := range chainToHook {
			tx.Add(&knftables.Chain{
				Name:     chain,
				Comment:  new("top level " + chain + " chain for kube-router"),
				Type:     knftables.PtrTo(knftables.FilterType),
				Hook:     new(hook),
				Priority: knftables.PtrTo(knftables.FilterPriority),
			})
			tx.Flush(&knftables.Chain{Name: chain})
		}

		// 2. Static exemption rules in kubeInputChainName: cluster-IP, nodeport,
		//    external-IP, and LoadBalancer ranges bypass policy enforcement.
		for _, serviceRange := range npc.ipRanges.ClusterIPRanges(family) {
			tx.Add(&knftables.Rule{
				Chain:   kubeInputChainName,
				Rule:    knftables.Concat(addrKeyword, "daddr", serviceRange.String(), "counter", "return"),
				Comment: new("allow cluster IP range"),
			})
		}
		for _, protocol := range []string{"tcp", "udp", "sctp"} {
			ruleParts := []any{
				"meta l4proto", protocol,
				"fib", "daddr", "type", "local", protocol,
				"dport", npc.nftablesNodePortRange(),
				"counter", "return",
			}
			tx.Add(&knftables.Rule{
				Chain:   kubeInputChainName,
				Rule:    knftables.Concat(ruleParts...),
				Comment: new("allow " + protocol + " nodeport"),
			})
		}
		for _, externalIPRange := range npc.ipRanges.ExternalIPRanges(family) {
			tx.Add(&knftables.Rule{
				Chain:   kubeInputChainName,
				Rule:    knftables.Concat(addrKeyword, "daddr", externalIPRange.String(), "counter", "return"),
				Comment: new("allow traffic to External IP range"),
			})
		}
		for _, lbIPRange := range npc.ipRanges.LoadBalancerIPRanges(family) {
			tx.Add(&knftables.Rule{
				Chain:   kubeInputChainName,
				Rule:    knftables.Concat(addrKeyword, "daddr", lbIPRange.String(), "counter", "return"),
				Comment: new("allow LB IP range"),
			})
		}

		// 3. Per-pod jump rules: route pod traffic through the pod-fw chains.
		for _, j := range podJumps[family] {
			podFwComment := idComment(j.podNS, j.podName, cmtJumpIn)
			outboundComment := idComment(j.podNS, j.podName, cmtJumpOut)
			tx.Add(&knftables.Rule{
				Chain:   kubeForwardChainName,
				Rule:    knftables.Concat(addrKeyword, "daddr", j.podIP, "counter jump", j.podFwChain),
				Comment: new(podFwComment),
			})
			tx.Add(&knftables.Rule{
				Chain:   kubeOutputChainName,
				Rule:    knftables.Concat(addrKeyword, "daddr", j.podIP, "counter jump", j.podFwChain),
				Comment: new(podFwComment),
			})
			for _, chain := range defaultChains {
				tx.Add(&knftables.Rule{
					Chain:   chain,
					Rule:    knftables.Concat(addrKeyword, "saddr", j.podIP, "counter jump", j.podFwChain),
					Comment: new(outboundComment),
				})
			}
		}

		// 4. TAIL jump at the end of each top-level chain.
		for chain := range chainToHook {
			tx.Add(&knftables.Rule{
				Chain:   chain,
				Rule:    knftables.Concat("counter jump", kubeTailNetpolChain),
				Comment: new("netpol accept/reject"),
			})
		}

		// 5. Explicit ACCEPT for traffic marked by policy chains (defence-in-depth).
		for chain := range chainToHook {
			tx.Add(&knftables.Rule{
				Chain:   chain,
				Rule:    nftMarkAcceptRule,
				Comment: new("accept netpol-ok"),
			})
		}

		if err := nft.Run(ctx, tx); err != nil {
			return fmt.Errorf("nftables: failed to atomically rebuild top-level chains (family %s): %w",
				family, err)
		}
	}
	return nil
}

// ensureDefaultTailChain (re)creates KUBE-NWPLCY-TAIL per family and the kube-router-local-pods named set
// that gates the default-deny REJECT rules. Both objects are flushed before re-populating so the chain and
// set always reflect the current configuration. populateProtectedPodsIPSet during fullPolicySync fills the set.
func (npc *NetworkPolicyControllerNftables) ensureDefaultTailChain() {
	ctx := npc.ctx
	for family, nft := range npc.knftInterfaces {
		tx := nft.NewTransaction()

		tx.Add(&knftables.Chain{
			Name:    kubeTailNetpolChain,
			Comment: new(kubeTailNetpolChain + " chain for kube-router"),
		})
		tx.Flush(&knftables.Chain{Name: kubeTailNetpolChain})

		setType := "ipv4_addr"
		if family == v1core.IPv6Protocol {
			setType = "ipv6_addr"
		}
		tx.Add(&knftables.Set{
			Name:    kubeLocalPodsIPSetName,
			Type:    setType,
			Comment: new("programmed local pod IPs"),
		})

		npc.populateDefaultTailChain(family, tx)

		if err := nft.Run(ctx, tx); err != nil {
			klog.Errorf("nftables: couldn't setup %s chain for family %s: %v",
				kubeTailNetpolChain, family, err)
		}
	}
}

// populateDefaultTailChain appends rules into KUBE-NWPLCY-TAIL on tx. Callers must ensure the chain exists.
//
// When --netpol-default-deny is disabled, only the ACCEPT-on-mark rule is appended (1 rule total).
//
// When --netpol-default-deny is enabled, the chain layout is, per CIDR:
//  1. <CIDR> saddr AND saddr not in @kube-router-local-pods -> REJECT  (set-gated, NEW)
//  2. <CIDR> daddr AND daddr not in @kube-router-local-pods -> REJECT  (set-gated, NEW)
//  3. meta mark & 0x20000 == 0x20000 -> ACCEPT
//  4. <CIDR> saddr -> REJECT  (defense-in-depth)
//  5. <CIDR> daddr -> REJECT  (defense-in-depth)
func (npc *NetworkPolicyControllerNftables) populateDefaultTailChain(
	family v1core.IPFamily, tx *knftables.Transaction,
) {
	addrKeyword := "ip"
	if family == v1core.IPv6Protocol {
		addrKeyword = "ip6"
	}

	if npc.defaultDeny {
		gatedComment := "reject unprogrammed local pod (default-deny)"
		for _, cidr := range npc.podCIDRs[family] {
			tx.Add(&knftables.Rule{
				Chain: kubeTailNetpolChain,
				Rule: knftables.Concat(
					addrKeyword, "saddr", cidr,
					addrKeyword, "saddr", "!=", "@"+kubeLocalPodsIPSetName,
					"counter", "reject",
				),
				Comment: new(gatedComment),
			})
			tx.Add(&knftables.Rule{
				Chain: kubeTailNetpolChain,
				Rule: knftables.Concat(
					addrKeyword, "daddr", cidr,
					addrKeyword, "daddr", "!=", "@"+kubeLocalPodsIPSetName,
					"counter", "reject",
				),
				Comment: new(gatedComment),
			})
		}
	}

	tx.Add(&knftables.Rule{
		Chain:   kubeTailNetpolChain,
		Rule:    nftMarkAcceptRule,
		Comment: new("accept netpol-ok"),
	})

	if !npc.defaultDeny {
		return
	}

	rejectComment := "reject pre-netpol (default-deny)"
	for _, cidr := range npc.podCIDRs[family] {
		tx.Add(&knftables.Rule{
			Chain:   kubeTailNetpolChain,
			Rule:    knftables.Concat(addrKeyword, "saddr", cidr, "counter", "reject"),
			Comment: new(rejectComment),
		})
		tx.Add(&knftables.Rule{
			Chain:   kubeTailNetpolChain,
			Rule:    knftables.Concat(addrKeyword, "daddr", cidr, "counter", "reject"),
			Comment: new(rejectComment),
		})
	}
}

// populateProtectedPodsIPSet refreshes the kube-router-local-pods named set (per family) with the IPs of local
// pods whose pod firewall chain was programmed this sync. No-op when --netpol-default-deny is disabled. The
// flush+add pair runs in a single nftables transaction, so readers never observe a partially-updated set.
func (npc *NetworkPolicyControllerNftables) populateProtectedPodsIPSet(activePodIPs map[v1core.IPFamily][]string) {
	if !npc.defaultDeny {
		return
	}
	ctx := npc.ctx
	for family, nft := range npc.knftInterfaces {
		tx := nft.NewTransaction()
		tx.Flush(&knftables.Set{Name: kubeLocalPodsIPSetName})
		for _, ip := range activePodIPs[family] {
			tx.Add(&knftables.Element{
				Set: kubeLocalPodsIPSetName,
				Key: []string{ip},
			})
		}
		if err := nft.Run(ctx, tx); err != nil {
			klog.Errorf("nftables: failed to refresh %s set for family %s: %v",
				kubeLocalPodsIPSetName, family, err)
			continue
		}
		klog.V(2).Infof("nftables: refreshed %s set for family %s with %d entries",
			kubeLocalPodsIPSetName, family, len(activePodIPs[family]))
	}
}

// Cleanup removes the nftables tables created by kube-router for network policies.
func (npc *NetworkPolicyControllerNftables) Cleanup() {
	klog.Info("Cleaning up NetworkPolicyController nftables configurations...")

	if len(npc.knftInterfaces) < 1 {
		ctx := context.Background()
		interfaces, err := NewKnftablesInterfaces(ctx, &options.KubeRouterConfig{
			EnableIPv4:           true,
			EnableIPv6:           true,
			UseNftablesForNetpol: true,
		})
		if err != nil {
			klog.Errorf("unable to get nftables interfaces for cleanup: %v", err)
			return
		}
		npc.knftInterfaces = interfaces
	}

	ctx := context.Background()
	for _, nft := range npc.knftInterfaces {
		tx := nft.NewTransaction()
		tx.Delete(&knftables.Table{})
		if err := nft.Run(ctx, tx); err != nil {
			klog.Errorf("nftables: error while deleting table during cleanup: %v", err)
		}
	}

	klog.Info("Successfully cleaned the NetworkPolicyController nftables configurations done by kube-router")
}
