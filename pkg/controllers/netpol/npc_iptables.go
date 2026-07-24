package netpol

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"errors"
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
	v1core "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
)

// NetworkPolicyControllerIptables is the iptables-based implementation of NetworkPolicyController.
// It uses iptables chains and ipsets to enforce Kubernetes network policies. This is the original
// implementation and is used when UseNftablesForNetpol is disabled (the default behavior).
type NetworkPolicyControllerIptables struct {
	*NetworkPolicyControllerBase

	iptablesCmdHandlers map[v1core.IPFamily]utils.IPTablesHandler
	iptablesSaveRestore map[v1core.IPFamily]utils.IPTablesSaveRestorer
	ipSetHandlers       map[v1core.IPFamily]utils.IPSetHandler
}

// Run runs forever till we receive notification on stopCh
func (npc *NetworkPolicyControllerIptables) Run(
	healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) {
	t := time.NewTicker(npc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	klog.Info("Starting network policy controller")
	npc.healthChan = healthChan

	// setup kube-router specific top level custom chains (KUBE-ROUTER-INPUT, KUBE-ROUTER-FORWARD, KUBE-ROUTER-OUTPUT)
	if err := npc.ensureTopLevelChains(); err != nil {
		klog.Fatalf("Failed to setup top level chains: %v", err)
	}

	// setup default network policy chain that is applied to traffic from/to the pods that does not match any network
	// policy
	npc.ensureDefaultNetworkPolicyChain()

	// setup common network policy chain that is applied to all bi-directional traffic
	npc.ensureCommonPolicyChain()

	// setup KUBE-ROUTER-(INPUT/OUTPUT/FORWARD) tail chain which contains explicit ACCEPT / REJECT rules
	npc.ensureDefaultTailChain()

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

// Sync synchronizes iptables to desired state of network policies
func (npc *NetworkPolicyControllerIptables) fullPolicySync() {

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
	if err := npc.ensureTopLevelChains(); err != nil {
		klog.Errorf("Aborting sync. Failed to ensure top level chains: %v", err)
		return
	}

	// ensure default network policy chain that is applied to traffic from/to the pods that does not match any network
	// policy
	npc.ensureDefaultNetworkPolicyChain()

	// ensure common network policy chain that is applied to all bi-directional traffic
	npc.ensureCommonPolicyChain()

	// Per-sync safety net for KUBE-NWPLCY-TAIL; the chain itself is built by ensureDefaultTailChain() in Run().
	npc.ensureDefaultTailChainExists()

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

	activePodFwChains, activePodIPs := npc.syncPodFirewallChains(networkPoliciesInfo, syncVersion)

	// Refresh the kube-router-local-pods ipset before ensureTailChainPosition installs the TAIL jump, so the
	// rules never reference a stale set. No-op when --netpol-default-deny is disabled.
	npc.populateProtectedPodsIPSet(activePodIPs)

	// Ensure the KUBE-NWPLCY-TAIL jump sits at the end of each top-level chain, after the per-pod jumps above.
	npc.ensureTailChainPosition()

	// Makes sure that the ACCEPT rules for packets marked with "0x20000" are added to the end of each of kube-router's
	// top level chains
	npc.ensureExplicitAccept()

	err = npc.cleanupStaleRules(activePolicyChains, activePodFwChains, false)
	if err != nil {
		klog.Errorf("Aborting sync. Failed to cleanup stale iptables rules: %v", err.Error())
		return
	}

	for ipFamily, iptablesSaveRestore := range npc.iptablesSaveRestore {
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

func (npc *NetworkPolicyControllerIptables) iptablesCmdHandlerForCIDR(cidr *net.IPNet) (utils.IPTablesHandler, error) {
	if netutils.IsIPv4CIDR(cidr) {
		return npc.iptablesCmdHandlers[v1core.IPv4Protocol], nil
	}
	if netutils.IsIPv6CIDR(cidr) {
		return npc.iptablesCmdHandlers[v1core.IPv6Protocol], nil
	}

	return nil, errors.New("invalid CIDR")
}

func (npc *NetworkPolicyControllerIptables) allowTrafficToClusterIPRange(
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
//
// The comments here are frozen: they are hashed into the rule UUID and matched against live state,
// so rewording them churns every positioned rule on upgrade (see the note on ensureExplicitAccept).
func (npc *NetworkPolicyControllerIptables) ensureTopLevelChains() error {
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

	if len(npc.ipRanges.ClusterIPRanges()) == 0 {
		klog.Fatalf("Primary service cluster IP range is not configured")
	}
	for _, family := range []v1core.IPFamily{v1core.IPv4Protocol, v1core.IPv6Protocol} {
		for _, serviceRange := range npc.ipRanges.ClusterIPRanges(family) {
			klog.V(2).Infof("Allow traffic to ingress towards Cluster IP Range: %s for family: %s",
				serviceRange.String(), family)
			npc.allowTrafficToClusterIPRange(rulePosition[family], &serviceRange,
				addUUIDForRuleSpec, ensureRuleAtPosition, "allow traffic to primary/secondary cluster IP range")
			rulePosition[family]++
		}
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

		whitelistSCTPNodeports := []string{"-p", "sctp", "-m", "comment", "--comment",
			"allow LOCAL SCTP traffic to node ports", "-m", "addrtype", "--dst-type", "LOCAL",
			"-m", "multiport", "--dports", npc.serviceNodePortRange, "-j", "RETURN"}
		uuid, err = addUUIDForRuleSpec(kubeInputChainName, &whitelistSCTPNodeports)
		if err != nil {
			klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
		}
		klog.V(2).Infof("Allow SCTP traffic to ingress towards node port range: %s for family: %s",
			npc.serviceNodePortRange, family)
		ensureRuleAtPosition(handler,
			kubeInputChainName, whitelistSCTPNodeports, uuid, rulePosition[family])
		rulePosition[family]++
	}

	for _, family := range []v1core.IPFamily{v1core.IPv4Protocol, v1core.IPv6Protocol} {
		handler := npc.iptablesCmdHandlers[family]
		if handler == nil {
			continue
		}
		for _, externalIPRange := range npc.ipRanges.ExternalIPRanges(family) {
			whitelistServiceVips := []string{"-m", "comment", "--comment",
				"allow traffic to external IP range: " + externalIPRange.String(), "-d", externalIPRange.String(),
				"-j", "RETURN"}
			uuid, err := addUUIDForRuleSpec(kubeInputChainName, &whitelistServiceVips)
			if err != nil {
				klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
			}
			klog.V(2).Infof("Allow traffic to ingress towards External IP Range: %s for family: %s",
				externalIPRange.String(), family)
			ensureRuleAtPosition(handler,
				kubeInputChainName, whitelistServiceVips, uuid, rulePosition[family])
			rulePosition[family]++
		}
		for _, loadBalancerIPRange := range npc.ipRanges.LoadBalancerIPRanges(family) {
			whitelistServiceVips := []string{"-m", "comment", "--comment",
				"allow traffic to load balancer IP range: " + loadBalancerIPRange.String(), "-d", loadBalancerIPRange.String(),
				"-j", "RETURN"}
			uuid, err := addUUIDForRuleSpec(kubeInputChainName, &whitelistServiceVips)
			if err != nil {
				klog.Fatalf("Failed to get uuid for rule: %s", err.Error())
			}
			klog.V(2).Infof("Allow traffic to ingress towards Load Balancer IP Range: %s for family: %s",
				loadBalancerIPRange.String(), family)
			ensureRuleAtPosition(handler,
				kubeInputChainName, whitelistServiceVips, uuid, rulePosition[family])
			rulePosition[family]++
		}
	}
	return nil
}

// IMPORTANT: this comment (and the ones flagged "frozen" in ensureTailChainPosition,
// ensureCommonPolicyChain, ensureDefaultNetworkPolicyChain, ensureTopLevelChains) feeds an
// AppendUnique/Exists check against live iptables, so it is part of the rule's identity: rewording
// it orphans the old rule on upgrade and appends a duplicate that nothing cleans up.
func (npc *NetworkPolicyControllerIptables) ensureExplicitAccept() {
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

// ensureDefaultTailChain (re)creates KUBE-NWPLCY-TAIL and populates it from scratch, wiping any prior contents so
// toggling --netpol-default-deny across restarts is idempotent. Call from Run() only; fullPolicySync uses
// ensureDefaultTailChainExists to avoid a ClearChain/Append leak window on every pod event.
func (npc *NetworkPolicyControllerIptables) ensureDefaultTailChain() {
	// Set must exist before the rules that reference it are appended. Empty is fine — the first
	// populateProtectedPodsIPSet during fullPolicySync fills it.
	npc.ensureLocalPodsIPSetExists()

	for family, iptablesCmdHandler := range npc.iptablesCmdHandlers {
		exists, err := iptablesCmdHandler.ChainExists("filter", kubeTailNetpolChain)
		if err != nil {
			klog.Fatalf("failed to check for the existence of chain %s, error: %v",
				kubeTailNetpolChain, err)
		}
		if !exists {
			if err = iptablesCmdHandler.NewChain("filter", kubeTailNetpolChain); err != nil {
				klog.Fatalf("failed to create %s chain due to %s",
					kubeTailNetpolChain, err.Error())
			}
		} else {
			// Wipe stale contents (e.g. REJECT rules from a previous run where --netpol-default-deny was
			// enabled but is now disabled, or vice versa).
			if err = iptablesCmdHandler.ClearChain("filter", kubeTailNetpolChain); err != nil {
				klog.Fatalf("failed to clear %s chain due to %s",
					kubeTailNetpolChain, err.Error())
			}
		}
		npc.populateDefaultTailChain(family, iptablesCmdHandler)
	}
}

// ensureDefaultTailChainExists is the per-sync safety net: it recreates KUBE-NWPLCY-TAIL only if the chain has
// gone missing entirely, otherwise it runs a cheap rule-count drift check. With --netpol-default-deny on it
// also makes sure the kube-router-local-pods ipset still exists; the next populateProtectedPodsIPSet repopulates
// it.
func (npc *NetworkPolicyControllerIptables) ensureDefaultTailChainExists() {
	npc.ensureLocalPodsIPSetExists()

	for family, iptablesCmdHandler := range npc.iptablesCmdHandlers {
		exists, err := iptablesCmdHandler.ChainExists("filter", kubeTailNetpolChain)
		if err != nil {
			klog.Fatalf("failed to check for the existence of chain %s, error: %v",
				kubeTailNetpolChain, err)
		}
		if !exists {
			klog.Warningf("%s chain was missing during sync; recreating", kubeTailNetpolChain)
			if err = iptablesCmdHandler.NewChain("filter", kubeTailNetpolChain); err != nil {
				klog.Fatalf("failed to create %s chain due to %s",
					kubeTailNetpolChain, err.Error())
			}
			npc.populateDefaultTailChain(family, iptablesCmdHandler)
			continue
		}

		// Cheap drift detection: count the rules and compare to what we expect to be there. This catches
		// the case where someone (or something) has tampered with the chain, without rebuilding it
		// underneath live traffic.
		rules, err := iptablesCmdHandler.List("filter", kubeTailNetpolChain)
		if err != nil {
			klog.Warningf("unable to list rules in %s for drift check: %v", kubeTailNetpolChain, err)
			continue
		}
		// List returns "-N CHAIN" as rules[0] followed by one "-A CHAIN ..." per rule, so subtract one.
		expected := 1
		if npc.defaultDeny {
			// 2 ipset-gated REJECTs (src/dst) + 2 CIDR REJECTs (src/dst) per CIDR, plus the single
			// ACCEPT-on-mark rule.
			expected += 4 * len(npc.podCIDRs[family])
		}
		if actual := len(rules) - 1; actual != expected {
			klog.Warningf("%s has %d rules but expected %d; chain contents have drifted, "+
				"restart kube-router to rebuild", kubeTailNetpolChain, actual, expected)
		}
	}
}

// ensureLocalPodsIPSetExists makes sure the kube-router-local-pods ipset exists for every IP family. No-op when
// --netpol-default-deny is disabled. The Save+Sets lookup exists only so we can log a one-shot "was missing"
// warning on drift; Create itself is idempotent via `create -exist`.
func (npc *NetworkPolicyControllerIptables) ensureLocalPodsIPSetExists() {
	if !npc.defaultDeny {
		return
	}
	if npc.ipsetMutex != nil {
		klog.V(2).Infof("Attempting to attain ipset mutex lock for protected-pods ipset check")
		npc.ipsetMutex.Lock()
		klog.V(2).Infof("Attained ipset mutex lock for protected-pods ipset check, continuing...")
		defer func() {
			npc.ipsetMutex.Unlock()
			klog.V(2).Infof("Returned ipset mutex lock for protected-pods ipset check")
		}()
	}
	for family, ipSetHandler := range npc.ipSetHandlers {
		if err := ipSetHandler.Save(); err != nil {
			klog.Warningf("failed to save ipsets while checking %s on family %s: %v",
				kubeLocalPodsIPSetName, family, err)
		}
		setNameForFamily := ipSetHandler.Name(kubeLocalPodsIPSetName)
		if _, exists := ipSetHandler.Sets()[setNameForFamily]; exists {
			continue
		}
		klog.Warningf("%s ipset for family %s was missing; creating",
			setNameForFamily, family)
		if _, err := ipSetHandler.Create(kubeLocalPodsIPSetName, utils.TypeHashIP, utils.OptionTimeout, "0"); err != nil {
			klog.Fatalf("failed to create %s ipset for family %s: %v",
				setNameForFamily, family, err)
		}
	}
}

// destroyLocalPodsIPSet removes the kube-router-local-pods ipset per family if it exists; otherwise a no-op.
func (npc *NetworkPolicyControllerIptables) destroyLocalPodsIPSet() {
	for family, ipSetHandler := range npc.ipSetHandlers {
		if err := ipSetHandler.Save(); err != nil {
			klog.Errorf("failed to save ipsets for %s cleanup on family %s: %v",
				kubeLocalPodsIPSetName, family, err)
			continue
		}
		setNameForFamily := ipSetHandler.Name(kubeLocalPodsIPSetName)
		if _, ok := ipSetHandler.Sets()[setNameForFamily]; !ok {
			continue
		}
		if err := ipSetHandler.Destroy(kubeLocalPodsIPSetName); err != nil {
			klog.Errorf("failed to destroy %s ipset for family %s: %v",
				setNameForFamily, family, err)
		}
	}
}

// populateDefaultTailChain appends rules into KUBE-NWPLCY-TAIL. Callers must ensure the chain exists and is empty.
//
// When --netpol-default-deny is disabled, only the ACCEPT-on-mark rule is appended (1 rule total).
//
// When --netpol-default-deny is enabled, the chain layout is, per CIDR:
//  1. -s <CIDR> -m set ! --match-set kube-router-local-pods src -j REJECT  (ipset-gated, NEW)
//  2. -d <CIDR> -m set ! --match-set kube-router-local-pods dst -j REJECT  (ipset-gated, NEW)
//  3. -m mark --mark 0x20000/0x20000                              -j ACCEPT
//  4. -s <CIDR>                                                   -j REJECT  (existing defense-in-depth)
//  5. -d <CIDR>                                                   -j REJECT  (existing defense-in-depth)
//
// The ipset-gated REJECTs are placed ahead of the ACCEPT so they fire for traffic to or from a local pod whose
// KUBE-POD-FW-* chain has not yet been programmed; this closes the race window where another local pod's chain
// would mark the packet 0x20000 and the ACCEPT would let it through. The existing CIDR-scoped REJECTs at the
// tail of the chain remain as defense-in-depth for traffic between unprotected local pods and external
// destinations (no destination chain to mark, no ipset entry on either end).
func (npc *NetworkPolicyControllerIptables) populateDefaultTailChain(
	family v1core.IPFamily, iptablesCmdHandler utils.IPTablesHandler,
) {
	if npc.defaultDeny {
		npc.appendIPSetGatedRejects(family, iptablesCmdHandler)
	}

	acceptComment := "accept netpol-ok"
	acceptArgs := []string{"-m", "comment", "--comment", acceptComment,
		"-m", "mark", "--mark", "0x20000/0x20000", "-j", "ACCEPT"}
	if err := iptablesCmdHandler.Append("filter", kubeTailNetpolChain, acceptArgs...); err != nil {
		klog.Fatalf("failed to add ACCEPT rule to %s due to %s",
			kubeTailNetpolChain, err.Error())
	}

	if !npc.defaultDeny {
		return
	}
	npc.appendCIDRRejects(family, iptablesCmdHandler)
}

// appendIPSetGatedRejects emits rules 1-2 of the per-CIDR layout documented on populateDefaultTailChain — the
// REJECTs that fire when a source/destination is in the node's pod CIDR but not yet in kube-router-local-pods.
func (npc *NetworkPolicyControllerIptables) appendIPSetGatedRejects(
	family v1core.IPFamily, iptablesCmdHandler utils.IPTablesHandler,
) {
	ipSetName := npc.ipSetHandlers[family].Name(kubeLocalPodsIPSetName)
	comment := "reject unprogrammed local pod (default-deny)"
	for _, cidr := range npc.podCIDRs[family] {
		srcArgs := []string{"-s", cidr, "-m", "comment", "--comment", comment,
			"-m", "set", "!", "--match-set", ipSetName, "src", "-j", "REJECT"}
		if err := iptablesCmdHandler.Append("filter", kubeTailNetpolChain, srcArgs...); err != nil {
			klog.Fatalf("failed to add ipset-gated source REJECT rule to %s due to %s",
				kubeTailNetpolChain, err.Error())
		}
		dstArgs := []string{"-d", cidr, "-m", "comment", "--comment", comment,
			"-m", "set", "!", "--match-set", ipSetName, "dst", "-j", "REJECT"}
		if err := iptablesCmdHandler.Append("filter", kubeTailNetpolChain, dstArgs...); err != nil {
			klog.Fatalf("failed to add ipset-gated destination REJECT rule to %s due to %s",
				kubeTailNetpolChain, err.Error())
		}
	}
}

// appendCIDRRejects emits rules 4-5 of the per-CIDR layout documented on populateDefaultTailChain — the
// CIDR-scoped REJECTs that catch unprotected pods talking to external destinations.
func (npc *NetworkPolicyControllerIptables) appendCIDRRejects(
	family v1core.IPFamily, iptablesCmdHandler utils.IPTablesHandler,
) {
	rejectComment := "reject pre-netpol (default-deny)"
	for _, cidr := range npc.podCIDRs[family] {
		srcArgs := []string{"-s", cidr, "-m", "comment", "--comment", rejectComment, "-j", "REJECT"}
		if err := iptablesCmdHandler.Append("filter", kubeTailNetpolChain, srcArgs...); err != nil {
			klog.Fatalf("failed to add source REJECT rule to %s due to %s",
				kubeTailNetpolChain, err.Error())
		}
		dstArgs := []string{"-d", cidr, "-m", "comment", "--comment", rejectComment, "-j", "REJECT"}
		if err := iptablesCmdHandler.Append("filter", kubeTailNetpolChain, dstArgs...); err != nil {
			klog.Fatalf("failed to add destination REJECT rule to %s due to %s",
				kubeTailNetpolChain, err.Error())
		}
	}
}

// populateProtectedPodsIPSet refreshes the kube-router-local-pods ipset (per family) with the IPs of local pods
// whose KUBE-POD-FW-* chains were programmed this sync, and is a no-op when --netpol-default-deny is disabled.
// RestoreSets is atomic per set, so readers never see a partially-updated ipset.
func (npc *NetworkPolicyControllerIptables) populateProtectedPodsIPSet(activePodIPs map[v1core.IPFamily][]string) {
	if !npc.defaultDeny {
		return
	}
	if npc.ipsetMutex != nil {
		klog.V(2).Infof("Attempting to attain ipset mutex lock for protected-pods refresh")
		npc.ipsetMutex.Lock()
		klog.V(2).Infof("Attained ipset mutex lock for protected-pods refresh, continuing...")
		defer func() {
			npc.ipsetMutex.Unlock()
			klog.V(2).Infof("Returned ipset mutex lock for protected-pods refresh")
		}()
	}
	for family, ipSetHandler := range npc.ipSetHandlers {
		// Snapshot the kernel state so the handler's internal Sets() map matches reality before RestoreSets.
		if err := ipSetHandler.Save(); err != nil {
			klog.Errorf("failed to save ipsets before refreshing %s for family %s: %v",
				kubeLocalPodsIPSetName, family, err)
			continue
		}

		entries := make([][]string, 0, len(activePodIPs[family]))
		for _, ip := range activePodIPs[family] {
			entries = append(entries, []string{ip, utils.OptionTimeout, "0"})
		}
		ipSetHandler.RefreshSet(kubeLocalPodsIPSetName, entries, utils.TypeHashIP)

		setNameForFamily := ipSetHandler.Name(kubeLocalPodsIPSetName)
		if err := ipSetHandler.RestoreSets([]string{setNameForFamily}); err != nil {
			klog.Errorf("failed to restore %s ipset for family %s: %v",
				setNameForFamily, family, err)
			continue
		}
		klog.V(2).Infof("refreshed %s ipset for family %s with %d entries",
			setNameForFamily, family, len(entries))
	}
}

// ensureTailChainPosition ensures each KUBE-ROUTER-{INPUT,FORWARD,OUTPUT} chain ends with a jump into
// KUBE-NWPLCY-TAIL, placing it after the per-pod KUBE-POD-FW-* jumps written earlier in the same sync.
func (npc *NetworkPolicyControllerIptables) ensureTailChainPosition() {
	for _, filterTableRules := range npc.filterTableRules {
		for _, chain := range defaultChains {
			// Frozen comment: rule identity for AppendUnique, see the note on ensureExplicitAccept
			comment := "\"rule to explicitly handle traffic for network policies ACCEPT/REJECT decision\""
			args := []string{"-m", "comment", "--comment", comment, "-j", kubeTailNetpolChain}
			utils.AppendUnique(filterTableRules, chain, args)
		}
	}
}

// Creates custom chain KUBE-NWPLCY-COMMON which holds rules that are applicable to all bi-directional traffic. Which
// includes the following:
// - Accept Related & Established traffic
// - Drop Invalid state traffic
// - ICMP rules
func (npc *NetworkPolicyControllerIptables) ensureCommonPolicyChain() {
	klog.V(1).Infof("Ensuring common policy chain")
	for family, iptablesCmdHandler := range npc.iptablesCmdHandlers {
		exists, err := iptablesCmdHandler.ChainExists("filter", kubeCommonNetpolChain)
		if err != nil {
			klog.Fatalf("failed to check for the existence of chain %s, error: %v", kubeCommonNetpolChain, err)
		}
		if !exists {
			klog.V(1).Infof("Creating chain %s", kubeCommonNetpolChain)
			err = iptablesCmdHandler.NewChain("filter", kubeCommonNetpolChain)
			if err != nil {
				klog.Fatalf("failed to run iptables command to create %s chain due to %s", kubeCommonNetpolChain,
					err.Error())
			}
		} else {
			klog.V(1).Infof("Chain %s already exists", kubeCommonNetpolChain)
		}

		// ensure stateful firewall drops INVALID state traffic from/to the pod
		// For full context see: https://bugzilla.netfilter.org/show_bug.cgi?id=693
		// The NAT engine ignores any packet with state INVALID, because there's no reliable way to determine what kind of
		// NAT should be performed. So the proper way to prevent the leakage is to drop INVALID packets.
		// In the future, if we ever allow services or nodes to disable conntrack checking, we may need to make this
		// conditional so that non-tracked traffic doesn't get dropped as invalid.
		// Frozen comment: rule identity for AppendUnique, see the note on ensureExplicitAccept
		comment := "\"rule to drop invalid state for pod\""
		args := []string{"-m", "comment", "--comment", comment, "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"}
		err = iptablesCmdHandler.AppendUnique("filter", kubeCommonNetpolChain, args...)
		if err != nil {
			klog.Fatalf("failed to run iptables command: %v", err)
		}

		// ensure stateful firewall that permits RELATED,ESTABLISHED traffic from/to the pod
		comment = "\"rule for stateful firewall for pod\""
		args = []string{"-m", "comment", "--comment", comment, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
			"-j", "ACCEPT"}
		err = iptablesCmdHandler.AppendUnique("filter", kubeCommonNetpolChain, args...)
		if err != nil {
			klog.Fatalf("failed to run iptables command: %v", err)
		}

		icmpRules := utils.CommonICMPRules(family)
		for _, icmpRule := range icmpRules {
			icmpArgs := []string{"-m", "comment", "--comment", icmpRule.Comment, "-p", icmpRule.IPTablesProto,
				icmpRule.IPTablesType, icmpRule.ICMPType, "-j", "ACCEPT"}
			err = iptablesCmdHandler.AppendUnique("filter", kubeCommonNetpolChain, icmpArgs...)
			if err != nil {
				klog.Fatalf("failed to run iptables command: %v", err)
			}
		}
	}
}

// Creates custom chains KUBE-NWPLCY-DEFAULT which holds rules for the default network policy. This is applied to
// traffic which is not selected by any network policy and is primarily used to allow traffic that is accepted by
// default.
//
// NOTE: This chain is only targeted by unidirectional network traffic selectors.
func (npc *NetworkPolicyControllerIptables) ensureDefaultNetworkPolicyChain() {
	for _, iptablesCmdHandler := range npc.iptablesCmdHandlers {
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

		// Start off by marking traffic with an invalid mark so that we can allow list only traffic accepted by a
		// matching policy. Anything that still has 0x10000
		markArgs := make([]string, 0)
		// Frozen comment: rule identity for AppendUnique, see the note on ensureExplicitAccept
		markComment := "rule to mark traffic matching a network policy"
		markArgs = append(markArgs, "-j", "MARK", "-m", "comment", "--comment", markComment,
			"--set-xmark", "0x10000/0x10000")
		err = iptablesCmdHandler.AppendUnique("filter", kubeDefaultNetpolChain, markArgs...)
		if err != nil {
			klog.Fatalf("Failed to run iptables command: %s", err.Error())
		}
	}
}

func (npc *NetworkPolicyControllerIptables) cleanupStaleRules(activePolicyChains, activePodFwChains map[string]bool,
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
				if chain == kubeCommonNetpolChain {
					continue
				}
				if chain == kubeTailNetpolChain {
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
					kubeDefaultNetpolChain, kubeCommonNetpolChain} {
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

func (npc *NetworkPolicyControllerIptables) cleanupStaleIPSets(activePolicyIPSets map[string]bool) error {
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
func (npc *NetworkPolicyControllerIptables) Cleanup() {
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

	// cleanupStaleIPSets only handles KUBE-SRC-/KUBE-DST- per-policy sets; the singleton needs an explicit pass.
	npc.destroyLocalPodsIPSet()

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

// NewNetworkPolicyControllerIptables returns new NetworkPolicyControllerIptables object
func NewNetworkPolicyControllerIptables(
	npcBase *NetworkPolicyControllerBase, clientset kubernetes.Interface,
	config *options.KubeRouterConfig, podInformer cache.SharedIndexInformer,
	npInformer cache.SharedIndexInformer, nsInformer cache.SharedIndexInformer,
	linkQ utils.LocalLinkQuerier,
	iptablesCmdHandlers map[v1core.IPFamily]utils.IPTablesHandler,
	ipSetHandlers map[v1core.IPFamily]utils.IPSetHandler) (*NetworkPolicyControllerIptables, error) {

	npc := NetworkPolicyControllerIptables{NetworkPolicyControllerBase: npcBase}

	npc.iptablesCmdHandlers = iptablesCmdHandlers
	npc.iptablesSaveRestore = make(map[v1core.IPFamily]utils.IPTablesSaveRestorer, 2)
	npc.ipSetHandlers = ipSetHandlers

	if config.EnableIPv4 {
		if !npc.krNode.IsIPv4Capable() {
			return nil, errors.New("IPv4 was enabled but no IPv4 address was found on node")
		}
		klog.V(2).Infof("IPv4 is enabled")
		npc.iptablesSaveRestore[v1core.IPv4Protocol] = utils.NewIPTablesSaveRestore(v1core.IPv4Protocol)
		var buf bytes.Buffer
		npc.filterTableRules[v1core.IPv4Protocol] = &buf
	}
	if config.EnableIPv6 {
		if !npc.krNode.IsIPv6Capable() {
			return nil, errors.New("IPv6 was enabled but no IPv6 address was found on node")
		}
		klog.V(2).Infof("IPv6 is enabled")
		npc.iptablesSaveRestore[v1core.IPv6Protocol] = utils.NewIPTablesSaveRestore(v1core.IPv6Protocol)
		var buf bytes.Buffer
		npc.filterTableRules[v1core.IPv6Protocol] = &buf
	}

	return &npc, nil
}
