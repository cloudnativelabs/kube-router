//go:build integration

package netpol

// Integration tests for Phase 2 of the network policy test plan.
//
// These tests exercise the nftables backend at the kernel level (real nft
// binary + netlink, no Kubernetes API server required). They are tagged with
// the "integration" build tag and are excluded from the normal `go test` run.
//
// Prerequisites:
//   - A Linux host with nft ≥ 1.0.1 installed and kernel ≥ 5.2.
//   - CAP_NET_ADMIN or running as root (required to manipulate nftables).
//
// Run with:
//
//	go test -tags integration ./pkg/controllers/netpol/... -v -run TestIntegration
//
// Each test uses an isolated nftables table whose name is unique to that test.
// A t.Cleanup handler deletes the table after the test completes so that no
// kernel state leaks between tests or after a test failure.

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	v1 "k8s.io/api/core/v1"
	v1core "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/knftables"
)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// skipIfNoNftables attempts to create a real nftables table via initTable. If
// nftables is not available (missing nft binary, kernel support, or
// insufficient permissions) the test is skipped. On success, a t.Cleanup
// handler that deletes the table is registered and the interface is returned.
func skipIfNoNftables(t *testing.T, family knftables.Family, table string) knftables.Interface {
	t.Helper()
	ctx := context.Background()
	nft, err := initTable(ctx, family, table)
	if err != nil {
		t.Skipf("nftables not available (requires nft binary ≥ 1.0.1 and CAP_NET_ADMIN): %v", err)
	}
	t.Cleanup(func() {
		tx := nft.NewTransaction()
		tx.Delete(&knftables.Table{})
		// ignore error: table may already be absent if an earlier cleanup ran
		_ = nft.Run(context.Background(), tx)
	})
	return nft
}

// newIntegrationNPC constructs a NetworkPolicyControllerNftables backed by the
// provided real (kernel-level) nftables interface. It mirrors
// newUneventfulNfTablesNPC but accepts a pre-initialised interface.
func newIntegrationNPC(
	podInformer, npInformer, nsInformer cache.SharedIndexInformer,
	nftItf knftables.Interface,
) *NetworkPolicyControllerNftables {
	npc := NetworkPolicyControllerNftables{
		NetworkPolicyControllerBase: &NetworkPolicyControllerBase{},
	}
	npc.ctx = context.Background()
	npc.syncPeriod = time.Hour
	npc.filterTableRules = make(map[v1.IPFamily]*bytes.Buffer)
	npc.knftInterfaces = map[v1core.IPFamily]knftables.Interface{
		v1core.IPv4Protocol: nftItf,
	}
	var buf bytes.Buffer
	npc.filterTableRules[v1.IPv4Protocol] = &buf

	npc.krNode = &utils.KRNode{
		NodeName:      "node",
		NodeIPv4Addrs: map[v1.NodeAddressType][]net.IP{v1.NodeInternalIP: {net.IPv4(10, 10, 10, 10)}},
	}
	npc.serviceClusterIPRanges = []net.IPNet{{IP: net.IPv4(10, 43, 0, 0), Mask: net.CIDRMask(16, 32)}}
	npc.serviceNodePortRange = "30000-32767"
	npc.serviceExternalIPRanges = []net.IPNet{{IP: net.IPv4(10, 44, 0, 0), Mask: net.CIDRMask(16, 32)}}
	npc.podLister = podInformer.GetIndexer()
	npc.nsLister = nsInformer.GetIndexer()
	npc.npLister = npInformer.GetIndexer()
	return &npc
}

// setupIntegrationEnv creates the Kubernetes fake informers and a real-nftables
// NPC for use in integration tests. tableName must be unique per test.
// It also calls tCreateFakePods so that pod-selector based policies can be
// evaluated.
func setupIntegrationEnv(t *testing.T, tableName string) (
	npc *NetworkPolicyControllerNftables,
	nftItf knftables.Interface,
	npStore cache.Store,
) {
	t.Helper()
	nftItf = skipIfNoNftables(t, knftables.IPv4Family, tableName)

	client := fake.NewSimpleClientset(
		&v1.NodeList{Items: []v1.Node{*newFakeNode("node", []string{"10.10.10.10"})}},
	)
	informerFactory, podInformer, nsInformer, netpolInformer := newFakeInformersFromClient(client)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	informerFactory.Start(ctx.Done())
	cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced)

	tCreateFakePods(t, podInformer, nsInformer)
	// Re-add nsB pods with PodIPs (same fix as in unit tests).
	for _, p := range []struct {
		name   string
		labels map[string]string
		ip     string
	}{
		{"Ba", map[string]string{"app": "a"}, "2.1.1.1"},
		{"Baa", map[string]string{"app": "a", "component": "a"}, "2.2.2.2"},
		{"Bab", map[string]string{"app": "a", "component": "b"}, "2.3.2.2"},
	} {
		tAddToInformerStore(t, podInformer, &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: p.name, Namespace: "nsB", Labels: p.labels},
			Status:     v1.PodStatus{PodIP: p.ip, PodIPs: []v1.PodIP{{IP: p.ip}}},
		})
	}

	npc = newIntegrationNPC(podInformer, netpolInformer, nsInformer, nftItf)
	npStore = netpolInformer.GetStore()
	return npc, nftItf, npStore
}

// syncPolicies is a thin wrapper: it builds policy info from the informer and
// calls syncNetworkPolicyChains.
func syncPolicies(t *testing.T, npc *NetworkPolicyControllerNftables, version string) {
	t.Helper()
	netpols, err := npc.buildNetworkPoliciesInfo()
	if err != nil {
		t.Fatalf("buildNetworkPoliciesInfo: %v", err)
	}
	_, _, err = npc.syncNetworkPolicyChains(netpols, version)
	if err != nil {
		t.Fatalf("syncNetworkPolicyChains: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test 49 – Create nftables table + chains; verify via List()
// ---------------------------------------------------------------------------

// TestIntegrationTableAndChains verifies that a table and two regular chains
// created through the knftables.Interface are visible through List("chains").
func TestIntegrationTableAndChains(t *testing.T) {
	ctx := context.Background()
	// The table is created (and registered for cleanup) inside skipIfNoNftables.
	nft := skipIfNoNftables(t, knftables.IPv4Family, "kube-router-intg-49")

	// Add two chains to the table.
	tx := nft.NewTransaction()
	tx.Add(&knftables.Chain{Name: "INTG-CHAIN-A", Comment: knftables.PtrTo("integration test chain A")})
	tx.Add(&knftables.Chain{Name: "INTG-CHAIN-B", Comment: knftables.PtrTo("integration test chain B")})
	if err := nft.Run(ctx, tx); err != nil {
		t.Fatalf("failed to add chains: %v", err)
	}

	// Verify both chains appear in List output.
	chains, err := nft.List(ctx, "chains")
	if err != nil {
		t.Fatalf("List(chains): %v", err)
	}
	chainSet := make(map[string]bool, len(chains))
	for _, c := range chains {
		chainSet[c] = true
	}
	for _, want := range []string{"INTG-CHAIN-A", "INTG-CHAIN-B"} {
		if !chainSet[want] {
			t.Errorf("expected chain %q in kernel list, got: %v", want, chains)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 50 – Apply a policy chain; verify via List() and ListRules()
// ---------------------------------------------------------------------------

// TestIntegrationPolicyChainApplied verifies that when a NetworkPolicy is
// synced the corresponding KUBE-NWPLCY-* chain is created in the kernel and
// contains a rule with the expected comment.
func TestIntegrationPolicyChainApplied(t *testing.T) {
	ctx := context.Background()
	npc, nftItf, npStore := setupIntegrationEnv(t, "kube-router-intg-50")

	// Add a simple ingress-allow-all policy targeting nsA pods.
	pol := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-all-ingress", Namespace: "nsA"},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
			Ingress:     []netv1.NetworkPolicyIngressRule{{}},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
	if err := npStore.Add(pol); err != nil {
		t.Fatalf("add policy to store: %v", err)
	}

	syncPolicies(t, npc, "1")

	// There must be at least one KUBE-NWPLCY-* chain (excluding DEFAULT/COMMON).
	chains, err := nftItf.List(ctx, "chains")
	if err != nil {
		t.Fatalf("List(chains): %v", err)
	}
	var policyChain string
	for _, c := range chains {
		if strings.HasPrefix(c, kubeNetworkPolicyChainPrefix) &&
			c != kubeDefaultNetpolChain &&
			c != kubeCommonNetpolChain {
			policyChain = c
			break
		}
	}
	if policyChain == "" {
		t.Fatalf("no KUBE-NWPLCY-* policy chain found; chains in kernel: %v", chains)
	}

	// ListRules returns rules with their comments filled in.
	rules, err := nftItf.ListRules(ctx, policyChain)
	if err != nil {
		t.Fatalf("ListRules(%s): %v", policyChain, err)
	}
	if len(rules) == 0 {
		t.Fatalf("policy chain %s exists but has no rules", policyChain)
	}

	// The allow-all-ingress rule comment should reference the policy namespace/name.
	var found bool
	for _, r := range rules {
		if r.Comment != nil && strings.Contains(*r.Comment, "allow-all-ingress") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no rule with comment containing 'allow-all-ingress' found in chain %s; rules: %+v",
			policyChain, rules)
	}
}

// ---------------------------------------------------------------------------
// Test 51 – Policy deleted; stale chain removed from kernel on next sync
// ---------------------------------------------------------------------------

// TestIntegrationStalePolicyChainRemoved verifies that when a NetworkPolicy is
// deleted, the corresponding nftables chain is removed during the next sync.
func TestIntegrationStalePolicyChainRemoved(t *testing.T) {
	ctx := context.Background()
	npc, nftItf, npStore := setupIntegrationEnv(t, "kube-router-intg-51")

	pol := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "transient-policy", Namespace: "nsA"},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
			Ingress:     []netv1.NetworkPolicyIngressRule{{}},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
	if err := npStore.Add(pol); err != nil {
		t.Fatalf("add policy: %v", err)
	}

	// First sync: policy chain should be created in the kernel.
	syncPolicies(t, npc, "1")

	chains, err := nftItf.List(ctx, "chains")
	if err != nil {
		t.Fatalf("List(chains) after first sync: %v", err)
	}
	var chainBefore string
	for _, c := range chains {
		if strings.HasPrefix(c, kubeNetworkPolicyChainPrefix) &&
			c != kubeDefaultNetpolChain &&
			c != kubeCommonNetpolChain {
			chainBefore = c
			break
		}
	}
	if chainBefore == "" {
		t.Fatalf("policy chain not created on first sync; chains: %v", chains)
	}

	// Remove the policy from the informer store, then sync again.
	if err := npStore.Delete(pol); err != nil {
		t.Fatalf("delete policy from store: %v", err)
	}
	syncPolicies(t, npc, "2")

	// The stale chain must now be absent.
	chainsAfter, err := nftItf.List(ctx, "chains")
	if err != nil {
		t.Fatalf("List(chains) after second sync: %v", err)
	}
	for _, c := range chainsAfter {
		if c == chainBefore {
			t.Errorf("stale chain %s still present after policy deletion; chains: %v",
				chainBefore, chainsAfter)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 52 – Dual-stack: both IPv4 and IPv6 tables present in kernel
// ---------------------------------------------------------------------------

// TestIntegrationDualStackTables verifies that both the IPv4 and IPv6 nftables
// tables are created and that KUBE-ROUTER-FORWARD chains are present in each.
func TestIntegrationDualStackTables(t *testing.T) {
	ctx := context.Background()

	// Create IPv4 table.
	ipv4Nft := skipIfNoNftables(t, knftables.IPv4Family, "kube-router-intg-52-v4")
	// Create IPv6 table; if IPv6 nftables is also unavailable, skip.
	ipv6Nft, err := initTable(ctx, knftables.IPv6Family, "kube-router-intg-52-v6")
	if err != nil {
		t.Skipf("IPv6 nftables not available: %v", err)
	}
	t.Cleanup(func() {
		tx := ipv6Nft.NewTransaction()
		tx.Delete(&knftables.Table{})
		_ = ipv6Nft.Run(context.Background(), tx)
	})

	// Build a dual-stack NPC and call ensureTopLevelChains on both families.
	client := fake.NewSimpleClientset(
		&v1.NodeList{Items: []v1.Node{*newFakeNode("node", []string{"10.10.10.10"})}},
	)
	informerFactory, podInformer, nsInformer, netpolInformer := newFakeInformersFromClient(client)
	ctxC, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	informerFactory.Start(ctxC.Done())
	cache.WaitForCacheSync(ctxC.Done(), podInformer.HasSynced)

	npc := NetworkPolicyControllerNftables{
		NetworkPolicyControllerBase: &NetworkPolicyControllerBase{},
	}
	npc.ctx = ctx
	npc.syncPeriod = time.Hour
	npc.filterTableRules = make(map[v1.IPFamily]*bytes.Buffer)
	npc.knftInterfaces = map[v1core.IPFamily]knftables.Interface{
		v1core.IPv4Protocol: ipv4Nft,
		v1core.IPv6Protocol: ipv6Nft,
	}
	for _, fam := range []v1.IPFamily{v1.IPv4Protocol, v1.IPv6Protocol} {
		var buf bytes.Buffer
		npc.filterTableRules[fam] = &buf
	}
	npc.krNode = &utils.KRNode{
		NodeName:      "node",
		NodeIPv4Addrs: map[v1.NodeAddressType][]net.IP{v1.NodeInternalIP: {net.IPv4(10, 10, 10, 10)}},
	}
	npc.serviceClusterIPRanges = []net.IPNet{{IP: net.IPv4(10, 43, 0, 0), Mask: net.CIDRMask(16, 32)}}
	npc.serviceNodePortRange = "30000-32767"
	npc.serviceExternalIPRanges = []net.IPNet{{IP: net.IPv4(10, 44, 0, 0), Mask: net.CIDRMask(16, 32)}}
	npc.podLister = podInformer.GetIndexer()
	npc.nsLister = nsInformer.GetIndexer()
	npc.npLister = netpolInformer.GetIndexer()

	npc.ensureTopLevelChains()

	// Both IPv4 and IPv6 tables must contain the KUBE-ROUTER-FORWARD chain.
	for family, itf := range map[string]knftables.Interface{
		"IPv4": ipv4Nft,
		"IPv6": ipv6Nft,
	} {
		chains, err := itf.List(ctx, "chains")
		if err != nil {
			t.Errorf("%s List(chains): %v", family, err)
			continue
		}
		found := false
		for _, c := range chains {
			if c == kubeForwardChainName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s table: %q chain not found; chains: %v", family, kubeForwardChainName, chains)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 53 – ipBlock CIDR set: kernel set contains the expected CIDR element
// ---------------------------------------------------------------------------

// TestIntegrationIPBlockSetElements verifies that after syncing a NetworkPolicy
// with an ipBlock peer the corresponding nftables set exists in the kernel and
// its elements include the configured CIDR.
func TestIntegrationIPBlockSetElements(t *testing.T) {
	ctx := context.Background()
	npc, nftItf, npStore := setupIntegrationEnv(t, "kube-router-intg-53")

	pol := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "ipblock-ingress", Namespace: "nsA"},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
			Ingress: []netv1.NetworkPolicyIngressRule{{
				From: []netv1.NetworkPolicyPeer{{
					IPBlock: &netv1.IPBlock{CIDR: "192.168.0.0/24"},
				}},
			}},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
	if err := npStore.Add(pol); err != nil {
		t.Fatalf("add policy: %v", err)
	}

	syncPolicies(t, npc, "1")

	// Determine the expected set name the same way the implementation does.
	setName := nftIndexedSourceIPBlockSetName("nsA", "ipblock-ingress", 0, v1core.IPv4Protocol)

	sets, err := nftItf.List(ctx, "sets")
	if err != nil {
		t.Fatalf("List(sets): %v", err)
	}
	found := false
	for _, s := range sets {
		if s == setName {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ipBlock set %q not found; sets in kernel: %v", setName, sets)
	}

	// The set must contain "192.168.0.0/24" as a prefix element.
	elements, err := nftItf.ListElements(ctx, "set", setName)
	if err != nil {
		t.Fatalf("ListElements(set, %s): %v", setName, err)
	}
	var cidrFound bool
	for _, el := range elements {
		if len(el.Key) > 0 && el.Key[0] == "192.168.0.0/24" {
			cidrFound = true
			break
		}
	}
	if !cidrFound {
		t.Errorf("CIDR 192.168.0.0/24 not found in kernel set %q; elements: %+v", setName, elements)
	}
}

// ---------------------------------------------------------------------------
// Test 54 – ipBlock with except: except CIDR absent from kernel set
// ---------------------------------------------------------------------------

// TestIntegrationIPBlockExceptAbsentFromSet verifies that when an ipBlock peer
// has an Except list the excepted CIDR is NOT added to the nftables set, while
// the primary CIDR IS present.
func TestIntegrationIPBlockExceptAbsentFromSet(t *testing.T) {
	ctx := context.Background()
	npc, nftItf, npStore := setupIntegrationEnv(t, "kube-router-intg-54")

	pol := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "ipblock-except", Namespace: "nsA"},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
			Ingress: []netv1.NetworkPolicyIngressRule{{
				From: []netv1.NetworkPolicyPeer{{
					IPBlock: &netv1.IPBlock{
						CIDR:   "10.0.0.0/8",
						Except: []string{"10.1.0.0/16"},
					},
				}},
			}},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
	if err := npStore.Add(pol); err != nil {
		t.Fatalf("add policy: %v", err)
	}

	syncPolicies(t, npc, "1")

	setName := nftIndexedSourceIPBlockSetName("nsA", "ipblock-except", 0, v1core.IPv4Protocol)
	exceptSetName := nftIndexedSourceIPBlockExceptSetName("nsA", "ipblock-except", 0, v1core.IPv4Protocol)

	// Confirm both sets exist.
	sets, err := nftItf.List(ctx, "sets")
	if err != nil {
		t.Fatalf("List(sets): %v", err)
	}
	var setFound, exceptSetFound bool
	for _, s := range sets {
		switch s {
		case setName:
			setFound = true
		case exceptSetName:
			exceptSetFound = true
		}
	}
	if !setFound {
		t.Fatalf("expected ipBlock set %q not found; sets: %v", setName, sets)
	}
	if !exceptSetFound {
		t.Fatalf("expected ipBlock except set %q not found; sets: %v", exceptSetName, sets)
	}

	// Main set must contain the primary CIDR but NOT the excepted one.
	elements, err := nftItf.ListElements(ctx, "set", setName)
	if err != nil {
		t.Fatalf("ListElements(set, %s): %v", setName, err)
	}

	var mainCIDRFound, exceptCIDRInMainSet bool
	for _, el := range elements {
		if len(el.Key) == 0 {
			continue
		}
		switch el.Key[0] {
		case "10.0.0.0/8":
			mainCIDRFound = true
		case "10.1.0.0/16":
			exceptCIDRInMainSet = true
		}
	}
	if !mainCIDRFound {
		t.Errorf("main CIDR 10.0.0.0/8 not found in kernel set %q; elements: %+v", setName, elements)
	}
	if exceptCIDRInMainSet {
		t.Errorf("except CIDR 10.1.0.0/16 must NOT be in main set %q; elements: %+v", setName, elements)
	}

	// Except set must contain exactly the excepted CIDR.
	exceptElements, err := nftItf.ListElements(ctx, "set", exceptSetName)
	if err != nil {
		t.Fatalf("ListElements(set, %s): %v", exceptSetName, err)
	}
	var exceptCIDRFound bool
	for _, el := range exceptElements {
		if len(el.Key) > 0 && el.Key[0] == "10.1.0.0/16" {
			exceptCIDRFound = true
			break
		}
	}
	if !exceptCIDRFound {
		t.Errorf("except CIDR 10.1.0.0/16 not found in except set %q; elements: %+v", exceptSetName, exceptElements)
	}

	// The policy chain must contain a return rule referencing the except set
	// before the accept rule referencing the main set.
	netpols, err := npc.buildNetworkPoliciesInfo()
	if err != nil {
		t.Fatalf("buildNetworkPoliciesInfo: %v", err)
	}
	var policyChainName string
	for _, np := range netpols {
		if np.name == "ipblock-except" {
			policyChainName = networkPolicyChainName(np.namespace, np.name, "1", v1core.IPv4Protocol)
			break
		}
	}
	if policyChainName == "" {
		t.Fatal("could not find policy chain name for ipblock-except")
	}
	rules, err := nftItf.ListRules(ctx, policyChainName)
	if err != nil {
		t.Fatalf("ListRules(%s): %v", policyChainName, err)
	}
	// ListRules on a real nftables interface does not populate r.Rule (the
	// expression text is not parsed back from JSON). It does populate r.Comment,
	// which we set on every rule, so match on that instead.
	var returnRuleIdx, acceptRuleIdx int = -1, -1
	for i, r := range rules {
		if r.Comment == nil {
			continue
		}
		if strings.Contains(*r.Comment, "skip excepted source CIDRs") {
			returnRuleIdx = i
		}
		if strings.Contains(*r.Comment, "ACCEPT traffic from specified ipBlocks") {
			acceptRuleIdx = i
		}
	}
	if returnRuleIdx == -1 {
		t.Errorf("expected a return rule (comment containing \"skip excepted source CIDRs\") in chain %q; rules: %+v",
			policyChainName, rules)
	}
	if acceptRuleIdx == -1 {
		t.Errorf("expected an accept rule (comment containing \"ACCEPT traffic from specified ipBlocks\") in chain %q; rules: %+v",
			policyChainName, rules)
	}
	if returnRuleIdx != -1 && acceptRuleIdx != -1 && returnRuleIdx > acceptRuleIdx {
		t.Errorf("return rule (idx %d) must appear before accept rule (idx %d) in chain %q",
			returnRuleIdx, acceptRuleIdx, policyChainName)
	}
}
