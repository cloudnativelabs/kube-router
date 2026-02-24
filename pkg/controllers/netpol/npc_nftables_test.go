package netpol

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/controllers/testhelpers"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/svcip"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/stretchr/testify/require"
	v1core "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"sigs.k8s.io/knftables"
)

// newUneventfulNfTablesNPC returns new NetworkPolicyController object without any event handler
func newUneventfulNfTablesNPC(podInformer cache.SharedIndexInformer,
	npInformer cache.SharedIndexInformer, nsInformer cache.SharedIndexInformer) *NetworkPolicyControllerNftables {

	npc := NetworkPolicyControllerNftables{NetworkPolicyControllerBase: &NetworkPolicyControllerBase{}}
	npc.syncPeriod = time.Hour

	npc.filterTableRules = make(map[v1core.IPFamily]*bytes.Buffer)
	npc.knftInterfaces = make(map[v1core.IPFamily]knftables.Interface, 2)
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	//TODO: handle IPv6
	npc.knftInterfaces[v1core.IPv4Protocol] = knftables.NewFake(knftables.IPv4Family, ipv4Table)
	tx := npc.knftInterfaces[v1core.IPv4Protocol].NewTransaction()

	tx.Add(&knftables.Table{
		Comment: knftables.PtrTo("rules for " + ipv4Table),
	})
	err = npc.knftInterfaces[v1core.IPv4Protocol].Run(ctx, tx)
	if err != nil {
		klog.Errorf("nftables: couldn't initialise table %s: %v", ipv4Table, err)
		return nil
	}

	var buf bytes.Buffer
	npc.filterTableRules[v1core.IPv4Protocol] = &buf

	krNode := utils.KRNode{
		NodeName:      "node",
		NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.IPv4(10, 10, 10, 10)}},
	}
	npc.krNode = &krNode
	ipRanges, err := svcip.NewValidator(svcip.Config{
		ClusterIPCIDRs:  []string{"10.43.0.0/16"},
		ExternalIPCIDRs: []string{"10.44.0.0/16"},
		EnableIPv4:      true,
	})
	if err != nil {
		panic("failed to create svcip validator for test: " + err.Error())
	}
	npc.ipRanges = ipRanges
	npc.serviceNodePortRange = "30000-32767"
	npc.podLister = podInformer.GetIndexer()
	npc.nsLister = nsInformer.GetIndexer()
	npc.npLister = npInformer.GetIndexer()

	return &npc
}

func TestBasicChains(t *testing.T) {
	client := fake.NewSimpleClientset(&v1core.NodeList{Items: []v1core.Node{*newFakeNode([]string{"10.10.10.10"})}})
	informerFactory, podInformer, nsInformer, netpolInformer := newFakeInformersFromClient(client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	informerFactory.Start(ctx.Done())
	cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced)
	krNetPol := newUneventfulNfTablesNPC(podInformer, netpolInformer, nsInformer)
	tCreateFakePods(t, podInformer, nsInformer)

	require.NoError(t, krNetPol.ensureTopLevelChains())
	krNetPol.ensureDefaultNetworkPolicyChain()
	krNetPol.ensureCommonPolicyChain()
	fakeIPv4Itf, ok := krNetPol.knftInterfaces[v1core.IPv4Protocol].(*knftables.Fake)
	if !ok {
		t.Fatalf("Expected knftInterfaces[v1.IPv4Protocol] to be of type *knftables.Fake")
	} else {
		ipv4Dump := fakeIPv4Itf.Dump()
		if !strings.Contains(ipv4Dump, "add table ip kube-router-filter-ipv4 { comment \"rules for kube-router-filter-ipv4\" ; }") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add chain ip kube-router-filter-ipv4 KUBE-ROUTER-FORWARD { type filter hook forward priority 0 ; comment \"top level KUBE-ROUTER-FORWARD chain for kube-router\" ; }") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add chain ip kube-router-filter-ipv4 KUBE-ROUTER-INPUT { type filter hook input priority 0 ; comment \"top level KUBE-ROUTER-INPUT chain for kube-router\" ; }") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add chain ip kube-router-filter-ipv4 KUBE-ROUTER-OUTPUT { type filter hook output priority 0 ; comment \"top level KUBE-ROUTER-OUTPUT chain for kube-router\" ; }") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-ROUTER-INPUT ip daddr 10.43.0.0/16 counter return") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-ROUTER-INPUT meta l4proto tcp fib daddr type local tcp dport 30000-32767 counter return") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-ROUTER-INPUT meta l4proto udp fib daddr type local udp dport 30000-32767 counter return") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-ROUTER-INPUT ip daddr 10.44.0.0/16 counter return") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add chain ip kube-router-filter-ipv4 KUBE-NWPLCY-DEFAULT { comment \"KUBE-NWPLCY-DEFAULT chain for kube-router\" ; }") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-DEFAULT counter meta mark set mark or 0x10000") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add chain ip kube-router-filter-ipv4 KUBE-NWPLCY-COMMON { comment \"KUBE-NWPLCY-COMMON chain for kube-router\" ; }") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-COMMON ct state invalid counter drop") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-COMMON ct state invalid counter drop") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-COMMON ct state established,related counter") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-COMMON icmp type echo-request counter accept") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-COMMON icmp type destination-unreachable counter accept") {
			t.Errorf("Expected nftables rules not found in dump")
		}
		if !strings.Contains(ipv4Dump, "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-COMMON icmp type time-exceeded counter accept") {
			t.Errorf("Expected nftables rules not found in dump")
		}
	}

}

func TestNetworkPolicyBuilderNft(t *testing.T) {
	port, port1 := intstr.FromInt(30000), intstr.FromInt(34000)
	ingressPort := intstr.FromInt(37000)
	endPort, endPort1 := int32(31000), int32(35000)
	testCases := []tNetpolTestCase{
		{
			name: "Simple Egress Destination Port",
			netpol: tNetpol{name: "simple-egress", namespace: "nsA",
				podSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "app",
							Operator: "In",
							Values:   []string{"a"},
						},
					},
				},
				egress: []netv1.NetworkPolicyEgressRule{
					{
						Ports: []netv1.NetworkPolicyPort{
							{
								Port: &port,
							},
						},
					},
				},
			},
			expectedRule: "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-C23KD7UE4TAT3Y5M tcp dport 30000 counter meta mark set meta mark or 0x10000 return comment \"ACCEPT traffic from source pods to all destinations selected by policy name: simple-egress namespace nsA\"\n",
		},
		{
			name: "Simple Ingress/Egress Destination Port",
			netpol: tNetpol{name: "simple-ingress-egress", namespace: "nsA",
				podSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "app",
							Operator: "In",
							Values:   []string{"a"},
						},
					},
				},
				egress: []netv1.NetworkPolicyEgressRule{
					{
						Ports: []netv1.NetworkPolicyPort{
							{
								Port: &port,
							},
						},
					},
				},
				ingress: []netv1.NetworkPolicyIngressRule{
					{
						Ports: []netv1.NetworkPolicyPort{
							{
								Port: &ingressPort,
							},
						},
					},
				},
			},
			expectedRule: "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-IDIX352DRLNY3D23 tcp dport 30000 counter meta mark set meta mark or 0x10000 return comment \"ACCEPT traffic from source pods to all destinations selected by policy name: simple-ingress-egress namespace nsA\"\n" +
				"add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-IDIX352DRLNY3D23 tcp dport 37000 counter meta mark set meta mark or 0x10000 return comment \"ACCEPT traffic from all sources to dest pods selected by policy name: simple-ingress-egress namespace nsA\"\n",
		},
		{
			name: "Simple Egress Destination Port Range",
			netpol: tNetpol{name: "simple-egress-pr", namespace: "nsA",
				podSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "app",
							Operator: "In",
							Values:   []string{"a"},
						},
					},
				},
				egress: []netv1.NetworkPolicyEgressRule{
					{
						Ports: []netv1.NetworkPolicyPort{
							{
								Port:    &port,
								EndPort: &endPort,
							},
							{
								Port:    &port1,
								EndPort: &endPort1,
							},
						},
					},
				},
			},
			expectedRule: "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-2UTXQIFBI5TAPUCL tcp dport 30000-31000 counter meta mark set meta mark or 0x10000 return comment \"ACCEPT traffic from source pods to all destinations selected by policy name: simple-egress-pr namespace nsA\"\n" +
				"add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-2UTXQIFBI5TAPUCL tcp dport 34000-35000 counter meta mark set meta mark or 0x10000 return comment \"ACCEPT traffic from source pods to all destinations selected by policy name: simple-egress-pr namespace nsA\"\n",
		},
		{
			name: "Port > EndPort (invalid condition, should drop endport)",
			netpol: tNetpol{name: "invalid-endport", namespace: "nsA",
				podSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "app",
							Operator: "In",
							Values:   []string{"a"},
						},
					},
				},
				egress: []netv1.NetworkPolicyEgressRule{
					{
						Ports: []netv1.NetworkPolicyPort{
							{
								Port:    &port1,
								EndPort: &endPort,
							},
						},
					},
				},
			},
			expectedRule: "add rule ip kube-router-filter-ipv4 KUBE-NWPLCY-N5DQE4SCQ56JEMH7 tcp dport 34000 counter meta mark set meta mark or 0x10000 return comment \"ACCEPT traffic from source pods to all destinations selected by policy name: invalid-endport namespace nsA\"\n",
		},
	}

	client := fake.NewSimpleClientset(&v1core.NodeList{Items: []v1core.Node{*newFakeNode([]string{"10.10.10.10"})}})
	informerFactory, podInformer, nsInformer, netpolInformer := newFakeInformersFromClient(client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	informerFactory.Start(ctx.Done())
	cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced)
	krNetPol := newUneventfulNfTablesNPC(podInformer, netpolInformer, nsInformer)
	tCreateFakePods(t, podInformer, nsInformer)
	for _, test := range testCases {
		test.netpol.createFakeNetpol(t, netpolInformer)
		netpols, err := krNetPol.buildNetworkPoliciesInfo()
		if err != nil {
			t.Errorf("Problems building policies: %s", err)
		}
		for ipFamily, nft := range krNetPol.knftInterfaces {
			for _, np := range netpols {
				fmt.Print(np.policyType)
				policyChainName := networkPolicyChainName(np.namespace, np.name, "1", ipFamily)

				tx := nft.NewTransaction()

				// Declare (or reset) the policy chain.
				tx.Add(&knftables.Chain{
					Name:    policyChainName,
					Comment: knftables.PtrTo("chain for network policy " + np.namespace + "/" + np.name),
				})
				tx.Flush(&knftables.Chain{Name: policyChainName})

				if np.policyType == kubeEgressPolicyType || np.policyType == kubeBothPolicyType {
					krNetPol.processEgressRulesNft(tx, np, "", nil, "1", ipFamily)
				}
				if np.policyType == kubeIngressPolicyType || np.policyType == kubeBothPolicyType {
					krNetPol.processIngressRulesNft(tx, np, "", nil, "1", ipFamily)
				}
				if err = nft.Run(ctx, tx); err != nil {
					t.Errorf("Error running nftables transaction: %s", err)
				}
			}
			fakeItf, ok := krNetPol.knftInterfaces[ipFamily].(*knftables.Fake)
			if !ok {
				t.Fatalf("Expected knftInterfaces[%v] to be of type *knftables.Fake", ipFamily)
			}
			ipv4Dump := fakeItf.Dump()
			t.Logf("IPv4 rules: %s\n", ipv4Dump)
			if !strings.Contains(ipv4Dump, test.expectedRule) {
				t.Errorf("Expected nftables rules not found in dump for test case %s", test.name)
			}

			key := fmt.Sprintf("%s/%s", test.netpol.namespace, test.netpol.name)
			obj, exists, err := krNetPol.npLister.GetByKey(key)
			if err != nil {
				t.Errorf("Failed to get Netpol from store: %s", err)
			}
			if exists {
				err = krNetPol.npLister.Delete(obj)
				if err != nil {
					t.Errorf("Failed to remove Netpol from store: %s", err)
				}
			}
		}
	}
}

func TestFullPolicySync(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "..", "testdata", "ipset_test_1")

	pods := testhelpers.LoadPodList(t, filepath.Join(fixtureDir, "pods.yaml"))
	networkPolicies := testhelpers.LoadNetworkPolicyList(t, filepath.Join(fixtureDir, "networkpolicy.yaml"))
	nodes := testhelpers.LoadNodeList(t, filepath.Join(fixtureDir, "nodes.yaml"))
	namespaces := deriveNamespaces(pods, networkPolicies)

	client := fake.NewSimpleClientset()
	for i := range nodes.Items {
		_, err := client.CoreV1().Nodes().Create(context.Background(), nodes.Items[i].DeepCopy(), metav1.CreateOptions{})
		require.NoError(t, err)
	}

	config := &options.KubeRouterConfig{
		EnableIPv4:       true,
		EnableIPv6:       true,
		ClusterIPCIDRs:   []string{"10.96.0.0/16", "2001:db8:42:1::/112"},
		HostnameOverride: nodes.Items[0].Name,
		NodePortRange:    "30000-32767",
	}

	informerFactory := informers.NewSharedInformerFactory(client, 0)
	podInformer := informerFactory.Core().V1().Pods().Informer()
	npInformer := informerFactory.Networking().V1().NetworkPolicies().Informer()
	nsInformer := informerFactory.Core().V1().Namespaces().Informer()

	ipv4KNftInterface := knftables.NewFake(knftables.IPv4Family, ipv4Table)
	ipv6KNftInterface := knftables.NewFake(knftables.IPv6Family, ipv6Table)

	// Don't forget to create the table before adding chains to it (idempotent).
	tx := ipv4KNftInterface.NewTransaction()
	tx.Add(&knftables.Table{
		Comment: knftables.PtrTo("rules for " + ipv4Table),
	})
	err := ipv4KNftInterface.Run(context.TODO(), tx)
	if err != nil {
		t.Fatalf("nftables: couldn't initialise table %s: %v", ipv4Table, err)
		return
	}
	tx = ipv6KNftInterface.NewTransaction()
	tx.Add(&knftables.Table{
		Comment: knftables.PtrTo("rules for " + ipv6Table),
	})
	err = ipv6KNftInterface.Run(context.TODO(), tx)
	if err != nil {
		t.Fatalf("nftables: couldn't initialise table %s: %v", ipv6Table, err)
		return
	}
	linkQ := utils.NewFakeLocalLinkQuerier(collectNodeIPs(nodes), nil)
	ipRanges, err := svcip.NewValidator(svcip.Config{
		ClusterIPCIDRs: config.ClusterIPCIDRs,
		EnableIPv4:     config.EnableIPv4,
		EnableIPv6:     config.EnableIPv6,
	})
	require.NoError(t, err)

	npc, err := NewNetworkPolicyController(
		client,
		config,
		podInformer,
		npInformer,
		nsInformer,
		&sync.Mutex{},
		linkQ,
		nil,
		nil,
		ipRanges,
		map[v1core.IPFamily]knftables.Interface{
			v1core.IPv4Protocol: ipv4KNftInterface,
			v1core.IPv6Protocol: ipv6KNftInterface,
		},
		true,
	)
	require.NoError(t, err)

	addPodsToInformer(t, podInformer.GetStore(), pods)
	addNetworkPoliciesToInformer(t, npInformer.GetStore(), networkPolicies)
	addNamespacesToInformer(nsInformer.GetStore(), namespaces)

	require.NoError(t, npc.ensureTopLevelChains())
	npc.ensureDefaultNetworkPolicyChain()
	npc.ensureCommonPolicyChain()

	ipv4Dump := ipv4KNftInterface.Dump()
	t.Logf("nftables dump: \n%s", ipv4Dump)

	netpolInfo, err := npc.buildNetworkPoliciesInfo()
	require.NoError(t, err)

	_, _, err = npc.syncNetworkPolicyChains(netpolInfo, "fixture")
	ipv4Dump = ipv4KNftInterface.Dump()
	t.Logf("nftables dump: \n%s", ipv4Dump)

	ipv6Dump := ipv6KNftInterface.Dump()
	t.Logf("nftables dump: \n%s", ipv6Dump)

	require.NoError(t, err)

	// --- IPv4 assertions ---
	// Common infrastructure chains must be present.
	require.Contains(t, ipv4Dump, `add chain ip kube-router-filter-ipv4 KUBE-NWPLCY-COMMON`,
		"ipv4: KUBE-NWPLCY-COMMON chain missing")
	require.Contains(t, ipv4Dump, `add chain ip kube-router-filter-ipv4 KUBE-NWPLCY-DEFAULT`,
		"ipv4: KUBE-NWPLCY-DEFAULT chain missing")
	require.Contains(t, ipv4Dump, `add chain ip kube-router-filter-ipv4 KUBE-ROUTER-FORWARD`,
		"ipv4: KUBE-ROUTER-FORWARD chain missing")
	require.Contains(t, ipv4Dump, `add chain ip kube-router-filter-ipv4 KUBE-ROUTER-INPUT`,
		"ipv4: KUBE-ROUTER-INPUT chain missing")

	// Common chain stateful-firewall and ICMP rules.
	require.Contains(t, ipv4Dump, `ct state invalid counter drop comment "drop invalid state for pod"`,
		"ipv4: drop-invalid rule missing")
	require.Contains(t, ipv4Dump, `ct state established,related counter accept comment "rule for stateful firewall for pod"`,
		"ipv4: stateful-accept rule missing")
	require.Contains(t, ipv4Dump, `icmp type echo-request counter accept`,
		"ipv4: ICMP echo-request rule missing")

	// Per-policy chains for the two fixture policies must exist.
	require.Contains(t, ipv4Dump, `comment "chain for network policy default/whoami"`,
		"ipv4: whoami policy chain missing")
	require.Contains(t, ipv4Dump, `comment "chain for network policy default/debug"`,
		"ipv4: debug policy chain missing")

	// "whoami" ingress policy: allow TCP 5000 from ipBlock 10.95.0.239/32 to whoami pod IPs.
	require.Contains(t, ipv4Dump, `tcp dport 5000 counter meta mark set meta mark or 0x10000 return comment "ACCEPT traffic from specified ipBlocks to dest pods selected by policy name: whoami namespace default"`,
		"ipv4: whoami ipBlock ingress rule missing")

	// ipBlock set must contain the fixture CIDR.
	require.Contains(t, ipv4Dump, `10.95.0.239/32`,
		"ipv4: ipBlock element 10.95.0.239/32 missing from set")

	// Destination sets for whoami pods must contain both pod IPs.
	require.Contains(t, ipv4Dump, `{ 10.242.0.5 }`,
		"ipv4: whoami pod IP 10.242.0.5 missing from destination set")
	require.Contains(t, ipv4Dump, `{ 10.242.1.4 }`,
		"ipv4: whoami pod IP 10.242.1.4 missing from destination set")

	// "debug" egress policy: allow traffic from debug-toolbox pods to whoami pods (no port restriction).
	require.Contains(t, ipv4Dump, `counter meta mark set meta mark or 0x10000 return comment "ACCEPT traffic from source pods to dest pods selected by policy name debug namespace default"`,
		"ipv4: debug egress rule missing")

	// Cluster-IP and node-port pass-through rules in KUBE-ROUTER-INPUT.
	require.Contains(t, ipv4Dump, `ip daddr 10.96.0.0/16 counter return comment "allow traffic to primary/secondary cluster IP range"`,
		"ipv4: cluster-IP pass-through rule missing")
	require.Contains(t, ipv4Dump, `tcp dport 30000-32767 counter return comment "allow LOCAL tcp traffic to node ports"`,
		"ipv4: TCP node-port pass-through rule missing")
	require.Contains(t, ipv4Dump, `udp dport 30000-32767 counter return comment "allow LOCAL udp traffic to node ports"`,
		"ipv4: UDP node-port pass-through rule missing")

	// --- IPv6 assertions ---
	require.Contains(t, ipv6Dump, `add chain ip6 kube-router-filter-ipv6 KUBE-NWPLCY-COMMON`,
		"ipv6: KUBE-NWPLCY-COMMON chain missing")
	require.Contains(t, ipv6Dump, `add chain ip6 kube-router-filter-ipv6 KUBE-NWPLCY-DEFAULT`,
		"ipv6: KUBE-NWPLCY-DEFAULT chain missing")

	// IPv6 ICMP NDP rules (extra compared to IPv4).
	require.Contains(t, ipv6Dump, `icmpv6 type nd-neighbor-solicit counter accept`,
		"ipv6: NDP neighbor-solicit rule missing")
	require.Contains(t, ipv6Dump, `icmpv6 type nd-neighbor-advert counter accept`,
		"ipv6: NDP neighbor-advert rule missing")

	// Per-policy chains for IPv6.
	require.Contains(t, ipv6Dump, `comment "chain for network policy default/whoami"`,
		"ipv6: whoami policy chain missing")
	require.Contains(t, ipv6Dump, `comment "chain for network policy default/debug"`,
		"ipv6: debug policy chain missing")

	// "debug" egress rule for IPv6.
	require.Contains(t, ipv6Dump, `counter meta mark set meta mark or 0x10000 return comment "ACCEPT traffic from source pods to dest pods selected by policy name debug namespace default"`,
		"ipv6: debug egress rule missing")

	// IPv6 destination sets for whoami pods.
	require.Contains(t, ipv6Dump, `{ 2001:db8:42:1000::5 }`,
		"ipv6: whoami pod IP 2001:db8:42:1000::5 missing from destination set")
	require.Contains(t, ipv6Dump, `{ 2001:db8:42:1001::4 }`,
		"ipv6: whoami pod IP 2001:db8:42:1001::4 missing from destination set")

	// Cluster-IP pass-through rule for IPv6.
	require.Contains(t, ipv6Dump, `ip6 daddr 2001:db8:42:1::/112 counter return comment "allow traffic to primary/secondary cluster IP range"`,
		"ipv6: cluster-IP pass-through rule missing")
}

// runNftPolicyRules is a helper shared by extended nftables tests.
// It builds policy info from the informer, then for each active nft family processes
// ingress and egress rules into a fresh transaction and commits it to the fake interface.
func runNftPolicyRules(t *testing.T, npc *NetworkPolicyControllerNftables) {
	t.Helper()
	ctx := context.Background()
	netpols, err := npc.buildNetworkPoliciesInfo()
	if err != nil {
		t.Fatalf("buildNetworkPoliciesInfo failed: %v", err)
	}
	for ipFamily, nft := range npc.knftInterfaces {
		for _, np := range netpols {
			policyChainName := networkPolicyChainName(np.namespace, np.name, "1", ipFamily)
			tx := nft.NewTransaction()
			tx.Add(&knftables.Chain{
				Name:    policyChainName,
				Comment: knftables.PtrTo("chain for " + np.namespace + "/" + np.name),
			})
			tx.Flush(&knftables.Chain{Name: policyChainName})
			activeSets := make(map[string]bool)

			if np.policyType == kubeEgressPolicyType || np.policyType == kubeBothPolicyType {
				npc.processEgressRulesNft(tx, np, "", activeSets, "1", ipFamily)
			}
			if np.policyType == kubeIngressPolicyType || np.policyType == kubeBothPolicyType {
				npc.processIngressRulesNft(tx, np, "", activeSets, "1", ipFamily)
			}
			if err := nft.Run(ctx, tx); err != nil {
				t.Fatalf("nft.Run failed: %v", err)
			}
		}
	}
}

// TestNetworkPolicyBuilderNftExtended covers nftables rule generation for scenarios
// not exercised by TestNetworkPolicyBuilderNft: allow-all ingress/egress, source-pod-only
// rules, egress allow-all, and ipBlock CIDRs with and without except entries.
func TestNetworkPolicyBuilderNftExtended(t *testing.T) {
	port8080 := intstr.FromInt(8080)
	proto := v1core.ProtocolTCP

	testCases := []struct {
		name       string
		netpol     tNetpol
		assertDump func(t *testing.T, dump string, netpolName string)
	}{
		{
			name: "Ingress allow-all generates match-all accept rule",
			netpol: tNetpol{
				name:        "ingress-allow-all",
				namespace:   "nsA",
				podSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
				ingress:     []netv1.NetworkPolicyIngressRule{{}},
			},
			assertDump: func(t *testing.T, dump, polName string) {
				t.Helper()
				expected := "counter meta mark set meta mark or 0x10000 return"
				if !strings.Contains(dump, expected) {
					t.Errorf("allow-all ingress: expected %q in dump, got:\n%s", expected, dump)
				}
				comment := "ACCEPT traffic from all sources to dest pods selected by policy name: " + polName + " namespace nsA"
				if !strings.Contains(dump, comment) {
					t.Errorf("allow-all ingress: comment %q not found in dump", comment)
				}
			},
		},
		{
			name: "Egress allow-all generates match-all accept rule",
			netpol: tNetpol{
				name:        "egress-allow-all",
				namespace:   "nsA",
				podSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
				egress:      []netv1.NetworkPolicyEgressRule{{}},
			},
			assertDump: func(t *testing.T, dump, polName string) {
				t.Helper()
				expected := "counter meta mark set meta mark or 0x10000 return"
				if !strings.Contains(dump, expected) {
					t.Errorf("allow-all egress: expected %q in dump, got:\n%s", expected, dump)
				}
				comment := "ACCEPT traffic from source pods to all destinations selected by policy name: " + polName + " namespace nsA"
				if !strings.Contains(dump, comment) {
					t.Errorf("allow-all egress: comment %q not found in dump", comment)
				}
			},
		},
		{
			name: "Ingress ports-only generates dport rule without src/dst set",
			netpol: tNetpol{
				name:        "ingress-ports-only",
				namespace:   "nsA",
				podSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
				ingress: []netv1.NetworkPolicyIngressRule{{
					Ports: []netv1.NetworkPolicyPort{{Protocol: &proto, Port: &port8080}},
				}},
			},
			assertDump: func(t *testing.T, dump, polName string) {
				t.Helper()
				// nftables keywords are case-sensitive and must be lowercase; the fix
				// in appendRuleToPolicyChainNft lowercases the protocol before emitting it.
				if !strings.Contains(dump, "tcp dport 8080") {
					t.Errorf("ingress ports-only: expected 'tcp dport 8080' in dump, got:\n%s", dump)
				}
				// When targetDestPodSetName is "" there must be no daddr set reference.
				if strings.Contains(dump, "ip daddr @") {
					t.Errorf("ingress ports-only: unexpected 'ip daddr @...' in dump (target set was empty)")
				}
			},
		},
		{
			name: "Ingress from nsB pods generates saddr set with pod IPs",
			netpol: tNetpol{
				name:        "ingress-src-pods",
				namespace:   "nsA",
				podSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
				ingress: []netv1.NetworkPolicyIngressRule{{
					From: []netv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"name": "b"}},
					}},
				}},
			},
			assertDump: func(t *testing.T, dump, _ string) {
				t.Helper()
				// Rule must reference the source pod set.
				if !strings.Contains(dump, "ip saddr @") {
					t.Errorf("ingress srcPods: expected 'ip saddr @...' in dump, got:\n%s", dump)
				}
				// nsB pods: Ba=2.1.1.1, Baa=2.2.2.2, Bab=2.3.2.2 – all should be in the set.
				for _, ip := range []string{"2.1.1.1", "2.2.2.2", "2.3.2.2"} {
					if !strings.Contains(dump, ip) {
						t.Errorf("ingress srcPods: IP %s not found in nft dump", ip)
					}
				}
			},
		},
		{
			name: "Ingress from ipBlock CIDR creates interval set with CIDR element",
			netpol: tNetpol{
				name:        "ingress-ipblock",
				namespace:   "nsA",
				podSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
				ingress: []netv1.NetworkPolicyIngressRule{{
					From: []netv1.NetworkPolicyPeer{{
						IPBlock: &netv1.IPBlock{CIDR: "192.168.0.0/24"},
					}},
				}},
			},
			assertDump: func(t *testing.T, dump, _ string) {
				t.Helper()
				setName := nftIndexedSourceIPBlockSetName("nsA", "ingress-ipblock", 0, v1core.IPv4Protocol)
				if !strings.Contains(dump, setName) {
					t.Errorf("ipBlock ingress: set %s not found in dump", setName)
				}
				if !strings.Contains(dump, "192.168.0.0/24") {
					t.Errorf("ipBlock ingress: CIDR 192.168.0.0/24 not in dump")
				}
				if !strings.Contains(dump, "ip saddr @"+setName) {
					t.Errorf("ipBlock ingress: rule 'ip saddr @%s' not found in dump", setName)
				}
			},
		},
		{
			name: "Ingress from ipBlock with except puts except CIDR in except set with return rule",
			netpol: tNetpol{
				name:        "ingress-ipblock-except",
				namespace:   "nsA",
				podSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
				ingress: []netv1.NetworkPolicyIngressRule{{
					From: []netv1.NetworkPolicyPeer{{
						IPBlock: &netv1.IPBlock{
							CIDR:   "10.0.0.0/8",
							Except: []string{"10.1.0.0/16"},
						},
					}},
				}},
			},
			assertDump: func(t *testing.T, dump, _ string) {
				t.Helper()
				mainSetName := nftIndexedSourceIPBlockSetName("nsA", "ingress-ipblock-except", 0, v1core.IPv4Protocol)
				exceptSetName := nftIndexedSourceIPBlockExceptSetName("nsA", "ingress-ipblock-except", 0, v1core.IPv4Protocol)
				// Main CIDR must be present in the main set.
				if !strings.Contains(dump, "10.0.0.0/8") {
					t.Errorf("ipBlock except: main CIDR 10.0.0.0/8 must be in nft dump")
				}
				// The except CIDR must appear in the except set, not the main set.
				if !strings.Contains(dump, "10.1.0.0/16") {
					t.Errorf("ipBlock except: except CIDR 10.1.0.0/16 must be in nft dump (in except set)")
				}
				if !strings.Contains(dump, exceptSetName) {
					t.Errorf("ipBlock except: except set %s not found in dump", exceptSetName)
				}
				// A return rule for the except set must precede the accept rule for the main set.
				returnRuleStr := "ip saddr @" + exceptSetName
				acceptRuleStr := "ip saddr @" + mainSetName
				returnIdx := strings.Index(dump, returnRuleStr)
				acceptIdx := strings.Index(dump, acceptRuleStr)
				if returnIdx == -1 {
					t.Errorf("ipBlock except: return rule referencing except set %q not found in dump", exceptSetName)
				}
				if acceptIdx == -1 {
					t.Errorf("ipBlock except: accept rule referencing main set %q not found in dump", mainSetName)
				}
				if returnIdx != -1 && acceptIdx != -1 && returnIdx > acceptIdx {
					t.Errorf("ipBlock except: return rule must appear before accept rule in dump")
				}
			},
		},
		{
			name: "Egress to ipBlock CIDR creates interval set with CIDR element",
			netpol: tNetpol{
				name:        "egress-ipblock",
				namespace:   "nsA",
				podSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
				egress: []netv1.NetworkPolicyEgressRule{{
					To: []netv1.NetworkPolicyPeer{{
						IPBlock: &netv1.IPBlock{CIDR: "172.16.0.0/12"},
					}},
				}},
			},
			assertDump: func(t *testing.T, dump, _ string) {
				t.Helper()
				setName := nftIndexedDestinationIPBlockSetName("nsA", "egress-ipblock", 0, v1core.IPv4Protocol)
				if !strings.Contains(dump, setName) {
					t.Errorf("ipBlock egress: set %s not found in dump", setName)
				}
				if !strings.Contains(dump, "172.16.0.0/12") {
					t.Errorf("ipBlock egress: CIDR 172.16.0.0/12 not in dump")
				}
				if !strings.Contains(dump, "ip daddr @"+setName) {
					t.Errorf("ipBlock egress: rule 'ip daddr @%s' not found in dump", setName)
				}
			},
		},
	}

	client := fake.NewSimpleClientset(&v1core.NodeList{Items: []v1core.Node{*newFakeNode([]string{"10.10.10.10"})}})
	informerFactory, podInformer, nsInformer, netpolInformer := newFakeInformersFromClient(client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	informerFactory.Start(ctx.Done())
	cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced)
	npc := newUneventfulNfTablesNPC(podInformer, netpolInformer, nsInformer)
	tCreateFakePods(t, podInformer, nsInformer)
	// Re-add nsB pods with PodIPs populated; tCreateFakePods only sets PodIP (legacy
	// single-IP field) which is ignored by getIPsFromPods. Override here so that
	// source-pod set membership assertions can find the expected addresses.
	for _, p := range []struct {
		name   string
		labels map[string]string
		ip     string
	}{
		{"Ba", map[string]string{"app": "a"}, "2.1.1.1"},
		{"Baa", map[string]string{"app": "a", "component": "a"}, "2.2.2.2"},
		{"Bab", map[string]string{"app": "a", "component": "b"}, "2.3.2.2"},
	} {
		tAddToInformerStore(t, podInformer, &v1core.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: p.name, Namespace: "nsB", Labels: p.labels},
			Status:     v1core.PodStatus{PodIP: p.ip, PodIPs: []v1core.PodIP{{IP: p.ip}}},
		})
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.netpol.createFakeNetpol(t, netpolInformer)
			runNftPolicyRules(t, npc)

			fakeItf, ok := npc.knftInterfaces[v1core.IPv4Protocol].(*knftables.Fake)
			if !ok {
				t.Fatal("expected *knftables.Fake for IPv4")
			}
			dump := fakeItf.Dump()
			t.Logf("nft dump:\n%s", dump)
			tc.assertDump(t, dump, tc.netpol.name)

			// Clean up policy from informer store before next test.
			key := tc.netpol.namespace + "/" + tc.netpol.name
			obj, exists, err := npc.npLister.GetByKey(key)
			if err == nil && exists {
				_ = npc.npLister.Delete(obj)
			}
		})
	}
}

// TestNftablesChainsIdempotency verifies that calling the chain-setup helpers multiple
// times produces an identical nftables state (no duplicated rules or chains).
func TestNftablesChainsIdempotency(t *testing.T) {
	client := fake.NewSimpleClientset(&v1core.NodeList{Items: []v1core.Node{*newFakeNode([]string{"10.10.10.10"})}})
	informerFactory, podInformer, nsInformer, netpolInformer := newFakeInformersFromClient(client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	informerFactory.Start(ctx.Done())
	cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced)
	npc := newUneventfulNfTablesNPC(podInformer, netpolInformer, nsInformer)

	// First invocation.
	require.NoError(t, npc.ensureTopLevelChains())
	npc.ensureDefaultNetworkPolicyChain()
	npc.ensureCommonPolicyChain()

	fakeItf, ok := npc.knftInterfaces[v1core.IPv4Protocol].(*knftables.Fake)
	require.True(t, ok, "expected *knftables.Fake for IPv4")
	dumpAfterFirst := fakeItf.Dump()

	// Second invocation – must produce the same state.
	require.NoError(t, npc.ensureTopLevelChains())
	npc.ensureDefaultNetworkPolicyChain()
	npc.ensureCommonPolicyChain()
	dumpAfterSecond := fakeItf.Dump()

	if dumpAfterFirst != dumpAfterSecond {
		t.Errorf("nftables state changed on second call to ensure* helpers:\nFIRST:\n%s\nSECOND:\n%s",
			dumpAfterFirst, dumpAfterSecond)
	}
}

// TestNftablesStalePolicyCleanup verifies that policy chains and named sets that no longer
// correspond to an active NetworkPolicy are deleted during the next syncNetworkPolicyChains
// call.
func TestNftablesStalePolicyCleanup(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "..", "testdata", "ipset_test_1")
	nodes := testhelpers.LoadNodeList(t, filepath.Join(fixtureDir, "nodes.yaml"))

	client := fake.NewSimpleClientset()
	for i := range nodes.Items {
		_, err := client.CoreV1().Nodes().Create(
			context.Background(), nodes.Items[i].DeepCopy(), metav1.CreateOptions{})
		require.NoError(t, err)
	}

	config := &options.KubeRouterConfig{
		EnableIPv4:       true,
		EnableIPv6:       false,
		ClusterIPCIDRs:   []string{"10.96.0.0/16"},
		HostnameOverride: nodes.Items[0].Name,
		NodePortRange:    "30000-32767",
	}

	informerFactory := informers.NewSharedInformerFactory(client, 0)
	podInformer := informerFactory.Core().V1().Pods().Informer()
	npInformer := informerFactory.Networking().V1().NetworkPolicies().Informer()
	nsInformer := informerFactory.Core().V1().Namespaces().Informer()

	ipv4KNft := knftables.NewFake(knftables.IPv4Family, ipv4Table)
	tx := ipv4KNft.NewTransaction()
	tx.Add(&knftables.Table{Comment: knftables.PtrTo("rules for " + ipv4Table)})
	require.NoError(t, ipv4KNft.Run(context.TODO(), tx))

	linkQ := utils.NewFakeLocalLinkQuerier(collectNodeIPs(nodes), nil)
	ipRanges, err := svcip.NewValidator(svcip.Config{
		ClusterIPCIDRs: config.ClusterIPCIDRs,
		EnableIPv4:     config.EnableIPv4,
		EnableIPv6:     config.EnableIPv6,
	})
	require.NoError(t, err)
	npc, err := NewNetworkPolicyController(
		client, config,
		podInformer, npInformer, nsInformer,
		&sync.Mutex{}, linkQ, nil, nil,
		ipRanges,
		map[v1core.IPFamily]knftables.Interface{v1core.IPv4Protocol: ipv4KNft},
		true,
	)
	require.NoError(t, err)

	require.NoError(t, npc.ensureTopLevelChains())
	npc.ensureDefaultNetworkPolicyChain()
	npc.ensureCommonPolicyChain()

	// Create two simple policies: policy-keep and policy-delete.
	makePolicy := func(name string) *netv1.NetworkPolicy {
		return &netv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: netv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
				Ingress:     []netv1.NetworkPolicyIngressRule{{}},
			},
		}
	}
	_ = npInformer.GetStore().Add(makePolicy("policy-keep"))
	_ = npInformer.GetStore().Add(makePolicy("policy-delete"))
	// Need a namespace so pod lookups don't fail.
	_ = nsInformer.GetStore().Add(&v1core.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	})

	// First sync: both policies → both chains created.
	info1, err := npc.buildNetworkPoliciesInfo()
	require.NoError(t, err)
	_, _, err = npc.syncNetworkPolicyChains(info1, "v1")
	require.NoError(t, err)

	// Compute chain names so we can assert on the dump.
	keepChain := networkPolicyChainName("default", "policy-keep", "v1", v1core.IPv4Protocol)
	deleteChain := networkPolicyChainName("default", "policy-delete", "v1", v1core.IPv4Protocol)

	dumpAfterFirst := ipv4KNft.Dump()
	t.Logf("dump after first sync:\n%s", dumpAfterFirst)

	require.Contains(t, dumpAfterFirst, keepChain, "policy-keep chain must exist after first sync")
	require.Contains(t, dumpAfterFirst, deleteChain, "policy-delete chain must exist after first sync")

	// Remove policy-delete from the informer store and re-sync.
	obj, exists, err := npInformer.GetStore().GetByKey("default/policy-delete")
	require.NoError(t, err)
	require.True(t, exists)
	require.NoError(t, npInformer.GetStore().Delete(obj))

	info2, err := npc.buildNetworkPoliciesInfo()
	require.NoError(t, err)
	_, _, err = npc.syncNetworkPolicyChains(info2, "v1")
	require.NoError(t, err)

	dumpAfterSecond := ipv4KNft.Dump()
	t.Logf("dump after second sync:\n%s", dumpAfterSecond)

	require.Contains(t, dumpAfterSecond, keepChain, "policy-keep chain must still exist after second sync")
	if strings.Contains(dumpAfterSecond, deleteChain) {
		t.Errorf("policy-delete chain %s must be removed after second sync, but found in dump", deleteChain)
	}
}

// TestNftablesNodePortRange verifies that node-port ranges supplied in either
// colon-separated form ("30000:32767") or hyphen-separated form ("30000-32767")
// always produce nftables dport rules that use the hyphen separator, which is
// the only syntax accepted by nftables.  Using a colon in a dport expression
// causes a nftables syntax error at rule-install time.
func TestNftablesNodePortRange(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "..", "testdata", "ipset_test_1")
	nodes := testhelpers.LoadNodeList(t, filepath.Join(fixtureDir, "nodes.yaml"))

	for _, tc := range []struct {
		name          string
		nodePortRange string // value passed in config (as a user would write it)
	}{
		{
			name:          "hyphen-separated range is preserved as hyphen in nftables rule",
			nodePortRange: "30000-32767",
		},
		{
			name:          "colon-separated range is converted to hyphen in nftables rule",
			nodePortRange: "30000:32767",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			for i := range nodes.Items {
				_, err := client.CoreV1().Nodes().Create(
					context.Background(), nodes.Items[i].DeepCopy(), metav1.CreateOptions{})
				require.NoError(t, err)
			}

			config := &options.KubeRouterConfig{
				EnableIPv4:       true,
				EnableIPv6:       false,
				ClusterIPCIDRs:   []string{"10.96.0.0/16"},
				HostnameOverride: nodes.Items[0].Name,
				NodePortRange:    tc.nodePortRange,
			}

			informerFactory := informers.NewSharedInformerFactory(client, 0)
			podInformer := informerFactory.Core().V1().Pods().Informer()
			npInformer := informerFactory.Networking().V1().NetworkPolicies().Informer()
			nsInformer := informerFactory.Core().V1().Namespaces().Informer()

			ipv4KNft := knftables.NewFake(knftables.IPv4Family, ipv4Table)
			tx := ipv4KNft.NewTransaction()
			tx.Add(&knftables.Table{Comment: knftables.PtrTo("rules for " + ipv4Table)})
			require.NoError(t, ipv4KNft.Run(context.Background(), tx))

			linkQ := utils.NewFakeLocalLinkQuerier(collectNodeIPs(nodes), nil)
			ipRanges, err := svcip.NewValidator(svcip.Config{
				ClusterIPCIDRs: config.ClusterIPCIDRs,
				EnableIPv4:     config.EnableIPv4,
				EnableIPv6:     config.EnableIPv6,
			})
			require.NoError(t, err)
			npc, err := NewNetworkPolicyController(
				client, config,
				podInformer, npInformer, nsInformer,
				&sync.Mutex{}, linkQ, nil, nil,
				ipRanges,
				map[v1core.IPFamily]knftables.Interface{v1core.IPv4Protocol: ipv4KNft},
				true,
			)
			require.NoError(t, err)

			require.NoError(t, npc.ensureTopLevelChains())

			dump := ipv4KNft.Dump()
			t.Logf("nftables dump:\n%s", dump)

			// nftables requires a hyphen as the port-range separator; a colon
			// causes a syntax error and would have been caught at rule-install time.
			tcpRule := "meta l4proto tcp fib daddr type local tcp dport 30000-32767 counter return"
			udpRule := "meta l4proto udp fib daddr type local udp dport 30000-32767 counter return"
			sctpRule := "meta l4proto sctp fib daddr type local sctp dport 30000-32767 counter return"
			require.Contains(t, dump, tcpRule,
				"expected TCP node-port rule with hyphen-separated range in nftables dump")
			require.Contains(t, dump, udpRule,
				"expected UDP node-port rule with hyphen-separated range in nftables dump")
			require.Contains(t, dump, sctpRule,
				"expected SCTP node-port rule with hyphen-separated range in nftables dump")

			// Also assert the colon form is absent – if it appeared it would be a
			// syntax error against a real nftables kernel subsystem.
			require.NotContains(t, dump, "dport 30000:32767",
				"colon-separated port range must not appear in nftables rules")
		})
	}
}
