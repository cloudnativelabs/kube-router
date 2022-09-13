package netpol

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-iptables/iptables"

	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/cache"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
)

// newFakeInformersFromClient creates the different informers used in the uneventful network policy controller
func newFakeInformersFromClient(kubeClient clientset.Interface) (informers.SharedInformerFactory, cache.SharedIndexInformer, cache.SharedIndexInformer, cache.SharedIndexInformer) {
	informerFactory := informers.NewSharedInformerFactory(kubeClient, 0)
	podInformer := informerFactory.Core().V1().Pods().Informer()
	npInformer := informerFactory.Networking().V1().NetworkPolicies().Informer()
	nsInformer := informerFactory.Core().V1().Namespaces().Informer()
	return informerFactory, podInformer, nsInformer, npInformer
}

type tNamespaceMeta struct {
	name   string
	labels labels.Set
}

// Add resources to Informer Store object to simulate updating the Informer
func tAddToInformerStore(t *testing.T, informer cache.SharedIndexInformer, obj interface{}) {
	err := informer.GetStore().Add(obj)
	if err != nil {
		t.Fatalf("error injecting object to Informer Store: %v", err)
	}
}

type tNetpol struct {
	name        string
	namespace   string
	podSelector metav1.LabelSelector
	ingress     []netv1.NetworkPolicyIngressRule
	egress      []netv1.NetworkPolicyEgressRule
}

// createFakeNetpol is a helper to create the network policy from the tNetpol struct
func (ns *tNetpol) createFakeNetpol(t *testing.T, informer cache.SharedIndexInformer) {
	polTypes := make([]netv1.PolicyType, 0)
	if len(ns.ingress) != 0 {
		polTypes = append(polTypes, netv1.PolicyTypeIngress)
	}
	if len(ns.egress) != 0 {
		polTypes = append(polTypes, netv1.PolicyTypeEgress)
	}
	tAddToInformerStore(t, informer,
		&netv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: ns.name, Namespace: ns.namespace},
			Spec: netv1.NetworkPolicySpec{
				PodSelector: ns.podSelector,
				PolicyTypes: polTypes,
				Ingress:     ns.ingress,
				Egress:      ns.egress,
			}})
}

func (ns *tNetpol) findNetpolMatch(netpols *[]networkPolicyInfo) *networkPolicyInfo {
	for _, netpol := range *netpols {
		if netpol.namespace == ns.namespace && netpol.name == ns.name {
			return &netpol
		}
	}
	return nil
}

// tPodNamespaceMap is a helper to create sets of namespace,pod names
type tPodNamespaceMap map[string]map[string]bool

func (t tPodNamespaceMap) addPod(pod podInfo) {
	if _, ok := t[pod.namespace]; !ok {
		t[pod.namespace] = make(map[string]bool)
	}
	t[pod.namespace][pod.name] = true
}
func (t tPodNamespaceMap) delPod(pod podInfo) {
	delete(t[pod.namespace], pod.name)
	if len(t[pod.namespace]) == 0 {
		delete(t, pod.namespace)
	}
}
func (t tPodNamespaceMap) addNSPodInfo(ns, podname string) {
	if _, ok := t[ns]; !ok {
		t[ns] = make(map[string]bool)
	}
	t[ns][podname] = true
}
func (t tPodNamespaceMap) copy() tPodNamespaceMap {
	newMap := make(tPodNamespaceMap)
	for ns, pods := range t {
		for p := range pods {
			newMap.addNSPodInfo(ns, p)
		}
	}
	return newMap
}
func (t tPodNamespaceMap) toStrSlice() (r []string) {
	for ns, pods := range t {
		for pod := range pods {
			r = append(r, ns+":"+pod)
		}
	}
	return
}

// tNewPodNamespaceMapFromTC creates a new tPodNamespaceMap from the info of the testcase
func tNewPodNamespaceMapFromTC(target map[string]string) tPodNamespaceMap {
	newMap := make(tPodNamespaceMap)
	for ns, pods := range target {
		for _, pod := range strings.Split(pods, ",") {
			newMap.addNSPodInfo(ns, pod)
		}
	}
	return newMap
}

// tCreateFakePods creates the Pods and Namespaces that will be affected by the network policies
//	returns a map like map[Namespace]map[PodName]bool
func tCreateFakePods(t *testing.T, podInformer cache.SharedIndexInformer, nsInformer cache.SharedIndexInformer) {
	podNamespaceMap := make(tPodNamespaceMap)
	pods := []podInfo{
		{name: "Aa", labels: labels.Set{"app": "a"}, namespace: "nsA", ips: []v1.PodIP{{IP: "1.1.1.1"}}},
		{name: "Aaa", labels: labels.Set{"app": "a", "component": "a"}, namespace: "nsA", ips: []v1.PodIP{{IP: "1.2.3.4"}}},
		{name: "Aab", labels: labels.Set{"app": "a", "component": "b"}, namespace: "nsA", ips: []v1.PodIP{{IP: "1.3.2.2"}}},
		{name: "Aac", labels: labels.Set{"app": "a", "component": "c"}, namespace: "nsA", ips: []v1.PodIP{{IP: "1.4.2.2"}}},
		{name: "Ba", labels: labels.Set{"app": "a"}, namespace: "nsB", ips: []v1.PodIP{{IP: "2.1.1.1"}}},
		{name: "Baa", labels: labels.Set{"app": "a", "component": "a"}, namespace: "nsB", ips: []v1.PodIP{{IP: "2.2.2.2"}}},
		{name: "Bab", labels: labels.Set{"app": "a", "component": "b"}, namespace: "nsB", ips: []v1.PodIP{{IP: "2.3.2.2"}}},
		{name: "Ca", labels: labels.Set{"app": "a"}, namespace: "nsC", ips: []v1.PodIP{{IP: "3.1"}}},
	}
	namespaces := []tNamespaceMeta{
		{name: "nsA", labels: labels.Set{"name": "a", "team": "a"}},
		{name: "nsB", labels: labels.Set{"name": "b", "team": "a"}},
		{name: "nsC", labels: labels.Set{"name": "c"}},
		{name: "nsD", labels: labels.Set{"name": "d"}},
	}
	ipsUsed := make(map[string]bool)
	for _, pod := range pods {
		podNamespaceMap.addPod(pod)
		// TODO: test multiple IPs
		ipaddr := pod.ips[0].IP
		if ipsUsed[ipaddr] {
			t.Fatalf("there is another pod with the same Ip address %s as this pod %s namespace %s",
				ipaddr, pod.name, pod.name)
		}
		ipsUsed[ipaddr] = true
		tAddToInformerStore(t, podInformer,
			&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod.name, Labels: pod.labels, Namespace: pod.namespace},
				Status: v1.PodStatus{PodIP: ipaddr}})
	}
	for _, ns := range namespaces {
		tAddToInformerStore(t, nsInformer, &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns.name, Labels: ns.labels}})
	}
}

// newFakeNode is a helper function for creating Nodes for testing.
func newFakeNode(name string, addr string) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: v1.NodeStatus{
			Capacity: v1.ResourceList{
				v1.ResourceCPU:    resource.MustParse("1"),
				v1.ResourceMemory: resource.MustParse("1G"),
			},
			Addresses: []v1.NodeAddress{{Type: v1.NodeExternalIP, Address: addr}},
		},
	}
}

// newUneventfulNetworkPolicyController returns new NetworkPolicyController object without any event handler
func newUneventfulNetworkPolicyController(podInformer cache.SharedIndexInformer,
	npInformer cache.SharedIndexInformer, nsInformer cache.SharedIndexInformer) *NetworkPolicyController {

	npc := NetworkPolicyController{}
	npc.syncPeriod = time.Hour

	npc.iptablesCmdHandlers = make(map[v1.IPFamily]utils.IPTablesHandler)
	npc.iptablesSaveRestore = make(map[v1.IPFamily]*utils.IPTablesSaveRestore)
	npc.filterTableRules = make(map[v1.IPFamily]*bytes.Buffer)
	npc.ipSetHandlers = make(map[v1.IPFamily]utils.IPSetHandler)
	npc.nodeIPs = make(map[v1.IPFamily]net.IP)

	// TODO: Handle both IP families
	npc.iptablesCmdHandlers[v1.IPv4Protocol] = newFakeIPTables(iptables.ProtocolIPv4)
	npc.iptablesSaveRestore[v1.IPv4Protocol] = utils.NewIPTablesSaveRestore(v1.IPv4Protocol)
	var buf bytes.Buffer
	npc.filterTableRules[v1.IPv4Protocol] = &buf
	npc.ipSetHandlers[v1.IPv4Protocol] = &fakeIPSet{}
	npc.nodeIPs[v1.IPv4Protocol] = net.IPv4(10, 10, 10, 10)

	npc.nodeHostName = "node"
	npc.podLister = podInformer.GetIndexer()
	npc.nsLister = nsInformer.GetIndexer()
	npc.npLister = npInformer.GetIndexer()

	return &npc
}

// tNetpolTestCase helper struct to define the inputs to the test case (netpols) and
// 				  the expected selected targets (targetPods, inSourcePods for ingress targets, and outDestPods
//				  for egress targets) as maps with key being the namespace and a csv of pod names
type tNetpolTestCase struct {
	name         string
	netpol       tNetpol
	targetPods   tPodNamespaceMap
	inSourcePods tPodNamespaceMap
	outDestPods  tPodNamespaceMap
	expectedRule string
}

// tGetNotTargetedPods finds set of pods that should not be targeted by netpol selectors
func tGetNotTargetedPods(podsGot []podInfo, wanted tPodNamespaceMap) []string {
	unwanted := make(tPodNamespaceMap)
	for _, pod := range podsGot {
		if !wanted[pod.namespace][pod.name] {
			unwanted.addPod(pod)
		}
	}
	return unwanted.toStrSlice()
}

// tGetTargetPodsMissing returns the set of pods that should have been targeted but were missing by netpol selectors
func tGetTargetPodsMissing(podsGot []podInfo, wanted tPodNamespaceMap) []string {
	missing := wanted.copy()
	for _, pod := range podsGot {
		if wanted[pod.namespace][pod.name] {
			missing.delPod(pod)
		}
	}
	return missing.toStrSlice()
}

func tListOfPodsFromTargets(target map[string]podInfo) (r []podInfo) {
	for _, pod := range target {
		r = append(r, pod)
	}
	return
}

func testForMissingOrUnwanted(t *testing.T, targetMsg string, got []podInfo, wanted tPodNamespaceMap) {
	if missing := tGetTargetPodsMissing(got, wanted); len(missing) != 0 {
		t.Errorf("Some Pods were not selected %s: %s", targetMsg, strings.Join(missing, ", "))
	}
	if missing := tGetNotTargetedPods(got, wanted); len(missing) != 0 {
		t.Errorf("Some Pods NOT expected were selected on %s: %s", targetMsg, strings.Join(missing, ", "))
	}
}

func newMinimalKubeRouterConfig(clusterIPCIDR string, nodePortRange string, hostNameOverride string, externalIPs []string) *options.KubeRouterConfig {
	kubeConfig := options.NewKubeRouterConfig()
	if clusterIPCIDR != "" {
		kubeConfig.ClusterIPCIDR = clusterIPCIDR
	}
	if nodePortRange != "" {
		kubeConfig.NodePortRange = nodePortRange
	}
	if hostNameOverride != "" {
		kubeConfig.HostnameOverride = hostNameOverride
	}
	if externalIPs != nil {
		kubeConfig.ExternalIPCIDRs = externalIPs
	}
	return kubeConfig
}

type tNetPolConfigTestCase struct {
	name        string
	config      *options.KubeRouterConfig
	expectError bool
	errorText   string
}

func TestNewNetworkPolicySelectors(t *testing.T) {
	testCases := []tNetpolTestCase{
		{
			name:       "Non-Existent Namespace",
			netpol:     tNetpol{name: "nsXX", podSelector: metav1.LabelSelector{}, namespace: "nsXX"},
			targetPods: nil,
		},
		{
			name:       "Empty Namespace",
			netpol:     tNetpol{name: "nsD", podSelector: metav1.LabelSelector{}, namespace: "nsD"},
			targetPods: nil,
		},
		{
			name:       "All pods in nsA",
			netpol:     tNetpol{name: "nsA", podSelector: metav1.LabelSelector{}, namespace: "nsA"},
			targetPods: tNewPodNamespaceMapFromTC(map[string]string{"nsA": "Aa,Aaa,Aab,Aac"}),
		},
		{
			name:       "All pods in nsB",
			netpol:     tNetpol{name: "nsB", podSelector: metav1.LabelSelector{}, namespace: "nsB"},
			targetPods: tNewPodNamespaceMapFromTC(map[string]string{"nsB": "Ba,Baa,Bab"}),
		},
		{
			name:       "All pods in nsC",
			netpol:     tNetpol{name: "nsC", podSelector: metav1.LabelSelector{}, namespace: "nsC"},
			targetPods: tNewPodNamespaceMapFromTC(map[string]string{"nsC": "Ca"}),
		},
		{
			name: "All pods app=a in nsA using matchExpressions",
			netpol: tNetpol{
				name:      "nsA-app-a-matchExpression",
				namespace: "nsA",
				podSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "app",
						Operator: "In",
						Values:   []string{"a"},
					}}}},
			targetPods: tNewPodNamespaceMapFromTC(map[string]string{"nsA": "Aa,Aaa,Aab,Aac"}),
		},
		{
			name: "All pods app=a in nsA using matchLabels",
			netpol: tNetpol{name: "nsA-app-a-matchLabels", namespace: "nsA",
				podSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "a"}}},
			targetPods: tNewPodNamespaceMapFromTC(map[string]string{"nsA": "Aa,Aaa,Aab,Aac"}),
		},
		{
			name: "All pods app=a in nsA using matchLabels ingress allow from any pod in nsB",
			netpol: tNetpol{name: "nsA-app-a-matchLabels-2", namespace: "nsA",
				podSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
				ingress:     []netv1.NetworkPolicyIngressRule{{From: []netv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"name": "b"}}}}}},
			},
			targetPods:   tNewPodNamespaceMapFromTC(map[string]string{"nsA": "Aa,Aaa,Aab,Aac"}),
			inSourcePods: tNewPodNamespaceMapFromTC(map[string]string{"nsB": "Ba,Baa,Bab"}),
		},
		{
			name: "All pods app=a in nsA using matchLabels ingress allow from pod in nsB with component = b",
			netpol: tNetpol{name: "nsA-app-a-matchExpression-2", namespace: "nsA",
				podSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
				ingress: []netv1.NetworkPolicyIngressRule{{From: []netv1.NetworkPolicyPeer{
					{
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"name": "b"}},
						PodSelector: &metav1.LabelSelector{
							MatchExpressions: []metav1.LabelSelectorRequirement{{
								Key:      "component",
								Operator: "In",
								Values:   []string{"b"},
							}}},
					},
				}}}},
			targetPods:   tNewPodNamespaceMapFromTC(map[string]string{"nsA": "Aa,Aaa,Aab,Aac"}),
			inSourcePods: tNewPodNamespaceMapFromTC(map[string]string{"nsB": "Bab"}),
		},
		{
			name: "All pods app=a,component=b or c in nsA",
			netpol: tNetpol{name: "nsA-app-a-matchExpression-3", namespace: "nsA",
				podSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "app",
							Operator: "In",
							Values:   []string{"a"},
						},
						{
							Key:      "component",
							Operator: "In",
							Values:   []string{"b", "c"},
						}}},
			},
			targetPods: tNewPodNamespaceMapFromTC(map[string]string{"nsA": "Aab,Aac"}),
		},
	}

	client := fake.NewSimpleClientset(&v1.NodeList{Items: []v1.Node{*newFakeNode("node", "10.10.10.10")}})
	informerFactory, podInformer, nsInformer, netpolInformer := newFakeInformersFromClient(client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	informerFactory.Start(ctx.Done())
	cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced)
	krNetPol := newUneventfulNetworkPolicyController(podInformer, netpolInformer, nsInformer)
	tCreateFakePods(t, podInformer, nsInformer)
	for _, test := range testCases {
		test.netpol.createFakeNetpol(t, netpolInformer)
	}
	netpols, err := krNetPol.buildNetworkPoliciesInfo()
	if err != nil {
		t.Errorf("Problems building policies")
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			np := test.netpol.findNetpolMatch(&netpols)
			testForMissingOrUnwanted(t, "targetPods", tListOfPodsFromTargets(np.targetPods), test.targetPods)
			for _, ingress := range np.ingressRules {
				testForMissingOrUnwanted(t, "ingress srcPods", ingress.srcPods, test.inSourcePods)
			}
			for _, egress := range np.egressRules {
				testForMissingOrUnwanted(t, "egress dstPods", egress.dstPods, test.outDestPods)
			}
		})
	}
}

func TestNetworkPolicyBuilder(t *testing.T) {
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
			expectedRule: "-A KUBE-NWPLCY-C23KD7UE4TAT3Y5M -m comment --comment \"rule to ACCEPT traffic from source pods to all destinations selected by policy name: simple-egress namespace nsA\" --dport 30000 -j MARK --set-xmark 0x10000/0x10000 \n" +
				"-A KUBE-NWPLCY-C23KD7UE4TAT3Y5M -m comment --comment \"rule to ACCEPT traffic from source pods to all destinations selected by policy name: simple-egress namespace nsA\" --dport 30000 -m mark --mark 0x10000/0x10000 -j RETURN \n",
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
			expectedRule: "-A KUBE-NWPLCY-IDIX352DRLNY3D23 -m comment --comment \"rule to ACCEPT traffic from source pods to all destinations selected by policy name: simple-ingress-egress namespace nsA\" --dport 30000 -j MARK --set-xmark 0x10000/0x10000 \n" +
				"-A KUBE-NWPLCY-IDIX352DRLNY3D23 -m comment --comment \"rule to ACCEPT traffic from source pods to all destinations selected by policy name: simple-ingress-egress namespace nsA\" --dport 30000 -m mark --mark 0x10000/0x10000 -j RETURN \n" +
				"-A KUBE-NWPLCY-IDIX352DRLNY3D23 -m comment --comment \"rule to ACCEPT traffic from all sources to dest pods selected by policy name: simple-ingress-egress namespace nsA\" --dport 37000 -j MARK --set-xmark 0x10000/0x10000 \n" +
				"-A KUBE-NWPLCY-IDIX352DRLNY3D23 -m comment --comment \"rule to ACCEPT traffic from all sources to dest pods selected by policy name: simple-ingress-egress namespace nsA\" --dport 37000 -m mark --mark 0x10000/0x10000 -j RETURN \n",
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
			expectedRule: "-A KUBE-NWPLCY-2UTXQIFBI5TAPUCL -m comment --comment \"rule to ACCEPT traffic from source pods to all destinations selected by policy name: simple-egress-pr namespace nsA\" --dport 30000:31000 -j MARK --set-xmark 0x10000/0x10000 \n" +
				"-A KUBE-NWPLCY-2UTXQIFBI5TAPUCL -m comment --comment \"rule to ACCEPT traffic from source pods to all destinations selected by policy name: simple-egress-pr namespace nsA\" --dport 30000:31000 -m mark --mark 0x10000/0x10000 -j RETURN \n" +
				"-A KUBE-NWPLCY-2UTXQIFBI5TAPUCL -m comment --comment \"rule to ACCEPT traffic from source pods to all destinations selected by policy name: simple-egress-pr namespace nsA\" --dport 34000:35000 -j MARK --set-xmark 0x10000/0x10000 \n" +
				"-A KUBE-NWPLCY-2UTXQIFBI5TAPUCL -m comment --comment \"rule to ACCEPT traffic from source pods to all destinations selected by policy name: simple-egress-pr namespace nsA\" --dport 34000:35000 -m mark --mark 0x10000/0x10000 -j RETURN \n",
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
			expectedRule: "-A KUBE-NWPLCY-N5DQE4SCQ56JEMH7 -m comment --comment \"rule to ACCEPT traffic from source pods to all destinations selected by policy name: invalid-endport namespace nsA\" --dport 34000 -j MARK --set-xmark 0x10000/0x10000 \n" +
				"-A KUBE-NWPLCY-N5DQE4SCQ56JEMH7 -m comment --comment \"rule to ACCEPT traffic from source pods to all destinations selected by policy name: invalid-endport namespace nsA\" --dport 34000 -m mark --mark 0x10000/0x10000 -j RETURN \n",
		},
	}

	client := fake.NewSimpleClientset(&v1.NodeList{Items: []v1.Node{*newFakeNode("node", "10.10.10.10")}})
	informerFactory, podInformer, nsInformer, netpolInformer := newFakeInformersFromClient(client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	informerFactory.Start(ctx.Done())
	cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced)
	krNetPol := newUneventfulNetworkPolicyController(podInformer, netpolInformer, nsInformer)
	tCreateFakePods(t, podInformer, nsInformer)
	for _, test := range testCases {
		test.netpol.createFakeNetpol(t, netpolInformer)
		netpols, err := krNetPol.buildNetworkPoliciesInfo()
		if err != nil {
			t.Errorf("Problems building policies: %s", err)
		}
		for ipFamily, filterTableRules := range krNetPol.filterTableRules {
			for _, np := range netpols {
				fmt.Printf(np.policyType)
				if np.policyType == kubeEgressPolicyType || np.policyType == kubeBothPolicyType {
					err = krNetPol.processEgressRules(np, "", nil, "1", ipFamily)
					if err != nil {
						t.Errorf("Error syncing the rules: %s", err)
					}
				}
				if np.policyType == kubeIngressPolicyType || np.policyType == kubeBothPolicyType {
					err = krNetPol.processIngressRules(np, "", nil, "1", ipFamily)
					if err != nil {
						t.Errorf("Error syncing the rules: %s", err)
					}
				}
			}

			if !bytes.Equal([]byte(test.expectedRule), filterTableRules.Bytes()) {
				t.Errorf("Invalid rule %s created:\nExpected:\n%s \nGot:\n%s", test.name, test.expectedRule, filterTableRules.String())
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
			filterTableRules.Reset()
		}
	}

}

type fakeIPTables struct {
	protocol iptables.Protocol
}

func newFakeIPTables(protocol iptables.Protocol) *fakeIPTables {
	return &fakeIPTables{protocol}
}

func (ipt *fakeIPTables) Proto() iptables.Protocol {
	return ipt.protocol
}

func (ipt *fakeIPTables) Exists(table, chain string, rulespec ...string) (bool, error) {
	return true, nil
}

func (ipt *fakeIPTables) Insert(table, chain string, pos int, rulespec ...string) error {
	return nil
}

func (ipt *fakeIPTables) Append(table, chain string, rulespec ...string) error {
	return nil
}

func (ipt *fakeIPTables) AppendUnique(table, chain string, rulespec ...string) error {
	return nil
}

func (ipt *fakeIPTables) Delete(table, chain string, rulespec ...string) error {
	return nil
}

func (ipt *fakeIPTables) DeleteIfExists(table, chain string, rulespec ...string) error {
	return nil
}

func (ipt *fakeIPTables) List(table, chain string) ([]string, error) {
	return nil, nil
}

func (ipt *fakeIPTables) ListWithCounters(table, chain string) ([]string, error) {
	return nil, nil
}

func (ipt *fakeIPTables) ListChains(table string) ([]string, error) {
	return nil, nil
}

func (ipt *fakeIPTables) ChainExists(table, chain string) (bool, error) {
	return true, nil
}

func (ipt *fakeIPTables) Stats(table, chain string) ([][]string, error) {
	return nil, nil
}

func (ipt *fakeIPTables) ParseStat(stat []string) (iptables.Stat, error) {
	return iptables.Stat{}, nil
}

func (ipt *fakeIPTables) StructuredStats(table, chain string) ([]iptables.Stat, error) {
	return nil, nil
}

func (ipt *fakeIPTables) NewChain(table, chain string) error {
	return nil
}

func (ipt *fakeIPTables) ClearChain(table, chain string) error {
	return nil
}

func (ipt *fakeIPTables) RenameChain(table, oldChain, newChain string) error {
	return nil
}

func (ipt *fakeIPTables) DeleteChain(table, chain string) error {
	return nil
}

func (ipt *fakeIPTables) ClearAndDeleteChain(table, chain string) error {
	return nil
}

func (ipt *fakeIPTables) ClearAll() error {
	return nil
}

func (ipt *fakeIPTables) DeleteAll() error {
	return nil
}

func (ipt *fakeIPTables) ChangePolicy(table, chain, target string) error {
	return nil
}

func (ipt *fakeIPTables) HasRandomFully() bool {
	return true
}

func (ipt *fakeIPTables) GetIptablesVersion() (int, int, int) {
	return 1, 8, 0
}

type fakeIPSet struct{}

func (ips *fakeIPSet) Create(setName string, createOptions ...string) (*utils.Set, error) {
	return nil, nil
}

func (ips *fakeIPSet) Add(set *utils.Set) error {
	return nil
}

func (ips *fakeIPSet) RefreshSet(setName string, entriesWithOptions [][]string, setType string) {}

func (ips *fakeIPSet) Destroy(setName string) error {
	return nil
}

func (ips *fakeIPSet) DestroyAllWithin() error {
	return nil
}

func (ips *fakeIPSet) Save() error {
	return nil
}

func (ips *fakeIPSet) Restore() error {
	return nil
}

func (ips *fakeIPSet) Flush() error {
	return nil
}

func (ips *fakeIPSet) Get(setName string) *utils.Set {
	return nil
}

func (ips *fakeIPSet) Sets() map[string]*utils.Set {
	return nil
}

func TestNetworkPolicyController(t *testing.T) {
	testCases := []tNetPolConfigTestCase{
		{
			"Default options are successful",
			newMinimalKubeRouterConfig("", "", "node", nil),
			false,
			"",
		},
		{
			"Missing nodename fails appropriately",
			newMinimalKubeRouterConfig("", "", "", nil),
			true,
			"failed to identify the node by NODE_NAME, hostname or --hostname-override",
		},
		{
			"Test bad cluster CIDR (not properly formatting ip address)",
			newMinimalKubeRouterConfig("10.10.10", "", "node", nil),
			true,
			"failed to get parse --service-cluster-ip-range parameter: invalid CIDR address: 10.10.10",
		},
		{
			"Test bad cluster CIDR (not using an ip address)",
			newMinimalKubeRouterConfig("foo", "", "node", nil),
			true,
			"failed to get parse --service-cluster-ip-range parameter: invalid CIDR address: foo",
		},
		{
			"Test bad cluster CIDR (using an ip address that is not a CIDR)",
			newMinimalKubeRouterConfig("10.10.10.10", "", "node", nil),
			true,
			"failed to get parse --service-cluster-ip-range parameter: invalid CIDR address: 10.10.10.10",
		},
		{
			"Test bad cluster CIDRs (using more than 2 ip addresses, including 2 ipv4)",
			newMinimalKubeRouterConfig("10.96.0.0/12,10.244.0.0/16,2001:db8:42:1::/112", "", "node", nil),
			true,
			"too many CIDRs provided in --service-cluster-ip-range parameter, only two addresses are allowed at once for dual-stack",
		},
		{
			"Test bad cluster CIDRs (using more than 2 ip addresses, including 2 ipv6)",
			newMinimalKubeRouterConfig("10.96.0.0/12,2001:db8:42:0::/56,2001:db8:42:1::/112", "", "node", nil),
			true,
			"too many CIDRs provided in --service-cluster-ip-range parameter, only two addresses are allowed at once for dual-stack",
		},
		{
			"Test good cluster CIDR (using single IP with a /32)",
			newMinimalKubeRouterConfig("10.10.10.10/32", "", "node", nil),
			false,
			"",
		},
		{
			"Test good cluster CIDR (using normal range with /24)",
			newMinimalKubeRouterConfig("10.10.10.0/24", "", "node", nil),
			false,
			"",
		},
		{
			"Test good cluster CIDR (using ipv6)",
			newMinimalKubeRouterConfig("2001:db8:42:1::/112", "", "node", nil),
			false,
			"",
		},
		{
			"Test good cluster CIDRs (with dual-stack)",
			newMinimalKubeRouterConfig("10.96.0.0/12,2001:db8:42:1::/112", "", "node", nil),
			false,
			"",
		},
		{
			"Test bad node port specification (using commas)",
			newMinimalKubeRouterConfig("", "8080,8081", "node", nil),
			true,
			"failed to parse node port range given: '8080,8081' please see specification in help text",
		},
		{
			"Test bad node port specification (not using numbers)",
			newMinimalKubeRouterConfig("", "foo:bar", "node", nil),
			true,
			"failed to parse node port range given: 'foo:bar' please see specification in help text",
		},
		{
			"Test bad node port specification (using anything in addition to range)",
			newMinimalKubeRouterConfig("", "8080,8081-8090", "node", nil),
			true,
			"failed to parse node port range given: '8080,8081-8090' please see specification in help text",
		},
		{
			"Test bad node port specification (using reversed range)",
			newMinimalKubeRouterConfig("", "8090-8080", "node", nil),
			true,
			"port 1 is greater than or equal to port 2 in range given: '8090-8080'",
		},
		{
			"Test bad node port specification (port out of available range)",
			newMinimalKubeRouterConfig("", "132000-132001", "node", nil),
			true,
			"could not parse first port number from range given: '132000-132001'",
		},
		{
			"Test good node port specification (using colon separator)",
			newMinimalKubeRouterConfig("", "8080:8090", "node", nil),
			false,
			"",
		},
		{
			"Test good node port specification (using hyphen separator)",
			newMinimalKubeRouterConfig("", "8080-8090", "node", nil),
			false,
			"",
		},
		{
			"Test bad external IP CIDR (not properly formatting ip address)",
			newMinimalKubeRouterConfig("", "", "node", []string{"199.10.10"}),
			true,
			"failed to get parse --service-external-ip-range parameter: '199.10.10'. Error: invalid CIDR address: 199.10.10",
		},
		{
			"Test bad external IP CIDR (not using an ip address)",
			newMinimalKubeRouterConfig("", "", "node", []string{"foo"}),
			true,
			"failed to get parse --service-external-ip-range parameter: 'foo'. Error: invalid CIDR address: foo",
		},
		{
			"Test bad external IP CIDR (using an ip address that is not a CIDR)",
			newMinimalKubeRouterConfig("", "", "node", []string{"199.10.10.10"}),
			true,
			"failed to get parse --service-external-ip-range parameter: '199.10.10.10'. Error: invalid CIDR address: 199.10.10.10",
		},
		{
			"Test bad external IP CIDR (making sure that it processes all items in the list)",
			newMinimalKubeRouterConfig("", "", "node", []string{"199.10.10.10/32", "199.10.10.11"}),
			true,
			"failed to get parse --service-external-ip-range parameter: '199.10.10.11'. Error: invalid CIDR address: 199.10.10.11",
		},
		{
			"Test good external IP CIDR (using single IP with a /32)",
			newMinimalKubeRouterConfig("", "", "node", []string{"199.10.10.10/32"}),
			false,
			"",
		},
		{
			"Test good external IP CIDR (using normal range with /24)",
			newMinimalKubeRouterConfig("", "", "node", []string{"199.10.10.10/24"}),
			false,
			"",
		},
	}
	client := fake.NewSimpleClientset(&v1.NodeList{Items: []v1.Node{*newFakeNode("node", "10.10.10.10")}})
	_, podInformer, nsInformer, netpolInformer := newFakeInformersFromClient(client)
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// TODO: Handle IPv6
			iptablesHandlers := make(map[v1.IPFamily]utils.IPTablesHandler, 1)
			iptablesHandlers[v1.IPv4Protocol] = newFakeIPTables(iptables.ProtocolIPv4)
			ipSetHandlers := make(map[v1.IPFamily]utils.IPSetHandler, 1)
			ipSetHandlers[v1.IPv4Protocol] = &fakeIPSet{}

			_, err := NewNetworkPolicyController(client, test.config, podInformer, netpolInformer, nsInformer, &sync.Mutex{},
				iptablesHandlers, ipSetHandlers)
			if err == nil && test.expectError {
				t.Error("This config should have failed, but it was successful instead")
			} else if err != nil {
				// Unfortunately without doing a ton of extra refactoring work, we can't remove this reference easily
				// from the controllers start up. Luckily it's one of the last items to be processed in the controller
				// so for now we'll consider that if we hit this error that we essentially didn't hit an error at all
				// TODO: refactor NPC to use an injectable interface for ipset operations
				if !test.expectError && err.Error() != "Ipset utility not found" {
					t.Errorf("This config should have been successful, but it failed instead. Error: %s", err)
				} else if test.expectError && err.Error() != test.errorText {
					t.Errorf("Expected error: '%s' but instead got: '%s'", test.errorText, err)
				}
			}
		})
	}
}

// Ref:
// https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/podgc/gc_controller_test.go
// https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/testutil/test_utils.go
