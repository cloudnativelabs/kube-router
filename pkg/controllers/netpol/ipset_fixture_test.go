package netpol

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/pkg/controllers/testhelpers"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"

	"github.com/stretchr/testify/require"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func TestNetworkPolicyFixtureIPSets(t *testing.T) {
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

	ipv4Handler := testhelpers.NewFakeIPSetHandler(false)
	ipv6Handler := testhelpers.NewFakeIPSetHandler(true)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("ipv4 restore script:\n%s", ipv4Handler.Restored())
			t.Logf("ipv6 restore script:\n%s", ipv6Handler.Restored())
		}
	})

	linkQ := utils.NewFakeLocalLinkQuerier(collectNodeIPs(nodes), nil)

	controller, err := NewNetworkPolicyController(
		client,
		config,
		podInformer,
		npInformer,
		nsInformer,
		&sync.Mutex{},
		linkQ,
		map[v1.IPFamily]utils.IPTablesHandler{
			v1.IPv4Protocol: &fakeIPTables{},
			v1.IPv6Protocol: &fakeIPTables{},
		},
		map[v1.IPFamily]utils.IPSetHandler{
			v1.IPv4Protocol: ipv4Handler,
			v1.IPv6Protocol: ipv6Handler,
		},
	)
	require.NoError(t, err)

	addPodsToInformer(t, podInformer.GetStore(), pods)
	addNetworkPoliciesToInformer(t, npInformer.GetStore(), networkPolicies)
	addNamespacesToInformer(nsInformer.GetStore(), namespaces)

	netpolInfo, err := controller.buildNetworkPoliciesInfo()
	require.NoError(t, err)

	_, _, err = controller.syncNetworkPolicyChains(netpolInfo, "fixture")
	require.NoError(t, err)

	actual := testhelpers.MergeExpectations(
		testhelpers.ParseRestoreScript(ipv4Handler.Restored()),
		testhelpers.ParseRestoreScript(ipv6Handler.Restored()),
	)
	expected := testhelpers.ParseSnapshot(t, filepath.Join(fixtureDir, "ipset_save.txt"))

	require.NotEmpty(t, expected, "expected snapshot should not be empty")
	require.Equal(t, testhelpers.ExpectedKeys(expected), testhelpers.ExpectedKeys(actual))

	for name, exp := range expected {
		act := actual[name]
		require.Equal(t, exp.SetType, act.SetType, "set type mismatch for %s", name)
		require.Equal(t, exp.Entries, act.Entries, "entries mismatch for %s", name)
	}
}

func addPodsToInformer(t *testing.T, store cache.Store, pods *v1.PodList) {
	for i := range pods.Items {
		pod := pods.Items[i].DeepCopy()
		pod.SetResourceVersion("1")
		if len(pod.Status.PodIPs) > 0 {
			pod.Status.PodIP = pod.Status.PodIPs[0].IP
		}
		require.NoError(t, store.Add(pod))
	}
}

func addNetworkPoliciesToInformer(t *testing.T, store cache.Store, policies *networkingv1.NetworkPolicyList) {
	for i := range policies.Items {
		pol := policies.Items[i].DeepCopy()
		pol.SetResourceVersion("1")
		for j := range pol.Spec.Ingress {
			for k := range pol.Spec.Ingress[j].Ports {
				if pol.Spec.Ingress[j].Ports[k].Protocol == nil {
					proto := v1.ProtocolTCP
					pol.Spec.Ingress[j].Ports[k].Protocol = &proto
				}
				if pol.Spec.Ingress[j].Ports[k].Port == nil {
					port := intstr.FromInt(0)
					pol.Spec.Ingress[j].Ports[k].Port = &port
				}
			}
		}
		require.NoError(t, store.Add(pol))
	}
}

func addNamespacesToInformer(store cache.Store, namespaces *v1.NamespaceList) {
	for i := range namespaces.Items {
		_ = store.Add(namespaces.Items[i].DeepCopy())
	}
}

func deriveNamespaces(pods *v1.PodList, policies *networkingv1.NetworkPolicyList) *v1.NamespaceList {
	nsSet := map[string]struct{}{}
	for _, pod := range pods.Items {
		nsSet[pod.Namespace] = struct{}{}
	}
	for _, pol := range policies.Items {
		nsSet[pol.Namespace] = struct{}{}
	}
	list := &v1.NamespaceList{}
	for ns := range nsSet {
		list.Items = append(list.Items, v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	}
	return list
}

func collectNodeIPs(nodes *v1.NodeList) []string {
	ipSet := map[string]struct{}{}
	for _, node := range nodes.Items {
		for _, addr := range node.Status.Addresses {
			ipSet[addr.Address] = struct{}{}
		}
	}
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	return ips
}
