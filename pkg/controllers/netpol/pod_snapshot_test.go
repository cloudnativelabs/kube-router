package netpol

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// A pod that joins the informer after the snapshot is invisible to the whole sync: it is a target and a peer of no
// policy and gets no firewall chain, so it never has a chain that lacks some of its policies. The next sync's
// snapshot has it everywhere.
func TestPodSnapshotHoldsOneViewForAWholeSync(t *testing.T) {
	policy := func(name string, types ...netv1.PolicyType) *netv1.NetworkPolicy {
		return &netv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name},
			Spec:       netv1.NetworkPolicySpec{PolicyTypes: types},
		}
	}
	allowInternal := policy("allow-internal", netv1.PolicyTypeIngress)
	allowInternal.Spec.Ingress = []netv1.NetworkPolicyIngressRule{
		{From: []netv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}}}},
	}
	npc := newPodFwTestController(t, []api.IPFamily{api.IPv4Protocol}, podFwTestPod("ns", "early", "10.1.0.1"))
	npc.nsLister = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	npc.npLister = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	require.NoError(t, npc.npLister.Add(policy("default-deny-all", netv1.PolicyTypeIngress, netv1.PolicyTypeEgress)))
	require.NoError(t, npc.npLister.Add(policy("allow-dns", netv1.PolicyTypeEgress)))
	require.NoError(t, npc.npLister.Add(allowInternal))

	assertSyncSees := func(pods *podSnapshot, ips ...string) {
		t.Helper()
		info, err := npc.buildNetworkPoliciesInfo(pods)
		require.NoError(t, err)
		require.Len(t, info, 3)
		for _, p := range info {
			assert.ElementsMatch(t, ips, slices.Collect(maps.Keys(p.targetPods)), "targets of %s", p.name)
			for _, rule := range p.ingressRules {
				assert.Len(t, rule.srcPods, len(ips), "peers of %s", p.name)
			}
		}
		_, activePodIPs := npc.syncPodFirewallChains(info, "v", pods)
		assert.ElementsMatch(t, ips, activePodIPs[api.IPv4Protocol], "pod firewall chains")
	}

	pods := newPodSnapshot(npc.podLister)
	require.NoError(t, npc.podLister.Add(podFwTestPod("ns", "late", "10.1.0.2")))

	assertSyncSees(pods, "10.1.0.1")
	assertSyncSees(newPodSnapshot(npc.podLister), "10.1.0.1", "10.1.0.2")
}

func TestPodSnapshotSelectsByNamespaceAndLabels(t *testing.T) {
	a := podFwTestPod("a", "p", "10.1.0.1")
	a.Labels = map[string]string{"app": "x"}
	b := podFwTestPod("b", "p", "10.1.0.2")
	b.Labels = map[string]string{"app": "x"}
	other := podFwTestPod("a", "q", "10.1.0.3")
	other.Labels = map[string]string{"app": "y"}
	pods := newPodSnapshot(newPodFwTestController(t, []api.IPFamily{api.IPv4Protocol}, a, b, other).podLister)

	assert.Equal(t, []*api.Pod{a}, pods.byNamespaceAndLabels("a", labels.SelectorFromSet(labels.Set{"app": "x"})))
	assert.ElementsMatch(t, []*api.Pod{a, other}, pods.byNamespaceAndLabels("a", labels.Everything()))
	assert.Empty(t, pods.byNamespaceAndLabels("missing", labels.Everything()))
	assert.ElementsMatch(t, []*api.Pod{a, b, other}, pods.all)
}
