package netpol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// A pod that joins the informer while a sync runs must be invisible to every read of that sync (policy targets,
// peers and local pods alike), and visible to the next one.
func TestPodSnapshotHoldsOneViewForAWholeSync(t *testing.T) {
	early := podFwTestPod("ns", "early", "10.1.0.1")
	early.Labels = map[string]string{"app": "x"}
	late := podFwTestPod("ns", "late", "10.1.0.2")
	late.Labels = map[string]string{"app": "x"}
	npc := newPodFwTestController(t, []api.IPFamily{api.IPv4Protocol}, early)
	selector := labels.SelectorFromSet(labels.Set{"app": "x"})

	npc.snapshotPods()
	require.NoError(t, npc.podLister.Add(late))

	targets, err := npc.ListPodsByNamespaceAndLabels("ns", selector)
	require.NoError(t, err)
	assert.Equal(t, []*api.Pod{early}, targets, "policy read during the sync")
	local := map[string]podInfo{}
	npc.getLocalPods(local, podFwTestNodeIP)
	assert.Len(t, local, 1, "firewall chains of the same sync")
	assert.Contains(t, local, "10.1.0.1")

	npc.dropPodSnapshot()

	targets, err = npc.ListPodsByNamespaceAndLabels("ns", selector)
	require.NoError(t, err)
	assert.ElementsMatch(t, []*api.Pod{early, late}, targets, "next sync")
	local = map[string]podInfo{}
	npc.getLocalPods(local, podFwTestNodeIP)
	assert.Len(t, local, 2)
}

func TestPodSnapshotKeepsNamespacesAndSelectorsApart(t *testing.T) {
	a := podFwTestPod("a", "p", "10.1.0.1")
	a.Labels = map[string]string{"app": "x"}
	b := podFwTestPod("b", "p", "10.1.0.2")
	b.Labels = map[string]string{"app": "x"}
	other := podFwTestPod("a", "q", "10.1.0.3")
	other.Labels = map[string]string{"app": "y"}
	npc := newPodFwTestController(t, []api.IPFamily{api.IPv4Protocol}, a, b, other)

	npc.snapshotPods()
	defer npc.dropPodSnapshot()

	got, err := npc.ListPodsByNamespaceAndLabels("a", labels.SelectorFromSet(labels.Set{"app": "x"}))
	require.NoError(t, err)
	assert.Equal(t, []*api.Pod{a}, got)
	got, err = npc.ListPodsByNamespaceAndLabels("a", labels.Everything())
	require.NoError(t, err)
	assert.ElementsMatch(t, []*api.Pod{a, other}, got)
	got, err = npc.ListPodsByNamespaceAndLabels("missing", labels.Everything())
	require.NoError(t, err)
	assert.Empty(t, got)
	got, err = npc.ListPodsByNamespaceAndLabels(api.NamespaceAll, labels.SelectorFromSet(labels.Set{"app": "x"}))
	require.NoError(t, err)
	assert.ElementsMatch(t, []*api.Pod{a, b}, got, "all namespaces")
}

// onListIndexer runs onCall before every List of the wrapped pod indexer and counts the calls.
type onListIndexer struct {
	cache.Indexer
	calls  int
	onCall func(call int)
}

func (i *onListIndexer) List() []any {
	i.calls++
	if i.onCall != nil {
		i.onCall(i.calls)
	}
	return i.Indexer.List()
}

// A pod that gets its IP while buildNetworkPoliciesInfo runs must be a target of every policy that selects it
// or of none. Read live, it is a target of the policies listed after it appeared only: pod "late" ends up under
// default-deny-all without allow-dns' egress rule, which refuses its DNS lookups until the next sync.
func TestPodAppearingDuringPolicyBuildIsInAllPoliciesOrNone(t *testing.T) {
	policy := func(name string, types ...netv1.PolicyType) *netv1.NetworkPolicy {
		return &netv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name},
			Spec:       netv1.NetworkPolicySpec{PolicyTypes: types},
		}
	}
	setup := func(t *testing.T) (*NetworkPolicyControllerBase, *onListIndexer, *api.Pod) {
		early := podFwTestPod("ns", "early", "10.1.0.1")
		late := podFwTestPod("ns", "late", "10.1.0.2")
		npc := newPodFwTestController(t, []api.IPFamily{api.IPv4Protocol}, early)
		pods := &onListIndexer{Indexer: npc.podLister}
		npc.podLister = pods
		npc.nsLister = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
		npc.npLister = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
		denyAll := policy("default-deny-all", netv1.PolicyTypeIngress, netv1.PolicyTypeEgress)
		require.NoError(t, npc.npLister.Add(denyAll))
		require.NoError(t, npc.npLister.Add(policy("allow-dns", netv1.PolicyTypeEgress)))
		return npc, pods, late
	}
	targetsOfLate := func(t *testing.T, npc *NetworkPolicyControllerBase) (inPolicies int) {
		info, err := npc.buildNetworkPoliciesInfo()
		require.NoError(t, err)
		require.Len(t, info, 2)
		for _, p := range info {
			assert.Contains(t, p.targetPods, "10.1.0.1")
			if _, ok := p.targetPods["10.1.0.2"]; ok {
				inPolicies++
			}
		}
		return inPolicies
	}

	t.Run("live listing splits the pod across policies", func(t *testing.T) {
		npc, pods, late := setup(t)
		pods.onCall = func(call int) {
			if call == 2 {
				require.NoError(t, pods.Add(late))
			}
		}
		assert.Equal(t, 1, targetsOfLate(t, npc))
	})

	t.Run("snapshot keeps it out of every policy and out of the pod chains", func(t *testing.T) {
		npc, pods, late := setup(t)
		npc.snapshotPods()
		defer npc.dropPodSnapshot()
		pods.onCall = func(call int) { t.Errorf("pod list read live during the sync (call %d)", call) }
		require.NoError(t, pods.Add(late))
		assert.Equal(t, 0, targetsOfLate(t, npc))
		local := map[string]podInfo{}
		npc.getLocalPods(local, podFwTestNodeIP)
		assert.Len(t, local, 1)
	})
}
