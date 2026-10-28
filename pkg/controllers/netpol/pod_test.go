package netpol

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func TestSanitizeForComment(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "clean string passes through",
			input: "my-pod-name",
			want:  "my-pod-name",
		},
		{
			name:  "newlines stripped",
			input: "my-pod\n-A INJECT -j DROP\n",
			want:  "my-pod-A INJECT -j DROP",
		},
		{
			name:  "tabs stripped",
			input: "my-pod\tinjected",
			want:  "my-podinjected",
		},
		{
			name:  "carriage return stripped",
			input: "my-pod\rinjected",
			want:  "my-podinjected",
		},
		{
			name:  "null bytes stripped",
			input: "my-pod\x00injected",
			want:  "my-podinjected",
		},
		{
			name:  "normal characters preserved",
			input: "nginx-deployment-7c79f4c9b8-abc12",
			want:  "nginx-deployment-7c79f4c9b8-abc12",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeForComment(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

const podFwTestNodeIP = "10.10.10.10"

// podFwTestPod returns a running pod on the test node. The first IP is the primary pod IP.
func podFwTestPod(namespace, name string, ips ...string) *api.Pod {
	podIPs := make([]api.PodIP, 0, len(ips))
	for _, ip := range ips {
		podIPs = append(podIPs, api.PodIP{IP: ip})
	}
	return &api.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: api.PodStatus{
			Phase:  api.PodRunning,
			HostIP: podFwTestNodeIP,
			PodIP:  ips[0],
			PodIPs: podIPs,
		},
	}
}

// newPodFwTestController returns a controller with an empty filter table buffer for each family, whose pod lister
// holds pods.
func newPodFwTestController(t testing.TB, families []api.IPFamily, pods ...*api.Pod) *NetworkPolicyControllerBase {
	t.Helper()
	npc := &NetworkPolicyControllerBase{
		filterTableRules: make(map[api.IPFamily]*bytes.Buffer, len(families)),
		krNode: &utils.KRNode{
			NodeName:      "node",
			NodeIPv4Addrs: map[api.NodeAddressType][]net.IP{api.NodeInternalIP: {net.ParseIP(podFwTestNodeIP)}},
		},
		podLister: cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{}),
	}
	for _, family := range families {
		npc.filterTableRules[family] = &bytes.Buffer{}
	}
	for _, pod := range pods {
		require.NoError(t, npc.podLister.Add(pod))
	}
	return npc
}

// podFwTestHasFamily reports whether pod has an address in the given family.
func podFwTestHasFamily(pod *api.Pod, family api.IPFamily) bool {
	for _, ip := range pod.Status.PodIPs {
		if strings.Contains(ip.IP, ":") == (family == api.IPv6Protocol) {
			return true
		}
	}
	return false
}

// podFwTestChainRules returns the "-A <chain> ..." lines that buf holds for chain, without trailing whitespace.
func podFwTestChainRules(buf *bytes.Buffer, chain string) []string {
	var rules []string
	for line := range strings.SplitSeq(buf.String(), "\n") {
		if strings.HasPrefix(line, "-A "+chain+" ") {
			rules = append(rules, strings.TrimSpace(line))
		}
	}
	return rules
}

// podFwTestRules returns the "-A" rules that syncPodFirewallChains writes to a pod's firewall chain.
func podFwTestRules(chain string, pod *api.Pod) []string {
	identity := pod.Namespace + "/" + pod.Name
	return []string{
		fmt.Sprintf("-A %s -m comment --comment \"%s log-drop\" -m mark ! --mark 0x10000/0x10000 -j NFLOG "+
			"--nflog-group 100 -m limit --limit 10/minute --limit-burst 10", chain, identity),
		fmt.Sprintf("-A %s -m comment --comment \"%s reject\" -m mark ! --mark 0x10000/0x10000 -j REJECT",
			chain, identity),
		fmt.Sprintf("-A %s -j MARK --set-mark 0/0x10000", chain),
		fmt.Sprintf("-A %s -m comment --comment \"set netpol-ok mark\" -j MARK --set-mark 0x20000/0x20000", chain),
	}
}

// assertPodFwRules checks that, in every family, each chain holds exactly the rules of the pods that belong to it
// and that are addressed in that family.
func assertPodFwRules(t *testing.T, npc *NetworkPolicyControllerBase, version string, pods ...*api.Pod) {
	t.Helper()
	for family, buf := range npc.filterTableRules {
		want := make(map[string][]string)
		for _, pod := range pods {
			chain := podFirewallChainName(pod.Namespace, pod.Name, version)
			if podFwTestHasFamily(pod, family) {
				want[chain] = append(want[chain], podFwTestRules(chain, pod)...)
			} else if _, ok := want[chain]; !ok {
				want[chain] = nil
			}
		}
		for chain, rules := range want {
			assert.ElementsMatch(t, rules, podFwTestChainRules(buf, chain), "family %s chain %s", family, chain)
		}
	}
}

func TestSyncPodFirewallChainsDropRules(t *testing.T) {
	const version = "1"
	dualStack := []api.IPFamily{api.IPv4Protocol, api.IPv6Protocol}
	// Guard the premise of the "used to share a chain name" case below.
	require.NotEqual(t, podFirewallChainName("a", "bc", version), podFirewallChainName("ab", "c", version))
	tests := []struct {
		name     string
		families []api.IPFamily
		pods     []*api.Pod
	}{
		{
			name:     "single family",
			families: []api.IPFamily{api.IPv4Protocol},
			pods: []*api.Pod{
				podFwTestPod("ns1", "pod-a", "10.1.0.1"),
				podFwTestPod("ns1", "pod-b", "10.1.0.2"),
				podFwTestPod("ns2", "pod-a", "10.1.0.3"),
			},
		},
		{
			name:     "dual stack cluster with single and dual stack pods",
			families: dualStack,
			pods: []*api.Pod{
				podFwTestPod("ns1", "v4-only", "10.1.0.1"),
				podFwTestPod("ns1", "dual", "10.1.0.2", "fd00::2"),
				podFwTestPod("ns1", "v6-only", "fd00::3"),
			},
		},
		{
			// These pods shared a chain back when the chain name hashed namespace+name without a separator, so we
			// make sure each one now gets its own chain holding only its own drop rules.
			name:     "pods that used to share a chain name",
			families: dualStack,
			pods: []*api.Pod{
				podFwTestPod("a", "bc", "10.1.0.1", "fd00::1"),
				podFwTestPod("ab", "c", "10.1.0.2", "fd00::2"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			npc := newPodFwTestController(t, tt.families, tt.pods...)

			activeChains, _ := npc.syncPodFirewallChains(nil, version)

			assertPodFwRules(t, npc, version, tt.pods...)
			for _, pod := range tt.pods {
				assert.True(t, activeChains[podFirewallChainName(pod.Namespace, pod.Name, version)])
			}
		})
	}
}

// BenchmarkSyncPodFirewallChains measures a sync of 80 local pods when the filter table buffer already holds about
// 1 MiB of rules, as it does after iptables-save and the network policy chains were written on a busy node.
func BenchmarkSyncPodFirewallChains(b *testing.B) {
	const podCount = 80
	pods := make([]*api.Pod, 0, podCount)
	for i := range podCount {
		pods = append(pods, podFwTestPod("ns", fmt.Sprintf("pod-%d", i), fmt.Sprintf("10.1.%d.%d", i/200, i%200+1)))
	}
	npc := newPodFwTestController(b, []api.IPFamily{api.IPv4Protocol}, pods...)
	buf := npc.filterTableRules[api.IPv4Protocol]

	var existing bytes.Buffer
	for i := 0; existing.Len() < 1<<20; i++ {
		fmt.Fprintf(&existing, "-A KUBE-NWPLCY-%016X -m comment --comment \"ns-%d/policy-%d ingress pods\" "+
			"-m set --match-set KUBE-SRC-%016X src -j MARK --set-xmark 0x10000/0x10000\n", i, i%40, i, i)
	}

	for b.Loop() {
		buf.Reset()
		buf.Write(existing.Bytes())
		npc.syncPodFirewallChains(nil, "bench")
	}
}

func TestPodEventsRequestFullSyncOnlyWhenRelevant(t *testing.T) {
	actionable := func() *api.Pod {
		pod := fakePod.DeepCopy()
		pod.Status.Phase = api.PodRunning
		return pod
	}
	pendingWithoutIP := func() *api.Pod {
		pod := actionable()
		pod.Status.Phase = api.PodPending
		pod.Status.PodIP, pod.Status.PodIPs, pod.Status.HostIP = "", nil, ""
		return pod
	}
	finished := func() *api.Pod {
		pod := actionable()
		pod.Status.Phase = api.PodSucceeded
		return pod
	}

	tests := []struct {
		name string
		// run delivers one event to the handler
		run  func(h cache.ResourceEventHandler)
		want bool
	}{
		{
			name: "HostIP set at scheduling, pod still has no IP",
			run: func(h cache.ResourceEventHandler) {
				updated := pendingWithoutIP()
				updated.Status.HostIP = "10.0.0.1"
				h.OnUpdate(pendingWithoutIP(), updated)
			},
			want: false,
		},
		{
			name: "Pending to Running with the IP already set",
			run: func(h cache.ResourceEventHandler) {
				pending := actionable()
				pending.Status.Phase = api.PodPending
				h.OnUpdate(pending, actionable())
			},
			want: false,
		},
		{
			name: "label change of a finished pod",
			run: func(h cache.ResourceEventHandler) {
				updated := finished()
				updated.Labels = map[string]string{"bar": "foo"}
				h.OnUpdate(finished(), updated)
			},
			want: false,
		},
		{
			name: "delete of a finished pod",
			run:  func(h cache.ResourceEventHandler) { h.OnDelete(finished()) },
			want: false,
		},
		{
			name: "delete of a pod that never got an IP, as a tombstone",
			run: func(h cache.ResourceEventHandler) {
				h.OnDelete(cache.DeletedFinalStateUnknown{Key: "testnamespace/testpod", Obj: pendingWithoutIP()})
			},
			want: false,
		},
		{
			name: "pod IP assigned",
			run: func(h cache.ResourceEventHandler) {
				h.OnUpdate(pendingWithoutIP(), actionable())
			},
			want: true,
		},
		{
			name: "pod finished",
			run:  func(h cache.ResourceEventHandler) { h.OnUpdate(actionable(), finished()) },
			want: true,
		},
		{
			name: "label change of an actionable pod",
			run: func(h cache.ResourceEventHandler) {
				updated := actionable()
				updated.Labels = map[string]string{"bar": "foo"}
				h.OnUpdate(actionable(), updated)
			},
			want: true,
		},
		{
			name: "IP change of an actionable pod",
			run: func(h cache.ResourceEventHandler) {
				updated := actionable()
				updated.Status.PodIP = "172.16.0.2"
				updated.Status.PodIPs = []api.PodIP{{IP: "172.16.0.2"}}
				h.OnUpdate(actionable(), updated)
			},
			want: true,
		},
		{
			name: "delete of an actionable pod",
			run:  func(h cache.ResourceEventHandler) { h.OnDelete(actionable()) },
			want: true,
		},
		{
			name: "delete of an actionable pod, as a tombstone",
			run: func(h cache.ResourceEventHandler) {
				h.OnDelete(cache.DeletedFinalStateUnknown{Key: "testnamespace/testpod", Obj: actionable()})
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			npc := &NetworkPolicyControllerBase{fullSyncRequestChan: make(chan struct{}, 1)}
			tt.run(npc.newPodEventHandler())
			assert.Equal(t, tt.want, len(npc.fullSyncRequestChan) == 1)
		})
	}
}
