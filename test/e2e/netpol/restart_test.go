package netpol_e2e

// Lifecycle coverage for a kube-router rollout. Commit cda3eb9b fixed a startup
// bug where the nftables backend flushed its top-level chains before it had
// repopulated them, opening a brief allow-all window every time kube-router
// (re)started. Steady-state connectivity specs cannot see that window because
// they never restart the controller; this spec does.
//
// It is gated behind E2E_LONG because a DaemonSet rollout takes tens of seconds
// and CI only runs it on push/dispatch, not on every PR.

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	// rolloutTimeout bounds how long we wait for the kube-router DaemonSet to
	// finish restarting.
	rolloutTimeout = 3 * time.Minute
	// restartProbeInterval paces the connectivity probes during the rollout.
	// canConnect's own 2s connect timeout dominates the cadence.
	restartProbeInterval = 250 * time.Millisecond
)

// podReady reports whether pod is Running with a Ready condition of True.
func podReady(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// kubeRouterPodUIDs returns the set of current kube-router pod UIDs so we can
// tell fresh pods from the ones that existed before a restart.
func kubeRouterPodUIDs() map[types.UID]bool {
	GinkgoHelper()
	set := map[types.UID]bool{}
	for _, p := range kubeRouterPods() {
		set[p.UID] = true
	}
	return set
}

// kubeRouterRolloutComplete reports whether every kube-router pod is a fresh
// (not in oldUIDs) Ready pod and the count matches desired.
func kubeRouterRolloutComplete(oldUIDs map[types.UID]bool, desired int) bool {
	GinkgoHelper()
	pods := kubeRouterPods()
	ready := 0
	for i := range pods {
		p := &pods[i]
		if oldUIDs[p.UID] {
			return false
		}
		if podReady(p) {
			ready++
		}
	}
	return desired > 0 && ready == desired
}

// restartKubeRouter triggers a rolling restart of the kube-router DaemonSet by
// stamping a restartedAt annotation on the pod template, exactly as
// `kubectl rollout restart` does, and returns the pre-restart pod UID set and
// the desired pod count.
func restartKubeRouter(ctx context.Context) (map[types.UID]bool, int) {
	GinkgoHelper()
	ds, err := k8sClient.AppsV1().DaemonSets(kubeSystemNS).Get(ctx, "kube-router", metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred(), "get kube-router daemonset")
	desired := int(ds.Status.DesiredNumberScheduled)
	Expect(desired).To(BeNumerically(">", 0), "kube-router daemonset has no scheduled pods")

	oldUIDs := kubeRouterPodUIDs()

	patch := fmt.Appendf(nil,
		`{"spec":{"template":{"metadata":{"annotations":{"kube-router.io/restartedAt":%q}}}}}`,
		time.Now().Format(time.RFC3339Nano))
	_, err = k8sClient.AppsV1().DaemonSets(kubeSystemNS).Patch(ctx, "kube-router",
		types.StrategicMergePatchType, patch, metav1.PatchOptions{})
	Expect(err).NotTo(HaveOccurred(), "patch kube-router daemonset to trigger restart")

	return oldUIDs, desired
}

// Serial: this spec restarts the kube-router DaemonSet, which would disrupt any
// spec running concurrently under --procs.
var _ = Describe("controller restart", Ordered, Serial, func() {
	BeforeEach(func() {
		skipUnlessLong()
	})

	// A deny-all-ingress policy must keep blocking traffic for the entire
	// duration of a kube-router rollout. If the new pod flushes its chains
	// before repopulating them, the probe will connect and fail the spec.
	It("never opens enforcement while kube-router restarts", func() {
		ctx := context.Background()
		ns := createNamespace(nil)
		server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
		client := launchClient(ns.Name, "client", map[string]string{"app": "client"})
		serverIP := podIPv4(server)

		// Baseline: reachable before the policy, blocked after it.
		assertConnected(client, serverIP, serverPort)
		applyPolicy(denyAllIngress(ns.Name, "deny-all-ingress",
			metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}}))
		assertBlocked(client, serverIP, serverPort)

		oldUIDs, desired := restartKubeRouter(ctx)

		// Probe connectivity tightly for the whole rollout; enforcement must
		// never lapse, and the rollout must finish within the timeout.
		deadline := time.Now().Add(rolloutTimeout)
		rolledOut := false
		for time.Now().Before(deadline) {
			Expect(canConnect(client, serverIP, serverPort)).To(BeFalse(),
				"connectivity opened during kube-router restart - enforcement gap")
			if kubeRouterRolloutComplete(oldUIDs, desired) {
				rolledOut = true
				break
			}
			time.Sleep(restartProbeInterval)
		}
		Expect(rolledOut).To(BeTrue(),
			"kube-router rollout did not complete within %s", rolloutTimeout)

		// Steady state after the rollout: still blocked.
		assertBlocked(client, serverIP, serverPort)
	})
})
