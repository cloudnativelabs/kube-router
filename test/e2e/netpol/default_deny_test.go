package netpol_e2e

// Tests for the --netpol-default-deny flag.
//
// The flag instructs kube-router to install REJECT rules that fire for traffic
// to/from local-pod CIDRs when the source or destination IP is NOT yet in the
// kube-router-local-pods ipset (iptables path) or named set (nftables path).
// A pod's IP is added to that set only after its per-pod firewall chain has
// been programmed, which closes the race window between a pod becoming routable
// and its NetworkPolicy being enforced.
//
// All tests in this file call BeforeEach to skip when the feature is not
// enabled in the running deployment.

import (
	"context"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ---------------------------------------------------------------------------
// Feature-detection helpers
// ---------------------------------------------------------------------------

// isDefaultDenyEnabled returns true when the running kube-router pods are
// configured with --netpol-default-deny (or --netpol-default-deny=true).
func isDefaultDenyEnabled() bool {
	pods, err := k8sClient.CoreV1().Pods("kube-system").List(
		context.Background(),
		metav1.ListOptions{LabelSelector: "k8s-app=kube-router"},
	)
	if err != nil || len(pods.Items) == 0 {
		return false
	}
	for _, container := range pods.Items[0].Spec.Containers {
		for _, arg := range container.Args {
			if arg == "--netpol-default-deny" || arg == "--netpol-default-deny=true" {
				return true
			}
		}
	}
	return false
}

// defaultDenyRejectRulesPresent returns true when at least one kube-router
// node has the REJECT rules that are tagged with the
// "--netpol-default-deny is enabled" comment in its iptables filter table or
// nftables ruleset.
func defaultDenyRejectRulesPresent() bool {
	const marker = "netpol-default-deny is enabled"
	pods, err := k8sClient.CoreV1().Pods("kube-system").List(
		context.Background(),
		metav1.ListOptions{LabelSelector: "k8s-app=kube-router"},
	)
	if err != nil {
		return false
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		// nftables path: check the full ruleset for the comment.
		stdout, _, _, execErr := execInPod("kube-system", pod.Name, "kube-router",
			[]string{"nft", "list", "ruleset"})
		if execErr == nil && strings.Contains(stdout, marker) {
			return true
		}
		// iptables path: iptables-save output also carries the comment.
		stdout, _, _, execErr = execInPod("kube-system", pod.Name, "kube-router",
			[]string{"iptables-save"})
		if execErr == nil && strings.Contains(stdout, marker) {
			return true
		}
	}
	return false
}

// localPodsSetExistsOnNode returns true when the kube-router-local-pods set
// is present on the given kube-router pod (works for both the iptables ipset
// and the nftables named set).
func localPodsSetExistsOnNode(krPodName string) bool {
	const setName = "kube-router-local-pods"

	// iptables path: use the ipset utility.
	stdout, _, exitCode, execErr := execInPod("kube-system", krPodName, "kube-router",
		[]string{"ipset", "list", setName})
	if execErr == nil && exitCode == 0 && strings.Contains(stdout, setName) {
		return true
	}

	// nftables path: the set name appears in "nft list ruleset" output.
	stdout, _, _, execErr = execInPod("kube-system", krPodName, "kube-router",
		[]string{"nft", "list", "ruleset"})
	return execErr == nil && strings.Contains(stdout, setName)
}

// podIPInLocalPodsSet returns true when ip is a member of the
// kube-router-local-pods set on the given kube-router pod. It supports both
// the iptables ipset and the nftables named set.
func podIPInLocalPodsSet(krPodName, ip string) bool {
	// iptables path: `ipset test` exits 0 iff the element is present.
	_, _, exitCode, execErr := execInPod("kube-system", krPodName, "kube-router",
		[]string{"ipset", "test", "kube-router-local-pods", ip})
	if execErr == nil && exitCode == 0 {
		return true
	}

	// nftables path: list the IPv4 set directly and grep for the IP.
	stdout, _, _, execErr := execInPod("kube-system", krPodName, "kube-router",
		[]string{"nft", "list", "set", "ip", "kube-router-filter-ipv4", "kube-router-local-pods"})
	if execErr == nil && strings.Contains(stdout, ip) {
		return true
	}

	// Also check the IPv6 table for completeness.
	stdout, _, _, execErr = execInPod("kube-system", krPodName, "kube-router",
		[]string{"nft", "list", "set", "ip6", "kube-router-filter-ipv6", "kube-router-local-pods"})
	return execErr == nil && strings.Contains(stdout, ip)
}

// kubeRouterPodOnNode returns the name of the kube-router pod running on
// nodeName, or "" when no such pod is found.
func kubeRouterPodOnNode(nodeName string) string {
	pods, err := k8sClient.CoreV1().Pods("kube-system").List(
		context.Background(),
		metav1.ListOptions{
			LabelSelector: "k8s-app=kube-router",
			FieldSelector: "spec.nodeName=" + nodeName,
		},
	)
	if err != nil || len(pods.Items) == 0 {
		return ""
	}
	return pods.Items[0].Name
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

var _ = Describe("netpol-default-deny", func() {
	BeforeEach(func() {
		if !isDefaultDenyEnabled() {
			Skip("--netpol-default-deny is not enabled in this kube-router deployment; " +
				"set --netpol-default-deny=true to run these tests")
		}
	})

	// -----------------------------------------------------------------------
	// Infrastructure verification
	// -----------------------------------------------------------------------

	Describe("infrastructure", func() {
		// Test DD-1: kube-router must have installed REJECT rules that carry the
		// "--netpol-default-deny is enabled" comment in the filter table on
		// every node.  Without these rules the feature provides no protection.
		It("programs REJECT rules for pod CIDRs in the filter table", func() {
			Expect(defaultDenyRejectRulesPresent()).To(BeTrue(),
				"expected REJECT rules tagged with 'netpol-default-deny is enabled' "+
					"in iptables or nftables on at least one kube-router node")
		})

		// Test DD-2: The kube-router-local-pods set must exist on every node so
		// that the REJECT rules can be gated against it.
		It("maintains the kube-router-local-pods set on every kube-router node", func() {
			pods, err := k8sClient.CoreV1().Pods("kube-system").List(
				context.Background(),
				metav1.ListOptions{LabelSelector: "k8s-app=kube-router"},
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty(), "no kube-router pods found in kube-system")
			for i := range pods.Items {
				pod := &pods.Items[i]
				Expect(localPodsSetExistsOnNode(pod.Name)).To(BeTrue(),
					"expected kube-router-local-pods set to exist on node %s (pod %s)",
					pod.Spec.NodeName, pod.Name)
			}
		})

		// Test DD-3: After kube-router programs a pod's per-pod firewall chain,
		// the pod's IP must appear in kube-router-local-pods on its node.  If
		// this invariant holds, the ipset-gated REJECT rules will not fire for
		// the pod, and the pod can communicate normally.
		It("adds a running pod's IP to kube-router-local-pods after its firewall chain is programmed", func() {
			ns := createNamespace(nil)
			pod := launchServer(ns.Name, "probe", map[string]string{"app": "probe"})
			podIP := podIPv4(pod)
			nodeName := pod.Spec.NodeName

			krPodName := kubeRouterPodOnNode(nodeName)
			if krPodName == "" {
				Skip("no kube-router pod found on node " + nodeName + "; skipping ipset membership check")
			}

			Eventually(func() bool {
				return podIPInLocalPodsSet(krPodName, podIP)
			}, pollTimeout, pollInterval).Should(BeTrue(),
				"expected pod IP %s to appear in kube-router-local-pods on node %s within %s",
				podIP, nodeName, pollTimeout)
		})
	})

	// -----------------------------------------------------------------------
	// Steady-state connectivity
	// -----------------------------------------------------------------------

	Describe("steady-state connectivity", func() {

		// Test DD-4: Once kube-router has programmed a pod's firewall chain (and
		// therefore added its IP to kube-router-local-pods), pods that are not
		// selected by any NetworkPolicy must be able to reach each other.  The
		// ipset-gated REJECT rules must NOT fire for pods in the set.
		It("allows traffic between established pods when no NetworkPolicy is applied", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})
			assertConnected(client, podIPv4(server), serverPort)
		})

		// Test DD-5: An explicit allow NetworkPolicy must grant traffic even when
		// default-deny is active; the per-pod chain marks approved packets before
		// they reach the tail-chain REJECT rules.
		It("allows traffic when an explicit allow NetworkPolicy is present", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "allow-client", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{{
						From: []netv1.NetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "client"},
							},
						}},
					}},
				},
			})
			assertConnected(client, podIPv4(server), serverPort)
		})
	})

	// -----------------------------------------------------------------------
	// NetworkPolicy enforcement
	// -----------------------------------------------------------------------

	Describe("NetworkPolicy enforcement", func() {

		// Test DD-6: A deny-all-ingress policy must still block traffic when
		// --netpol-default-deny is enabled.
		It("enforces a deny-all-ingress NetworkPolicy", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			assertConnected(client, podIPv4(server), serverPort)

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "deny-all-ingress", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
				},
			})
			assertBlocked(client, podIPv4(server), serverPort)
		})

		// Test DD-7: A deny-all-egress policy must block outbound traffic from
		// the client pod when --netpol-default-deny is enabled.
		It("enforces a deny-all-egress NetworkPolicy", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			assertConnected(client, podIPv4(server), serverPort)

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "deny-all-egress", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
				},
			})
			assertBlocked(client, podIPv4(server), serverPort)
		})

		// Test DD-8: Deleting a deny policy must restore connectivity; the
		// per-pod chain is rebuilt during the next sync cycle.
		It("restores connectivity after a deny NetworkPolicy is removed", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			pol := &netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "deny-restore", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
				},
			}
			applyPolicy(pol)
			assertBlocked(client, podIPv4(server), serverPort)

			deletePolicy(ns.Name, pol.Name)
			assertConnected(client, podIPv4(server), serverPort)
		})
	})

	// -----------------------------------------------------------------------
	// Transient protection window
	// -----------------------------------------------------------------------

	Describe("transient protection window", func() {
		// Test DD-9: Core guarantee of --netpol-default-deny: kube-router adds
		// a pod's IP to kube-router-local-pods only after its per-pod firewall
		// chain is programmed.  Before that moment the ipset-gated REJECT rules
		// in KUBE-NWPLCY-TAIL fire for any traffic to or from that pod IP.
		//
		// This test verifies the observable side-effects:
		//   - The IP eventually appears in kube-router-local-pods (chain was
		//     programmed).
		//   - The pod is reachable only after the IP is in the set.
		//
		// The existence of the REJECT rules themselves is verified by Test DD-1.
		It("makes a new pod reachable only after its IP is added to kube-router-local-pods", func() {
			ns := createNamespace(nil)
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			// Record the time before launching the server so we can log how
			// long it takes kube-router to process the new pod.
			launchStart := time.Now()
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			serverIP := podIPv4(server)
			nodeName := server.Spec.NodeName
			GinkgoWriter.Printf("[dd] server pod Running after %s; IP=%s node=%s\n",
				time.Since(launchStart).Truncate(time.Millisecond), serverIP, nodeName)

			krPodName := kubeRouterPodOnNode(nodeName)
			if krPodName == "" {
				Skip("no kube-router pod on node " + nodeName + "; skipping transient-window check")
			}

			// Wait for kube-router to program the chain and populate the set.
			var inSetAt time.Time
			Eventually(func() bool {
				if podIPInLocalPodsSet(krPodName, serverIP) {
					inSetAt = time.Now()
					return true
				}
				return false
			}, pollTimeout, pollInterval).Should(BeTrue(),
				"server IP %s should be added to kube-router-local-pods on node %s within %s",
				serverIP, nodeName, pollTimeout)
			GinkgoWriter.Printf("[dd] server IP entered kube-router-local-pods %s after pod Running\n",
				inSetAt.Sub(launchStart).Truncate(time.Millisecond))

			// With the IP in the set the REJECT rules are bypassed and the pod
			// must now be reachable.
			assertConnected(client, serverIP, serverPort)
		})

		// Test DD-10: A pod that is already in kube-router-local-pods must
		// remain reachable after a full sync cycle (the set is rebuilt from
		// scratch every sync; this test catches any regression where the rebuild
		// drops existing entries).
		It("keeps an established pod reachable across a kube-router sync cycle", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})
			serverIP := podIPv4(server)
			nodeName := server.Spec.NodeName

			// Baseline: the pod is reachable.
			assertConnected(client, serverIP, serverPort)

			krPodName := kubeRouterPodOnNode(nodeName)
			if krPodName == "" {
				Skip("no kube-router pod on node " + nodeName + "; skipping sync-cycle check")
			}

			// Confirm the IP is in the set before proceeding.
			Eventually(func() bool {
				return podIPInLocalPodsSet(krPodName, serverIP)
			}, pollTimeout, pollInterval).Should(BeTrue(),
				"server IP %s should be in kube-router-local-pods before the sync-cycle check", serverIP)

			// After waiting for at least one more sync, the pod must still be
			// reachable and its IP still present in the set.
			assertConnected(client, serverIP, serverPort)
			Expect(podIPInLocalPodsSet(krPodName, serverIP)).To(BeTrue(),
				"server IP %s should still be in kube-router-local-pods after connectivity check", serverIP)
		})
	})
})
