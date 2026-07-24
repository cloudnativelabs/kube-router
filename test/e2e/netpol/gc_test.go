package netpol_e2e

// Garbage-collection coverage for the nftables backend. Commit c0ecd57a fixed a
// pod firewall chain leak caused by GC running in the wrong order: stale
// KUBE-POD-FW-* chains were never deleted and accumulated across pod churn.
//
// This spec churns pods and policies in a dedicated namespace, deletes the
// namespace, and asserts that every chain kube-router attributes to it (via the
// "podfw <ns>/<pod>" / "netpol <ns>/<policy>" chain comments) disappears. We
// count only namespace-attributed chains because a global count vs a pre-churn
// baseline was racy against suite order, system pod startup, default-deny mode,
// and the number of enabled IP families.

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// chainKindPodFW and chainKindPolicy mirror the comment prefixes kube-router
	// writes on its per-pod and per-policy nftables chains (npc_nftables.go).
	// We can't import them from the controller package, so we redeclare them.
	chainKindPodFW  = "podfw"
	chainKindPolicy = "netpol"

	// churnPods is the batch size created and destroyed each cycle.
	churnPods = 4
	// gcConvergeTimeout bounds how long we wait for kube-router to program and
	// then GC the churn namespace's chains. Generous because in dual-stack +
	// default-deny mode every sync rewrites both address families' rulesets.
	gcConvergeTimeout = 3 * time.Minute
	gcConvergePoll    = 3 * time.Second
)

// nsChainCount returns the number of distinct chains, across every kube-router
// pod and both filter tables, whose chain comment attributes them to namespace
// ns with the given kind. We count distinct names so a per-pod chain (same name
// in both family tables) counts once while a leaked old-version chain (new
// name, same comment) still registers.
func nsChainCount(kind, ns string) int {
	GinkgoHelper()
	// Matches the start of a chain's own comment line, e.g. `comment "podfw <ns>/srv-0"`
	marker := `comment "` + kind + " " + ns + "/"

	seen := make(map[string]struct{})
	for _, kr := range kubeRouterPods() {
		for _, table := range [][]string{
			{"ip", "kube-router-filter-ipv4"},
			{"ip6", "kube-router-filter-ipv6"},
		} {
			args := []string{"nft", "list", "table", table[0], table[1]}
			stdout, _, _, execErr := execInPod(kubeSystemNS, kr.Name, "kube-router", args)
			if execErr != nil {
				continue
			}
			// Walk the output attributing standalone `comment "..."` lines (the
			// chain's own comment) to the enclosing chain block.
			current := ""
			for line := range strings.SplitSeq(stdout, "\n") {
				trimmed := strings.TrimSpace(line)
				fields := strings.Fields(trimmed)
				switch {
				case len(fields) >= 2 && fields[0] == "chain":
					current = fields[1]
				case strings.HasSuffix(trimmed, "{") || trimmed == "}":
					// entering a non-chain block (set, map) or leaving any block
					current = ""
				case current != "" && strings.HasPrefix(trimmed, marker):
					seen[current] = struct{}{}
				}
			}
		}
	}
	return len(seen)
}

// waitNamespaceGone blocks until the named namespace is fully deleted so that
// kube-router observes the pod/policy removals and can GC their chains.
func waitNamespaceGone(ctx context.Context, name string) {
	GinkgoHelper()
	Eventually(func() bool {
		_, err := k8sClient.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
		return apierrors.IsNotFound(err)
	}, gcConvergeTimeout, gcConvergePoll).Should(BeTrue(),
		"namespace %s should be deleted within %s", name, gcConvergeTimeout)
}

var _ = Describe("nftables chain GC", Ordered, Serial, func() {
	BeforeEach(func() {
		skipUnlessLong()
		if backend() != "nftables" {
			Skip("nftables chain-GC spec; set BACKEND=nftables to run it")
		}
	})

	// runChurn creates a batch of server pods, each with its own deny-all
	// ingress policy, waits for kube-router to program their chains, then
	// deletes the whole namespace and asserts every chain attributed to it is
	// garbage collected.
	runChurn := func(ctx context.Context) {
		ns := createNamespace(nil)

		for i := range churnPods {
			name := fmt.Sprintf("srv-%d", i)
			labels := map[string]string{"app": name}
			launchServer(ns.Name, name, labels)
			applyPolicy(denyAllIngress(ns.Name, "deny-"+name,
				metav1.LabelSelector{MatchLabels: labels}))
		}

		// Confirm the churn actually created chains, so a passing convergence
		// assertion can't be a false negative from nothing having happened. We
		// use >= because chain versioning can briefly leave old- and new-version
		// chains coexisting mid-sync.
		Eventually(func() int {
			return nsChainCount(chainKindPodFW, ns.Name)
		}, gcConvergeTimeout, gcConvergePoll).Should(BeNumerically(">=", churnPods),
			"expected per-pod firewall chains for the churn namespace to be programmed")
		Eventually(func() int {
			return nsChainCount(chainKindPolicy, ns.Name)
		}, gcConvergeTimeout, gcConvergePoll).Should(BeNumerically(">=", churnPods),
			"expected policy chains for the churn namespace to be programmed")

		// Delete the namespace to remove every pod and policy at once, then wait
		// for it to fully disappear before checking convergence.
		err := k8sClient.CoreV1().Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred(), "delete churn namespace")
		waitNamespaceGone(ctx, ns.Name)

		// After GC settles, no chain attributed to the deleted namespace may
		// remain in either family's table. If the GC-ordering bug regresses,
		// stale KUBE-POD-FW-* chains keep their podfw comment and this never
		// converges.
		Eventually(func() int {
			return nsChainCount(chainKindPodFW, ns.Name)
		}, gcConvergeTimeout, gcConvergePoll).Should(BeZero(),
			"per-pod firewall chains for the deleted namespace should be garbage collected")
		Eventually(func() int {
			return nsChainCount(chainKindPolicy, ns.Name)
		}, gcConvergeTimeout, gcConvergePoll).Should(BeZero(),
			"policy chains for the deleted namespace should be garbage collected")
	}

	It("reclaims per-pod and per-policy chains across repeated pod/policy churn", func() {
		ctx := context.Background()

		// Two cycles: the first proves GC reclaims chains; the second proves the
		// reclamation is repeatable and chains don't grow monotonically.
		runChurn(ctx)
		runChurn(ctx)
	})
})
