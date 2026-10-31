package netpol_e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

const (
	testImage = "registry.k8s.io/e2e-test-images/agnhost:2.43"

	// kubeSystemNS is where the kube-router DaemonSet runs.
	kubeSystemNS = "kube-system"
	// kubeRouterLabelSelector selects the kube-router pods.
	kubeRouterLabelSelector = "k8s-app=kube-router"

	serverPort = 8080
	altPort    = 8081

	// pollTimeout is the maximum time to wait for a connectivity state to be
	// reached after a NetworkPolicy is applied or deleted.
	pollTimeout = 60 * time.Second
	// pollInterval is the retry cadence for heavier polls, like reading kube-router's sets on every node.
	pollInterval = 2 * time.Second
	// probeInterval is the retry cadence for connectivity probes.
	probeInterval = 1 * time.Second
	// stayBlockedDuration is how long a block has to hold once we've seen it, which is how we catch enforcement that
	// flaps back open.
	stayBlockedDuration = 4 * time.Second
	// podPollInterval is how often we check a pod's phase, which is cheap and usually changes within a second
	podPollInterval = 250 * time.Millisecond
	// warmUpTimeout is longer than pollTimeout because, on a cluster where nobody preloaded the test image, the
	// warm-up pods are the ones that pull it
	warmUpTimeout = 3 * time.Minute
)

// serverNode and clientNode are where launchServer and launchClient put their pods. We keep them apart so that
// every spec exercises cross-node traffic, and leave them empty (scheduler's choice) on a single-node cluster.
var serverNode, clientNode string

// ---------------------------------------------------------------------------
// Topology helpers
// ---------------------------------------------------------------------------

// assignNodes picks the first two schedulable nodes, by name, as the server and client nodes
func assignNodes() {
	GinkgoHelper()
	nodes, err := k8sClient.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred(), "list nodes")

	var schedulable []string
	for i := range nodes.Items {
		if isSchedulable(&nodes.Items[i]) {
			schedulable = append(schedulable, nodes.Items[i].Name)
		}
	}
	slices.Sort(schedulable)
	if len(schedulable) < 2 {
		GinkgoWriter.Printf("[topology] only %d schedulable node(s), so specs won't exercise cross-node traffic\n",
			len(schedulable))
		return
	}
	serverNode, clientNode = schedulable[0], schedulable[1]
	GinkgoWriter.Printf("[topology] servers on %s, clients on %s\n", serverNode, clientNode)
}

// warmUpNodes runs a throwaway pod on every schedulable node and waits for them all to finish. A fresh node's first
// pod can need a sandbox retry before it starts, and we'd rather pay for that here than in whichever spec goes first.
func warmUpNodes() {
	GinkgoHelper()
	ctx := context.Background()
	ns, err := k8sClient.CoreV1().Namespaces().Create(ctx,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "netpol-e2e-warm-up-"}}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "create warm-up namespace")
	defer func() {
		_ = k8sClient.CoreV1().Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{})
	}()

	nodes, err := k8sClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred(), "list nodes")
	var pods []string
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if !isSchedulable(node) {
			continue
		}
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "warm-up-" + node.Name, Namespace: ns.Name},
			Spec: corev1.PodSpec{
				NodeName: node.Name,
				Containers: []corev1.Container{{
					Name:    "warm-up",
					Image:   testImage,
					Command: []string{"/bin/sh", "-c", "true"},
				}},
				RestartPolicy: corev1.RestartPolicyNever,
			},
		}
		_, err := k8sClient.CoreV1().Pods(ns.Name).Create(ctx, pod, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred(), "create warm-up pod on %s", node.Name)
		pods = append(pods, pod.Name)
	}

	start := time.Now()
	for _, name := range pods {
		Eventually(func() corev1.PodPhase {
			pod, err := k8sClient.CoreV1().Pods(ns.Name).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return ""
			}
			return pod.Status.Phase
		}, warmUpTimeout, podPollInterval).Should(Equal(corev1.PodSucceeded), "warm-up pod %s to finish", name)
	}
	GinkgoWriter.Printf("[topology] warmed up %d node(s) in %s\n", len(pods), time.Since(start).Round(time.Second))
}

func isSchedulable(node *corev1.Node) bool {
	if node.Spec.Unschedulable {
		return false
	}
	for _, taint := range node.Spec.Taints {
		if taint.Effect == corev1.TaintEffectNoSchedule || taint.Effect == corev1.TaintEffectNoExecute {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Namespace helpers
// ---------------------------------------------------------------------------

// createNamespace creates a short-lived namespace with GenerateName and
// registers DeferCleanup to ensure it is deleted after the test.
func createNamespace(labels map[string]string) *corev1.Namespace {
	GinkgoHelper()
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "netpol-e2e-",
			Labels:       labels,
		},
	}
	created, err := k8sClient.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "create namespace")
	DeferCleanup(func() {
		_ = k8sClient.CoreV1().Namespaces().Delete(context.Background(), created.Name, metav1.DeleteOptions{})
	})
	return created
}

// createNamespaceNamed creates a namespace with an explicit name (rather than
// GenerateName) so specs can exercise maximum-length identities. Cleanup is
// registered via DeferCleanup.
func createNamespaceNamed(name string, labels map[string]string) *corev1.Namespace {
	GinkgoHelper()
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
	}
	created, err := k8sClient.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "create namespace %s", name)
	DeferCleanup(func() {
		_ = k8sClient.CoreV1().Namespaces().Delete(context.Background(), created.Name, metav1.DeleteOptions{})
	})
	return created
}

// paddedName builds a DNS-1123 name of exactly length characters: prefix plus a
// random token, padded with 'a' (or truncated) as needed. We use it to drive
// maximum-length namespace (63) and policy (253) identities into the nftables
// comments that derive from them.
func paddedName(prefix string, length int) string {
	GinkgoHelper()
	name := prefix + rand.String(8)
	if len(name) > length {
		return name[:length]
	}
	return name + strings.Repeat("a", length-len(name))
}

// patchNamespaceLabels replaces all labels on ns with newLabels and returns
// the updated Namespace object.
func patchNamespaceLabels(ns *corev1.Namespace, newLabels map[string]string) *corev1.Namespace {
	GinkgoHelper()
	nsCopy := ns.DeepCopy()
	nsCopy.Labels = newLabels
	updated, err := k8sClient.CoreV1().Namespaces().Update(context.Background(), nsCopy, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred(), "patch namespace labels")
	return updated
}

// ---------------------------------------------------------------------------
// Pod helpers
// ---------------------------------------------------------------------------

// launchServer creates a pod running agnhost serve-hostname on serverPort and
// waits for it to reach Running phase.
func launchServer(ns, name string, labels map[string]string) *corev1.Pod {
	GinkgoHelper()
	return launchServerOnPort(ns, name, labels, serverPort)
}

// launchServerOnPort is like launchServer but with a custom port.
func launchServerOnPort(ns, name string, labels map[string]string, port int) *corev1.Pod {
	GinkgoHelper()
	return startPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: corev1.PodSpec{
			NodeName: serverNode,
			Containers: []corev1.Container{{
				Name:  "server",
				Image: testImage,
				Args:  serveHostnameArgs(port),
			}},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	})
}

// launchNamedPortServer creates a server that exposes serverPort as portName, plus an unnamed listener on altPort so
// that specs can show a named-port policy opens only the port it names
func launchNamedPortServer(ns, name string, labels map[string]string, portName string) *corev1.Pod {
	GinkgoHelper()
	return startPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: corev1.PodSpec{
			NodeName: serverNode,
			Containers: []corev1.Container{
				{
					Name:  "server",
					Image: testImage,
					Args:  serveHostnameArgs(serverPort),
					Ports: []corev1.ContainerPort{{
						Name:          portName,
						ContainerPort: serverPort,
						Protocol:      corev1.ProtocolTCP,
					}},
				},
				{Name: "server-alt", Image: testImage, Args: serveHostnameArgs(altPort)},
			},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	})
}

// launchClient creates a connectivity probe source on the client node and waits for it to reach Running. It also
// listens on serverPort so that specs can probe ingress to a client.
func launchClient(ns, name string, labels map[string]string) *corev1.Pod {
	GinkgoHelper()
	return launchClientOnNode(ns, name, labels, clientNode)
}

// launchClientOnNode is like launchClient but pins the pod to node, or leaves placement to the scheduler when node
// is empty
func launchClientOnNode(ns, name string, labels map[string]string, node string) *corev1.Pod {
	GinkgoHelper()
	return startPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: corev1.PodSpec{
			NodeName: node,
			Containers: []corev1.Container{{
				Name:  "client",
				Image: testImage,
				Args:  serveHostnameArgs(serverPort),
			}},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	})
}

// serveHostnameArgs returns the agnhost args for a plain TCP listener on port
func serveHostnameArgs(port int) []string {
	return []string{"serve-hostname", "--http=false", "--tcp=true", fmt.Sprintf("--port=%d", port)}
}

// startPod creates p, registers its cleanup, and waits for it to reach Running
func startPod(p *corev1.Pod) *corev1.Pod {
	GinkgoHelper()
	// agnhost ignores SIGTERM, so without this every namespace deletion waits out the default 30s grace period
	noGrace := int64(0)
	p.Spec.TerminationGracePeriodSeconds = &noGrace
	created, err := k8sClient.CoreV1().Pods(p.Namespace).Create(context.Background(), p, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "create pod %s/%s", p.Namespace, p.Name)
	DeferCleanup(deletePod, p.Namespace, p.Name)
	return waitForRunning(p.Namespace, created.Name)
}

// waitForRunning polls until pod phase is Running, then returns the latest pod
// object (with IPs populated).
func waitForRunning(ns, name string) *corev1.Pod {
	GinkgoHelper()
	return waitForPhase(ns, name, corev1.PodRunning)
}

// waitForPhase polls until the pod reaches phase, then returns the latest pod object
func waitForPhase(ns, name string, phase corev1.PodPhase) *corev1.Pod {
	GinkgoHelper()
	var pod *corev1.Pod
	Eventually(func() bool {
		var err error
		pod, err = k8sClient.CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		return pod.Status.Phase == phase
	}, pollTimeout, podPollInterval).Should(BeTrue(), "pod %s/%s to reach %s", ns, name, phase)
	return pod
}

// deletePod force-deletes a pod (gracePeriod=0). Used by DeferCleanup.
func deletePod(ns, name string) {
	grace := int64(0)
	_ = k8sClient.CoreV1().Pods(ns).Delete(context.Background(), name,
		metav1.DeleteOptions{GracePeriodSeconds: &grace})
}

// podIPv4 returns the first IPv4 address from pod.Status.PodIPs, falling back
// to pod.Status.PodIP. Fails the spec if no IPv4 address is found.
func podIPv4(pod *corev1.Pod) string {
	GinkgoHelper()
	for _, pip := range pod.Status.PodIPs {
		if !strings.Contains(pip.IP, ":") {
			return pip.IP
		}
	}
	if pod.Status.PodIP != "" && !strings.Contains(pod.Status.PodIP, ":") {
		return pod.Status.PodIP
	}
	Fail(fmt.Sprintf("pod %s/%s has no IPv4 address (PodIPs=%v)", pod.Namespace, pod.Name, pod.Status.PodIPs))
	return ""
}

// podIPv6 returns the pod's IPv6 address, or "" when the cluster isn't dual-stack
func podIPv6(pod *corev1.Pod) string {
	for _, pip := range pod.Status.PodIPs {
		if strings.Contains(pip.IP, ":") {
			return pip.IP
		}
	}
	return ""
}

// patchPodLabels replaces the pod's labels with newLabels and returns the
// updated pod.
func patchPodLabels(pod *corev1.Pod, newLabels map[string]string) *corev1.Pod {
	GinkgoHelper()
	p := pod.DeepCopy()
	p.Labels = newLabels
	updated, err := k8sClient.CoreV1().Pods(pod.Namespace).Update(context.Background(), p, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred(), "patch pod labels")
	return updated
}

// ---------------------------------------------------------------------------
// NetworkPolicy helpers
// ---------------------------------------------------------------------------

// applyPolicy creates the NetworkPolicy and registers cleanup for its deletion.
func applyPolicy(pol *netv1.NetworkPolicy) {
	GinkgoHelper()
	_, err := k8sClient.NetworkingV1().NetworkPolicies(pol.Namespace).Create(
		context.Background(), pol, metav1.CreateOptions{},
	)
	Expect(err).NotTo(HaveOccurred(), "create NetworkPolicy %s", pol.Name)
	DeferCleanup(func() {
		_ = k8sClient.NetworkingV1().NetworkPolicies(pol.Namespace).Delete(
			context.Background(), pol.Name, metav1.DeleteOptions{},
		)
	})
}

// deletePolicy deletes a NetworkPolicy immediately (used in tests that verify
// traffic is restored after policy removal).
func deletePolicy(ns, name string) {
	GinkgoHelper()
	err := k8sClient.NetworkingV1().NetworkPolicies(ns).Delete(
		context.Background(), name, metav1.DeleteOptions{},
	)
	Expect(err).NotTo(HaveOccurred(), "delete NetworkPolicy %s/%s", ns, name)
}

// ---------------------------------------------------------------------------
// Connectivity probes
// ---------------------------------------------------------------------------

// canConnect runs `nc -zw2 <ip> <port>` inside clientPod's first container and
// returns true if the connection succeeds (exit code 0). Any launched pod can be
// the source, since they all use the agnhost image.
func canConnect(clientPod *corev1.Pod, dstIP string, port int) bool {
	GinkgoHelper()
	cmd := []string{"nc", "-zw2", dstIP, strconv.Itoa(port)}
	container := clientPod.Spec.Containers[0].Name
	stdout, stderr, exitCode, err := execInPod(clientPod.Namespace, clientPod.Name, container, cmd)
	connected := err == nil && exitCode == 0
	GinkgoWriter.Printf("[probe] %s/%s → %s:%d  connected=%v (exit=%d err=%v stdout=%q stderr=%q)\n",
		clientPod.Namespace, clientPod.Name, dstIP, port, connected, exitCode, err,
		strings.TrimSpace(stdout), strings.TrimSpace(stderr))
	return connected
}

// assertConnected polls until a connection from clientPod to dstIP:port
// succeeds, or fails the spec after pollTimeout. Because it passes on the first
// success it can't tell a just-applied policy from no policy at all, so specs
// run assertBlocked (which waits out the sync) before checking an allow path.
func assertConnected(clientPod *corev1.Pod, dstIP string, port int) {
	GinkgoHelper()
	GinkgoWriter.Printf("[assert] assertConnected: pod %s/%s → %s:%d (timeout=%s)\n",
		clientPod.Namespace, clientPod.Name, dstIP, port, pollTimeout)
	Eventually(func() bool {
		return canConnect(clientPod, dstIP, port)
	}, pollTimeout, probeInterval).Should(BeTrue(),
		"expected %s to be reachable from pod %s/%s",
		fmt.Sprintf("%s:%d", dstIP, port), clientPod.Namespace, clientPod.Name)
}

// assertBlocked waits for traffic from clientPod to dstIP:port to be blocked,
// which covers the time kube-router takes to sync a policy change, and then
// checks that it stays blocked for stayBlockedDuration.
func assertBlocked(clientPod *corev1.Pod, dstIP string, port int) {
	GinkgoHelper()
	GinkgoWriter.Printf("[assert] assertBlocked: pod %s/%s → %s:%d (within=%s)\n",
		clientPod.Namespace, clientPod.Name, dstIP, port, pollTimeout)
	Eventually(func() bool {
		return canConnect(clientPod, dstIP, port)
	}, pollTimeout, probeInterval).Should(BeFalse(),
		"expected %s to become BLOCKED from pod %s/%s",
		fmt.Sprintf("%s:%d", dstIP, port), clientPod.Namespace, clientPod.Name)
	assertStaysBlocked(clientPod, dstIP, port)
}

// assertStaysBlocked checks that traffic which should already be blocked stays
// blocked for stayBlockedDuration, without allowing any time for a sync. Use it
// where an opening at any point would be a bug, such as across a restart.
func assertStaysBlocked(clientPod *corev1.Pod, dstIP string, port int) {
	GinkgoHelper()
	GinkgoWriter.Printf("[assert] assertStaysBlocked: pod %s/%s → %s:%d (for=%s)\n",
		clientPod.Namespace, clientPod.Name, dstIP, port, stayBlockedDuration)
	Consistently(func() bool {
		return canConnect(clientPod, dstIP, port)
	}, stayBlockedDuration, probeInterval).Should(BeFalse(),
		"expected %s to stay BLOCKED from pod %s/%s",
		fmt.Sprintf("%s:%d", dstIP, port), clientPod.Namespace, clientPod.Name)
}

// execInPod runs cmd inside the given container of a pod and returns stdout,
// stderr, exit code, and any exec setup error.
func execInPod(ns, podName, containerName string, cmd []string) (string, string, int, error) {
	req := k8sClient.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(ns).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   cmd,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
	if err != nil {
		return "", "", -1, fmt.Errorf("SPDYExecutor: %w", err)
	}

	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(context.Background(), remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	exitCode := 0
	if err != nil {
		// remotecommand wraps non-zero exit codes as an error implementing
		// ExitStatus(); treat those as a non-zero exit while keeping err==nil
		// so callers can distinguish a command failure from a transport failure.
		var exitErr interface{ ExitStatus() int }
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitStatus()
		} else {
			// Real transport / stream failure — propagate it.
			return stdout.String(), stderr.String(), -1, fmt.Errorf("stream: %w", err)
		}
	}
	return stdout.String(), stderr.String(), exitCode, nil
}

// ---------------------------------------------------------------------------
// Policy builder helpers (reduce boilerplate in specs)
// ---------------------------------------------------------------------------

// tcpPort returns a *netv1.NetworkPolicyPort for a numeric TCP port.
func tcpPort(port int) netv1.NetworkPolicyPort {
	proto := corev1.ProtocolTCP
	p := intstr.FromInt(port)
	return netv1.NetworkPolicyPort{Protocol: &proto, Port: &p}
}

// tcpPortRange returns a *netv1.NetworkPolicyPort covering [start, end].
func tcpPortRange(start, end int32) netv1.NetworkPolicyPort {
	proto := corev1.ProtocolTCP
	p := intstr.FromInt(int(start))
	return netv1.NetworkPolicyPort{Protocol: &proto, Port: &p, EndPort: &end}
}

// namedTCPPort returns a *netv1.NetworkPolicyPort for a named TCP port.
func namedTCPPort(name string) netv1.NetworkPolicyPort {
	proto := corev1.ProtocolTCP
	p := intstr.FromString(name)
	return netv1.NetworkPolicyPort{Protocol: &proto, Port: &p}
}

// allowIngressFromCIDR returns a policy that only lets cidr into the app=server pods in ns
func allowIngressFromCIDR(ns, policyName, cidr string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: ns},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
			Ingress: []netv1.NetworkPolicyIngressRule{{
				From: []netv1.NetworkPolicyPeer{{IPBlock: &netv1.IPBlock{CIDR: cidr}}},
			}},
		},
	}
}

// denyAllIngress returns a deny-all-ingress NetworkPolicy for the given
// namespace and pod label selector.
func denyAllIngress(ns, policyName string, podSelector metav1.LabelSelector) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: ns},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: podSelector,
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}
}

// ---------------------------------------------------------------------------
// Debug helpers – called on spec failure via ReportAfterEach
// ---------------------------------------------------------------------------

// dumpKubeRouterLogs streams the last 200 lines of every kube-router pod's
// log to GinkgoWriter so they appear in the test report when a spec fails.
func dumpKubeRouterLogs(ctx context.Context) {
	GinkgoWriter.Println("[debug] === kube-router pod logs ===")
	pods, err := k8sClient.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=kube-router",
	})
	if err != nil {
		GinkgoWriter.Printf("[debug] list kube-router pods: %v\n", err)
		return
	}
	tail := int64(200)
	for i := range pods.Items {
		pod := &pods.Items[i]
		GinkgoWriter.Printf("[debug] --- pod %s (node %s) ---\n", pod.Name, pod.Spec.NodeName)
		req := k8sClient.CoreV1().Pods("kube-system").GetLogs(pod.Name, &corev1.PodLogOptions{
			TailLines: &tail,
		})
		rc, err := req.Stream(ctx)
		if err != nil {
			GinkgoWriter.Printf("[debug] GetLogs(%s): %v\n", pod.Name, err)
			continue
		}
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rc)
		rc.Close()
		GinkgoWriter.Print(buf.String())
	}
}

// dumpNFTablesState executes `nft list ruleset` inside each kube-router pod
// and writes the ruleset to GinkgoWriter.
func dumpNFTablesState(ctx context.Context) {
	GinkgoWriter.Println("[debug] === nftables ruleset (per kube-router pod) ===")
	pods, err := k8sClient.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=kube-router",
	})
	if err != nil {
		GinkgoWriter.Printf("[debug] list kube-router pods for nft dump: %v\n", err)
		return
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		GinkgoWriter.Printf("[debug] --- nft list ruleset: pod %s (node %s) ---\n", pod.Name, pod.Spec.NodeName)
		stdout, stderr, _, execErr := execInPod("kube-system", pod.Name, "kube-router", []string{"nft", "list", "ruleset"})
		if execErr != nil {
			GinkgoWriter.Printf("[debug] nft list ruleset failed: %v\n  stderr: %s\n", execErr, stderr)
			continue
		}
		GinkgoWriter.Print(stdout)
	}
}

// ---------------------------------------------------------------------------
// Lifecycle-test gating & environment helpers
// ---------------------------------------------------------------------------

// e2eLong reports whether the slow lifecycle specs (controller restart, GC
// churn) are enabled via the E2E_LONG environment variable. CI sets it only on
// push events and manual dispatch so PRs skip them.
func e2eLong() bool {
	v := strings.ToLower(os.Getenv("E2E_LONG"))
	return v != "" && v != "0" && v != "false"
}

// skipUnlessLong skips the current spec unless E2E_LONG opts in.
func skipUnlessLong() {
	GinkgoHelper()
	if !e2eLong() {
		Skip("slow lifecycle spec; set E2E_LONG=1 to enable")
	}
}

// backend returns the configured NetworkPolicy backend, defaulting to iptables
// when BACKEND is unset. Used to gate backend-specific specs such as the
// nftables chain-GC test.
func backend() string {
	if b := os.Getenv("BACKEND"); b != "" {
		return b
	}
	return "iptables"
}

// kubeRouterPods returns the current list of kube-router pods in kube-system.
func kubeRouterPods() []corev1.Pod {
	GinkgoHelper()
	pods, err := k8sClient.CoreV1().Pods(kubeSystemNS).List(context.Background(),
		metav1.ListOptions{LabelSelector: kubeRouterLabelSelector})
	Expect(err).NotTo(HaveOccurred(), "list kube-router pods")
	return pods.Items
}

// ---------------------------------------------------------------------------
// Set inspection helpers
// ---------------------------------------------------------------------------

// kubeRouterSetsHolding returns "<kube-router pod>: <set>" for every set or map, on any node, with ip as an element.
// We read both `ipset save` and `nft list ruleset` so that it works the same against either backend.
func kubeRouterSetsHolding(ip string) []string {
	GinkgoHelper()
	want, err := netip.ParseAddr(ip)
	Expect(err).NotTo(HaveOccurred(), "parse IP %q", ip)

	var holders []string
	for _, kr := range kubeRouterPods() {
		for _, cmd := range [][]string{{"ipset", "save"}, {"nft", "list", "ruleset"}} {
			stdout, _, _, execErr := execInPod(kubeSystemNS, kr.Name, "kube-router", cmd)
			if execErr != nil {
				continue
			}
			for _, set := range setsHolding(stdout, want) {
				holders = append(holders, kr.Name+": "+set)
			}
		}
	}
	return holders
}

// setsHolding walks `ipset save` or `nft list ruleset` output and returns the names of the sets and maps that have
// want as an element. Addresses in rules don't count.
func setsHolding(output string, want netip.Addr) []string {
	isWant := func(tok string) bool {
		if prefix, err := netip.ParsePrefix(tok); err == nil {
			return prefix.IsSingleIP() && prefix.Addr() == want
		}
		addr, err := netip.ParseAddr(tok)
		return err == nil && addr == want
	}

	var sets []string
	current := ""
	for line := range strings.SplitSeq(output, "\n") {
		trimmed := strings.TrimSpace(line)
		// Splitting on commas and braces too pulls bare addresses out of nft element lists and ipset ip,port entries
		fields := strings.FieldsFunc(trimmed, func(r rune) bool {
			return unicode.IsSpace(r) || r == ',' || r == '{' || r == '}'
		})
		name := ""
		switch {
		case len(fields) >= 3 && fields[0] == "add":
			// ipset save: add <set> <entry> [options]
			if isWant(fields[2]) {
				name = fields[1]
			}
		case len(fields) >= 2 && (fields[0] == "set" || fields[0] == "map") && strings.HasSuffix(trimmed, "{"):
			current = fields[1]
		case trimmed == "}":
			current = ""
		case current != "" && slices.ContainsFunc(fields, isWant):
			name = current
		}
		if name != "" && !slices.Contains(sets, name) {
			sets = append(sets, name)
		}
	}
	return sets
}

// ---------------------------------------------------------------------------
// Suite-level log health check
// ---------------------------------------------------------------------------

// syncErrorMarkers are substrings kube-router logs when a NetworkPolicy sync
// fails to apply cleanly - a sync abort, a top-level chain rebuild failure, or
// an nftables transaction failure. Any of them appearing after the suite
// started means enforcement may have silently diverged from desired state.
var syncErrorMarkers = []string{
	"Aborting sync",
	"failed to ensure top level chains",
	"failed to atomically rebuild top-level chains",
	// Isolated per-policy failures no longer abort the sync, so match their log line directly
	"failed to sync policy chain",
}

// assertNoSyncErrors fails the suite if any kube-router pod logged one of the
// syncErrorMarkers since the given time. Scoping to the suite start keeps
// pre-existing noise on a reused cluster from false-positiving.
func assertNoSyncErrors(ctx context.Context, since time.Time) {
	GinkgoHelper()
	pods, err := k8sClient.CoreV1().Pods(kubeSystemNS).List(ctx,
		metav1.ListOptions{LabelSelector: kubeRouterLabelSelector})
	Expect(err).NotTo(HaveOccurred(), "list kube-router pods for log health check")

	sinceTime := metav1.NewTime(since)
	var offenders []string
	for i := range pods.Items {
		pod := &pods.Items[i]
		req := k8sClient.CoreV1().Pods(kubeSystemNS).GetLogs(pod.Name, &corev1.PodLogOptions{
			SinceTime: &sinceTime,
		})
		rc, streamErr := req.Stream(ctx)
		if streamErr != nil {
			GinkgoWriter.Printf("[health] GetLogs(%s): %v\n", pod.Name, streamErr)
			continue
		}
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rc)
		rc.Close()
		for line := range strings.SplitSeq(buf.String(), "\n") {
			for _, marker := range syncErrorMarkers {
				if strings.Contains(line, marker) {
					offenders = append(offenders,
						fmt.Sprintf("%s: %s", pod.Name, strings.TrimSpace(line)))
				}
			}
		}
	}
	Expect(offenders).To(BeEmpty(),
		"kube-router logged NetworkPolicy sync failures during the suite:\n%s",
		strings.Join(offenders, "\n"))
}
