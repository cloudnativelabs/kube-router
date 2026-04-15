package netpol_e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

const (
	testImage = "registry.k8s.io/e2e-test-images/agnhost:2.43"

	serverPort = 8080
	altPort    = 8081

	// pollTimeout is the maximum time to wait for a connectivity state to be
	// reached after a NetworkPolicy is applied or deleted.
	pollTimeout = 60 * time.Second
	// pollInterval is the retry cadence used by Eventually/Consistently.
	pollInterval = 2 * time.Second
	// consistentlyDuration is how long Consistently checks for stable blocking.
	consistentlyDuration = 10 * time.Second
)

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
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "server",
				Image: testImage,
				Args:  []string{"serve-hostname", "--http=false", "--tcp=true", fmt.Sprintf("--port=%d", port)},
			}},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}
	created, err := k8sClient.CoreV1().Pods(ns).Create(context.Background(), p, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "create server pod")
	DeferCleanup(deletePod, ns, name)
	return waitForRunning(ns, created.Name)
}

// launchClient creates a long-running sleep pod used as the connectivity probe
// source and waits for it to reach Running phase.
func launchClient(ns, name string, labels map[string]string) *corev1.Pod {
	GinkgoHelper()
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "client",
				Image:   testImage,
				Command: []string{"/bin/sleep"},
				Args:    []string{"3600"},
			}},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}
	created, err := k8sClient.CoreV1().Pods(ns).Create(context.Background(), p, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "create client pod")
	DeferCleanup(deletePod, ns, name)
	return waitForRunning(ns, created.Name)
}

// waitForRunning polls until pod phase is Running, then returns the latest pod
// object (with IPs populated).
func waitForRunning(ns, name string) *corev1.Pod {
	GinkgoHelper()
	var pod *corev1.Pod
	Eventually(func() bool {
		var err error
		pod, err = k8sClient.CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		return pod.Status.Phase == corev1.PodRunning
	}, pollTimeout, pollInterval).Should(BeTrue(), "pod %s/%s to reach Running", ns, name)
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

// canConnect runs `nc -zw2 <ip> <port>` inside clientPod's container and
// returns true if the connection succeeds (exit code 0).
func canConnect(clientPod *corev1.Pod, dstIP string, port int) bool {
	GinkgoHelper()
	cmd := []string{"nc", "-zw2", dstIP, fmt.Sprintf("%d", port)}
	stdout, stderr, exitCode, err := execInPod(clientPod.Namespace, clientPod.Name, "client", cmd)
	connected := err == nil && exitCode == 0
	GinkgoWriter.Printf("[probe] %s/%s → %s:%d  connected=%v (exit=%d err=%v stdout=%q stderr=%q)\n",
		clientPod.Namespace, clientPod.Name, dstIP, port, connected, exitCode, err,
		strings.TrimSpace(stdout), strings.TrimSpace(stderr))
	return connected
}

// assertConnected polls until a connection from clientPod to dstIP:port
// succeeds, or fails the spec after pollTimeout.
func assertConnected(clientPod *corev1.Pod, dstIP string, port int) {
	GinkgoHelper()
	GinkgoWriter.Printf("[assert] assertConnected: pod %s/%s → %s:%d (timeout=%s)\n",
		clientPod.Namespace, clientPod.Name, dstIP, port, pollTimeout)
	Eventually(func() bool {
		return canConnect(clientPod, dstIP, port)
	}, pollTimeout, pollInterval).Should(BeTrue(),
		"expected %s to be reachable from pod %s/%s",
		fmt.Sprintf("%s:%d", dstIP, port), clientPod.Namespace, clientPod.Name)
}

// assertBlocked verifies that traffic from clientPod to dstIP:port is
// consistently blocked throughout consistentlyDuration. The check is run
// after a brief initial wait (one poll interval) so that kube-router has had
// time to program the policy.
func assertBlocked(clientPod *corev1.Pod, dstIP string, port int) {
	GinkgoHelper()
	GinkgoWriter.Printf("[assert] assertBlocked: pod %s/%s → %s:%d (for=%s)\n",
		clientPod.Namespace, clientPod.Name, dstIP, port, consistentlyDuration)
	// Give kube-router time to sync before sampling.
	time.Sleep(pollInterval)
	Consistently(func() bool {
		return canConnect(clientPod, dstIP, port)
	}, consistentlyDuration, pollInterval).Should(BeFalse(),
		"expected %s to be BLOCKED from pod %s/%s",
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
		// remotecommand wraps non-zero exit codes as errors; treat them as
		// connection failures rather than fatal test errors.
		exitCode = 1
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
func tcpPortRange(start, end int) netv1.NetworkPolicyPort {
	proto := corev1.ProtocolTCP
	p := intstr.FromInt(start)
	e := int32(end)
	return netv1.NetworkPolicyPort{Protocol: &proto, Port: &p, EndPort: &e}
}

// namedTCPPort returns a *netv1.NetworkPolicyPort for a named TCP port.
func namedTCPPort(name string) netv1.NetworkPolicyPort {
	proto := corev1.ProtocolTCP
	p := intstr.FromString(name)
	return netv1.NetworkPolicyPort{Protocol: &proto, Port: &p}
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
