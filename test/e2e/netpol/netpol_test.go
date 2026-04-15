package netpol_e2e

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var _ = Describe("NetworkPolicy", func() {

	// -----------------------------------------------------------------------
	// 3a. Default-deny semantics
	// -----------------------------------------------------------------------

	Describe("default-deny semantics", func() {

		// Test 55
		It("blocks non-matching inbound traffic when an ingress PolicyType is applied", func() {
			serverNS := createNamespace(nil)
			clientNS := createNamespace(nil)

			server := launchServer(serverNS.Name, "server", map[string]string{"app": "server"})
			client := launchClient(clientNS.Name, "client", map[string]string{"app": "client"})

			// Pre-policy baseline.
			assertConnected(client, podIPv4(server), serverPort)

			// Deny-all ingress (no ingress rules).
			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "deny-all-ingress", Namespace: serverNS.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
				},
			})
			assertBlocked(client, podIPv4(server), serverPort)
		})

		// Test 56
		It("blocks non-matching outbound traffic when an egress PolicyType is applied", func() {
			clientNS := createNamespace(nil)
			serverNS := createNamespace(nil)

			server := launchServer(serverNS.Name, "server", map[string]string{"app": "server"})
			client := launchClient(clientNS.Name, "client", map[string]string{"app": "client"})

			assertConnected(client, podIPv4(server), serverPort)

			// Deny-all egress from the client pod.
			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "deny-all-egress", Namespace: clientNS.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
				},
			})
			assertBlocked(client, podIPv4(server), serverPort)
		})

		// Test 57
		It("allows all traffic for pods not selected by any policy", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})
			assertConnected(client, podIPv4(server), serverPort)
		})
	})

	// -----------------------------------------------------------------------
	// 3b. Ingress rules
	// -----------------------------------------------------------------------

	Describe("ingress rules", func() {

		// Test 58
		It("allows traffic from a matching podSelector and blocks non-matching pods", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			allowed := launchClient(ns.Name, "allowed", map[string]string{"role": "allowed"})
			denied := launchClient(ns.Name, "denied", map[string]string{"role": "denied"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "ingress-pod-selector", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{{
						From: []netv1.NetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "allowed"}},
						}},
					}},
				},
			})
			assertConnected(allowed, podIPv4(server), serverPort)
			assertBlocked(denied, podIPv4(server), serverPort)
		})

		// Test 59
		It("allows traffic from a matching namespaceSelector and blocks other namespaces", func() {
			serverNS := createNamespace(nil)
			allowedNS := createNamespace(map[string]string{"team": "allowed"})
			blockedNS := createNamespace(map[string]string{"team": "blocked"})

			server := launchServer(serverNS.Name, "server", map[string]string{"app": "server"})
			allowed := launchClient(allowedNS.Name, "client", map[string]string{"app": "client"})
			blocked := launchClient(blockedNS.Name, "client", map[string]string{"app": "client"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "ingress-ns-selector", Namespace: serverNS.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{{
						From: []netv1.NetworkPolicyPeer{{
							NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "allowed"}},
						}},
					}},
				},
			})
			assertConnected(allowed, podIPv4(server), serverPort)
			assertBlocked(blocked, podIPv4(server), serverPort)
		})

		// Test 60
		It("requires both namespaceSelector AND podSelector to match (AND semantics)", func() {
			serverNS := createNamespace(nil)
			targetNS := createNamespace(map[string]string{"team": "frontend"})

			server := launchServer(serverNS.Name, "server", map[string]string{"app": "server"})
			// Correct namespace + correct pod label → allowed.
			allowed := launchClient(targetNS.Name, "good-client", map[string]string{"role": "web"})
			// Correct namespace, wrong pod label → blocked.
			wrongPod := launchClient(targetNS.Name, "bad-client", map[string]string{"role": "db"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "ingress-ns-and-pod", Namespace: serverNS.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{{
						From: []netv1.NetworkPolicyPeer{{
							NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "frontend"}},
							PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"role": "web"}},
						}},
					}},
				},
			})
			assertConnected(allowed, podIPv4(server), serverPort)
			assertBlocked(wrongPod, podIPv4(server), serverPort)
		})

		// Test 61
		It("allows traffic from IPs inside an ipBlock CIDR", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			clientIP := podIPv4(client)
			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "ingress-ipblock", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{{
						From: []netv1.NetworkPolicyPeer{{
							IPBlock: &netv1.IPBlock{CIDR: clientIP + "/32"},
						}},
					}},
				},
			})
			// The one IP that is in the /32 must be allowed.
			assertConnected(client, podIPv4(server), serverPort)
		})

		// Test 62
		It("blocks traffic from IPs listed in the ipBlock Except field", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			allowed := launchClient(ns.Name, "allowed", map[string]string{"role": "allowed"})
			denied := launchClient(ns.Name, "denied", map[string]string{"role": "denied"})

			deniedIP := podIPv4(denied)
			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "ingress-ipblock-except", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{{
						From: []netv1.NetworkPolicyPeer{{
							IPBlock: &netv1.IPBlock{
								CIDR:   "0.0.0.0/0",
								Except: []string{deniedIP + "/32"},
							},
						}},
					}},
				},
			})
			assertConnected(allowed, podIPv4(server), serverPort)
			assertBlocked(denied, podIPv4(server), serverPort)
		})

		// Test 63
		It("allows only the specified TCP port and blocks other ports", func() {
			ns := createNamespace(nil)
			// serverAllowed listens on serverPort (the policy-allowed port) so
			// assertConnected can complete a real TCP handshake.
			// serverBlocked listens on altPort (the policy-blocked port) so
			// assertBlocked verifies a genuine DROP rather than a vacuous
			// ECONNREFUSED from a missing listener.
			serverAllowed := launchServer(ns.Name, "server-allowed", map[string]string{"app": "server"})
			serverBlocked := launchServerOnPort(ns.Name, "server-blocked", map[string]string{"app": "server"}, altPort)
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "ingress-specific-port", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{{
						Ports: []netv1.NetworkPolicyPort{tcpPort(serverPort)},
					}},
				},
			})
			assertConnected(client, podIPv4(serverAllowed), serverPort)
			assertBlocked(client, podIPv4(serverBlocked), altPort)
		})

		// Test 64
		It("allows traffic within a port range and blocks ports outside the range", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "ingress-port-range", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{{
						Ports: []netv1.NetworkPolicyPort{tcpPortRange(serverPort, serverPort+10)},
					}},
				},
			})
			// Start of range: allowed.
			assertConnected(client, podIPv4(server), serverPort)
			// Beyond end of range: blocked.
			assertBlocked(client, podIPv4(server), serverPort+11)
		})

		// Test 65
		It("resolves a named port and allows traffic to it", func() {
			ns := createNamespace(nil)

			// Server pod with an explicitly named container port.
			serverPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "server",
					Namespace: ns.Name,
					Labels:    map[string]string{"app": "server"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "server",
						Image: testImage,
						Args:  []string{"serve-hostname", "--http=false", "--tcp=true", fmt.Sprintf("--port=%d", serverPort)},
						Ports: []corev1.ContainerPort{{
							Name:          "http-named",
							ContainerPort: serverPort,
							Protocol:      corev1.ProtocolTCP,
						}},
					}},
					RestartPolicy: corev1.RestartPolicyNever,
				},
			}
			_, err := k8sClient.CoreV1().Pods(ns.Name).Create(context.Background(), serverPod, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(deletePod, ns.Name, "server")
			server := waitForRunning(ns.Name, "server")

			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "ingress-named-port", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{{
						Ports: []netv1.NetworkPolicyPort{namedTCPPort("http-named")},
					}},
				},
			})
			assertConnected(client, podIPv4(server), serverPort)
		})

		// Test 66
		It("allows all inbound traffic when ingress rule list contains an empty rule", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			// First establish deny-all, then override with allow-all.
			applyPolicy(denyAllIngress(ns.Name, "deny-all", metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "server"},
			}))
			assertBlocked(client, podIPv4(server), serverPort)

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "allow-all-ingress", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress:     []netv1.NetworkPolicyIngressRule{{}},
				},
			})
			assertConnected(client, podIPv4(server), serverPort)
		})
	})

	// -----------------------------------------------------------------------
	// 3c. Egress rules
	// -----------------------------------------------------------------------

	Describe("egress rules", func() {

		// Test 67
		It("allows egress to a matching podSelector and blocks non-matching pods", func() {
			ns := createNamespace(nil)
			allowed := launchServer(ns.Name, "allowed-server", map[string]string{"role": "allowed"})
			blocked := launchServer(ns.Name, "blocked-server", map[string]string{"role": "blocked"})
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "egress-pod-selector", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
					Egress: []netv1.NetworkPolicyEgressRule{{
						To: []netv1.NetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "allowed"}},
						}},
					}},
				},
			})
			assertConnected(client, podIPv4(allowed), serverPort)
			assertBlocked(client, podIPv4(blocked), serverPort)
		})

		// Test 68
		It("allows egress to a matching namespaceSelector and blocks other namespaces", func() {
			clientNS := createNamespace(nil)
			allowedNS := createNamespace(map[string]string{"env": "prod"})
			blockedNS := createNamespace(map[string]string{"env": "dev"})

			client := launchClient(clientNS.Name, "client", map[string]string{"app": "client"})
			allowed := launchServer(allowedNS.Name, "server", map[string]string{"app": "server"})
			blocked := launchServer(blockedNS.Name, "server", map[string]string{"app": "server"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "egress-ns-selector", Namespace: clientNS.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
					Egress: []netv1.NetworkPolicyEgressRule{{
						To: []netv1.NetworkPolicyPeer{{
							NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
						}},
					}},
				},
			})
			assertConnected(client, podIPv4(allowed), serverPort)
			assertBlocked(client, podIPv4(blocked), serverPort)
		})

		// Test 69
		It("requires both namespaceSelector AND podSelector to match for egress (AND semantics)", func() {
			clientNS := createNamespace(nil)
			targetNS := createNamespace(map[string]string{"env": "prod"})

			client := launchClient(clientNS.Name, "client", map[string]string{"app": "client"})
			allowed := launchServer(targetNS.Name, "allowed-server", map[string]string{"tier": "web"})
			blocked := launchServer(targetNS.Name, "blocked-server", map[string]string{"tier": "db"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "egress-combined", Namespace: clientNS.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
					Egress: []netv1.NetworkPolicyEgressRule{{
						To: []netv1.NetworkPolicyPeer{{
							NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
							PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "web"}},
						}},
					}},
				},
			})
			assertConnected(client, podIPv4(allowed), serverPort)
			assertBlocked(client, podIPv4(blocked), serverPort)
		})

		// Test 70
		It("allows egress to a destination inside an ipBlock CIDR", func() {
			ns := createNamespace(nil)
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})

			serverIP := podIPv4(server)
			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "egress-ipblock", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
					Egress: []netv1.NetworkPolicyEgressRule{{
						To: []netv1.NetworkPolicyPeer{{
							IPBlock: &netv1.IPBlock{CIDR: serverIP + "/32"},
						}},
					}},
				},
			})
			assertConnected(client, serverIP, serverPort)
		})

		// Test 71
		It("blocks egress to IPs listed in ipBlock Except for egress", func() {
			ns := createNamespace(nil)
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})
			allowed := launchServer(ns.Name, "allowed-server", map[string]string{"role": "allowed"})
			blocked := launchServer(ns.Name, "blocked-server", map[string]string{"role": "blocked"})

			blockedIP := podIPv4(blocked)
			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "egress-ipblock-except", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
					Egress: []netv1.NetworkPolicyEgressRule{{
						To: []netv1.NetworkPolicyPeer{{
							IPBlock: &netv1.IPBlock{
								CIDR:   "0.0.0.0/0",
								Except: []string{blockedIP + "/32"},
							},
						}},
					}},
				},
			})
			assertConnected(client, podIPv4(allowed), serverPort)
			assertBlocked(client, blockedIP, serverPort)
		})

		// Test 72
		It("allows egress to a specific port only and blocks other ports", func() {
			ns := createNamespace(nil)
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})
			// serverAllowed listens on serverPort (the policy-allowed port) so
			// assertConnected can complete a real TCP handshake.
			// serverBlocked listens on altPort (the policy-blocked port) so
			// assertBlocked verifies a genuine DROP rather than a vacuous
			// ECONNREFUSED from a missing listener.
			serverAllowed := launchServer(ns.Name, "server-allowed", map[string]string{"app": "server"})
			serverBlocked := launchServerOnPort(ns.Name, "server-blocked", map[string]string{"app": "server"}, altPort)

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "egress-specific-port", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
					Egress: []netv1.NetworkPolicyEgressRule{{
						Ports: []netv1.NetworkPolicyPort{tcpPort(serverPort)},
					}},
				},
			})
			assertConnected(client, podIPv4(serverAllowed), serverPort)
			assertBlocked(client, podIPv4(serverBlocked), altPort)
		})

		// Test 73
		It("allows egress within a port range and blocks ports outside the range", func() {
			ns := createNamespace(nil)
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "egress-port-range", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
					Egress: []netv1.NetworkPolicyEgressRule{{
						Ports: []netv1.NetworkPolicyPort{tcpPortRange(serverPort, serverPort+10)},
					}},
				},
			})
			assertConnected(client, podIPv4(server), serverPort)
			assertBlocked(client, podIPv4(server), serverPort+11)
		})

		// Test 74
		It("resolves a named port for egress and allows traffic to it", func() {
			ns := createNamespace(nil)

			serverPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "server",
					Namespace: ns.Name,
					Labels:    map[string]string{"app": "server"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "server",
						Image: testImage,
						Args:  []string{"serve-hostname", "--http=false", "--tcp=true", fmt.Sprintf("--port=%d", serverPort)},
						Ports: []corev1.ContainerPort{{
							Name:          "grpc",
							ContainerPort: serverPort,
							Protocol:      corev1.ProtocolTCP,
						}},
					}},
					RestartPolicy: corev1.RestartPolicyNever,
				},
			}
			_, err := k8sClient.CoreV1().Pods(ns.Name).Create(context.Background(), serverPod, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(deletePod, ns.Name, "server")
			server := waitForRunning(ns.Name, "server")

			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "egress-named-port", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
					Egress: []netv1.NetworkPolicyEgressRule{{
						To: []netv1.NetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
						}},
						Ports: []netv1.NetworkPolicyPort{namedTCPPort("grpc")},
					}},
				},
			})
			assertConnected(client, podIPv4(server), serverPort)
		})

		// Test 75
		It("allows all egress when egress rule list contains an empty rule", func() {
			ns := createNamespace(nil)
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})

			// Deny-all egress first.
			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "deny-all-egress", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
				},
			})
			assertBlocked(client, podIPv4(server), serverPort)

			// Allow-all egress overrides.
			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "allow-all-egress", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
					Egress:      []netv1.NetworkPolicyEgressRule{{}},
				},
			})
			assertConnected(client, podIPv4(server), serverPort)
		})
	})

	// -----------------------------------------------------------------------
	// 3d. Interaction / compound scenarios
	// -----------------------------------------------------------------------

	Describe("interaction and compound scenarios", func() {

		// Test 76
		It("allows traffic matching ANY of multiple ingress rules (OR semantics)", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			clientA := launchClient(ns.Name, "client-a", map[string]string{"group": "a"})
			clientB := launchClient(ns.Name, "client-b", map[string]string{"group": "b"})
			denied := launchClient(ns.Name, "denied", map[string]string{"group": "c"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "multi-ingress", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{
						{From: []netv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"group": "a"}}}}},
						{From: []netv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"group": "b"}}}}},
					},
				},
			})
			assertConnected(clientA, podIPv4(server), serverPort)
			assertConnected(clientB, podIPv4(server), serverPort)
			assertBlocked(denied, podIPv4(server), serverPort)
		})

		// Test 77
		It("allows traffic allowed by ANY of multiple policies (OR across policies)", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			clientA := launchClient(ns.Name, "client-a", map[string]string{"group": "a"})
			clientB := launchClient(ns.Name, "client-b", map[string]string{"group": "b"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "pol-a", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{{
						From: []netv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"group": "a"}}}},
					}},
				},
			})
			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "pol-b", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{{
						From: []netv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"group": "b"}}}},
					}},
				},
			})
			assertConnected(clientA, podIPv4(server), serverPort)
			assertConnected(clientB, podIPv4(server), serverPort)
		})

		// Test 78
		It("does not restrict egress when only an ingress policyType is applied to a pod", func() {
			ns := createNamespace(nil)
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})

			// Deny all INGRESS to the client pod; its own EGRESS must be unaffected.
			applyPolicy(denyAllIngress(ns.Name, "deny-client-ingress",
				metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}))

			assertConnected(client, podIPv4(server), serverPort)
		})

		// Test 79
		It("does not restrict ingress when only an egress policyType is applied to a pod", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			// Deny all EGRESS from the server pod; inbound connections must still arrive.
			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "deny-server-egress", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
				},
			})
			assertConnected(client, podIPv4(server), serverPort)
		})

		// Test 80
		It("restores traffic after a NetworkPolicy is deleted", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			applyPolicy(denyAllIngress(ns.Name, "block-all",
				metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}}))
			assertBlocked(client, podIPv4(server), serverPort)

			deletePolicy(ns.Name, "block-all")
			assertConnected(client, podIPv4(server), serverPort)
		})

		// Test 81
		It("enforces policy when pod labels are changed to match a selector", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			// Client starts with a label that does NOT match the allowed selector.
			client := launchClient(ns.Name, "client", map[string]string{"app": "other"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "label-change-test", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{{
						From: []netv1.NetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "privileged"}},
						}},
					}},
				},
			})
			assertBlocked(client, podIPv4(server), serverPort)

			// Re-label: add "role=privileged".
			client = patchPodLabels(client, map[string]string{"app": "other", "role": "privileged"})
			assertConnected(client, podIPv4(server), serverPort)
		})

		// Test 82
		It("enforces policy when namespace labels are changed to match a namespaceSelector", func() {
			serverNS := createNamespace(nil)
			// Client namespace starts with a label that does NOT match env=prod.
			clientNS := createNamespace(map[string]string{"env": "staging"})

			server := launchServer(serverNS.Name, "server", map[string]string{"app": "server"})
			client := launchClient(clientNS.Name, "client", map[string]string{"app": "client"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "ns-label-change", Namespace: serverNS.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{{
						From: []netv1.NetworkPolicyPeer{{
							NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
						}},
					}},
				},
			})
			assertBlocked(client, podIPv4(server), serverPort)

			// Re-label the namespace to env=prod.
			patchNamespaceLabels(clientNS, map[string]string{"env": "prod"})
			// Allow extra sync time for kube-router to pick up the namespace change.
			time.Sleep(pollInterval * 2)
			assertConnected(client, podIPv4(server), serverPort)
		})
	})

	// -----------------------------------------------------------------------
	// 3e. Dual-stack / IPv6
	// -----------------------------------------------------------------------

	Describe("dual-stack and IPv6", func() {

		// Test 83/84
		It("enforces policy independently on IPv4 and IPv6 addresses of the same pod", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			serverPodFull, err := k8sClient.CoreV1().Pods(ns.Name).Get(
				context.Background(), server.Name, metav1.GetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			var ipv4Addr, ipv6Addr string
			for _, pip := range serverPodFull.Status.PodIPs {
				if !strings.Contains(pip.IP, ":") && ipv4Addr == "" {
					ipv4Addr = pip.IP
				} else if strings.Contains(pip.IP, ":") && ipv6Addr == "" {
					ipv6Addr = pip.IP
				}
			}
			if ipv4Addr == "" {
				Skip("server pod has no IPv4 address")
			}

			// IPv4 must be reachable.
			assertConnected(client, ipv4Addr, serverPort)

			// IPv6 — skip gracefully if cluster is not dual-stack.
			if ipv6Addr == "" {
				Skip("server pod has no IPv6 address; cluster is not in dual-stack mode")
			}
			assertConnected(client, ipv6Addr, serverPort)
		})

		// Test 85
		It("enforces an IPv6 ipBlock CIDR for ingress", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			clientPodFull, err := k8sClient.CoreV1().Pods(ns.Name).Get(
				context.Background(), client.Name, metav1.GetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			var clientIPv6 string
			for _, pip := range clientPodFull.Status.PodIPs {
				if strings.Contains(pip.IP, ":") {
					clientIPv6 = pip.IP
					break
				}
			}
			if clientIPv6 == "" {
				Skip("client pod has no IPv6 address; cluster is not in dual-stack mode")
			}

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "ipv6-ipblock", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{{
						From: []netv1.NetworkPolicyPeer{{
							IPBlock: &netv1.IPBlock{CIDR: clientIPv6 + "/128"},
						}},
					}},
				},
			})
			assertConnected(client, podIPv4(server), serverPort)
		})
	})

	// -----------------------------------------------------------------------
	// 3f. Host-network pods and completed pods
	// -----------------------------------------------------------------------

	Describe("host-network and special pods", func() {

		// Test 86
		It("does not enforce NetworkPolicy against a host-network pod", func() {
			ns := createNamespace(nil)

			hostPort := int32(19080)
			hostServerPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "host-server",
					Namespace: ns.Name,
					Labels:    map[string]string{"app": "host-server"},
				},
				Spec: corev1.PodSpec{
					HostNetwork: true,
					Containers: []corev1.Container{{
						Name:  "server",
						Image: testImage,
						Args: []string{
							"serve-hostname", "--http=false", "--tcp=true",
							fmt.Sprintf("--port=%d", hostPort),
						},
					}},
					RestartPolicy: corev1.RestartPolicyNever,
				},
			}
			_, err := k8sClient.CoreV1().Pods(ns.Name).Create(
				context.Background(), hostServerPod, metav1.CreateOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(deletePod, ns.Name, "host-server")
			hostServer := waitForRunning(ns.Name, "host-server")

			client := launchClient(ns.Name, "client", map[string]string{"app": "client"})

			// Deny-all ingress policy selecting the host-network pod's labels.
			// kube-router must NOT enforce this against the host-network pod.
			applyPolicy(denyAllIngress(ns.Name, "deny-host-server",
				metav1.LabelSelector{MatchLabels: map[string]string{"app": "host-server"}}))

			// Traffic to the host-network pod must still be allowed.
			assertConnected(client, hostServer.Status.PodIP, int(hostPort))
		})

		// Test 87
		It("removes a completed pod's IP from nftables sets so stale IPs do not grant access", func() {
			ns := createNamespace(nil)
			server := launchServer(ns.Name, "server", map[string]string{"app": "server"})
			allowedClient := launchClient(ns.Name, "allowed-client", map[string]string{"group": "allowed"})

			applyPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "allow-group", Namespace: ns.Name},
				Spec: netv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "server"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
					Ingress: []netv1.NetworkPolicyIngressRule{{
						From: []netv1.NetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"group": "allowed"}},
						}},
					}},
				},
			})
			assertConnected(allowedClient, podIPv4(server), serverPort)

			// Record the IP before deletion.
			originalIP := podIPv4(allowedClient)

			// Delete the allowed client pod.
			grace := int64(0)
			err := k8sClient.CoreV1().Pods(ns.Name).Delete(
				context.Background(), allowedClient.Name,
				metav1.DeleteOptions{GracePeriodSeconds: &grace},
			)
			Expect(err).NotTo(HaveOccurred())

			// Wait for kube-router to sync and purge the stale IP.
			time.Sleep(pollTimeout / 6)

			// Launch a new pod without the matching label. If the CNI re-assigns
			// the same IP and kube-router has correctly removed it from the set,
			// this pod must be blocked.
			recycledPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "recycled",
					Namespace: ns.Name,
					Labels:    map[string]string{"group": "not-allowed"},
				},
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
			_, err = k8sClient.CoreV1().Pods(ns.Name).Create(
				context.Background(), recycledPod, metav1.CreateOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(deletePod, ns.Name, "recycled")
			recycled := waitForRunning(ns.Name, "recycled")

			// If the CNI assigned a different IP the stale-IP scenario cannot be
			// exercised; skip rather than generating a false pass/fail.
			if podIPv4(recycled) != originalIP {
				Skip(fmt.Sprintf(
					"CNI assigned a different IP (%s vs %s); stale-IP scenario is not reproducible",
					podIPv4(recycled), originalIP,
				))
			}
			assertBlocked(recycled, podIPv4(server), serverPort)
		})
	})
})

// Ensure the intstr import is used (named port helper).
var _ = intstr.FromString
