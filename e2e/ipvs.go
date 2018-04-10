package e2e

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"golang.org/x/crypto/ssh"

	apps_v1beta2 "k8s.io/api/apps/v1beta2"
	v1core "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

var _ = Describe("IPVS E2E", func() {
	var clientset kubernetes.Interface
	var nodes *v1core.NodeList
	var appName string
	var testsvc *v1core.Service
	var testdeploy *apps_v1beta2.Deployment
	var sshConfig *ssh.ClientConfig
	var err error

	BeforeEach(func() {
		clientset, err = clientFromKubeConfig()
		if err != nil {
			Fail(fmt.Sprintf("failed to setup clientset from kubeconfig: %s", err))
		}

		nodes, err = clientset.CoreV1().Nodes().List(meta_v1.ListOptions{})
		if err != nil {
			Fail(fmt.Sprintf("failed to get cluster nodes: %v", err))
		}

		sshConfig, err = newSSHClientConfig()
		if err != nil {
			Fail(fmt.Sprintf("failed to create ssh client config: %s", err))
		}
	})
	Context("IPVS with no backends", func() {
		BeforeEach(func() {
			appName = "test-" + randStringRunes(5)

			testsvc = generateSvc(appName)
			testsvc, err = clientset.CoreV1().Services(meta_v1.NamespaceDefault).Create(testsvc)
			if err != nil {
				Fail(fmt.Sprintf("failed to create test service: %v", err))
			}
		})
		It("should have the correct IPVS", func() {
			defer func() {
				clientset.CoreV1().Services(meta_v1.NamespaceDefault).Delete(testsvc.Name, &meta_v1.DeleteOptions{})
			}()

			for _, node := range nodes.Items {
				nodeIP, err := getNodePublicIP(node)
				if err != nil {
					Fail(fmt.Sprintf("failed to get node public IP: %s", err))
				}

				expectedOutput := fmt.Sprintf("TCP  %s:80 rr", testsvc.Spec.ClusterIP)

				ipvsOutput, err := executeSSHCmd("sudo ipvsadm --list --numeric", nodeIP, sshConfig)
				Expect(err).To(Succeed())

				if !strings.Contains(strings.TrimSpace(ipvsOutput), expectedOutput) {
					fmt.Fprintf(GinkgoWriter, fmt.Sprintf("expected IPVS output to contain: \n%s\n", expectedOutput))
					fmt.Fprintf(GinkgoWriter, fmt.Sprintf("actual IPVS output: \n%s\n", ipvsOutput))
					Fail("unexpected IPVS output")
				}
			}
		})

	})
	Context("IPVS with backends", func() {
		BeforeEach(func() {
			appName = "test-" + randStringRunes(5)

			testsvc = generateSvc(appName)
			testsvc, err = clientset.CoreV1().Services(meta_v1.NamespaceDefault).Create(testsvc)
			if err != nil {
				Fail(fmt.Sprintf("failed to create test service: %v", err))
			}

			testdeploy = generateDeploy(appName)
			testdeploy, err = clientset.AppsV1beta2().Deployments(meta_v1.NamespaceDefault).Create(testdeploy)
			if err != nil {
				Fail(fmt.Sprintf("failed to create test deployment: %v", err))
			}
			if err := waitForDeploymentWithTimeout(clientset, appName, 2*time.Minute); err != nil {
				Fail(fmt.Sprintf("failed waiting for deployment to finish: %v", err))
			}
		})

		It("should have the correct IPVS", func() {
			defer func() {
				clientset.CoreV1().Services(meta_v1.NamespaceDefault).Delete(testsvc.Name, &meta_v1.DeleteOptions{})
				clientset.AppsV1beta2().Deployments(meta_v1.NamespaceDefault).Delete(testdeploy.Name, &meta_v1.DeleteOptions{})
			}()

			for _, node := range nodes.Items {
				nodeIP, err := getNodePublicIP(node)
				if err != nil {
					Fail(fmt.Sprintf("failed to get node public IP: %s", err))
				}

				podIPs, err := getPodsIPsForApp(clientset, appName)
				if err != nil {
					Fail(fmt.Sprintf("failed to get pods for app %s, err: %s", appName, err))
				}

				expectedOutput := fmt.Sprintf("TCP  %s:80 rr", testsvc.Spec.ClusterIP)
				for _, podIP := range podIPs {
					expectedOutput += fmt.Sprintf("\n  -> %s:80                Masq    1      0          0         ", podIP)
				}

				ipvsOutput, err := executeSSHCmd("sudo ipvsadm --list --numeric", nodeIP, sshConfig)
				Expect(err).To(Succeed())

				if !strings.Contains(ipvsOutput, expectedOutput) {
					fmt.Fprintf(GinkgoWriter, fmt.Sprintf("expected IPVS output to contain: \n%s\n", expectedOutput))
					fmt.Fprintf(GinkgoWriter, fmt.Sprintf("actual IPVS output: \n%s\n", ipvsOutput))
					Fail("unexpected IPVS output")
				}
			}
		})

	})
})

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")

func generateSvc(name string) *v1core.Service {
	return &v1core.Service{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: meta_v1.NamespaceDefault,
		},
		Spec: v1core.ServiceSpec{
			Ports: []v1core.ServicePort{
				{
					Name:       "80-tcp",
					Port:       int32(80),
					TargetPort: intstr.FromInt(80),
					Protocol:   "TCP",
				},
			},
			Selector: map[string]string{
				"app": name,
			},
		},
	}
}

func generateDeploy(name string) *apps_v1beta2.Deployment {
	return &apps_v1beta2.Deployment{
		TypeMeta: meta_v1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"app": name,
			},
			Namespace: meta_v1.NamespaceDefault,
		},
		Spec: apps_v1beta2.DeploymentSpec{
			Replicas: int32Ptr(2),
			Selector: &meta_v1.LabelSelector{
				MatchLabels: map[string]string{
					"app": name,
				},
			},
			Template: v1core.PodTemplateSpec{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: name,
					Labels: map[string]string{
						"app": name,
					},
				},
				Spec: v1core.PodSpec{
					Containers: []v1core.Container{
						{
							Name:  name,
							Image: "nginx:1.7.9",
							Ports: []v1core.ContainerPort{
								{
									ContainerPort: int32(80),
								},
							},
						},
					},
				},
			},
		},
	}
}

func getPodsIPsForApp(clientset kubernetes.Interface, appName string) ([]string, error) {
	pods, err := clientset.CoreV1().Pods(meta_v1.NamespaceDefault).List(meta_v1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", appName),
	})
	if err != nil {
		return nil, fmt.Errorf("error listing pods: %s", err)
	}

	var ips []string
	for _, pod := range pods.Items {
		if pod.Status.PodIP == "" {
			return nil, fmt.Errorf("pod %s did not have an IP", pod.Name)
		}
		ips = append(ips, pod.Status.PodIP)
	}

	sort.Strings(ips)
	return ips, nil
}

func waitForDeploymentWithTimeout(clientset kubernetes.Interface, deployment string, timeout time.Duration) error {
	tick := time.Tick(1 * time.Second)
	timeoutCh := time.After(timeout)
	for {
		select {
		case <-timeoutCh:
			return fmt.Errorf("timed out waiting for deployment %s to finish", deployment)
		case <-tick:
			deploy, err := clientset.AppsV1beta2().Deployments(meta_v1.NamespaceDefault).Get(deployment, meta_v1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to check deployment status: %s", err)
			}

			if deploy.Status.Replicas == deploy.Status.ReadyReplicas {
				return nil
			}
		}
	}
}

func int32Ptr(val int32) *int32 {
	return &val
}

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
