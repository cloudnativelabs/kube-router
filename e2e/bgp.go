package e2e

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	v1core "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var _ = Describe("BGP E2E", func() {

	Context("BGP config", func() {
		var clientset kubernetes.Interface
		var nodes *v1core.NodeList
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
		})

		It("should have the correct number of neighbours", func() {
			expectedNeighbours := len(nodes.Items) - 1
			for _, node := range nodes.Items {
				ip, err := getNodePublicIP(node)
				if err != nil {
					Fail(fmt.Sprintf("could not find public IP for node %s, err: %s", ip, err))
				}

				bgpClient, err := newBGPClient(ip)
				if err != nil {
					Fail(fmt.Sprintf("failed to setup bgp client: %s", err))
				}
				defer bgpClient.Close()

				neighbors, err := bgpClient.ListNeighbor()
				Expect(neighbors).To(HaveLen(expectedNeighbours))
				Expect(err).To(Succeed())
			}
		})

	})
})
