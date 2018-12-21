package service_proxy

import (
	"time"

	. "github.com/cloudnativelabs/kube-router/test/ginkgo-ext"
	"github.com/cloudnativelabs/kube-router/test/helpers"
	. "github.com/onsi/gomega"
)

var _ = Describe("Service-Proxy", func() {

	var kubectlVM1 *helpers.Kubectl
	var kubectlVM2 *helpers.Kubectl

	BeforeAll(func() {
		kubectlVM1 = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		kubectlVM2 = helpers.CreateKubectl(helpers.K8s2VMName(), logger)

		kubectlVM1.ExpectKubeRouterHealthy()
		kubectlVM2.ExpectKubeRouterHealthy()
		kubectlVM1.ExpectGobgpNeighEstabl()
	})

	JustAfterEach(func() {
		// TODO: Duration requires that we upgrade "github.com/onsi/ginkgo" to something more recent.
		// kubectlVM1.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		kubectlVM1.ValidateNoErrorsInLogs(time.Minute)
		kubectlVM2.ValidateNoErrorsInLogs(time.Minute)

	})

	AfterEach(func() {
		kubectlVM1.ExpectAllPodsTerminated()
	})

	AfterFailed(func() {
		kubectlVM1.ReportFailed()
		kubectlVM2.ReportFailed()

	})

	Context("Basic Connectivity between pod and Cluster-IP Service", func() {

		var (
			bb1YAML          = helpers.ManifestGet("busybox-1.yaml")
			hostNamesSvcYAML = helpers.ManifestGet("hostnames-svc.yaml")
		)

		BeforeEach(func() {
			res := kubectlVM1.Apply(bb1YAML)
			res.ExpectSuccess("unable to apply %s", bb1YAML)
			res = kubectlVM1.Apply(hostNamesSvcYAML)
			res.ExpectSuccess("unable to apply %s", hostNamesSvcYAML)
		})

		AfterEach(func() {
			// Explicitly ignore result of deletion of resources to avoid incomplete
			// teardown if any step fails.
			_ = kubectlVM1.Delete(bb1YAML, true)
			_ = kubectlVM1.Delete(hostNamesSvcYAML, true)
		})

		It("with many replicas", func() {
			err := kubectlVM1.WaitforPods(helpers.DefaultNamespace, "-l app=busybox-1", 300)
			Expect(err).Should(BeNil())
			err = kubectlVM1.WaitforPods(helpers.DefaultNamespace, "-l app=hostnames", 300)
			Expect(err).Should(BeNil())
			for i := 0; i < 6; i++ {
				// We do this several times to hit different pods in the deployment
				res := kubectlVM1.ExecPodCmd(helpers.DefaultNamespace, "busybox-1", "wget -qO- hostnames")
				res.ExpectSuccess("cannot execute: %s", res.OutputPrettyPrint())
			}
		})
	})
	Context("Basic Connectivity to Nodeport Service", func() {

		var (
			hostNamesSvcYAML = helpers.ManifestGet("hostnames-svc-nodeport.yaml")
		)

		BeforeEach(func() {
			res := kubectlVM1.Apply(hostNamesSvcYAML)
			res.ExpectSuccess("unable to apply %s", hostNamesSvcYAML)
		})

		AfterEach(func() {
			// Explicitly ignore result of deletion of resources to avoid incomplete
			// teardown if any step fails.
			_ = kubectlVM1.Delete(hostNamesSvcYAML, true)
		})

		It("with many replicas", func() {
			err := kubectlVM1.WaitforPods(helpers.DefaultNamespace, "-l app=hostnames", 300)
			Expect(err).Should(BeNil())
			ips, err := kubectlVM1.GetNodesInternalIPs() // TODO: we should do this test using node's External-IP/Public-IP as well
			Expect(err).To(BeNil(), "Cannot get Nodes' InternalIPs")
			for node, ip := range ips {
				for i := 0; i < 3; i++ {
					// For each node, we make several attemps to access the service
					res := kubectlVM1.Exec(helpers.Curl(ip, helpers.NodePortPortNum))
					res.ExpectSuccess("curl to node %s with IP %s failed: %s", node, ip, res.OutputPrettyPrint())
				}
			}
		})
	})
})
