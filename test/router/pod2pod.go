package router

import (
	"fmt"
	"time"

	. "github.com/cloudnativelabs/kube-router/test/ginkgo-ext"
	"github.com/cloudnativelabs/kube-router/test/helpers"
	. "github.com/onsi/gomega"
)

var _ = Describe("Router", func() {

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

	Context("Basic Connectivity between pods", func() {

		var (
			bb1YAML = helpers.ManifestGet("busybox-1.yaml")
			bb2YAML = helpers.ManifestGet("busybox-2.yaml")
		)

		BeforeEach(func() {
			res := kubectlVM1.Apply(bb1YAML)
			res.ExpectSuccess("unable to apply %s", bb1YAML)
			res = kubectlVM1.Apply(bb2YAML)
			res.ExpectSuccess("unable to apply %s", bb2YAML)
		})

		AfterEach(func() {
			// Explicitly ignore result of deletion of resources to avoid incomplete
			// teardown if any step fails.
			_ = kubectlVM1.Delete(bb1YAML, true)
			_ = kubectlVM1.Delete(bb2YAML, true)
		})

		It("on different nodes", func() {
			err := kubectlVM1.WaitforPods(helpers.DefaultNamespace, "-l app=busybox-1", 300)
			Expect(err).Should(BeNil())
			err = kubectlVM1.WaitforPods(helpers.DefaultNamespace, "-l app=busybox-2", 300)
			Expect(err).Should(BeNil())
			ips, err := kubectlVM1.GetPodsIPs(helpers.DefaultNamespace, "app=busybox-2")
			Expect(err).To(BeNil(), "Cannot get busybox-2 IP(s)")
			pingCmd := fmt.Sprintf("ping -c 1 %s", ips["busybox-2"])
			res := kubectlVM1.ExecPodCmd(helpers.DefaultNamespace, "busybox-1", pingCmd)
			res.ExpectSuccess("cannot execute: %s", res.OutputPrettyPrint())
		})

	})
})
