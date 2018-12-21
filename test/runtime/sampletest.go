package RuntimeTest

import (
	"time"

	. "github.com/cloudnativelabs/kube-router/test/ginkgo-ext"
	"github.com/cloudnativelabs/kube-router/test/helpers"
	// . "github.com/onsi/gomega"
)

var _ = Describe("Runtime", func() {

	var k8s1 *helpers.SSHMeta

	BeforeAll(func() {
		k8s1 = helpers.InitRuntimeHelper(helpers.K8s1VMName(), logger)
		k8s1.ExpectKubeRouterHealthy()
		k8s1.ExpectGobgpNeighEstabl()
	})

	JustAfterEach(func() {
		// TODO: Duration requires that we upgrade "github.com/onsi/ginkgo" to something more recent.
		// k8s1.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		k8s1.ValidateNoErrorsInLogs(time.Minute)
	})

	AfterFailed(func() {
		k8s1.ReportFailed()
	})

	Context("Sample tests", func() {

		var (
			fooID       = "id.foo"
			namesLabels = [][]string{{"foo", fooID}, {"bar", "id.bar"}, {"baz", "id.baz"}}
		)

		BeforeAll(func() {
			for _, set := range namesLabels {
				GinkgoPrint("BeforeAll name %s\n", set[0])
			}
		})

		AfterAll(func() {
			for _, set := range namesLabels {
				GinkgoPrint("AfterAll name %s\n", set[0])
			}
		})

		It("Test 1", func() {
			// Fail("Fail!!!!!!!!!!")
		})
	})

})
