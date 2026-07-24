// Package netpol_e2e contains end-to-end tests for the kube-router
// NetworkPolicy implementation. Tests require a running Kubernetes cluster
// with kube-router deployed in --run-firewall mode.
//
// Run with:
//
//	go test -v ./test/e2e/netpol/... -timeout 600s
//
// Set the E2E environment variable to a non-empty value to opt in to running
// the suite:
//
//	E2E=1 go test -v ./test/e2e/netpol/... -timeout 600s
//
// The KUBECONFIG environment variable (or ~/.kube/config) is used to connect
// to the cluster. If no cluster is reachable the entire suite is skipped.
package netpol_e2e

import (
	"context"
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// k8sClient and restConfig are initialised once per suite in BeforeSuite and
// reused by all specs via the helper functions in framework_test.go.
var (
	k8sClient  *kubernetes.Clientset
	restConfig *rest.Config
	// suiteStartTime scopes the log health check so pre-existing noise on a
	// reused cluster does not false-positive assertNoSyncErrors.
	suiteStartTime time.Time
)

func TestNetpol(t *testing.T) {
	if os.Getenv("E2E") == "" {
		t.Skip("skipping e2e tests; set E2E=1 to enable")
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "Network Policy E2E Suite")
}

var _ = BeforeSuite(func() {
	suiteStartTime = time.Now()

	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			kubeconfig = home + "/.kube/config"
		}
	}

	var err error
	restConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		Skip("no Kubernetes cluster available (set KUBECONFIG): " + err.Error())
	}

	k8sClient, err = kubernetes.NewForConfig(restConfig)
	if err != nil {
		Fail("create Kubernetes client: " + err.Error())
	}
})

// ReportAfterEach dumps kube-router logs and nftables state to GinkgoWriter
// whenever a spec fails, providing context for CI failures.
var _ = ReportAfterEach(func(report SpecReport) {
	if !report.Failed() {
		return
	}
	ctx := context.Background()
	dumpKubeRouterLogs(ctx)
	dumpNFTablesState(ctx)
})

// AfterSuite scans every kube-router pod's logs for NetworkPolicy sync failures
// that occurred during the run. This is ungated, so it adds regression value to
// every run (including PRs) by catching sync aborts and nftables transaction
// failures that steady-state connectivity specs cannot observe directly.
var _ = AfterSuite(func() {
	assertNoSyncErrors(context.Background(), suiteStartTime)
})
