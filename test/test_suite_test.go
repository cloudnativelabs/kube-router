package kuberouterTest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cloudnativelabs/kube-router/test/config"
	. "github.com/cloudnativelabs/kube-router/test/ginkgo-ext"
	ginkgoext "github.com/cloudnativelabs/kube-router/test/ginkgo-ext"
	"github.com/cloudnativelabs/kube-router/test/helpers"
	gops "github.com/google/gops/agent"
	"github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/sirupsen/logrus"
)

var (
	log             = logrus.New()
	DefaultSettings = map[string]string{
		"K8S_VERSION": "1.13",
	}
	k8sNodesEnv         = "K8S_NODES"
	commandsLogFileName = "cmds.log"
)

func init() {

	// Open socket for using gops to get stacktraces in case the tests deadlock.
	if err := gops.Listen(gops.Options{}); err != nil {
		errorString := fmt.Sprintf("unable to start gops: %s", err)
		fmt.Println(errorString)
		os.Exit(-1)
	}

	for k, v := range DefaultSettings {
		getOrSetEnvVar(k, v)
	}
	config.KuberouterTestConfig.ParseFlags()

	os.RemoveAll(helpers.TestResultsPath)

	format.UseStringerRepresentation = true
}

func configLogsOutput() {
	log.SetLevel(logrus.DebugLevel)
	log.Out = &config.TestLogWriter
	logrus.SetFormatter(&config.Formatter)
	log.Formatter = &config.Formatter
	log.Hooks.Add(&config.LogHook{})

	ginkgoext.GinkgoWriter = NewWriter(log.Out)
}

func ShowCommands() {
	if !config.KuberouterTestConfig.ShowCommands {
		return
	}

	helpers.SSHMetaLogs = ginkgoext.NewWriter(os.Stdout)
}

func TestTest(t *testing.T) {
	if config.KuberouterTestConfig.TestScope != "" {
		helpers.UserDefinedScope = config.KuberouterTestConfig.TestScope
		fmt.Printf("User specified the scope:  %q\n", config.KuberouterTestConfig.TestScope)
	}

	configLogsOutput()
	ShowCommands()

	if config.KuberouterTestConfig.HoldEnvironment {
		RegisterFailHandler(helpers.Fail)
	} else {
		RegisterFailHandler(Fail)
	}

	RunSpecsWithDefaultAndCustomReporters(
		t, helpers.GetScopeWithVersion(), nil)
}

var _ = BeforeAll(func() {
	var err error

	logger := log.WithFields(logrus.Fields{"testName": "BeforeAll"})
	scope, err := helpers.GetScope()
	if err != nil {
		Fail(fmt.Sprintf(
			"Cannot get the scope for running test, please use --kuberouter.testScope option: %s",
			err))
	}

	// Boot / provision VMs if specified by configuration.
	if config.KuberouterTestConfig.Reprovision {
		Fail("Provisioning is not supported at this time.")
	}

	if config.KuberouterTestConfig.Provisioner != "vagrant" {
		Fail("Only provisioner supported at this time is vagrant")
	}

	if config.KuberouterTestConfig.SSHConfig == "" {
		Fail(fmt.Sprintf(
			"No ssh config specified, please use --kuberouter.SSHConfig option: %s",
			err))
	}

	switch scope {
	case helpers.Runtime:
		vm := helpers.InitRuntimeHelper(helpers.K8s1VMName(), logger)
		go vm.PprofReport()
	case helpers.IPv6C:
		// TODO: if kuberouter.provision, create an IPv6 cluster
		kubectl := helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		go kubectl.PprofReport()
	case helpers.IPv4C:
		// TODO: if kuberouter.provision, create an IPv6 cluster
	}
	return
})

var _ = AfterSuite(func() {
	if !helpers.IsRunningOnJenkins() {
		GinkgoPrint("AfterSuite: not running on Jenkins; leaving VMs running for debugging")
		return
	}
	// Errors are not checked here because it should fail on BeforeAll
	scope, _ := helpers.GetScope()
	GinkgoPrint("cleaning up VMs started for %s tests", scope)
	switch scope {
	case helpers.Runtime:
		// helpers.DestroyVM(helpers.Runtime)
	case helpers.IPv6C:
		// kubectl := helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		// kubectl.Apply(helpers.GetFilePath("./examples/kubernetes/addons/prometheus/prometheus.yaml"))
		// go kubectl.PprofReport()
	case helpers.IPv4C:
		// TODO
	}
	return
})

func getOrSetEnvVar(key, value string) {
	if val := os.Getenv(key); val == "" {
		log.Infof("environment variable %q was not set; setting to default value %q", key, value)
		os.Setenv(key, value)
	}
}

var _ = AfterEach(func() {

	// Send the Checks output to Junit report to be render on Jenkins.
	defer helpers.CheckLogs.Reset()
	GinkgoPrint("<Checks>\n%s\n</Checks>\n", helpers.CheckLogs.Buffer.String())

	defer config.TestLogWriterReset()
	err := helpers.CreateLogFile(config.TestLogFileName, config.TestLogWriter.Bytes())
	if err != nil {
		log.WithError(err).Errorf("cannot create log file '%s'", config.TestLogFileName)
		return
	}

	defer helpers.SSHMetaLogs.Reset()
	err = helpers.CreateLogFile(commandsLogFileName, helpers.SSHMetaLogs.Bytes())
	if err != nil {
		log.WithError(err).Errorf("cannot create log file '%s'", commandsLogFileName)
		return
	}

	// This piece of code is to enable zip attachments on Junit Output.
	if ginkgo.CurrentGinkgoTestDescription().Failed && helpers.IsRunningOnJenkins() {
		// ReportDirectory is already created. No check the error
		path, _ := helpers.CreateReportDirectory()
		zipFileName := fmt.Sprintf("%s_%s.zip", helpers.MakeUID(), ginkgoext.GetTestName())
		zipFilePath := filepath.Join(helpers.TestResultsPath, zipFileName)

		_, err := exec.Command(
			"/bin/bash", "-c",
			fmt.Sprintf("zip -qr %s %s", zipFilePath, path)).CombinedOutput()
		if err != nil {
			log.WithError(err).Errorf("cannot create zip file '%s'", zipFilePath)
		}

		// @eloy- This part is only if you use Jenkins Attachment plugin, has
		// been super useful for us.
		ginkgoext.GinkgoPrint("[[ATTACHMENT|%s]]", zipFileName)
	}
})
