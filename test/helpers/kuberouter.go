package helpers

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudnativelabs/kube-router/test/config"
	ginkgoext "github.com/cloudnativelabs/kube-router/test/ginkgo-ext"

	. "github.com/onsi/gomega"
)

// ExpectKubeRouterHealthy asserts that kube-router health is OK
func (s *SSHMeta) ExpectKubeRouterHealthy() {
	err := s.WaitUntilReady(10)
	ExpectWithOffset(1, err).To(BeNil(), "kube-router is not healthy on node %s", s.nodeName)
}

// ExecKubeRouterHealthCheck checks the health of kube-router
func (s *SSHMeta) ExecKubeRouterHealthCheck(ipv6 bool) *CmdRes {
	var command string
	if ipv6 {
		command = fmt.Sprintf("curl -g -6 http://[::1]:%v/healthz", KubeRouterHealthPort)
	} else {
		command = fmt.Sprintf("curl 127.0.0.1:%v/healthz", KubeRouterHealthPort)
	}
	return s.Exec(command)
}

// WaitUntilReady waits until the kube-router health is OK.
// Returns an error if the health never becomes OK after specified
// timeout has elapsed.
func (s *SSHMeta) WaitUntilReady(timeout int64) error {

	body := func() bool {
		res := s.ExecKubeRouterHealthCheck(true) // TODO: ipv6 flag needs to configured
		s.logger.Infof("Kube-router health is %s (%t) on node %s", res.Output(), res.WasSuccessful(), s.nodeName)
		return strings.Contains(res.Output().String(), "OK")
	}
	err := WithTimeout(body, "Kube-router is not ready", &TimeoutConfig{Timeout: timeout})
	return err
}

// ValidateNoErrorsInLogs checks in kube-router logs since the given duration (By
// default `CurrentGinkgoTestDescription().Duration`) do not contain `panic`,
// `deadlocks` or `segmentation faults` messages . In case of any of these
// messages, it'll mark the test as failed.
func (s *SSHMeta) ValidateNoErrorsInLogs(duration time.Duration) {
	logsCmd := fmt.Sprintf(`sudo journalctl -au %s --since '%v seconds ago'`,
		DaemonName, duration.Seconds())
	logs := s.Exec(logsCmd, ExecOptions{SkipLog: true}).Output().String()

	defer func() {
		// Keep the kube-router logs for the given test in a separate file.
		testPath, err := CreateReportDirectory()
		if err != nil {
			s.logger.WithError(err).Error("Cannot create report directory")
			return
		}
		err = ioutil.WriteFile(
			fmt.Sprintf("%s/%s", testPath, CreateKuberouterTestLogFilename(s.nodeName)),
			[]byte(logs), LogPerm)

		if err != nil {
			s.logger.WithError(err).Errorf("Cannot create %s", CreateKuberouterTestLogFilename(s.nodeName))
		}
	}()

	for _, message := range checkLogsMessages {
		if strings.Contains(logs, message) {
			fmt.Fprintf(CheckLogs, "⚠️  Found a %q in logs\n", message)
			ginkgoext.Fail(fmt.Sprintf("Found a %q in kube-router Logs", message))
		}
	}

	// Count part
	for _, message := range countLogsMessages {
		var prefix = ""
		result := strings.Count(logs, message)
		if result > 5 {
			// Added a warning emoji just in case that are more than 5 warning in the logs.
			prefix = "⚠️  "
		}
		fmt.Fprintf(CheckLogs, "%sNumber of %q in logs: %d\n", prefix, message, result)
	}
}

// PprofReport runs pprof each 5 minutes and saves the data into the test
// folder saved with pprof suffix.
func (s *SSHMeta) PprofReport() {
	PProfCadence := 5 * time.Minute
	ticker := time.NewTicker(PProfCadence)
	log := s.logger.WithField("subsys", "pprofReport")

	for {
		select {
		case <-ticker.C:

			testPath, err := CreateReportDirectory()
			if err != nil {
				log.WithError(err).Errorf("cannot create test result path '%s'", testPath)
				return
			}
			d := time.Now().Add(50 * time.Second)
			ctx, cancel := context.WithDeadline(context.Background(), d)

			// TODO: this requires that we use gops in kube-router.
			res := s.ExecInBackground(ctx, `sudo gops pprof-cpu $(pgrep kube-router)`)

			err = res.WaitUntilMatch("Profiling dump saved to")
			if err != nil {
				log.WithError(err).Error("Cannot get pprof report")
			}

			files := s.Exec("ls -1 /tmp/")
			for _, file := range files.ByLines() {
				if !strings.Contains(file, "profile") {
					continue
				}

				dest := filepath.Join(
					BasePath, testPath,
					fmt.Sprintf("%s.pprof", file))
				_ = s.ExecWithSudo(fmt.Sprintf("mv /tmp/%s %s", file, dest))
			}
			cancel()
		}
	}
}

// ReportFailed gathers relevant runtime data and logs for debugging purposes.
func (s *SSHMeta) ReportFailed(commands ...string) {
	if config.KuberouterTestConfig.SkipLogGathering {
		ginkgoext.GinkgoPrint("Skipped gathering logs (-kuberouter.skipLogs=true)\n")
		return
	}

	for _, cmd := range commands {
		res := s.ExecWithSudo(fmt.Sprintf("%s", cmd), ExecOptions{SkipLog: true})
		ginkgoext.GinkgoPrint(res.GetDebugMessage())
	}

	s.GatherLogs()
	// s.GatherDockerLogs()
}

// GatherLogs dumps kube-router logs, and gops output to the directory testResultsPath
func (s *SSHMeta) GatherLogs() {
	logFileName := fmt.Sprintf("kube-router-complete-%s.s", s.nodeName)
	kuberouterLogCommands := map[string]string{
		fmt.Sprintf("sudo journalctl -au %s --no-pager", DaemonName): logFileName,
	}

	testPath, err := CreateReportDirectory()
	if err != nil {
		s.logger.WithError(err).Errorf(
			"cannot create test results path '%s'", testPath)
		return
	}
	reportMap(testPath, kuberouterLogCommands, s)

	additionalCommands := []string{
		fmt.Sprintf("sudo ip -6 r"),
		fmt.Sprintf("sudo ipset list"),
		fmt.Sprintf("gobgp neighbor"),
	}

	for _, cmd := range additionalCommands {
		res := s.Exec(cmd, ExecOptions{SkipLog: false})
		if !res.WasSuccessful() {
			s.logger.Errorf("cannot gather files for cmd '%s': %s", cmd, res.CombineOutput())
		}
	}
}
