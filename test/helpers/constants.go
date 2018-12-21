// Copyright 2017 Authors of Cilium
// Modified for integration with kube-router
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package helpers

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/cloudnativelabs/kube-router/test/ginkgo-ext"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

var (
	// HelperTimeout is a predefined timeout value for commands, in seconds.
	HelperTimeout int64 = 300
	// HelperTimeoutDuration is a predefined timeout value for commands.
	HelperTimeoutDuration = time.Duration(HelperTimeout) * time.Second

	// BasePath is the path in the Vagrant VMs to which the test directory
	// is mounted
	BasePath = "/home/vagrant/go/src/github.com/cloudnativelabs/kube-router/test"
	// CheckLogs newtes a new buffer where all the warnings and checks that
	// happens during the test are saved. This buffer will be printed in the
	// test output inside <checks> labels.
	CheckLogs = ginkgoext.NewWriter(new(bytes.Buffer))
)

const (
	// KubectlCmd Kubernetes controller command
	KubectlCmd      = "kubectl"
	manifestsPath   = "manifests/"
	descriptorsPath = "../examples/kubernetes"
	kubeDNSLabel    = "k8s-app=kube-dns"

	DaemonName = "kube-router"

	// DNSHelperTimeout is a predefined timeout value for K8s DNS commands. It
	// must be larger than 5 minutes because kubedns has a hardcoded resync
	// period of 5 minutes. We have experienced test failures because kubedns
	// needed this time to recover from a connection problem to kube-apiserver.
	// The kubedns resyncPeriod is defined at
	// https://github.com/kubernetes/dns/blob/80fdd88276adba36a87c4f424b66fdf37cd7c9a8/pkg/dns/dns.go#L53
	DNSHelperTimeout int64 = 420

	//KuberouerPath is the path where kube-router test code is located.
	KuberouterPath = "/src/github.com/cloudnativelabs/kube-router/test"

	// K8sManifestBase tells ginkgo suite where to look for manifests
	K8sManifestBase = "k8sT/manifests"

	KubeRouterHealthPort = 20244

	// VM / Test suite constants.
	K8s     = "k8s"
	K8s1    = "k8s1"
	K8s2    = "k8s2"
	Runtime = "runtime"
	IPv4C   = "ipv4-cluster"
	IPv6C   = "ipv6-cluster"

	// IP Address families.
	IPv4 = "IPv4"
	IPv6 = "IPv6"

	DefaultNamespace    = "default"
	KubeSystemNamespace = "kube-system"

	TestResultsPath = "test_results/"

	// KuberouterTestLog is the filename where the Kuberouter logs that happens during
	// the test are saved.
	KuberouterTestLog = "kuberouter-test.log"

	// LogPerm is the permission for files that are created by this framework
	// that contain logs, outputs of CLI commands, etc.
	LogPerm = os.FileMode(0666)

	// Logs messages that should not be in the kube-router logs.
	panicMessage      = "panic:"
	deadLockHeader    = "POTENTIAL DEADLOCK:" // from github.com/sasha-s/go-deadlock/deadlock.go:header
	segmentationFault = "segmentation fault"

	contextDeadlineExceeded = "context deadline exceeded"
	ErrorLogs               = "level=error"
	WarningLogs             = "level=warning"
	APIPanicked             = "API handler panicked"

	NodePortPortNum = 30076
)

//GetFilePath returns the absolute path of the provided filename
func GetFilePath(filename string) string {
	return fmt.Sprintf("%s/%s", BasePath, filename)
}

// K8s1VMName is the name of the Kubernetes master node when running K8s tests.
func K8s1VMName() string {
	return fmt.Sprintf("k8s1")
}

// K8s2VMName is the name of the Kubernetes worker node when running K8s tests.
func K8s2VMName() string {
	return fmt.Sprintf("k8s2")
}

var checkLogsMessages = []string{panicMessage, deadLockHeader, segmentationFault}
var countLogsMessages = []string{contextDeadlineExceeded, ErrorLogs, WarningLogs, APIPanicked}
