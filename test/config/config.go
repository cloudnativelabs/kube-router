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

package config

import "flag"

// KuberouterTestConfigType holds all of the configurable elements of the testsuite
type KuberouterTestConfigType struct {
	Provisioner      string
	Reprovision      bool
	HoldEnvironment  bool
	SSHConfig        string
	ShowCommands     bool
	TestScope        string
	SkipLogGathering bool
}

// KuberouterTestConfig holds the global configuration of commandline flags
// in the ginkgo-based testing environment.
var KuberouterTestConfig = KuberouterTestConfigType{}

// ParseFlags parses commandline flags relevant to testing.
func (c *KuberouterTestConfigType) ParseFlags() {
	flag.StringVar(&c.Provisioner, "kuberouter.provisioner", "vagrant",
		"Specify a provisioner (default: vagrant)")
	flag.BoolVar(&c.Reprovision, "kuberouter.provision", false,
		"Provision using the specified provisioner before running test (default: false)")
	flag.BoolVar(&c.HoldEnvironment, "kuberouter.holdEnvironment", false,
		"On failure, hold the environment in its current state (default: false)")
	flag.BoolVar(&c.SkipLogGathering, "kuberouter.skipLogs", false,
		"skip gathering logs if a test fails (default: false)")
	flag.StringVar(&c.SSHConfig, "kuberouter.SSHConfig", "",
		"Specify a custom command to fetch SSH configuration (eg: 'vagrant ssh-config')")
	flag.BoolVar(&c.ShowCommands, "kuberouter.showCommands", false,
		"Output which commands are ran to stdout (default: false)")
	flag.StringVar(&c.TestScope, "kuberouter.testScope", "",
		"Specifies scope of test to be ran (runtime, ipv4-cluster, ipv6-cluster)")
}
