package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cloudnativelabs/kube-router/app"
	"github.com/cloudnativelabs/kube-router/app/options"
	"github.com/spf13/pflag"
)

func main() {

	config := options.NewKubeRouterConfig()
	config.AddFlags(pflag.CommandLine)
	pflag.Parse()

	flag.Set("logtostderr", "true")

	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "kube-router need to be run by user with previlages to execute iptables, ipset and configure ipvs\n")
		os.Exit(1)
	}

	if config.CleanupConfig {
		app.CleanupConfigAndExit()
		os.Exit(0)
	}

	kubeRouter, err := app.NewKubeRouterDefault(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse kube-router config: %v\n", err)
		os.Exit(1)
	}

	if err = kubeRouter.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to run kube-router: %v\n", err)
		os.Exit(1)
	}
}
