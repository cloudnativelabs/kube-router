package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	_ "net/http/pprof"

	"github.com/cloudnativelabs/kube-router/app"
	"github.com/cloudnativelabs/kube-router/app/options"
	"github.com/spf13/pflag"
)

func main() {

	config := options.NewKubeRouterConfig()
	config.AddFlags(pflag.CommandLine)
	pflag.Parse()

	// Workaround for this issue:
	// https://github.com/kubernetes/kubernetes/issues/17162
	flag.CommandLine.Parse([]string{})

	flag.Set("logtostderr", "true")
	flag.Set("v", config.VLevel)

	if config.HelpRequested {
		pflag.Usage()
		os.Exit(0)
	}

	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "kube-router needs to be run with privileges to execute iptables, ipset and configure ipvs\n")
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

	if config.EnablePprof {
		go func() {
			fmt.Fprintf(os.Stdout, http.ListenAndServe("0.0.0.0:6060", nil).Error())
		}()
	}

	err = kubeRouter.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to run kube-router: %v\n", err)
		os.Exit(1)
	}
}
