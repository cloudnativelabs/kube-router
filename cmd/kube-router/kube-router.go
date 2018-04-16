package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	_ "net/http/pprof"

	"github.com/cloudnativelabs/kube-router/pkg/cmd"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/spf13/pflag"
)

func main() {
	if err := Main(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func Main() error {
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
		return nil
	}

	if config.Version {
		cmd.PrintVersion(false)
		return nil
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("kube-router needs to be run with privileges to execute iptables, ipset and configure ipvs")
	}

	if config.CleanupConfig {
		cmd.CleanupConfigAndExit()
		return nil
	}

	kubeRouter, err := cmd.NewKubeRouterDefault(config)
	if err != nil {
		return fmt.Errorf("Failed to parse kube-router config: %v", err)
	}

	if config.EnablePprof {
		go func() {
			fmt.Fprintf(os.Stdout, http.ListenAndServe("0.0.0.0:6060", nil).Error())
		}()
	}

	err = kubeRouter.Run()
	if err != nil {
		return fmt.Errorf("Failed to run kube-router: %v", err)
	}

	return nil
}
