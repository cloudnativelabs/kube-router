package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	// nolint:gosec // we want to unconditionally expose pprof here for advanced troubleshooting scenarios
	_ "net/http/pprof"

	"github.com/cloudnativelabs/kube-router/pkg/cmd"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/cloudnativelabs/kube-router/pkg/version"
	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
)

func main() {
	if err := Main(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func Main() error {
	klog.InitFlags(nil)

	config := options.NewKubeRouterConfig()
	config.AddFlags(pflag.CommandLine)
	pflag.Parse()

	// Workaround for this issue:
	// https://github.com/kubernetes/kubernetes/issues/17162
	err := flag.CommandLine.Parse([]string{})
	if err != nil {
		return fmt.Errorf("failed to parse flags: %s", err)
	}
	err = flag.Set("logtostderr", "true")
	if err != nil {
		return fmt.Errorf("failed to set flag: %s", err)
	}
	err = flag.Set("v", config.VLevel)
	if err != nil {
		return fmt.Errorf("failed to set flag: %s", err)
	}

	if config.HelpRequested {
		pflag.Usage()
		return nil
	}

	if config.Version {
		version.PrintVersion(false)
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
		return fmt.Errorf("failed to parse kube-router config: %v", err)
	}

	if config.EnablePprof {
		go func() {
			fmt.Fprintf(os.Stdout, "%s\n", http.ListenAndServe("0.0.0.0:6060", nil).Error())
		}()
	}

	err = kubeRouter.Run()
	if err != nil {
		return fmt.Errorf("failed to run kube-router: %v", err)
	}

	return nil
}
