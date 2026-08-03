package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	//nolint:gosec // we want to unconditionally expose pprof here for advanced troubleshooting scenarios
	_ "net/http/pprof"

	"github.com/cloudnativelabs/kube-router/v2/pkg/cmd"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/version"
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
	config := options.NewKubeRouterConfig()
	config.AddFlags(pflag.CommandLine)
	pflag.Parse()

	// Level.Set() mutates klog's package-global verbosity rather than the receiver, so we can discard
	// vLevel afterwards. Everything else we need, logging to stderr included, is already klog's default.
	var vLevel klog.Level
	if err := vLevel.Set(config.VLevel); err != nil {
		return fmt.Errorf("failed to set log level to %q: %w", config.VLevel, err)
	}

	if args := pflag.Args(); len(args) > 0 {
		return fmt.Errorf("unrecognized positional argument(s): %v", args)
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
		return errors.New("kube-router needs to be run with privileges to execute iptables, ipset and configure ipvs")
	}

	if config.CleanupConfig {
		cmd.CleanupConfigAndExit(config)
		return nil
	}

	kubeRouter, err := cmd.NewKubeRouterDefault(config)
	if err != nil {
		return fmt.Errorf("failed to parse kube-router config: %w", err)
	}

	if config.EnablePprof {
		go func() {
			server := http.Server{
				Addr:              "0.0.0.0:6060",
				ReadHeaderTimeout: 5 * time.Second,
				Handler:           nil,
			}
			fmt.Fprintf(os.Stdout, "%s\n", server.ListenAndServe().Error())
		}()
	}

	err = kubeRouter.Run()
	if err != nil {
		return fmt.Errorf("failed to run kube-router: %w", err)
	}

	return nil
}
