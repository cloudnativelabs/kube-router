package options

import (
	"time"

	"github.com/spf13/pflag"
)

type KubeRouterConfig struct {
	Kubeconfig         string
	Master             string
	ConfigSyncPeriod   time.Duration
	CleanupConfig      bool
	IPTablesSyncPeriod time.Duration
	IpvsSyncPeriod     time.Duration
	RoutesSyncPeriod   time.Duration
	RunServiceProxy    bool
	RunFirewall        bool
	RunRouter          bool
	MasqueradeAll      bool
}

func NewKubeRouterConfig() *KubeRouterConfig {
	return &KubeRouterConfig{ConfigSyncPeriod: 1 * time.Minute,
		IpvsSyncPeriod:     1 * time.Minute,
		IPTablesSyncPeriod: 1 * time.Minute,
		RoutesSyncPeriod:   1 * time.Minute,
		MasqueradeAll:      false,
		RunServiceProxy:    true,
		RunFirewall:        true,
		RunRouter:          false}
}

func (s *KubeRouterConfig) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&s.RunServiceProxy, "run-service-proxy", s.RunServiceProxy, "If false, kube-router wont setup IPVS for services proxy. True by default.")
	fs.BoolVar(&s.RunFirewall, "run-firewall", s.RunFirewall, "If false, kube-router wont setup iptables to provide ingress firewall for pods. True by default.")
	fs.BoolVar(&s.RunRouter, "run-router", s.RunRouter, "If true each node advertise routes the rest of the nodes and learn the routes for the pods. True by default.")
	fs.StringVar(&s.Master, "master", s.Master, "The address of the Kubernetes API server (overrides any value in kubeconfig)")
	fs.StringVar(&s.Kubeconfig, "kubeconfig", s.Kubeconfig, "Path to kubeconfig file with authorization information (the master location is set by the master flag).")
	fs.BoolVar(&s.CleanupConfig, "cleanup-config", s.CleanupConfig, "If true cleanup iptables rules, ipvs, ipset configuration and exit.")
	fs.BoolVar(&s.MasqueradeAll, "masquerade-all", s.MasqueradeAll, "SNAT all traffic to cluster IP/node port. False by default")
	fs.DurationVar(&s.ConfigSyncPeriod, "config-sync-period", s.ConfigSyncPeriod, "How often configuration from the apiserver is refreshed.  Must be greater than 0.")
	fs.DurationVar(&s.IPTablesSyncPeriod, "iptables-sync-period", s.IPTablesSyncPeriod, "The maximum interval of how often iptables rules are refreshed (e.g. '5s', '1m'). Must be greater than 0.")
	fs.DurationVar(&s.IpvsSyncPeriod, "ipvs-sync-period", s.IpvsSyncPeriod, "The maximum interval of how often ipvs config is refreshed (e.g. '5s', '1m', '2h22m'). Must be greater than 0.")
	fs.DurationVar(&s.RoutesSyncPeriod, "routes-sync-period", s.RoutesSyncPeriod, "The maximum interval of how often routes are adrvertised and learned (e.g. '5s', '1m', '2h22m'). Must be greater than 0.")
}
