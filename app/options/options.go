package options

import (
	"time"

	"github.com/spf13/pflag"
)

type KubeRouterConfig struct {
	HelpRequested      bool
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
	ClusterCIDR        string
	HostnameOverride   string
	AdvertiseClusterIp bool
	PeerRouter         string
	ClusterAsn         string
	PeerAsn            string
	FullMeshMode       bool
	GlobalHairpinMode  bool
}

func NewKubeRouterConfig() *KubeRouterConfig {
	return &KubeRouterConfig{ConfigSyncPeriod: 1 * time.Minute,
		IpvsSyncPeriod:     1 * time.Minute,
		IPTablesSyncPeriod: 1 * time.Minute,
		RoutesSyncPeriod:   1 * time.Minute,
		MasqueradeAll:      false,
		RunServiceProxy:    true,
		RunFirewall:        true,
		RunRouter:          true,
		FullMeshMode:       true,
		AdvertiseClusterIp: false,
		GlobalHairpinMode:  false}
}

func (s *KubeRouterConfig) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVarP(&s.HelpRequested, "help", "h", false, "Print usage information.")
	fs.BoolVar(&s.RunServiceProxy, "run-service-proxy", s.RunServiceProxy, "If false, kube-router wont setup IPVS for services proxy. True by default.")
	fs.BoolVar(&s.RunFirewall, "run-firewall", s.RunFirewall, "If false, kube-router wont setup iptables to provide ingress firewall for pods. True by default.")
	fs.BoolVar(&s.RunRouter, "run-router", s.RunRouter, "If true each node advertise routes the rest of the nodes and learn the routes for the pods. True by default.")
	fs.StringVar(&s.Master, "master", s.Master, "The address of the Kubernetes API server (overrides any value in kubeconfig)")
	fs.StringVar(&s.Kubeconfig, "kubeconfig", s.Kubeconfig, "Path to kubeconfig file with authorization information (the master location is set by the master flag).")
	fs.BoolVar(&s.CleanupConfig, "cleanup-config", s.CleanupConfig, "If true cleanup iptables rules, ipvs, ipset configuration and exit.")
	fs.BoolVar(&s.MasqueradeAll, "masquerade-all", s.MasqueradeAll, "SNAT all traffic to cluster IP/node port. False by default")
	fs.StringVar(&s.ClusterCIDR, "cluster-cidr", s.ClusterCIDR, "CIDR range of pods in the cluster. It is used to identify traffic originating from and destinated to pods.")
	fs.DurationVar(&s.ConfigSyncPeriod, "config-sync-period", s.ConfigSyncPeriod, "How often configuration from the apiserver is refreshed.  Must be greater than 0.")
	fs.DurationVar(&s.IPTablesSyncPeriod, "iptables-sync-period", s.IPTablesSyncPeriod, "The maximum interval of how often iptables rules are refreshed (e.g. '5s', '1m'). Must be greater than 0.")
	fs.DurationVar(&s.IpvsSyncPeriod, "ipvs-sync-period", s.IpvsSyncPeriod, "The maximum interval of how often ipvs config is refreshed (e.g. '5s', '1m', '2h22m'). Must be greater than 0.")
	fs.DurationVar(&s.RoutesSyncPeriod, "routes-sync-period", s.RoutesSyncPeriod, "The maximum interval of how often routes are adrvertised and learned (e.g. '5s', '1m', '2h22m'). Must be greater than 0.")
	fs.BoolVar(&s.AdvertiseClusterIp, "advertise-cluster-ip", s.AdvertiseClusterIp, "If true then cluster IP will be added into the RIB and will be advertised to the peers. False by default.")
	fs.StringVar(&s.PeerRouter, "peer-router", s.PeerRouter, "The ip address of the external router to which all nodes will peer and advertise the cluster ip and pod cidr's")
	fs.StringVar(&s.ClusterAsn, "cluster-asn", s.ClusterAsn, "ASN number under which cluster nodes will run iBGP")
	fs.StringVar(&s.PeerAsn, "peer-asn", s.PeerAsn, "ASN number of the BGP peer to which cluster nodes will advertise cluster ip and node's pod cidr")
	fs.BoolVar(&s.FullMeshMode, "nodes-full-mesh", s.FullMeshMode, "When enabled each node in the cluster will setup BGP peer with rest of the nodes. True by default")
	fs.StringVar(&s.HostnameOverride, "hostname-override", s.HostnameOverride, "If non-empty, will use this string as identification instead of the actual hostname.")
	fs.BoolVar(&s.GlobalHairpinMode, "hairpin-mode", s.GlobalHairpinMode, "Adds iptable rules for every Service Endpoint to support hairpin traffic. False by default")
}
