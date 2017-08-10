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
	EnablePodEgress    bool
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
	}
}

func (s *KubeRouterConfig) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVarP(&s.HelpRequested, "help", "h", false,
		"Print usage information.")
	fs.BoolVar(&s.RunServiceProxy, "run-service-proxy", true,
		"Enables Service Proxy -- sets up IPVS for Kubernetes Services.")
	fs.BoolVar(&s.RunFirewall, "run-firewall", true,
		"Enables Network Policy -- sets up iptables to provide ingress firewall for pods.")
	fs.BoolVar(&s.RunRouter, "run-router", true,
		"Enables Pod Networking -- Advertises and learns the routes to Pods via iBGP.")
	fs.StringVar(&s.Master, "master", s.Master,
		"The address of the Kubernetes API server (overrides any value in kubeconfig).")
	fs.StringVar(&s.Kubeconfig, "kubeconfig", s.Kubeconfig,
		"Path to kubeconfig file with authorization information (the master location is set by the master flag).")
	fs.BoolVar(&s.CleanupConfig, "cleanup-config", false,
		"Cleanup iptables rules, ipvs, ipset configuration and exit.")
	fs.BoolVar(&s.MasqueradeAll, "masquerade-all", false,
		"SNAT all traffic to cluster IP/node port.")
	fs.StringVar(&s.ClusterCIDR, "cluster-cidr", s.ClusterCIDR,
		"CIDR range of pods in the cluster. It is used to identify traffic originating from and destinated to pods.")
	fs.BoolVar(&s.EnablePodEgress, "enable-pod-egress", true,
		"SNAT traffic from Pods to destinations outside the cluster.")
	fs.DurationVar(&s.ConfigSyncPeriod, "config-sync-period", s.ConfigSyncPeriod,
		"The delay between apiserver configuration synchronizations (e.g. '5s', '1m').  Must be greater than 0.")
	fs.DurationVar(&s.IPTablesSyncPeriod, "iptables-sync-period", s.IPTablesSyncPeriod,
		"The delay between iptables rule synchronizations (e.g. '5s', '1m'). Must be greater than 0.")
	fs.DurationVar(&s.IpvsSyncPeriod, "ipvs-sync-period", s.IpvsSyncPeriod,
		"The delay between ipvs config synchronizations (e.g. '5s', '1m', '2h22m'). Must be greater than 0.")
	fs.DurationVar(&s.RoutesSyncPeriod, "routes-sync-period", s.RoutesSyncPeriod,
		"The delay between route updates and advertisements (e.g. '5s', '1m', '2h22m'). Must be greater than 0.")
	fs.BoolVar(&s.AdvertiseClusterIp, "advertise-cluster-ip", false,
		"Add Cluster IP to the RIB and advertise to peers.")
	fs.StringVar(&s.PeerRouter, "peer-router", s.PeerRouter,
		"The ip address of the external router to which all nodes will peer and advertise the cluster ip and pod cidr's.")
	fs.StringVar(&s.ClusterAsn, "cluster-asn", s.ClusterAsn,
		"ASN number under which cluster nodes will run iBGP.")
	fs.StringVar(&s.PeerAsn, "peer-asn", s.PeerAsn,
		"ASN number of the BGP peer to which cluster nodes will advertise cluster ip and node's pod cidr.")
	fs.BoolVar(&s.FullMeshMode, "nodes-full-mesh", true,
		"Each node in the cluster will setup BGP peering with rest of the nodes.")
	fs.StringVar(&s.HostnameOverride, "hostname-override", s.HostnameOverride,
		"Overrides the NodeName of the node. Set this if kube-router is unable to determine your NodeName automatically.")
	fs.BoolVar(&s.GlobalHairpinMode, "hairpin-mode", false,
		"Add iptable rules for every Service Endpoint to support hairpin traffic.")
}
