package options

import (
	"net"
	"time"

	"strconv"

	"github.com/spf13/pflag"
)

const DEFAULT_BGP_PORT = 179

type KubeRouterConfig struct {
	AdvertiseClusterIp      bool
	AdvertiseExternalIp     bool
	AdvertiseNodePodCidr    bool
	AdvertiseLoadBalancerIp bool
	BGPGracefulRestart      bool
	BGPPort                 uint16
	CacheSyncTimeout        time.Duration
	CleanupConfig           bool
	ClusterAsn              uint
	ClusterCIDR             string
	DisableSrcDstCheck      bool
	EnableCNI               bool
	EnableiBGP              bool
	EnableOverlay           bool
	EnablePodEgress         bool
	EnablePprof             bool
	FullMeshMode            bool
	OverlayType             string
	GlobalHairpinMode       bool
	HealthPort              uint16
	HelpRequested           bool
	HostnameOverride        string
	IPTablesSyncPeriod      time.Duration
	IpvsSyncPeriod          time.Duration
	IpvsGracefulPeriod      time.Duration
	IpvsGracefulTermination bool
	Kubeconfig              string
	MasqueradeAll           bool
	Master                  string
	MetricsEnabled          bool
	MetricsPath             string
	MetricsPort             uint16
	NodePortBindOnAllIp     bool
	OverrideNextHop         bool
	PeerASNs                []uint
	PeerMultihopTtl         uint8
	PeerPasswords           []string
	PeerPorts               []uint
	PeerRouters             []net.IP
	RouterId                string
	RoutesSyncPeriod        time.Duration
	RunFirewall             bool
	RunRouter               bool
	RunServiceProxy         bool
	Version                 bool
	VLevel                  string
	// FullMeshPassword    string
}

func NewKubeRouterConfig() *KubeRouterConfig {
	return &KubeRouterConfig{
		CacheSyncTimeout:   1 * time.Minute,
		IpvsSyncPeriod:     5 * time.Minute,
		IPTablesSyncPeriod: 5 * time.Minute,
		IpvsGracefulPeriod: 30 * time.Second,
		RoutesSyncPeriod:   5 * time.Minute,
		EnableOverlay:      true,
		OverlayType:        "subnet",
	}
}

func (s *KubeRouterConfig) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVarP(&s.HelpRequested, "help", "h", false,
		"Print usage information.")
	fs.BoolVarP(&s.Version, "version", "V", false,
		"Print version information.")
	fs.DurationVar(&s.CacheSyncTimeout, "cache-sync-timeout", s.CacheSyncTimeout,
		"The timeout for cache synchronization (e.g. '5s', '1m'). Must be greater than 0.")
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
	fs.DurationVar(&s.IPTablesSyncPeriod, "iptables-sync-period", s.IPTablesSyncPeriod,
		"The delay between iptables rule synchronizations (e.g. '5s', '1m'). Must be greater than 0.")
	fs.DurationVar(&s.IpvsSyncPeriod, "ipvs-sync-period", s.IpvsSyncPeriod,
		"The delay between ipvs config synchronizations (e.g. '5s', '1m', '2h22m'). Must be greater than 0.")
	fs.DurationVar(&s.IpvsGracefulPeriod, "ipvs-graceful-period", s.IpvsGracefulPeriod,
		"The graceful period before removing destinations from IPVS services (e.g. '5s', '1m', '2h22m'). Must be greater than 0.")
	fs.BoolVar(&s.IpvsGracefulTermination, "ipvs-graceful-termination", false,
		"Enables the experimental IPVS graceful terminaton capability")
	fs.DurationVar(&s.RoutesSyncPeriod, "routes-sync-period", s.RoutesSyncPeriod,
		"The delay between route updates and advertisements (e.g. '5s', '1m', '2h22m'). Must be greater than 0.")
	fs.BoolVar(&s.AdvertiseClusterIp, "advertise-cluster-ip", false,
		"Add Cluster IP of the service to the RIB so that it gets advertises to the BGP peers.")
	fs.BoolVar(&s.AdvertiseExternalIp, "advertise-external-ip", false,
		"Add External IP of service to the RIB so that it gets advertised to the BGP peers.")
	fs.BoolVar(&s.AdvertiseLoadBalancerIp, "advertise-loadbalancer-ip", false,
		"Add LoadbBalancer IP of service status as set by the LB provider to the RIB so that it gets advertised to the BGP peers.")
	fs.BoolVar(&s.AdvertiseNodePodCidr, "advertise-pod-cidr", true,
		"Add Node's POD cidr to the RIB so that it gets advertised to the BGP peers.")
	fs.IPSliceVar(&s.PeerRouters, "peer-router-ips", s.PeerRouters,
		"The ip address of the external router to which all nodes will peer and advertise the cluster ip and pod cidr's.")
	fs.UintSliceVar(&s.PeerPorts, "peer-router-ports", s.PeerPorts,
		"The remote port of the external BGP to which all nodes will peer. If not set, default BGP port ("+strconv.Itoa(DEFAULT_BGP_PORT)+") will be used.")
	fs.UintVar(&s.ClusterAsn, "cluster-asn", s.ClusterAsn,
		"ASN number under which cluster nodes will run iBGP.")
	fs.UintSliceVar(&s.PeerASNs, "peer-router-asns", s.PeerASNs,
		"ASN numbers of the BGP peer to which cluster nodes will advertise cluster ip and node's pod cidr.")
	fs.Uint8Var(&s.PeerMultihopTtl, "peer-router-multihop-ttl", s.PeerMultihopTtl,
		"Enable eBGP multihop supports -- sets multihop-ttl. (Relevant only if ttl >= 2)")
	fs.BoolVar(&s.FullMeshMode, "nodes-full-mesh", true,
		"Each node in the cluster will setup BGP peering with rest of the nodes.")
	fs.BoolVar(&s.BGPGracefulRestart, "bgp-graceful-restart", false,
		"Enables the BGP Graceful Restart capability so that routes are preserved on unexpected restarts")
	fs.Uint16Var(&s.BGPPort, "bgp-port", DEFAULT_BGP_PORT,
		"The port open for incoming BGP connections and to use for connecting with other BGP peers.")
	fs.StringVar(&s.RouterId, "router-id", "", "BGP router-id. Must be specified in a ipv6 only cluster.")
	fs.BoolVar(&s.EnableCNI, "enable-cni", true,
		"Enable CNI plugin. Disable if you want to use kube-router features alongside another CNI plugin.")
	fs.BoolVar(&s.EnableiBGP, "enable-ibgp", true,
		"Enables peering with nodes with the same ASN, if disabled will only peer with external BGP peers")
	fs.StringVar(&s.HostnameOverride, "hostname-override", s.HostnameOverride,
		"Overrides the NodeName of the node. Set this if kube-router is unable to determine your NodeName automatically.")
	fs.BoolVar(&s.GlobalHairpinMode, "hairpin-mode", false,
		"Add iptables rules for every Service Endpoint to support hairpin traffic.")
	fs.BoolVar(&s.NodePortBindOnAllIp, "nodeport-bindon-all-ip", false,
		"For service of NodePort type create IPVS service that listens on all IP's of the node.")
	fs.BoolVar(&s.EnableOverlay, "enable-overlay", true,
		"When enable-overlay is set to true, IP-in-IP tunneling is used for pod-to-pod networking across nodes in different subnets. "+
			"When set to false no tunneling is used and routing infrastructure is expected to route traffic for pod-to-pod networking across nodes in different subnets")
	fs.StringVar(&s.OverlayType, "overlay-type", s.OverlayType,
		"Possible values: subnet,full - "+
			"When set to \"subnet\", the default, default \"--enable-overlay=true\" behavior is used. "+
			"When set to \"full\", it changes \"--enable-overlay=true\" default behavior so that IP-in-IP tunneling is used for pod-to-pod networking across nodes regardless of the subnet the nodes are in.")
	fs.StringSliceVar(&s.PeerPasswords, "peer-router-passwords", s.PeerPasswords,
		"Password for authenticating against the BGP peer defined with \"--peer-router-ips\".")
	fs.BoolVar(&s.EnablePprof, "enable-pprof", false,
		"Enables pprof for debugging performance and memory leak issues.")
	fs.Uint16Var(&s.MetricsPort, "metrics-port", 0, "Prometheus metrics port, (Default 0, Disabled)")
	fs.StringVar(&s.MetricsPath, "metrics-path", "/metrics", "Prometheus metrics path")
	// fs.StringVar(&s.FullMeshPassword, "nodes-full-mesh-password", s.FullMeshPassword,
	// 	"Password that cluster-node BGP servers will use to authenticate one another when \"--nodes-full-mesh\" is set.")
	fs.StringVarP(&s.VLevel, "v", "v", "0", "log level for V logs")
	fs.Uint16Var(&s.HealthPort, "health-port", 20244, "Health check port, 0 = Disabled")
	fs.BoolVar(&s.OverrideNextHop, "override-nexthop", false, "Override the next-hop in bgp routes sent to peers with the local ip.")
	fs.BoolVar(&s.DisableSrcDstCheck, "disable-source-dest-check", true,
		"Disable the source-dest-check attribute for AWS EC2 instances. When this option is false, it must be set some other way.")
}
