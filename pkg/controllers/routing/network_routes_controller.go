package routing

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cloudnativelabs/kube-router/v2/pkg/bgp"
	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/v2/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/routes"
	"github.com/cloudnativelabs/kube-router/v2/pkg/tunnels"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
	gobgpapi "github.com/osrg/gobgp/v3/api"
	gobgp "github.com/osrg/gobgp/v3/pkg/server"
	"github.com/vishvananda/netlink"
	v1core "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

const (
	IfaceNotFound = "Link not found"

	podSubnetsIPSetName = "kube-router-pod-subnets"
	nodeAddrsIPSetName  = "kube-router-node-ips"

	nodeASNAnnotation                = "kube-router.io/node.asn"
	nodeCommunitiesAnnotation        = "kube-router.io/node.bgp.communities"
	nodeCustomImportRejectAnnotation = "kube-router.io/node.bgp.customimportreject"
	pathPrependASNAnnotation         = "kube-router.io/path-prepend.as"
	pathPrependRepeatNAnnotation     = "kube-router.io/path-prepend.repeat-n"
	peerASNAnnotation                = "kube-router.io/peer.asns"
	peerIPAnnotation                 = "kube-router.io/peer.ips"
	peerLocalIPAnnotation            = "kube-router.io/peer.localips"
	//nolint:gosec // this is not a hardcoded password
	peerPasswordAnnotation             = "kube-router.io/peer.passwords"
	peerPortAnnotation                 = "kube-router.io/peer.ports"
	rrClientAnnotation                 = "kube-router.io/rr.client"
	rrServerAnnotation                 = "kube-router.io/rr.server"
	svcLocalAnnotation                 = "kube-router.io/service.local"
	bgpLocalAddressAnnotation          = "kube-router.io/bgp-local-addresses"
	svcAdvertiseClusterAnnotation      = "kube-router.io/service.advertise.clusterip"
	svcAdvertiseExternalAnnotation     = "kube-router.io/service.advertise.externalip"
	svcAdvertiseLoadBalancerAnnotation = "kube-router.io/service.advertise.loadbalancerip"

	// Deprecated: use kube-router.io/service.advertise.loadbalancer instead
	svcSkipLbIpsAnnotation = "kube-router.io/service.skiplbips"

	LoadBalancerST = "LoadBalancer"
	ClusterIPST    = "ClusterIP"
	NodePortST     = "NodePort"

	prependPathMaxBits  = 8
	asnMaxBitSize       = 32
	routeReflectorMaxID = 32
	ipv4MaskMinBits     = 32
)

// RouteSyncer is an interface that defines the methods needed to sync routes to the kernel's routing table
type RouteSyncer interface {
	AddInjectedRoute(dst *net.IPNet, route *netlink.Route)
	DelInjectedRoute(dst *net.IPNet)
	Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup)
	SyncLocalRouteTable() error
}

// PolicyBasedRouting is an interface that defines the methods needed to enable/disable policy based routing
type PolicyBasedRouter interface {
	Enable() error
	Disable() error
}

// NetworkRoutingController is struct to hold necessary information required by controller
type NetworkRoutingController struct {
	krNode                         utils.NodeAware
	routerID                       string
	activeNodes                    map[string]bool
	mu                             sync.Mutex
	clientset                      kubernetes.Interface
	bgpServer                      *gobgp.BgpServer
	syncPeriod                     time.Duration
	clusterCIDR                    string
	enablePodEgress                bool
	hostnameOverride               string
	advertiseClusterIP             bool
	advertiseExternalIP            bool
	advertiseLoadBalancerIP        bool
	advertisePodCidr               bool
	autoMTU                        bool
	defaultNodeAsnNumber           uint32
	nodeAsnNumber                  uint32
	nodeCustomImportRejectIPNets   []net.IPNet
	nodeCommunities                []string
	globalPeerRouters              []*gobgpapi.Peer
	nodePeerRouters                []string
	enableCNI                      bool
	bgpFullMeshMode                bool
	bgpEnableInternal              bool
	bgpGracefulRestart             bool
	bgpGracefulRestartTime         time.Duration
	bgpGracefulRestartDeferralTime time.Duration
	ipSetHandlers                  map[v1core.IPFamily]utils.IPSetHandler
	iptablesCmdHandlers            map[v1core.IPFamily]utils.IPTablesHandler
	enableOverlays                 bool
	overlayType                    string
	peerMultihopTTL                uint8
	MetricsEnabled                 bool
	bgpServerStarted               bool
	bgpHoldtime                    float64
	bgpPort                        uint32
	bgpRRClient                    bool
	bgpRRServer                    bool
	bgpClusterID                   string
	cniConfFile                    string
	disableSrcDstCheck             bool
	initSrcDstCheckDone            bool
	ec2IamAuthorized               bool
	pathPrependAS                  string
	pathPrependCount               uint8
	pathPrepend                    bool
	localAddressList               []string
	overrideNextHop                bool
	podCidr                        string
	podIPv4CIDRs                   []string
	podIPv6CIDRs                   []string
	CNIFirewallSetup               *sync.Cond
	ipsetMutex                     *sync.Mutex
	routeSyncer                    RouteSyncer
	pbr                            PolicyBasedRouter
	tunneler                       tunnels.Tunneler

	nodeLister cache.Indexer
	svcLister  cache.Indexer
	epLister   cache.Indexer

	NodeEventHandler      cache.ResourceEventHandler
	ServiceEventHandler   cache.ResourceEventHandler
	EndpointsEventHandler cache.ResourceEventHandler
}

// Run runs forever until we are notified on stop channel
func (nrc *NetworkRoutingController) Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{},
	wg *sync.WaitGroup) {
	var err error
	if nrc.enableCNI {
		nrc.updateCNIConfig()
	}

	klog.V(1).Info("Populating ipsets.")
	err = nrc.syncNodeIPSets(nrc.krNode)
	if err != nil {
		klog.Errorf("Failed initial ipset setup: %s", err)
	}

	// In case of cluster provisioned on AWS disable source-destination check
	if nrc.disableSrcDstCheck {
		nrc.disableSourceDestinationCheck()
		nrc.initSrcDstCheckDone = true
	}

	// enable IP forwarding for the packets coming in/out from the pods
	err = nrc.enableForwarding()
	if err != nil {
		klog.Errorf("Failed to enable IP forwarding of traffic from pods: %s", err.Error())
	}

	nrc.CNIFirewallSetup.Broadcast()

	nrc.pbr = routes.NewPolicyBasedRules(nrc.krNode, nrc.podIPv4CIDRs, nrc.podIPv6CIDRs)

	// Handle ipip tunnel overlay
	if nrc.enableOverlays {
		klog.V(1).Info("Tunnel Overlay enabled in configuration.")
		klog.V(1).Info("Setting up overlay networking.")
		err = nrc.pbr.Enable()
		if err != nil {
			klog.Errorf("Failed to enable required policy based routing: %s", err.Error())
		}
		if nrc.tunneler.EncapType() == tunnels.EncapTypeFOU {
			// enable FoU module for the overlay tunnel
			if _, err := exec.Command("modprobe", "fou").CombinedOutput(); err != nil {
				klog.Errorf("Failed to enable FoU for tunnel overlay: %s", err.Error())
			}
			if _, err := exec.Command("modprobe", "fou6").CombinedOutput(); err != nil {
				klog.Errorf("Failed to enable FoU6 for tunnel overlay: %s", err.Error())
			}
		}
	} else {
		klog.V(1).Info("Tunnel Overlay disabled in configuration.")
		klog.V(1).Info("Cleaning up old overlay networking if needed.")
		err = nrc.pbr.Disable()
		if err != nil {
			klog.Errorf("Failed to disable policy based routing: %s", err.Error())
		}
	}

	klog.V(1).Info("Performing cleanup of depreciated rules/ipsets (if needed).")
	err = nrc.deleteBadPodEgressRules()
	if err != nil {
		klog.Errorf("Error cleaning up old/bad Pod egress rules: %s", err.Error())
	}

	// Handle Pod egress masquerading configuration
	if nrc.enablePodEgress {
		klog.V(1).Infoln("Enabling Pod egress.")

		err = nrc.createPodEgressRule()
		if err != nil {
			klog.Errorf("Error enabling Pod egress: %s", err.Error())
		}
	} else {
		klog.V(1).Infoln("Disabling Pod egress.")

		err = nrc.deletePodEgressRule()
		if err != nil {
			klog.Warningf("Error cleaning up Pod Egress related networking: %s", err)
		}
	}

	// create 'kube-bridge' interface to which pods will be connected
	kubeBridgeIf, err := netlink.LinkByName("kube-bridge")
	if err != nil && err.Error() == IfaceNotFound {
		linkAttrs := netlink.NewLinkAttrs()
		linkAttrs.Name = "kube-bridge"
		bridge := &netlink.Bridge{LinkAttrs: linkAttrs}
		if err = netlink.LinkAdd(bridge); err != nil {
			klog.Errorf("Failed to create `kube-router` bridge due to %s. Will be created by CNI bridge "+
				"plugin when pod is launched.", err.Error())
		}
		kubeBridgeIf, err = netlink.LinkByName("kube-bridge")
		if err != nil {
			klog.Errorf("Failed to find created `kube-router` bridge due to %s. Will be created by CNI "+
				"bridge plugin when pod is launched.", err.Error())
		}
		err = netlink.LinkSetUp(kubeBridgeIf)
		if err != nil {
			klog.Errorf("Failed to bring `kube-router` bridge up due to %s. Will be created by CNI bridge "+
				"plugin at later point when pod is launched.", err.Error())
		}
	}

	if nrc.autoMTU {
		mtu, err := nrc.krNode.GetNodeMTU()
		if err != nil {
			klog.Errorf("Failed to find MTU for node IP: %s for intelligently setting the kube-bridge MTU "+
				"due to %s.", nrc.krNode.GetPrimaryNodeIP(), err.Error())
		}
		if mtu > 0 {
			klog.Infof("Setting MTU of kube-bridge interface to: %d", mtu)
			err = netlink.LinkSetMTU(kubeBridgeIf, mtu)
			if err != nil {
				klog.Errorf(
					"Failed to set MTU for kube-bridge interface due to: %s (kubeBridgeIf: %#v, mtu: %v)",
					err.Error(), kubeBridgeIf, mtu,
				)
				// need to correct kuberouter.conf because autoConfigureMTU() may have set an invalid value!
				currentMTU := kubeBridgeIf.Attrs().MTU
				if currentMTU > 0 && currentMTU != mtu {
					klog.Warningf("Updating config file with current MTU for kube-bridge: %d", currentMTU)
					cniNetConf, err := utils.NewCNINetworkConfig(nrc.cniConfFile)
					if err == nil {
						cniNetConf.SetMTU(currentMTU)
						if err = cniNetConf.WriteCNIConfig(); err != nil {
							klog.Errorf("Failed to update CNI config file due to: %v", err)
						}
					} else {
						klog.Errorf("Failed to load CNI config file to reset MTU due to: %v", err)
					}
				}
			}
		} else {
			klog.Infof("Not setting MTU of kube-bridge interface")
		}
	}
	// enable netfilter for the bridge
	if _, err := exec.Command("modprobe", "br_netfilter").CombinedOutput(); err != nil {
		klog.Errorf("Failed to enable netfilter for bridge. Network policies and service proxy may "+
			"not work: %s", err.Error())
	}
	sysctlErr := utils.SetSysctl(utils.BridgeNFCallIPTables, 1)
	if sysctlErr != nil {
		klog.Errorf("Failed to enable iptables for bridge. Network policies and service proxy may "+
			"not work: %s", sysctlErr.Error())
	}
	if nrc.krNode.IsIPv6Capable() {
		sysctlErr = utils.SetSysctl(utils.BridgeNFCallIP6Tables, 1)
		if sysctlErr != nil {
			klog.Errorf("Failed to enable ip6tables for bridge. Network policies and service proxy may "+
				"not work: %s", sysctlErr.Error())
		}
	}

	t := time.NewTicker(nrc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	klog.Infof("Starting network route controller")

	// Start route syncer
	nrc.routeSyncer.Run(healthChan, stopCh, wg)

	// Wait till we are ready to launch BGP server
	for {
		err := nrc.startBgpServer(true)
		if err != nil {
			klog.Errorf("Failed to start node BGP server: %s", err)
			select {
			case <-stopCh:
				klog.Infof("Shutting down network routes controller")
				return
			case <-t.C:
				klog.Infof("Retrying start of node BGP server")
				continue
			}
		} else {
			break
		}
	}

	nrc.bgpServerStarted = true
	if !nrc.bgpGracefulRestart {
		defer func() {
			err := nrc.bgpServer.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{})
			if err != nil {
				klog.Errorf("error shutting down BGP server: %s", err)
			}
		}()
	}

	// loop forever till notified to stop on stopCh
	for {
		var err error
		select {
		case <-stopCh:
			klog.Infof("Shutting down network routes controller")
			return
		default:
		}

		// Update ipset entries
		if nrc.enablePodEgress || nrc.enableOverlays {
			klog.V(1).Info("Syncing ipsets")
			err = nrc.syncNodeIPSets(nrc.krNode)
			if err != nil {
				klog.Errorf("Error synchronizing ipsets: %s", err.Error())
			}
		}

		// enable IP forwarding for the packets coming in/out from the pods
		err = nrc.enableForwarding()
		if err != nil {
			klog.Errorf("Failed to enable IP forwarding of traffic from pods: %s", err.Error())
		}

		// advertise or withdraw IPs for the services to be reachable via host
		toAdvertise, toWithdraw, err := nrc.getVIPs()
		if err != nil {
			klog.Errorf("failed to get routes to advertise/withdraw %s", err)
		}

		klog.V(1).Infof("Performing periodic sync of service VIP routes")
		nrc.advertiseVIPs(toAdvertise)
		nrc.withdrawVIPs(toWithdraw)

		klog.V(1).Info("Performing periodic sync of pod CIDR routes")
		err = nrc.advertisePodRoute()
		if err != nil {
			klog.Errorf("Error advertising route: %s", err.Error())
		}

		err = nrc.AddPolicies()
		if err != nil {
			klog.Errorf("Error adding BGP policies: %s", err.Error())
		}

		if nrc.bgpEnableInternal {
			nrc.syncInternalPeers()
		}

		if err == nil {
			healthcheck.SendHeartBeat(healthChan, healthcheck.NetworkRoutesController)
		} else {
			klog.Errorf("Error during periodic sync in network routing controller. Error: " + err.Error())
			klog.Errorf("Skipping sending heartbeat from network routing controller as periodic sync failed.")
		}

		select {
		case <-stopCh:
			klog.Infof("Shutting down network routes controller")
			return
		case <-t.C:
		}
	}
}

func (nrc *NetworkRoutingController) updateCNIConfig() {
	// Parse the existing IPAM CIDRs from the CNI conf file
	cniNetConf, err := utils.NewCNINetworkConfig(nrc.cniConfFile)
	if err != nil {
		klog.Errorf("failed to parse CNI Config: %v", err)
	}

	// Insert any IPv4 CIDRs that are missing from the IPAM configuration in the CNI
	for _, ipv4CIDR := range nrc.podIPv4CIDRs {
		err = cniNetConf.InsertPodCIDRIntoIPAM(ipv4CIDR)
		if err != nil {
			klog.Fatalf("failed to insert IPv4 `subnet`(pod CIDR) '%s' into CNI conf file: %v", ipv4CIDR, err)
		}
	}

	// Insert any IPv4 CIDRs that are missing from the IPAM configuration in the CNI
	for _, ipv6CIDR := range nrc.podIPv6CIDRs {
		err = cniNetConf.InsertPodCIDRIntoIPAM(ipv6CIDR)
		if err != nil {
			klog.Fatalf("failed to insert IPv6 `subnet`(pod CIDR) '%s' into CNI conf file: %v", ipv6CIDR, err)
		}
	}

	if nrc.autoMTU {
		// Get the MTU by looking at the node's interface that is associated with the primary IP of the cluster
		mtu, err := nrc.krNode.GetNodeMTU()
		if err != nil {
			klog.Fatalf("failed to generate MTU: %v", err)
		}

		cniNetConf.SetMTU(mtu)
	}

	err = cniNetConf.WriteCNIConfig()
	if err != nil {
		klog.Fatalf("failed to write CNI file: %v", err)
	}
}

func (nrc *NetworkRoutingController) watchBgpUpdates() {
	pathWatch := func(r *gobgpapi.WatchEventResponse) {
		if table := r.GetTable(); table != nil {
			for _, path := range table.Paths {
				if path.Family.Afi == gobgpapi.Family_AFI_IP ||
					path.Family.Afi == gobgpapi.Family_AFI_IP6 ||
					path.Family.Safi == gobgpapi.Family_SAFI_UNICAST {
					if nrc.MetricsEnabled {
						metrics.ControllerBGPadvertisementsReceived.Inc()
					}
					if path.NeighborIp == "<nil>" {
						return
					}
					klog.V(2).Infof("Processing bgp route advertisement from peer: %s", path.NeighborIp)
					if err := nrc.injectRoute(path); err != nil {
						klog.Errorf("Failed to inject routes due to: " + err.Error())
					}
				}
			}
		}
	}
	err := nrc.bgpServer.WatchEvent(context.Background(), &gobgpapi.WatchEventRequest{
		Table: &gobgpapi.WatchEventRequest_Table{
			Filters: []*gobgpapi.WatchEventRequest_Table_Filter{
				{
					Type: gobgpapi.WatchEventRequest_Table_Filter_BEST,
				},
			},
		},
	}, pathWatch)
	if err != nil {
		klog.Errorf("failed to register monitor global routing table callback due to : " + err.Error())
	}
}

func (nrc *NetworkRoutingController) advertisePodRoute() error {
	if nrc.MetricsEnabled {
		metrics.ControllerBGPadvertisementsSent.WithLabelValues("pod-route").Inc()
	}

	// Advertise IPv4 CIDRs
	nodePrimaryIPv4IP := nrc.krNode.FindBestIPv4NodeAddress()
	if nrc.krNode.IsIPv4Capable() && nodePrimaryIPv4IP == nil {
		return fmt.Errorf("previous logic marked this node as IPv4 capable, but we couldn't find any " +
			"available IPv4 node IPs, this shouldn't happen")
	}
	for _, cidr := range nrc.podIPv4CIDRs {
		ip, cidrNet, err := net.ParseCIDR(cidr)
		cidrLen, _ := cidrNet.Mask.Size()
		if err != nil || cidrLen < 0 || cidrLen > 32 {
			return fmt.Errorf("the pod CIDR IP given is not a proper mask: %d", cidrLen)
		}
		klog.V(2).Infof("Advertising route: '%s/%d via %s' to peers",
			ip, cidrLen, nrc.krNode.GetPrimaryNodeIP().String())
		nlri, _ := anypb.New(&gobgpapi.IPAddressPrefix{
			PrefixLen: uint32(cidrLen),
			Prefix:    ip.String(),
		})

		a1, _ := anypb.New(&gobgpapi.OriginAttribute{
			Origin: 0,
		})
		a2, _ := anypb.New(&gobgpapi.NextHopAttribute{
			NextHop: nodePrimaryIPv4IP.String(),
		})
		attrs := []*anypb.Any{a1, a2}

		response, err := nrc.bgpServer.AddPath(context.Background(), &gobgpapi.AddPathRequest{
			Path: &gobgpapi.Path{
				Family: &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP, Safi: gobgpapi.Family_SAFI_UNICAST},
				Nlri:   nlri,
				Pattrs: attrs,
			},
		})
		if err != nil {
			return fmt.Errorf(err.Error())
		}
		klog.V(1).Infof("Response from adding path: %s", response)
	}

	// Advertise IPv6 CIDRs
	if nrc.krNode.IsIPv6Capable() {
		nodePrimaryIPv6IP := nrc.krNode.FindBestIPv6NodeAddress()
		if nodePrimaryIPv6IP == nil {
			return fmt.Errorf("previous logic marked this node as IPv6 capable, but we couldn't find any " +
				"available IPv6 node IPs, this shouldn't happen")
		}

		for _, cidr := range nrc.podIPv6CIDRs {
			ip, cidrNet, err := net.ParseCIDR(cidr)
			cidrLen, _ := cidrNet.Mask.Size()
			if err != nil || cidrLen < 0 || cidrLen > 128 {
				return fmt.Errorf("the pod CIDR IP given is not a proper mask: %d", cidrLen)
			}

			klog.V(2).Infof("Advertising route: '%s/%d via %s' to peers", ip, cidrLen, nodePrimaryIPv6IP)

			v6Family := &gobgpapi.Family{
				Afi:  gobgpapi.Family_AFI_IP6,
				Safi: gobgpapi.Family_SAFI_UNICAST,
			}
			nlri, _ := anypb.New(&gobgpapi.IPAddressPrefix{
				PrefixLen: uint32(cidrLen),
				Prefix:    ip.String(),
			})
			a1, _ := anypb.New(&gobgpapi.OriginAttribute{
				Origin: 0,
			})
			v6Attrs, _ := anypb.New(&gobgpapi.MpReachNLRIAttribute{
				Family:   v6Family,
				NextHops: []string{nodePrimaryIPv6IP.String()},
				Nlris:    []*anypb.Any{nlri},
			})
			response, err := nrc.bgpServer.AddPath(context.Background(), &gobgpapi.AddPathRequest{
				Path: &gobgpapi.Path{
					Family: v6Family,
					Nlri:   nlri,
					Pattrs: []*anypb.Any{a1, v6Attrs},
				},
			})
			if err != nil {
				return fmt.Errorf(err.Error())
			}
			klog.V(1).Infof("Response from adding path: %s", response)
		}
	}

	return nil
}

func (nrc *NetworkRoutingController) injectRoute(path *gobgpapi.Path) error {
	klog.V(2).Infof("injectRoute Path Looks Like: %s", path.String())
	var route *netlink.Route
	var link netlink.Link

	dst, nextHop, err := bgp.ParsePath(path)
	if err != nil {
		return err
	}

	tunnelName := tunnels.GenerateTunnelName(nextHop.String())
	checkNHSameSubnet := func(needle net.IP, haystack []net.IP) bool {
		for _, nodeIP := range haystack {
			nodeSubnet, _, err := utils.GetNodeSubnet(nodeIP, nil)
			if err != nil {
				klog.Warningf("unable to get subnet for node IP: %s, err: %v... skipping", nodeIP, err)
				continue
			}
			// If we've found a subnet that contains our nextHop then we're done here
			if nodeSubnet.Contains(needle) {
				return true
			}
		}
		return false
	}

	var sameSubnet bool
	if nextHop.To4() != nil {
		sameSubnet = checkNHSameSubnet(nextHop, nrc.krNode.GetNodeIPv4Addrs())
	} else if nextHop.To16() != nil {
		sameSubnet = checkNHSameSubnet(nextHop, nrc.krNode.GetNodeIPv6Addrs())
	}

	// If we've made it this far, then it is likely that the node is holding a destination route for this path already.
	// If the path we've received from GoBGP is a withdrawal, we should clean up any lingering routes that may exist
	// on the host (rather than creating a new one or updating an existing one), and then return.
	if path.IsWithdraw {
		klog.V(2).Infof("Removing route: '%s via %s' from peer in the routing table", dst, nextHop)

		// The path might be withdrawn because the peer became unestablished or it may be withdrawn because just the
		// path was withdrawn. Check to see if the peer is still established before deciding whether to clean the
		// tunnel and tunnel routes or whether to just delete the destination route.
		peerEstablished, err := nrc.isPeerEstablished(nextHop.String())
		if err != nil {
			klog.Errorf("encountered error while checking peer status: %v", err)
		}
		if err == nil && !peerEstablished {
			klog.V(1).Infof("Peer '%s' was not found any longer, removing tunnel and routes",
				nextHop.String())
			// Also delete route from state map so that it doesn't get re-synced after deletion
			nrc.routeSyncer.DelInjectedRoute(dst)
			tunnels.CleanupTunnel(dst, tunnelName)
			return nil
		}

		// Also delete route from state map so that it doesn't get re-synced after deletion
		nrc.routeSyncer.DelInjectedRoute(dst)
		return routes.DeleteByDestination(dst)
	}

	shouldCreateTunnel := func() bool {
		if !nrc.enableOverlays {
			return false
		}
		if nrc.overlayType == "full" {
			return true
		}
		if nrc.overlayType == "subnet" && !sameSubnet {
			return true
		}
		return false
	}

	// create IPIP tunnels only when node is not in same subnet or overlay-type is set to 'full'
	// if the user has disabled overlays, don't create tunnels. If we're not creating a tunnel, check to see if there is
	// any cleanup that needs to happen.
	if shouldCreateTunnel() {
		link, err = nrc.tunneler.SetupOverlayTunnel(tunnelName, nextHop, dst)
		if err != nil {
			return err
		}
	} else {
		// knowing that a tunnel shouldn't exist for this route, check to see if there are any lingering tunnels /
		// routes that need to be cleaned up.
		nrc.routeSyncer.DelInjectedRoute(dst)
		tunnels.CleanupTunnel(dst, tunnelName)
	}

	switch {
	case link != nil:
		// if we set up an overlay tunnel link, then use it for destination routing
		var bestIPForFamily net.IP
		if dst.IP.To4() != nil {
			bestIPForFamily = nrc.krNode.FindBestIPv4NodeAddress()
		} else {
			// Need to activate the ip command in IPv6 mode
			bestIPForFamily = nrc.krNode.FindBestIPv6NodeAddress()
		}
		if bestIPForFamily == nil {
			return fmt.Errorf("not able to find an appropriate configured IP address on node for destination "+
				"IP family: %s", dst.String())
		}
		route = &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Src:       bestIPForFamily,
			Dst:       dst,
			Protocol:  routes.ZebraOriginator,
		}
	case sameSubnet:
		// if the nextHop is within the same subnet, add a route for the destination so that traffic can bet routed
		// at layer 2 and minimize the need to traverse a router
		// First check that destination and nexthop are in the same IP family
		dstIsIPv4 := dst.IP.To4() != nil
		gwIsIPv4 := nextHop.To4() != nil
		if dstIsIPv4 != gwIsIPv4 {
			return fmt.Errorf("not able to add route as destination %s and gateway %s are not in the same IP family - "+
				"this shouldn't ever happen from IPs that kube-router advertises, but if it does report it as a bug",
				dst.IP, nextHop)
		}
		route = &netlink.Route{
			Dst:      dst,
			Gw:       nextHop,
			Protocol: routes.ZebraOriginator,
		}
	default:
		// otherwise, let BGP do its thing, nothing to do here
		nrc.routeSyncer.DelInjectedRoute(dst)
		return nil
	}

	// Alright, everything is in place, and we have our route configured, let's add it to the host's routing table
	klog.V(2).Infof("Inject route: '%s via %s' from peer to routing table", dst, nextHop)
	nrc.routeSyncer.AddInjectedRoute(dst, route)
	// Immediately sync the local route table regardless of timer
	return nrc.routeSyncer.SyncLocalRouteTable()
}

func (nrc *NetworkRoutingController) isPeerEstablished(peerIP string) (bool, error) {
	var peerConnected bool
	peerFunc := func(peer *gobgpapi.Peer) {
		if peer.Conf.NeighborAddress == peerIP && peer.State.SessionState == gobgpapi.PeerState_ESTABLISHED {
			peerConnected = true
		}
	}
	err := nrc.bgpServer.ListPeer(context.Background(), &gobgpapi.ListPeerRequest{
		Address: peerIP,
	}, peerFunc)
	if err != nil {
		return false, fmt.Errorf("unable to list peers to see if tunnel & routes need to be removed: %v", err)
	}

	return peerConnected, nil
}

// Cleanup performs the cleanup of configurations done
func (nrc *NetworkRoutingController) Cleanup() {
	klog.Infof("Cleaning up NetworkRoutesController configurations")

	// In prep for further steps make sure that ipset and iptables handlers are created
	if len(nrc.iptablesCmdHandlers) < 1 {
		// Even though we have a config at this point (via passed param), we want to send nil so that the node will
		// discover which IP address families it has and act accordingly
		err := nrc.setupHandlers(nil)
		if err != nil {
			klog.Errorf("could not cleanup because iptables/ipset handlers could not be created due to: %v", err)
			return
		}
	}

	// Pod egress cleanup
	err := nrc.deletePodEgressRule()
	if err != nil {
		// Changed to level 1 logging as errors occur when ipsets have already been cleaned and needlessly worries users
		klog.V(1).Infof("Error deleting Pod egress iptables rule: %v", err)
	}

	err = nrc.deleteBadPodEgressRules()
	if err != nil {
		// Changed to level 1 logging as errors occur when ipsets have already been cleaned and needlessly worries users
		klog.V(1).Infof("Error deleting Pod egress iptables rule: %s", err.Error())
	}

	// For some reason, if we go too fast into the ipset logic below it causes the system to think that the above
	// iptables rules are still referencing the ipsets below, and we get errors
	time.Sleep(1 * time.Second)

	// delete all ipsets created by kube-router
	// There are certain actions like Cleanup() actions that aren't working with full instantiations of the controller
	// and in these instances the mutex may not be present and may not need to be present as they are operating out of a
	// single goroutine where there is no need for locking
	if nil != nrc.ipsetMutex {
		klog.V(1).Infof("Attempting to attain ipset mutex lock")
		nrc.ipsetMutex.Lock()
		klog.V(1).Infof("Attained ipset mutex lock, continuing...")
		defer func() {
			nrc.ipsetMutex.Unlock()
			klog.V(1).Infof("Returned ipset mutex lock")
		}()
	}
	for _, ipset := range nrc.ipSetHandlers {
		err = ipset.Save()
		if err != nil {
			klog.Errorf("Failed to clean up ipsets: " + err.Error())
		}
		err = ipset.DestroyAllWithin()
		if err != nil {
			klog.Warningf("Error deleting ipset: %s", err.Error())
		}
	}

	klog.Infof("Successfully cleaned the NetworkRoutesController configuration done by kube-router")
}

func (nrc *NetworkRoutingController) syncNodeIPSets(nodeIPAware utils.NodeIPAware) error {
	var err error
	start := time.Now()
	defer func() {
		if nrc.MetricsEnabled {
			metrics.ControllerRoutesSyncTime.Observe(time.Since(start).Seconds())
		}
	}()
	klog.V(1).Infof("Attempting to attain ipset mutex lock")
	nrc.ipsetMutex.Lock()
	klog.V(1).Infof("Attained ipset mutex lock, continuing...")
	defer func() {
		nrc.ipsetMutex.Unlock()
		klog.V(1).Infof("Returned ipset mutex lock")
	}()

	nodes := nrc.nodeLister.List()

	// Collect active PodCIDR(s) and NodeIPs from nodes
	currentPodCidrs := make(map[v1core.IPFamily][][]string)
	currentNodeIPs := make(map[v1core.IPFamily][][]string)
	for _, obj := range nodes {
		node := obj.(*v1core.Node)
		podCIDRs := getPodCIDRsFromAllNodeSources(node)
		if len(podCIDRs) < 1 {
			klog.Warningf("Couldn't determine any Pod CIDRs for the %v node, skipping", node.Name)
			continue
		}
		for _, cidr := range podCIDRs {
			ip, _, err := net.ParseCIDR(cidr)
			if err != nil {
				klog.Warningf("Wasn't able to parse pod CIDR %s for node %s, skipping", cidr, node.Name)
			}
			if ip.To4() != nil {
				currentPodCidrs[v1core.IPv4Protocol] = append(currentPodCidrs[v1core.IPv4Protocol],
					[]string{cidr, utils.OptionTimeout, "0"})
			} else {
				currentPodCidrs[v1core.IPv6Protocol] = append(currentPodCidrs[v1core.IPv6Protocol],
					[]string{cidr, utils.OptionTimeout, "0"})
			}
		}

		var ipv4Addrs, ipv6Addrs [][]string
		for _, nodeIPv4 := range nodeIPAware.GetNodeIPv4Addrs() {
			ipv4Addrs = append(ipv4Addrs, []string{nodeIPv4.String(), utils.OptionTimeout, "0"})
		}
		for _, nodeIPv6 := range nodeIPAware.GetNodeIPv6Addrs() {
			ipv6Addrs = append(ipv6Addrs, []string{nodeIPv6.String(), utils.OptionTimeout, "0"})
		}
		currentNodeIPs[v1core.IPv4Protocol] = append(currentNodeIPs[v1core.IPv4Protocol], ipv4Addrs...)
		currentNodeIPs[v1core.IPv6Protocol] = append(currentNodeIPs[v1core.IPv6Protocol], ipv6Addrs...)
	}

	// Syncing Pod subnet ipset entries
	for family, ipSetHandler := range nrc.ipSetHandlers {
		ipSetHandler.RefreshSet(podSubnetsIPSetName, currentPodCidrs[family], utils.TypeHashNet)

		ipSetHandler.RefreshSet(nodeAddrsIPSetName, currentNodeIPs[family], utils.TypeHashIP)

		err = ipSetHandler.Restore()
		if err != nil {
			return fmt.Errorf("failed to sync pod subnets / node addresses ipsets: %v", err)
		}
	}
	return nil
}

// ensure there is rule in filter table and FORWARD chain to permit in/out traffic from pods
// this rules will be appended so that any iptables rules for network policies will take
// precedence
func (nrc *NetworkRoutingController) enableForwarding() error {
	for _, iptablesCmdHandler := range nrc.iptablesCmdHandlers {
		comment := "allow outbound traffic from pods"
		args := []string{"-m", "comment", "--comment", comment, "-i", "kube-bridge", "-j", "ACCEPT"}
		exists, err := iptablesCmdHandler.Exists("filter", "FORWARD", args...)
		if err != nil {
			return fmt.Errorf("failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err := iptablesCmdHandler.Insert("filter", "FORWARD", 1, args...)
			if err != nil {
				return fmt.Errorf("failed to run iptables command: %s", err.Error())
			}
		}

		comment = "allow inbound traffic to pods"
		args = []string{"-m", "comment", "--comment", comment, "-o", "kube-bridge", "-j", "ACCEPT"}
		exists, err = iptablesCmdHandler.Exists("filter", "FORWARD", args...)
		if err != nil {
			return fmt.Errorf("failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err = iptablesCmdHandler.Insert("filter", "FORWARD", 1, args...)
			if err != nil {
				return fmt.Errorf("failed to run iptables command: %s", err.Error())
			}
		}

		comment = "allow outbound node port traffic on node interface with which node ip is associated"
		args = []string{"-m", "comment", "--comment", comment, "-o", nrc.krNode.GetNodeInterfaceName(), "-j", "ACCEPT"}
		exists, err = iptablesCmdHandler.Exists("filter", "FORWARD", args...)
		if err != nil {
			return fmt.Errorf("failed to run iptables command: %s", err.Error())
		}
		if !exists {
			err = iptablesCmdHandler.Insert("filter", "FORWARD", 1, args...)
			if err != nil {
				return fmt.Errorf("failed to run iptables command: %s", err.Error())
			}
		}
	}

	return nil
}

func (nrc *NetworkRoutingController) startBgpServer(grpcServer bool) error {
	var nodeAsnNumber uint32
	node, err := utils.GetNodeObject(nrc.clientset, nrc.hostnameOverride)
	if err != nil {
		return errors.New("failed to get node object from api server: " + err.Error())
	}

	if nrc.bgpFullMeshMode {
		nodeAsnNumber = nrc.defaultNodeAsnNumber
	} else {
		nodeasn, ok := node.ObjectMeta.Annotations[nodeASNAnnotation]
		if !ok {
			return errors.New("could not find ASN number for the node. " +
				"Node needs to be annotated with ASN number details to start BGP server")
		}
		klog.Infof("Found ASN for the node to be %s from the node annotations", nodeasn)
		asnNo, err := strconv.ParseUint(nodeasn, 0, asnMaxBitSize)
		if err != nil {
			return errors.New("failed to parse ASN number specified for the the node")
		}
		nodeAsnNumber = uint32(asnNo)
		nrc.nodeAsnNumber = nodeAsnNumber
	}

	if clusterid, ok := node.ObjectMeta.Annotations[rrServerAnnotation]; ok {
		klog.Infof("Found rr.server for the node to be %s from the node annotation", clusterid)
		_, err := strconv.ParseUint(clusterid, 0, routeReflectorMaxID)
		if err != nil {
			if ip := net.ParseIP(clusterid); ip == nil {
				return errors.New("failed to parse rr.server clusterId specified for the node")
			}
		}
		nrc.bgpClusterID = clusterid
		nrc.bgpRRServer = true
	} else if clusterid, ok := node.ObjectMeta.Annotations[rrClientAnnotation]; ok {
		klog.Infof("Found rr.client for the node to be %s from the node annotation", clusterid)
		_, err := strconv.ParseUint(clusterid, 0, routeReflectorMaxID)
		if err != nil {
			if ip := net.ParseIP(clusterid); ip == nil {
				return errors.New("failed to parse rr.client clusterId specified for the node")
			}
		}
		nrc.bgpClusterID = clusterid
		nrc.bgpRRClient = true
	}

	if prependASN, okASN := node.ObjectMeta.Annotations[pathPrependASNAnnotation]; okASN {
		prependRepeatN, okRepeatN := node.ObjectMeta.Annotations[pathPrependRepeatNAnnotation]

		if !okRepeatN {
			return fmt.Errorf("both %s and %s must be set", pathPrependASNAnnotation, pathPrependRepeatNAnnotation)
		}

		_, err := strconv.ParseUint(prependASN, 0, asnMaxBitSize)
		if err != nil {
			return errors.New("failed to parse ASN number specified to prepend")
		}

		repeatN, err := strconv.ParseUint(prependRepeatN, 0, prependPathMaxBits)
		if err != nil {
			return errors.New("failed to parse number of times ASN should be repeated")
		}

		nrc.pathPrepend = true
		nrc.pathPrependAS = prependASN
		nrc.pathPrependCount = uint8(repeatN)
	}

	var nodeCommunities []string
	nodeBGPCommunitiesAnnotation, ok := node.ObjectMeta.Annotations[nodeCommunitiesAnnotation]
	if !ok {
		klog.V(1).Info("Did not find any BGP communities on current node's annotations. " +
			"Not exporting communities.")
	} else {
		nodeCommunities = stringToSlice(nodeBGPCommunitiesAnnotation, ",")
		for _, nodeCommunity := range nodeCommunities {
			if err = bgp.ValidateCommunity(nodeCommunity); err != nil {
				klog.Warningf("cannot add BGP community '%s' from node annotation as it does not appear "+
					"to be a valid community identifier", nodeCommunity)
				continue
			}
			klog.V(1).Infof("Adding the node community found from node annotation: %s", nodeCommunity)
			nrc.nodeCommunities = append(nrc.nodeCommunities, nodeCommunity)
		}
		if len(nrc.nodeCommunities) < 1 {
			klog.Warningf("Found a community specified via annotation %s with value %s but none could be "+
				"validated", nodeCommunitiesAnnotation, nodeBGPCommunitiesAnnotation)
		}
	}

	// Get Custom Import Reject CIDRs from annotations
	nodeBGPCustomImportRejectAnnotation, ok := node.ObjectMeta.Annotations[nodeCustomImportRejectAnnotation]
	if !ok {
		klog.V(1).Info("Did not find any node.bgp.customimportreject on current node's annotations. " +
			"Skip configuring it.")
	} else {
		ipNetStrings := stringToSlice(nodeBGPCustomImportRejectAnnotation, ",")
		ipNets, err := stringSliceToIPNets(ipNetStrings)
		if err != nil {
			klog.Warningf("Failed to parse node.bgp.customimportreject specified for the node, skip configuring it")
		} else {
			nrc.nodeCustomImportRejectIPNets = ipNets
		}
	}

	if grpcServer {
		nrc.bgpServer = gobgp.NewBgpServer(
			gobgp.GrpcListenAddress(net.JoinHostPort(nrc.krNode.GetPrimaryNodeIP().String(),
				"50051") + "," + "127.0.0.1:50051"))
	} else {
		nrc.bgpServer = gobgp.NewBgpServer()
	}
	go nrc.bgpServer.Serve()

	var localAddressList []string

	if nrc.krNode.IsIPv4Capable() && !utils.ContainsIPv4Address(nrc.localAddressList) {
		klog.Warningf("List of local addresses did not contain a valid IPv4 address, but IPv4 was " +
			"enabled in kube-router's CLI options. BGP may not work as expected!")
	}

	if nrc.krNode.IsIPv6Capable() && !utils.ContainsIPv6Address(nrc.localAddressList) {
		klog.Warningf("List of local addresses did not contain a valid IPv6 address, but IPv6 was " +
			"enabled in kube-router's CLI options. BGP may not work as expected!")
	}

	for _, addr := range nrc.localAddressList {
		ip := net.ParseIP(addr)
		// This should have been caught in NewNetworkRoutingController, but we'll check once more just to be sure
		if ip == nil {
			klog.Warningf("was configured to listen on %s, but address was not valid, skipping (this should "+
				"have been caught earlier in execution, please report upstream!)", addr)
			continue
		}

		// Make sure that the address type matches what we're capable of before listening
		if ip.To4() != nil {
			if !nrc.krNode.IsIPv4Capable() {
				klog.Warningf("was configured to listen on %s, but node is not enabled for IPv4 or does not "+
					"have any IPv4 addresses configured for it, skipping", addr)
				continue
			}
		} else {
			if !nrc.krNode.IsIPv6Capable() {
				klog.Warningf("was configured to listen on %s, but node is not enabled for IPv6 or does not "+
					"have any IPv6 addresses configured for it, skipping", addr)
				continue
			}
		}
		localAddressList = append(localAddressList, addr)
	}

	global := &gobgpapi.Global{
		Asn:             nodeAsnNumber,
		RouterId:        nrc.routerID,
		ListenAddresses: localAddressList,
		ListenPort:      int32(nrc.bgpPort),
	}

	if err := nrc.bgpServer.StartBgp(context.Background(), &gobgpapi.StartBgpRequest{Global: global}); err != nil {
		return errors.New("failed to start BGP server due to : " + err.Error())
	}

	go nrc.watchBgpUpdates()

	// If the global routing peer is configured then peer with it
	// else attempt to get peers from node specific BGP annotations.
	if len(nrc.globalPeerRouters) == 0 {
		// Get Global Peer Router ASN configs
		nodeBgpPeerAsnsAnnotation, ok := node.ObjectMeta.Annotations[peerASNAnnotation]
		if !ok {
			klog.Infof("Could not find BGP peer info for the node in the node annotations so " +
				"skipping configuring peer.")
			return nil
		}

		asnStrings := stringToSlice(nodeBgpPeerAsnsAnnotation, ",")
		peerASNs, err := stringSliceToUInt32(asnStrings)
		if err != nil {
			err2 := nrc.bgpServer.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{})
			if err2 != nil {
				klog.Errorf("Failed to stop bgpServer: %s", err2)
			}
			return fmt.Errorf("failed to parse node's Peer ASN Numbers Annotation: %s", err)
		}

		// Get Global Peer Router IP Address configs
		nodeBgpPeersAnnotation, ok := node.ObjectMeta.Annotations[peerIPAnnotation]
		if !ok {
			klog.Infof("Could not find BGP peer info for the node in the node annotations " +
				"so skipping configuring peer.")
			return nil
		}
		ipStrings := stringToSlice(nodeBgpPeersAnnotation, ",")
		peerIPs, err := stringSliceToIPs(ipStrings)
		if err != nil {
			err2 := nrc.bgpServer.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{})
			if err2 != nil {
				klog.Errorf("Failed to stop bgpServer: %s", err2)
			}

			return fmt.Errorf("failed to parse node's Peer Addresses Annotation: %s", err)
		}

		// Get Global Peer Router ASN configs
		nodeBgpPeerPortsAnnotation, ok := node.ObjectMeta.Annotations[peerPortAnnotation]
		// Default to default BGP port if port annotation is not found
		var peerPorts = make([]uint32, 0)
		if ok {
			portStrings := stringToSlice(nodeBgpPeerPortsAnnotation, ",")
			peerPorts, err = stringSliceToUInt32(portStrings)
			if err != nil {
				err2 := nrc.bgpServer.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{})
				if err2 != nil {
					klog.Errorf("Failed to stop bgpServer: %s", err2)
				}
				return fmt.Errorf("failed to parse node's Peer Port Numbers Annotation: %s", err)
			}
		}

		// Get Global Peer Router Password configs
		var peerPasswords []string
		nodeBGPPasswordsAnnotation, ok := node.ObjectMeta.Annotations[peerPasswordAnnotation]
		if !ok {
			klog.Infof("Could not find BGP peer password info in the node's annotations. Assuming no passwords.")
		} else {
			passStrings := stringToSlice(nodeBGPPasswordsAnnotation, ",")
			peerPasswords, err = stringSliceB64Decode(passStrings)
			if err != nil {
				err2 := nrc.bgpServer.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{})
				if err2 != nil {
					klog.Errorf("Failed to stop bgpServer: %s", err2)
				}
				return fmt.Errorf("failed to parse node's Peer Passwords Annotation")
			}
		}

		// Get Global Peer Router LocalIP configs
		var peerLocalIPs []string
		nodeBGPPeerLocalIPs, ok := node.ObjectMeta.Annotations[peerLocalIPAnnotation]
		if !ok {
			klog.Infof("Could not find BGP peer local ip info in the node's annotations. Assuming node IP.")
		} else {
			peerLocalIPs = stringToSlice(nodeBGPPeerLocalIPs, ",")
			err = func() error {
				for _, s := range peerLocalIPs {
					if s != "" {
						ip := net.ParseIP(s)
						if ip == nil {
							return fmt.Errorf("could not parse \"%s\" as an IP", s)
						}
					}
				}

				return nil
			}()
			if err != nil {
				err2 := nrc.bgpServer.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{})
				if err2 != nil {
					klog.Errorf("Failed to stop bgpServer: %s", err2)
				}

				return fmt.Errorf("failed to parse node's Peer Local Addresses Annotation: %s", err)
			}
		}

		// Create and set Global Peer Router complete configs
		nrc.globalPeerRouters, err = newGlobalPeers(peerIPs, peerPorts, peerASNs, peerPasswords, peerLocalIPs,
			nrc.bgpHoldtime, nrc.krNode.GetPrimaryNodeIP().String())
		if err != nil {
			err2 := nrc.bgpServer.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{})
			if err2 != nil {
				klog.Errorf("Failed to stop bgpServer: %s", err2)
			}

			return fmt.Errorf("failed to process Global Peer Router configs: %s", err)
		}

		nrc.nodePeerRouters = ipStrings
	}

	if len(nrc.globalPeerRouters) != 0 {
		err := nrc.connectToExternalBGPPeers(nrc.bgpServer, nrc.globalPeerRouters, nrc.bgpGracefulRestart,
			nrc.bgpGracefulRestartDeferralTime, nrc.bgpGracefulRestartTime, nrc.peerMultihopTTL)
		if err != nil {
			err2 := nrc.bgpServer.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{})
			if err2 != nil {
				klog.Errorf("Failed to stop bgpServer: %s", err2)
			}

			return fmt.Errorf("failed to peer with Global Peer Router(s): %s",
				err)
		}
	} else {
		klog.Infof("No Global Peer Routers configured. Peering skipped.")
	}

	return nil
}

func (nrc *NetworkRoutingController) setupHandlers(node *v1core.Node) error {
	var err error

	// node being nil covers the case where this function is called by something that doesn't have a kube-apiserver
	// connection like the cleanup code. In this instance we want all possible iptables and ipset handlers
	if node != nil {
		nrc.podIPv4CIDRs, nrc.podIPv6CIDRs, err = utils.GetPodCIDRsFromNodeSpecDualStack(node)
		if err != nil {
			klog.Fatalf("Failed to get pod CIDRs from node spec. kube-router relies on kube-controller-manager to"+
				"allocate pod CIDRs for the node or an annotation `kube-router.io/pod-cidrs`. Error: %v", err)
			return fmt.Errorf("failed to get pod CIDRs detail from Node.spec: %v", err)
		}
	}

	nrc.iptablesCmdHandlers = make(map[v1core.IPFamily]utils.IPTablesHandler)
	nrc.ipSetHandlers = make(map[v1core.IPFamily]utils.IPSetHandler)
	if node == nil || nrc.krNode.IsIPv4Capable() {
		iptHandler, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		if err != nil {
			klog.Fatalf("Failed to allocate IPv4 iptables handler: %v", err)
			return fmt.Errorf("failed to create iptables handler: %w", err)
		}
		nrc.iptablesCmdHandlers[v1core.IPv4Protocol] = iptHandler

		ipset, err := utils.NewIPSet(false)
		if err != nil {
			klog.Fatalf("Failed to allocate IPv4 ipset handler: %v", err)
			return fmt.Errorf("failed to create ipset handler: %w", err)
		}
		nrc.ipSetHandlers[v1core.IPv4Protocol] = ipset
	}
	if node == nil || nrc.krNode.IsIPv6Capable() {
		iptHandler, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			klog.Fatalf("Failed to allocate IPv6 iptables handler: %v", err)
			return fmt.Errorf("failed to create iptables handler: %w", err)
		}
		nrc.iptablesCmdHandlers[v1core.IPv6Protocol] = iptHandler

		ipset, err := utils.NewIPSet(true)
		if err != nil {
			klog.Fatalf("Failed to allocate IPv6 ipset handler: %v", err)
			return fmt.Errorf("failed to create ipset handler: %w", err)
		}
		nrc.ipSetHandlers[v1core.IPv6Protocol] = ipset
	}

	return nil
}

// NewNetworkRoutingController returns new NetworkRoutingController object
func NewNetworkRoutingController(clientset kubernetes.Interface,
	kubeRouterConfig *options.KubeRouterConfig,
	nodeInformer cache.SharedIndexInformer, svcInformer cache.SharedIndexInformer,
	epInformer cache.SharedIndexInformer, ipsetMutex *sync.Mutex) (*NetworkRoutingController, error) {

	var err error

	nrc := NetworkRoutingController{ipsetMutex: ipsetMutex}
	if kubeRouterConfig.MetricsEnabled {
		// Register the metrics for this controller
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerBGPadvertisementsReceived)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerBGPadvertisementsSent)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerBGPInternalPeersSyncTime)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerBPGpeers)
		metrics.DefaultRegisterer.MustRegister(metrics.ControllerRoutesSyncTime)
		nrc.MetricsEnabled = true
	}

	nrc.bgpFullMeshMode = kubeRouterConfig.FullMeshMode
	nrc.enableCNI = kubeRouterConfig.EnableCNI
	nrc.bgpEnableInternal = kubeRouterConfig.EnableiBGP
	nrc.bgpGracefulRestart = kubeRouterConfig.BGPGracefulRestart
	nrc.bgpGracefulRestartDeferralTime = kubeRouterConfig.BGPGracefulRestartDeferralTime
	nrc.bgpGracefulRestartTime = kubeRouterConfig.BGPGracefulRestartTime
	nrc.peerMultihopTTL = kubeRouterConfig.PeerMultihopTTL
	nrc.enablePodEgress = kubeRouterConfig.EnablePodEgress
	nrc.syncPeriod = kubeRouterConfig.RoutesSyncPeriod
	nrc.overrideNextHop = kubeRouterConfig.OverrideNextHop
	nrc.clientset = clientset
	nrc.activeNodes = make(map[string]bool)
	nrc.bgpRRClient = false
	nrc.bgpRRServer = false
	nrc.bgpServerStarted = false
	nrc.disableSrcDstCheck = kubeRouterConfig.DisableSrcDstCheck
	nrc.initSrcDstCheckDone = false
	nrc.routeSyncer = routes.NewRouteSyncer(kubeRouterConfig.InjectedRoutesSyncPeriod)

	nrc.bgpHoldtime = kubeRouterConfig.BGPHoldTime.Seconds()
	if nrc.bgpHoldtime > 65536 || nrc.bgpHoldtime < 3 {
		return nil, errors.New("this is an incorrect BGP holdtime range, holdtime must be in the range " +
			"3s to 18h12m16s")
	}

	nrc.hostnameOverride = kubeRouterConfig.HostnameOverride
	node, err := utils.GetNodeObject(clientset, nrc.hostnameOverride)
	if err != nil {
		return nil, errors.New("failed getting node object from API server: " + err.Error())
	}

	nrc.krNode, err = utils.NewKRNode(node, nil, kubeRouterConfig.EnableIPv4, kubeRouterConfig.EnableIPv6)
	if err != nil {
		return nil, err
	}

	if kubeRouterConfig.EnableIPv6 {
		sysctlErr := utils.SetSysctl(utils.IPv6ConfAllDisableIPv6, 0)
		if sysctlErr != nil {
			klog.Errorf("Failed to set /proc/sys/net/ipv6/conf/all/disable_ipv6. IPv6 may "+
				"not work: %s", sysctlErr.Error())
		}
	}

	nrc.routerID, err = bgp.GenerateRouterID(nrc.krNode, kubeRouterConfig.RouterID)
	if err != nil {
		return nil, err
	}

	// let's start with assumption we have necessary IAM creds to access EC2 api
	nrc.ec2IamAuthorized = true

	if nrc.enableCNI {
		nrc.cniConfFile = os.Getenv("KUBE_ROUTER_CNI_CONF_FILE")
		if nrc.cniConfFile == "" {
			nrc.cniConfFile = "/etc/cni/net.d/10-kuberouter.conf"
		}
		if _, err := os.Stat(nrc.cniConfFile); os.IsNotExist(err) {
			return nil, errors.New("CNI conf file " + nrc.cniConfFile + " does not exist.")
		}
	}

	cidr, err := utils.GetPodCidrFromNodeSpec(node)
	if err != nil {
		klog.Fatalf("Failed to get pod CIDR from node spec. kube-router relies on kube-controller-manager to "+
			"allocate pod CIDR for the node or an annotation `kube-router.io/pod-cidr`. Error: %v", err)
		return nil, fmt.Errorf("failed to get pod CIDR details from Node.spec: %v", err)
	}
	nrc.podCidr = cidr

	err = nrc.setupHandlers(node)
	if err != nil {
		return nil, err
	}

	for _, handler := range nrc.ipSetHandlers {
		_, err = handler.Create(podSubnetsIPSetName, utils.TypeHashNet, utils.OptionTimeout, "0")
		if err != nil {
			return nil, err
		}

		_, err = handler.Create(nodeAddrsIPSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
		if err != nil {
			return nil, err
		}
	}

	if kubeRouterConfig.EnablePodEgress || len(nrc.clusterCIDR) != 0 {
		nrc.enablePodEgress = true
	}

	if kubeRouterConfig.ClusterAsn != 0 {
		if !((kubeRouterConfig.ClusterAsn >= 64512 && kubeRouterConfig.ClusterAsn <= 65535) ||
			(kubeRouterConfig.ClusterAsn >= 4200000000 && kubeRouterConfig.ClusterAsn <= 4294967294)) {
			return nil, errors.New("invalid ASN number for cluster ASN")
		}
		nrc.defaultNodeAsnNumber = uint32(kubeRouterConfig.ClusterAsn)
	} else {
		nrc.defaultNodeAsnNumber = 64512 // this magic number is first of the private ASN range, use it as default
	}

	nrc.advertiseClusterIP = kubeRouterConfig.AdvertiseClusterIP
	nrc.advertiseExternalIP = kubeRouterConfig.AdvertiseExternalIP
	nrc.advertiseLoadBalancerIP = kubeRouterConfig.AdvertiseLoadBalancerIP
	nrc.advertisePodCidr = kubeRouterConfig.AdvertiseNodePodCidr
	nrc.autoMTU = kubeRouterConfig.AutoMTU
	nrc.enableOverlays = kubeRouterConfig.EnableOverlay
	nrc.overlayType = kubeRouterConfig.OverlayType
	overlayEncap, ok := tunnels.ParseEncapType(kubeRouterConfig.OverlayEncap)
	if !ok {
		return nil, fmt.Errorf("unknown --overlay-encap option '%s' selected, unable to continue", overlayEncap)
	}
	overlayEncapPort, err := tunnels.ParseEncapPort(kubeRouterConfig.OverlayEncapPort)
	if err != nil {
		return nil, fmt.Errorf("unknown --overlay-encap-port option '%d' selected, unable to continue, err: %v",
			overlayEncapPort, err)
	}
	nrc.tunneler = tunnels.NewOverlayTunnel(nrc.krNode, overlayEncap, overlayEncapPort)
	nrc.CNIFirewallSetup = sync.NewCond(&sync.Mutex{})

	nrc.bgpPort = kubeRouterConfig.BGPPort

	// Convert ints to uint32s
	peerASNs := make([]uint32, 0)
	for _, i := range kubeRouterConfig.PeerASNs {
		peerASNs = append(peerASNs, uint32(i))
	}

	// Convert uints to uint16s
	peerPorts := make([]uint32, 0)
	for _, i := range kubeRouterConfig.PeerPorts {
		peerPorts = append(peerPorts, uint32(i))
	}

	// PeerPasswords as cli params take precedence over password file
	peerPasswords := make([]string, 0)
	if len(kubeRouterConfig.PeerPasswords) != 0 {
		peerPasswords, err = stringSliceB64Decode(kubeRouterConfig.PeerPasswords)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CLI Peer Passwords flag: %s", err)
		}
	} else if len(kubeRouterConfig.PeerPasswordsFile) != 0 {
		// Contents of the pw file should be in the same format as pw from CLI arg
		pwFileBytes, err := os.ReadFile(kubeRouterConfig.PeerPasswordsFile)
		if err != nil {
			return nil, fmt.Errorf("error loading Peer Passwords File : %s", err)
		}
		pws := strings.Split(string(pwFileBytes), ",")
		peerPasswords, err = stringSliceB64Decode(pws)
		if err != nil {
			return nil, fmt.Errorf("failed to decode CLI Peer Passwords file: %s", err)
		}
	}

	nrc.globalPeerRouters, err = newGlobalPeers(kubeRouterConfig.PeerRouters, peerPorts,
		peerASNs, peerPasswords, nil, nrc.bgpHoldtime, nrc.krNode.GetPrimaryNodeIP().String())
	if err != nil {
		return nil, fmt.Errorf("error processing Global Peer Router configs: %s", err)
	}

	bgpLocalAddressListAnnotation, ok := node.ObjectMeta.Annotations[bgpLocalAddressAnnotation]
	if !ok {
		if nrc.krNode.IsIPv4Capable() {
			nrc.localAddressList = append(nrc.localAddressList, nrc.krNode.FindBestIPv4NodeAddress().String())
		}
		if nrc.krNode.IsIPv6Capable() {
			nrc.localAddressList = append(nrc.localAddressList, nrc.krNode.FindBestIPv6NodeAddress().String())
		}
		klog.Infof("Could not find annotation `kube-router.io/bgp-local-addresses` on node object so BGP "+
			"will listen on node IP: %s addresses.", nrc.localAddressList)
	} else {
		klog.Infof("Found annotation `kube-router.io/bgp-local-addresses` on node object so BGP will listen "+
			"on local IP's: %s", bgpLocalAddressListAnnotation)
		localAddresses := stringToSlice(bgpLocalAddressListAnnotation, ",")
		for _, addr := range localAddresses {
			ip := net.ParseIP(addr)
			if ip == nil {
				klog.Fatalf("Invalid IP address %s specified in `kube-router.io/bgp-local-addresses`.", addr)
			}
			// Ensure that the IP address is able to bind on this host
			if l, err := net.Listen("tcp", "["+addr+"]:0"); err == nil {
				_ = l.Close()
			} else {
				klog.Fatalf("IP address %s specified in `kube-router.io/bgp-local-addresses` is not able to "+
					"be bound on this host", addr)
			}
		}
		nrc.localAddressList = append(nrc.localAddressList, localAddresses...)
	}
	nrc.svcLister = svcInformer.GetIndexer()
	nrc.ServiceEventHandler = nrc.newServiceEventHandler()

	nrc.epLister = epInformer.GetIndexer()
	nrc.EndpointsEventHandler = nrc.newEndpointsEventHandler()

	nrc.nodeLister = nodeInformer.GetIndexer()
	nrc.NodeEventHandler = nrc.newNodeEventHandler()

	return &nrc, nil
}
