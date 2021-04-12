package routing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	gobgpapi "github.com/osrg/gobgp/api"
	gobgp "github.com/osrg/gobgp/pkg/server"
	"k8s.io/klog/v2"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	v1core "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	IfaceNotFound = "Link not found"

	customRouteTableID   = "77"
	customRouteTableName = "kube-router"
	podSubnetsIPSetName  = "kube-router-pod-subnets"
	nodeAddrsIPSetName   = "kube-router-node-ips"

	nodeASNAnnotation                  = "kube-router.io/node.asn"
	nodeCommunitiesAnnotation          = "kube-router.io/node.bgp.communities"
	pathPrependASNAnnotation           = "kube-router.io/path-prepend.as"
	pathPrependRepeatNAnnotation       = "kube-router.io/path-prepend.repeat-n"
	peerASNAnnotation                  = "kube-router.io/peer.asns"
	peerIPAnnotation                   = "kube-router.io/peer.ips"
	peerPasswordAnnotation             = "kube-router.io/peer.passwords"
	peerPortAnnotation                 = "kube-router.io/peer.ports"
	rrClientAnnotation                 = "kube-router.io/rr.client"
	rrServerAnnotation                 = "kube-router.io/rr.server"
	svcLocalAnnotation                 = "kube-router.io/service.local"
	bgpLocalAddressAnnotation          = "kube-router.io/bgp-local-addresses"
	svcAdvertiseClusterAnnotation      = "kube-router.io/service.advertise.clusterip"
	svcAdvertiseExternalAnnotation     = "kube-router.io/service.advertise.externalip"
	svcAdvertiseLoadBalancerAnnotation = "kube-router.io/service.advertise.loadbalancerip"
	LeaderElectionRecordAnnotationKey  = "control-plane.alpha.kubernetes.io/leader"

	// Deprecated: use kube-router.io/service.advertise.loadbalancer instead
	svcSkipLbIpsAnnotation = "kube-router.io/service.skiplbips"
)

// NetworkRoutingController is struct to hold necessary information required by controller
type NetworkRoutingController struct {
	nodeIP                         net.IP
	nodeName                       string
	nodeSubnet                     net.IPNet
	nodeInterface                  string
	routerID                       string
	isIpv6                         bool
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
	nodeCommunities                []string
	globalPeerRouters              []*gobgpapi.Peer
	nodePeerRouters                []string
	enableCNI                      bool
	bgpFullMeshMode                bool
	bgpEnableInternal              bool
	bgpGracefulRestart             bool
	bgpGracefulRestartTime         time.Duration
	bgpGracefulRestartDeferralTime time.Duration
	ipSetHandler                   *utils.IPSet
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
	CNIFirewallSetup               *sync.Cond

	nodeLister cache.Indexer
	svcLister  cache.Indexer
	epLister   cache.Indexer

	NodeEventHandler      cache.ResourceEventHandler
	ServiceEventHandler   cache.ResourceEventHandler
	EndpointsEventHandler cache.ResourceEventHandler
}

// Run runs forever until we are notified on stop channel
func (nrc *NetworkRoutingController) Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) {
	var err error
	if nrc.enableCNI {
		nrc.updateCNIConfig()
	}

	klog.V(1).Info("Populating ipsets.")
	err = nrc.syncNodeIPSets()
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

	// Handle ipip tunnel overlay
	if nrc.enableOverlays {
		klog.V(1).Info("IPIP Tunnel Overlay enabled in configuration.")
		klog.V(1).Info("Setting up overlay networking.")
		err = nrc.enablePolicyBasedRouting()
		if err != nil {
			klog.Errorf("Failed to enable required policy based routing: %s", err.Error())
		}
	} else {
		klog.V(1).Info("IPIP Tunnel Overlay disabled in configuration.")
		klog.V(1).Info("Cleaning up old overlay networking if needed.")
		err = nrc.disablePolicyBasedRouting()
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
			klog.Errorf("Failed to create `kube-router` bridge due to %s. Will be created by CNI bridge plugin when pod is launched.", err.Error())
		}
		kubeBridgeIf, err = netlink.LinkByName("kube-bridge")
		if err != nil {
			klog.Errorf("Failed to find created `kube-router` bridge due to %s. Will be created by CNI bridge plugin when pod is launched.", err.Error())
		}
		err = netlink.LinkSetUp(kubeBridgeIf)
		if err != nil {
			klog.Errorf("Failed to bring `kube-router` bridge up due to %s. Will be created by CNI bridge plugin at later point when pod is launched.", err.Error())
		}
	}

	if nrc.autoMTU {
		mtu, err := utils.GetMTUFromNodeIP(nrc.nodeIP, nrc.enableOverlays)
		if err != nil {
			klog.Errorf("Failed to find MTU for node IP: %s for intelligently setting the kube-bridge MTU due to %s.", nrc.nodeIP, err.Error())
		}
		if mtu > 0 {
			klog.Infof("Setting MTU of kube-bridge interface to: %d", mtu)
			err = netlink.LinkSetMTU(kubeBridgeIf, mtu)
			if err != nil {
				klog.Errorf("Failed to set MTU for kube-bridge interface due to: %s", err.Error())
			}
		} else {
			klog.Infof("Not setting MTU of kube-bridge interface")
		}
	}
	// enable netfilter for the bridge
	if _, err := exec.Command("modprobe", "br_netfilter").CombinedOutput(); err != nil {
		klog.Errorf("Failed to enable netfilter for bridge. Network policies and service proxy may not work: %s", err.Error())
	}
	if err = ioutil.WriteFile("/proc/sys/net/bridge/bridge-nf-call-iptables", []byte(strconv.Itoa(1)), 0640); err != nil {
		klog.Errorf("Failed to enable iptables for bridge. Network policies and service proxy may not work: %s", err.Error())
	}
	if nrc.isIpv6 {
		if err = ioutil.WriteFile("/proc/sys/net/bridge/bridge-nf-call-ip6tables", []byte(strconv.Itoa(1)), 0640); err != nil {
			klog.Errorf("Failed to enable ip6tables for bridge. Network policies and service proxy may not work: %s", err.Error())
		}

	}

	t := time.NewTicker(nrc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	klog.Infof("Starting network route controller")

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
			err = nrc.syncNodeIPSets()
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
		toAdvertise, toWithdraw, err := nrc.getActiveVIPs()
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
			healthcheck.SendHeartBeat(healthChan, "NRC")
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
	cidr, err := utils.GetPodCidrFromCniSpec(nrc.cniConfFile)
	if err != nil {
		klog.Errorf("Failed to get pod CIDR from CNI conf file: %s", err)
	}

	if reflect.DeepEqual(cidr, net.IPNet{}) {
		klog.Infof("`subnet` in CNI conf file is empty so populating `subnet` in CNI conf file with pod CIDR assigned to the node obtained from node spec.")
	}
	cidrlen, _ := cidr.Mask.Size()
	oldCidr := cidr.IP.String() + "/" + strconv.Itoa(cidrlen)

	currentCidr := nrc.podCidr

	if len(cidr.IP) == 0 || strings.Compare(oldCidr, currentCidr) != 0 {
		err = utils.InsertPodCidrInCniSpec(nrc.cniConfFile, currentCidr)
		if err != nil {
			klog.Fatalf("Failed to insert `subnet`(pod CIDR) into CNI conf file: %s", err.Error())
		}
	}

	if nrc.autoMTU {
		err = nrc.autoConfigureMTU()
		if err != nil {
			klog.Errorf("Failed to auto-configure MTU due to: %s", err.Error())
		}
	}
}

func (nrc *NetworkRoutingController) autoConfigureMTU() error {
	mtu, err := utils.GetMTUFromNodeIP(nrc.nodeIP, nrc.enableOverlays)
	if err != nil {
		return fmt.Errorf("failed to generate MTU: %s", err.Error())
	}
	file, err := ioutil.ReadFile(nrc.cniConfFile)
	if err != nil {
		return fmt.Errorf("failed to load CNI conf file: %s", err.Error())
	}
	var config interface{}
	err = json.Unmarshal(file, &config)
	if err != nil {
		return fmt.Errorf("failed to parse JSON from CNI conf file: %s", err.Error())
	}
	if strings.HasSuffix(nrc.cniConfFile, ".conflist") {
		configMap := config.(map[string]interface{})
		for key := range configMap {
			if key != "plugins" {
				continue
			}
			pluginConfigs := configMap["plugins"].([]interface{})
			for _, pluginConfig := range pluginConfigs {
				pluginConfigMap := pluginConfig.(map[string]interface{})
				pluginConfigMap["mtu"] = mtu
			}
		}
	} else {
		pluginConfig := config.(map[string]interface{})
		pluginConfig["mtu"] = mtu
	}
	configJSON, _ := json.Marshal(config)
	err = ioutil.WriteFile(nrc.cniConfFile, configJSON, 0644)
	if err != nil {
		return fmt.Errorf("failed to insert `mtu` into CNI conf file: %s", err.Error())
	}
	return nil
}

func (nrc *NetworkRoutingController) watchBgpUpdates() {
	pathWatch := func(path *gobgpapi.Path) {
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
	err := nrc.bgpServer.MonitorTable(context.Background(), &gobgpapi.MonitorTableRequest{
		TableType: gobgpapi.TableType_GLOBAL,
		Family: &gobgpapi.Family{
			Afi:  gobgpapi.Family_AFI_IP,
			Safi: gobgpapi.Family_SAFI_UNICAST,
		},
	}, pathWatch)
	if err != nil {
		klog.Errorf("failed to register monitor global routing table callback due to : " + err.Error())
	}
}

func (nrc *NetworkRoutingController) advertisePodRoute() error {
	if nrc.MetricsEnabled {
		metrics.ControllerBGPadvertisementsSent.Inc()
	}

	cidrStr := strings.Split(nrc.podCidr, "/")
	subnet := cidrStr[0]
	cidrLen, err := strconv.Atoi(cidrStr[1])
	if err != nil || cidrLen < 0 || cidrLen > 32 {
		return fmt.Errorf("the pod CIDR IP given is not a proper mask: %d", cidrLen)
	}
	if nrc.isIpv6 {
		klog.V(2).Infof("Advertising route: '%s/%d via %s' to peers", subnet, cidrLen, nrc.nodeIP.String())

		v6Family := &gobgpapi.Family{
			Afi:  gobgpapi.Family_AFI_IP6,
			Safi: gobgpapi.Family_SAFI_UNICAST,
		}
		nlri, _ := ptypes.MarshalAny(&gobgpapi.IPAddressPrefix{
			PrefixLen: uint32(cidrLen),
			Prefix:    cidrStr[0],
		})
		a1, _ := ptypes.MarshalAny(&gobgpapi.OriginAttribute{
			Origin: 0,
		})
		v6Attrs, _ := ptypes.MarshalAny(&gobgpapi.MpReachNLRIAttribute{
			Family:   v6Family,
			NextHops: []string{nrc.nodeIP.String()},
			Nlris:    []*any.Any{nlri},
		})
		_, err := nrc.bgpServer.AddPath(context.Background(), &gobgpapi.AddPathRequest{
			Path: &gobgpapi.Path{
				Family: v6Family,
				Nlri:   nlri,
				Pattrs: []*any.Any{a1, v6Attrs},
			},
		})
		if err != nil {
			return fmt.Errorf(err.Error())
		}
	} else {

		klog.V(2).Infof("Advertising route: '%s/%d via %s' to peers", subnet, cidrLen, nrc.nodeIP.String())
		nlri, _ := ptypes.MarshalAny(&gobgpapi.IPAddressPrefix{
			PrefixLen: uint32(cidrLen),
			Prefix:    cidrStr[0],
		})

		a1, _ := ptypes.MarshalAny(&gobgpapi.OriginAttribute{
			Origin: 0,
		})
		a2, _ := ptypes.MarshalAny(&gobgpapi.NextHopAttribute{
			NextHop: nrc.nodeIP.String(),
		})
		attrs := []*any.Any{a1, a2}

		_, err := nrc.bgpServer.AddPath(context.Background(), &gobgpapi.AddPathRequest{
			Path: &gobgpapi.Path{
				Family: &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP, Safi: gobgpapi.Family_SAFI_UNICAST},
				Nlri:   nlri,
				Pattrs: attrs,
			},
		})
		if err != nil {
			return fmt.Errorf(err.Error())
		}
	}
	return nil
}

func (nrc *NetworkRoutingController) injectRoute(path *gobgpapi.Path) error {
	klog.V(2).Infof("injectRoute Path Looks Like: %s", path.String())
	var nextHop net.IP
out:
	for _, pAttr := range path.GetPattrs() {
		var value ptypes.DynamicAny
		if err := ptypes.UnmarshalAny(pAttr, &value); err != nil {
			return fmt.Errorf("failed to unmarshal path attribute: %s", err)
		}
		switch a := value.Message.(type) {
		case *gobgpapi.NextHopAttribute:
			nextHop = net.ParseIP(a.NextHop).To4()
			if nextHop == nil {
				if nextHop = net.ParseIP(a.NextHop).To16(); nextHop == nil {
					return fmt.Errorf("invalid nextHop address: %s", a.NextHop)
				}
			}
			break out
		}
	}
	if nextHop == nil {
		return fmt.Errorf("could not parse next hop received from GoBGP for path: %s", path)
	}
	nlri := path.GetNlri()
	var prefix gobgpapi.IPAddressPrefix
	err := ptypes.UnmarshalAny(nlri, &prefix)
	if err != nil {
		return fmt.Errorf("invalid nlri in advertised path")
	}
	dst, err := netlink.ParseIPNet(prefix.Prefix + "/" + fmt.Sprint(prefix.PrefixLen))
	if err != nil {
		return fmt.Errorf("invalid nlri in advertised path")
	}
	var route *netlink.Route

	tunnelName := generateTunnelName(nextHop.String())
	sameSubnet := nrc.nodeSubnet.Contains(nextHop)

	// cleanup route and tunnel if overlay is disabled or node is in same subnet and overlay-type is set to 'subnet'
	if !nrc.enableOverlays || (sameSubnet && nrc.overlayType == "subnet") {
		klog.Infof("Cleaning up old routes if there are any")
		routes, err := netlink.RouteListFiltered(nl.FAMILY_ALL, &netlink.Route{
			Dst: dst, Protocol: 0x11,
		}, netlink.RT_FILTER_DST|netlink.RT_FILTER_PROTOCOL)
		if err != nil {
			klog.Errorf("Failed to get routes from netlink")
		}
		for i, r := range routes {
			klog.V(2).Infof("Found route to remove: %s", r.String())
			if err := netlink.RouteDel(&routes[i]); err != nil {
				klog.Errorf("Failed to remove route due to " + err.Error())
			}
		}

		klog.Infof("Cleaning up if there is any existing tunnel interface for the node")
		if link, err := netlink.LinkByName(tunnelName); err == nil {
			if err = netlink.LinkDel(link); err != nil {
				klog.Errorf("Failed to delete tunnel link for the node due to " + err.Error())
			}
		}
	}

	// create IPIP tunnels only when node is not in same subnet or overlay-type is set to 'full'
	// if the user has disabled overlays, don't create tunnels
	if (!sameSubnet || nrc.overlayType == "full") && nrc.enableOverlays {
		// create ip-in-ip tunnel and inject route as overlay is enabled
		var link netlink.Link
		var err error
		link, err = netlink.LinkByName(tunnelName)
		if err != nil {
			out, err := exec.Command("ip", "tunnel", "add", tunnelName, "mode", "ipip", "local", nrc.nodeIP.String(),
				"remote", nextHop.String(), "dev", nrc.nodeInterface).CombinedOutput()
			if err != nil {
				return fmt.Errorf("route not injected for the route advertised by the node %s "+
					"Failed to create tunnel interface %s. error: %s, output: %s",
					nextHop, tunnelName, err, string(out))
			}

			link, err = netlink.LinkByName(tunnelName)
			if err != nil {
				return fmt.Errorf("route not injected for the route advertised by the node %s "+
					"Failed to get tunnel interface by name error: %s", tunnelName, err)
			}
			if err := netlink.LinkSetUp(link); err != nil {
				return errors.New("Failed to bring tunnel interface " + tunnelName + " up due to: " + err.Error())
			}
			// reduce the MTU by 20 bytes to accommodate ipip tunnel overhead
			if err := netlink.LinkSetMTU(link, link.Attrs().MTU-20); err != nil {
				return errors.New("Failed to set MTU of tunnel interface " + tunnelName + " up due to: " + err.Error())
			}
		} else {
			klog.Infof("Tunnel interface: " + tunnelName + " for the node " + nextHop.String() + " already exists.")
		}

		out, err := exec.Command("ip", "route", "list", "table", customRouteTableID).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "dev "+tunnelName+" scope") {
			if out, err = exec.Command("ip", "route", "add", nextHop.String(), "dev", tunnelName, "table",
				customRouteTableID).CombinedOutput(); err != nil {
				return fmt.Errorf("failed to add route in custom route table, err: %s, output: %s", err, string(out))
			}
		}

		route = &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Src:       nrc.nodeIP,
			Dst:       dst,
			Protocol:  0x11,
		}
	} else if sameSubnet {
		route = &netlink.Route{
			Dst:      dst,
			Gw:       nextHop,
			Protocol: 0x11,
		}
	} else {
		return nil
	}

	if path.IsWithdraw {
		klog.V(2).Infof("Removing route: '%s via %s' from peer in the routing table", dst, nextHop)
		return netlink.RouteDel(route)
	}
	klog.V(2).Infof("Inject route: '%s via %s' from peer to routing table", dst, nextHop)
	return netlink.RouteReplace(route)
}

// Cleanup performs the cleanup of configurations done
func (nrc *NetworkRoutingController) Cleanup() {
	// Pod egress cleanup
	err := nrc.deletePodEgressRule()
	if err != nil {
		klog.Warningf("Error deleting Pod egress iptables rule: %s", err.Error())
	}

	err = nrc.deleteBadPodEgressRules()
	if err != nil {
		klog.Warningf("Error deleting Pod egress iptables rule: %s", err.Error())
	}

	// delete all ipsets created by kube-router
	ipset, err := utils.NewIPSet(nrc.isIpv6)
	if err != nil {
		klog.Errorf("Failed to clean up ipsets: " + err.Error())
		return
	}
	err = ipset.Save()
	if err != nil {
		klog.Errorf("Failed to clean up ipsets: " + err.Error())
	}
	err = ipset.DestroyAllWithin()
	if err != nil {
		klog.Warningf("Error deleting ipset: %s", err.Error())
	}
}

func (nrc *NetworkRoutingController) syncNodeIPSets() error {
	var err error
	start := time.Now()
	defer func() {
		if nrc.MetricsEnabled {
			metrics.ControllerRoutesSyncTime.Observe(time.Since(start).Seconds())
		}
	}()

	nodes := nrc.nodeLister.List()

	// Collect active PodCIDR(s) and NodeIPs from nodes
	currentPodCidrs := make([]string, 0)
	currentNodeIPs := make([]string, 0)
	for _, obj := range nodes {
		node := obj.(*v1core.Node)
		podCIDR := node.GetAnnotations()["kube-router.io/pod-cidr"]
		if podCIDR == "" {
			podCIDR = node.Spec.PodCIDR
		}
		if podCIDR == "" {
			klog.Warningf("Couldn't determine PodCIDR of the %v node", node.Name)
			continue
		}
		currentPodCidrs = append(currentPodCidrs, podCIDR)
		nodeIP, err := utils.GetNodeIP(node)
		if err != nil {
			klog.Errorf("Failed to find a node IP, cannot add to node ipset which could affect routing: %v", err)
			continue
		}
		currentNodeIPs = append(currentNodeIPs, nodeIP.String())
	}

	// Syncing Pod subnet ipset entries
	psSet := nrc.ipSetHandler.Get(podSubnetsIPSetName)
	if psSet == nil {
		klog.Infof("Creating missing ipset \"%s\"", podSubnetsIPSetName)
		_, err = nrc.ipSetHandler.Create(podSubnetsIPSetName, utils.OptionTimeout, "0")
		if err != nil {
			return fmt.Errorf("ipset \"%s\" not found in controller instance",
				podSubnetsIPSetName)
		}
		psSet = nrc.ipSetHandler.Get(podSubnetsIPSetName)
		if nil == psSet {
			return fmt.Errorf("failed to get ipsethandler for ipset \"%s\"", podSubnetsIPSetName)
		}
	}
	err = psSet.Refresh(currentPodCidrs)
	if err != nil {
		return fmt.Errorf("failed to sync Pod Subnets ipset: %s", err)
	}

	// Syncing Node Addresses ipset entries
	naSet := nrc.ipSetHandler.Get(nodeAddrsIPSetName)
	if naSet == nil {
		klog.Infof("Creating missing ipset \"%s\"", nodeAddrsIPSetName)
		_, err = nrc.ipSetHandler.Create(nodeAddrsIPSetName, utils.OptionTimeout, "0")
		if err != nil {
			return fmt.Errorf("ipset \"%s\" not found in controller instance",
				nodeAddrsIPSetName)
		}
		naSet = nrc.ipSetHandler.Get(nodeAddrsIPSetName)
		if nil == naSet {
			return fmt.Errorf("failed to get ipsethandler for ipset \"%s\"", nodeAddrsIPSetName)
		}
	}
	err = naSet.Refresh(currentNodeIPs)
	if err != nil {
		return fmt.Errorf("failed to sync Node Addresses ipset: %s", err)
	}

	return nil
}

func (nrc *NetworkRoutingController) newIptablesCmdHandler() (*iptables.IPTables, error) {
	if nrc.isIpv6 {
		return iptables.NewWithProtocol(iptables.ProtocolIPv6)
	}
	return iptables.NewWithProtocol(iptables.ProtocolIPv4)
}

// ensure there is rule in filter table and FORWARD chain to permit in/out traffic from pods
// this rules will be appended so that any iptables rules for network policies will take
// precedence
func (nrc *NetworkRoutingController) enableForwarding() error {

	iptablesCmdHandler, _ := nrc.newIptablesCmdHandler()

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
	args = []string{"-m", "comment", "--comment", comment, "-o", nrc.nodeInterface, "-j", "ACCEPT"}
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
		asnNo, err := strconv.ParseUint(nodeasn, 0, 32)
		if err != nil {
			return errors.New("failed to parse ASN number specified for the the node")
		}
		nodeAsnNumber = uint32(asnNo)
		nrc.nodeAsnNumber = nodeAsnNumber
	}

	if clusterid, ok := node.ObjectMeta.Annotations[rrServerAnnotation]; ok {
		klog.Infof("Found rr.server for the node to be %s from the node annotation", clusterid)
		_, err := strconv.ParseUint(clusterid, 0, 32)
		if err != nil {
			if ip := net.ParseIP(clusterid).To4(); ip == nil {
				return errors.New("failed to parse rr.server clusterId specified for the node")
			}
		}
		nrc.bgpClusterID = clusterid
		nrc.bgpRRServer = true
	} else if clusterid, ok := node.ObjectMeta.Annotations[rrClientAnnotation]; ok {
		klog.Infof("Found rr.client for the node to be %s from the node annotation", clusterid)
		_, err := strconv.ParseUint(clusterid, 0, 32)
		if err != nil {
			if ip := net.ParseIP(clusterid).To4(); ip == nil {
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

		_, err := strconv.ParseUint(prependASN, 0, 32)
		if err != nil {
			return errors.New("failed to parse ASN number specified to prepend")
		}

		repeatN, err := strconv.ParseUint(prependRepeatN, 0, 8)
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
			if err = validateCommunity(nodeCommunity); err != nil {
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

	if grpcServer {
		nrc.bgpServer = gobgp.NewBgpServer(gobgp.GrpcListenAddress(nrc.nodeIP.String() + ":50051" + "," + "127.0.0.1:50051"))
	} else {
		nrc.bgpServer = gobgp.NewBgpServer()
	}
	go nrc.bgpServer.Serve()

	var localAddressList []string

	if ipv4IsEnabled() {
		localAddressList = append(localAddressList, nrc.localAddressList...)
	}

	if ipv6IsEnabled() {
		localAddressList = append(localAddressList, "::1")
	}

	global := &gobgpapi.Global{
		As:              nodeAsnNumber,
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
			klog.Infof("Could not find BGP peer info for the node in the node annotations so skipping configuring peer.")
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
			klog.Infof("Could not find BGP peer info for the node in the node annotations so skipping configuring peer.")
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

		// Create and set Global Peer Router complete configs
		nrc.globalPeerRouters, err = newGlobalPeers(peerIPs, peerPorts, peerASNs, peerPasswords, nrc.bgpHoldtime)
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
		err := connectToExternalBGPPeers(nrc.bgpServer, nrc.globalPeerRouters, nrc.bgpGracefulRestart,
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

// func (nrc *NetworkRoutingController) getExternalNodeIPs(

// NewNetworkRoutingController returns new NetworkRoutingController object
func NewNetworkRoutingController(clientset kubernetes.Interface,
	kubeRouterConfig *options.KubeRouterConfig,
	nodeInformer cache.SharedIndexInformer, svcInformer cache.SharedIndexInformer,
	epInformer cache.SharedIndexInformer) (*NetworkRoutingController, error) {

	var err error

	nrc := NetworkRoutingController{}
	if kubeRouterConfig.MetricsEnabled {
		//Register the metrics for this controller
		prometheus.MustRegister(metrics.ControllerBGPadvertisementsReceived)
		prometheus.MustRegister(metrics.ControllerBGPInternalPeersSyncTime)
		prometheus.MustRegister(metrics.ControllerBPGpeers)
		prometheus.MustRegister(metrics.ControllerRoutesSyncTime)
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

	nrc.bgpHoldtime = kubeRouterConfig.BGPHoldTime.Seconds()
	if nrc.bgpHoldtime > 65536 || nrc.bgpHoldtime < 3 {
		return nil, errors.New("this is an incorrect BGP holdtime range, holdtime must be in the range 3s to 18h12m16s")
	}

	nrc.hostnameOverride = kubeRouterConfig.HostnameOverride
	node, err := utils.GetNodeObject(clientset, nrc.hostnameOverride)
	if err != nil {
		return nil, errors.New("failed getting node object from API server: " + err.Error())
	}

	nrc.nodeName = node.Name

	nodeIP, err := utils.GetNodeIP(node)
	if err != nil {
		return nil, errors.New("failed getting IP address from node object: " + err.Error())
	}
	nrc.nodeIP = nodeIP
	nrc.isIpv6 = nodeIP.To4() == nil

	if kubeRouterConfig.RouterID != "" {
		nrc.routerID = kubeRouterConfig.RouterID
	} else {
		if nrc.isIpv6 {
			return nil, errors.New("router-id must be specified in ipv6 operation")
		}
		nrc.routerID = nrc.nodeIP.String()
	}

	// lets start with assumption we hace necessary IAM creds to access EC2 api
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

	cidr, err := utils.GetPodCidrFromNodeSpec(clientset, nrc.hostnameOverride)
	if err != nil {
		klog.Fatalf("Failed to get pod CIDR from node spec. kube-router relies on kube-controller-manager to allocate pod CIDR for the node or an annotation `kube-router.io/pod-cidr`. Error: %v", err)
		return nil, fmt.Errorf("failed to get pod CIDR details from Node.spec: %s", err.Error())
	}
	nrc.podCidr = cidr

	nrc.ipSetHandler, err = utils.NewIPSet(nrc.isIpv6)
	if err != nil {
		return nil, err
	}

	_, err = nrc.ipSetHandler.Create(podSubnetsIPSetName, utils.TypeHashNet, utils.OptionTimeout, "0")
	if err != nil {
		return nil, err
	}

	_, err = nrc.ipSetHandler.Create(nodeAddrsIPSetName, utils.TypeHashIP, utils.OptionTimeout, "0")
	if err != nil {
		return nil, err
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
		pwFileBytes, err := ioutil.ReadFile(kubeRouterConfig.PeerPasswordsFile)
		if err != nil {
			return nil, fmt.Errorf("error loading Peer Passwords File : %s", err)
		}
		pws := strings.Split(string(pwFileBytes), ",")
		peerPasswords, err = stringSliceB64Decode(pws)
		if err != nil {
			return nil, fmt.Errorf("failed to decode CLI Peer Passwords file: %s", err)
		}
	}

	nrc.globalPeerRouters, err = newGlobalPeers(kubeRouterConfig.PeerRouters, peerPorts, peerASNs, peerPasswords, nrc.bgpHoldtime)
	if err != nil {
		return nil, fmt.Errorf("error processing Global Peer Router configs: %s", err)
	}

	nrc.nodeSubnet, nrc.nodeInterface, err = getNodeSubnet(nodeIP)
	if err != nil {
		return nil, errors.New("failed find the subnet of the node IP and interface on" +
			"which its configured: " + err.Error())
	}

	bgpLocalAddressListAnnotation, ok := node.ObjectMeta.Annotations[bgpLocalAddressAnnotation]
	if !ok {
		klog.Infof("Could not find annotation `kube-router.io/bgp-local-addresses` on node object so BGP will listen on node IP: %s address.", nrc.nodeIP.String())
		nrc.localAddressList = append(nrc.localAddressList, nrc.nodeIP.String())
	} else {
		klog.Infof("Found annotation `kube-router.io/bgp-local-addresses` on node object so BGP will listen on local IP's: %s", bgpLocalAddressListAnnotation)
		localAddresses := stringToSlice(bgpLocalAddressListAnnotation, ",")
		for _, addr := range localAddresses {
			ip := net.ParseIP(addr)
			if ip == nil {
				klog.Fatalf("Invalid IP address %s specified in `kube-router.io/bgp-local-addresses`.", addr)
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
