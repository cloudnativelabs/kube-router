package routing

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
	bgpapi "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	gobgp "github.com/osrg/gobgp/server"
	"github.com/osrg/gobgp/table"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	IFACE_NOT_FOUND = "Link not found"

	customRouteTableID   = "77"
	customRouteTableName = "kube-router"
	podSubnetsIPSetName  = "kube-router-pod-subnets"
	nodeAddrsIPSetName   = "kube-router-node-ips"

	nodeASNAnnotation                 = "kube-router.io/node.asn"
	peerASNAnnotation                 = "kube-router.io/peer.asns"
	peerIPAnnotation                  = "kube-router.io/peer.ips"
	peerPasswordAnnotation            = "kube-router.io/peer.passwords"
	rrClientAnnotation                = "kube-router.io/rr.client"
	rrServerAnnotation                = "kube-router.io/rr.server"
	svcLocalAnnotation                = "kube-router.io/service.local"
	LeaderElectionRecordAnnotationKey = "control-plane.alpha.kubernetes.io/leader"
)

// NetworkRoutingController is struct to hold necessary information required by controller
type NetworkRoutingController struct {
	nodeIP                  net.IP
	nodeName                string
	nodeSubnet              net.IPNet
	nodeInterface           string
	activeNodes             map[string]bool
	mu                      sync.Mutex
	clientset               kubernetes.Interface
	bgpServer               *gobgp.BgpServer
	syncPeriod              time.Duration
	clusterCIDR             string
	enablePodEgress         bool
	hostnameOverride        string
	advertiseClusterIP      bool
	advertiseExternalIP     bool
	advertiseLoadBalancerIP bool
	advertisePodCidr        bool
	defaultNodeAsnNumber    uint32
	nodeAsnNumber           uint32
	globalPeerRouters       []*config.NeighborConfig
	nodePeerRouters         []string
	bgpFullMeshMode         bool
	bgpEnableInternal       bool
	bgpGracefulRestart      bool
	ipSetHandler            *utils.IPSet
	enableOverlays          bool
	peerMultihopTTL         uint8
	MetricsEnabled          bool
	bgpServerStarted        bool
	bgpRRClient             bool
	bgpRRServer             bool
	bgpClusterID            uint32
	cniConfFile             string
	initSrcDstCheckDone     bool
	ec2IamAuthorized        bool

	nodeLister cache.Indexer
	svcLister  cache.Indexer
	epLister   cache.Indexer

	NodeEventHandler      cache.ResourceEventHandler
	ServiceEventHandler   cache.ResourceEventHandler
	EndpointsEventHandler cache.ResourceEventHandler
}

// Run runs forever until we are notified on stop channel
func (nrc *NetworkRoutingController) Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) {
	cidr, err := utils.GetPodCidrFromCniSpec(nrc.cniConfFile)
	if err != nil {
		glog.Errorf("Failed to get pod CIDR from CNI conf file: %s", err.Error())
	}
	cidrlen, _ := cidr.Mask.Size()
	oldCidr := cidr.IP.String() + "/" + strconv.Itoa(cidrlen)

	currentCidr, err := utils.GetPodCidrFromNodeSpec(nrc.clientset, nrc.hostnameOverride)
	if err != nil {
		glog.Errorf("Failed to get pod CIDR from node spec: %s", err.Error())
	}

	if len(cidr.IP) == 0 || strings.Compare(oldCidr, currentCidr) != 0 {
		err = utils.InsertPodCidrInCniSpec(nrc.cniConfFile, currentCidr)
		if err != nil {
			glog.Errorf("Failed to insert pod CIDR into CNI conf file: %s", err.Error())
		}
	}

	glog.V(1).Info("Populating ipsets.")
	err = nrc.syncNodeIPSets()
	if err != nil {
		glog.Errorf("Failed initial ipset setup: %s", err)
	}

	// In case of cluster provisioned on AWS disable source-destination check
	nrc.disableSourceDestinationCheck()
	nrc.initSrcDstCheckDone = true

	// enable IP forwarding for the packets coming in/out from the pods
	err = nrc.enableForwarding()
	if err != nil {
		glog.Errorf("Failed to enable IP forwarding of traffic from pods: %s", err.Error())
	}

	// Handle ipip tunnel overlay
	if nrc.enableOverlays {
		glog.V(1).Info("IPIP Tunnel Overlay enabled in configuration.")
		glog.V(1).Info("Setting up overlay networking.")
		err = nrc.enablePolicyBasedRouting()
		if err != nil {
			glog.Errorf("Failed to enable required policy based routing: %s", err.Error())
		}
	} else {
		glog.V(1).Info("IPIP Tunnel Overlay disabled in configuration.")
		glog.V(1).Info("Cleaning up old overlay networking if needed.")
		err = nrc.disablePolicyBasedRouting()
		if err != nil {
			glog.Errorf("Failed to disable policy based routing: %s", err.Error())
		}
	}

	glog.V(1).Info("Performing cleanup of depreciated rules/ipsets (if needed).")
	err = deleteBadPodEgressRules()
	if err != nil {
		glog.Errorf("Error cleaning up old/bad Pod egress rules: %s", err.Error())
	}

	// Handle Pod egress masquerading configuration
	if nrc.enablePodEgress {
		glog.V(1).Infoln("Enabling Pod egress.")

		err = createPodEgressRule()
		if err != nil {
			glog.Errorf("Error enabling Pod egress: %s", err.Error())
		}
	} else {
		glog.V(1).Infoln("Disabling Pod egress.")

		err = deletePodEgressRule()
		if err != nil {
			glog.Warningf("Error cleaning up Pod Egress related networking: %s", err)
		}
	}

	// create 'kube-bridge' interface to which pods will be connected
	_, err = netlink.LinkByName("kube-bridge")
	if err != nil && err.Error() == IFACE_NOT_FOUND {
		linkAttrs := netlink.NewLinkAttrs()
		linkAttrs.Name = "kube-bridge"
		bridge := &netlink.Bridge{LinkAttrs: linkAttrs}
		if err = netlink.LinkAdd(bridge); err != nil {
			glog.Errorf("Failed to create `kube-router` bridge due to %s. Will be created by CNI bridge plugin when pod is launched.", err.Error())
		}
		kubeBridgeIf, err := netlink.LinkByName("kube-bridge")
		if err != nil {
			glog.Errorf("Failed to find created `kube-router` bridge due to %s. Will be created by CNI bridge plugin when pod is launched.", err.Error())
		}
		err = netlink.LinkSetUp(kubeBridgeIf)
		if err != nil {
			glog.Errorf("Failed to bring `kube-router` bridge up due to %s. Will be created by CNI bridge plugin at later point when pod is launched.", err.Error())
		}
	}

	// enable netfilter for the bridge
	if _, err := exec.Command("modprobe", "br_netfilter").CombinedOutput(); err != nil {
		glog.Errorf("Failed to enable netfilter for bridge. Network policies and service proxy may not work: %s", err.Error())
	}
	if err = ioutil.WriteFile("/proc/sys/net/bridge/bridge-nf-call-iptables", []byte(strconv.Itoa(1)), 0640); err != nil {
		glog.Errorf("Failed to enable netfilter for bridge. Network policies and service proxy may not work: %s", err.Error())
	}

	t := time.NewTicker(nrc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	glog.Infof("Starting network route controller")

	// Wait till we are ready to launch BGP server
	for {
		err := nrc.startBgpServer()
		if err != nil {
			glog.Errorf("Failed to start node BGP server: %s", err)
			select {
			case <-stopCh:
				glog.Infof("Shutting down network routes controller")
				return
			case <-t.C:
				glog.Infof("Retrying start of node BGP server")
				continue
			}
		} else {
			break
		}
	}

	nrc.bgpServerStarted = true
	defer nrc.bgpServer.Shutdown()

	// loop forever till notified to stop on stopCh
	for {
		select {
		case <-stopCh:
			glog.Infof("Shutting down network routes controller")
			return
		default:
		}

		// Update ipset entries
		if nrc.enablePodEgress || nrc.enableOverlays {
			glog.V(1).Info("Syncing ipsets")
			err := nrc.syncNodeIPSets()
			if err != nil {
				glog.Errorf("Error synchronizing ipsets: %s", err.Error())
			}
		}

		// advertise or withdraw IPs for the services to be reachable via host
		toAdvertise, toWithdraw, err := nrc.getActiveVIPs()
		if err != nil {
			glog.Errorf("failed to get routes to advertise/withdraw %s", err)
		}

		glog.V(1).Infof("Performing periodic sync of service VIP routes")
		nrc.advertiseVIPs(toAdvertise)
		nrc.withdrawVIPs(toWithdraw)

		glog.V(1).Info("Performing periodic sync of pod CIDR routes")
		err = nrc.advertisePodRoute()
		if err != nil {
			glog.Errorf("Error advertising route: %s", err.Error())
		}

		err = nrc.addExportPolicies()
		if err != nil {
			glog.Errorf("Error adding BGP export policies: %s", err.Error())
		}

		if nrc.bgpEnableInternal {
			nrc.syncInternalPeers()
		}

		healthcheck.SendHeartBeat(healthChan, "NRC")

		select {
		case <-stopCh:
			glog.Infof("Shutting down network routes controller")
			return
		case <-t.C:
		}
	}
}

func (nrc *NetworkRoutingController) watchBgpUpdates() {
	watcher := nrc.bgpServer.Watch(gobgp.WatchBestPath(false))
	for {
		select {
		case ev := <-watcher.Event():
			switch msg := ev.(type) {
			case *gobgp.WatchEventBestPath:
				glog.V(3).Info("Processing bgp route advertisement from peer")
				if nrc.MetricsEnabled {
					metrics.ControllerBGPadvertisementsReceived.WithLabelValues().Add(float64(1))
				}
				for _, path := range msg.PathList {
					if path.IsLocal() {
						continue
					}
					if err := nrc.injectRoute(path); err != nil {
						glog.Errorf("Failed to inject routes due to: " + err.Error())
						continue
					}
				}
			}
		}
	}
}

func (nrc *NetworkRoutingController) advertisePodRoute() error {
	cidr, err := utils.GetPodCidrFromNodeSpec(nrc.clientset, nrc.hostnameOverride)
	if err != nil {
		return err
	}

	cidrStr := strings.Split(cidr, "/")
	subnet := cidrStr[0]
	cidrLen, _ := strconv.Atoi(cidrStr[1])
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop(nrc.nodeIP.String()),
	}

	glog.V(2).Infof("Advertising route: '%s/%s via %s' to peers", subnet, strconv.Itoa(cidrLen), nrc.nodeIP.String())

	if _, err := nrc.bgpServer.AddPath("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(uint8(cidrLen),
		subnet), false, attrs, time.Now(), false)}); err != nil {
		return fmt.Errorf(err.Error())
	}

	return nil
}

func (nrc *NetworkRoutingController) injectRoute(path *table.Path) error {
	nexthop := path.GetNexthop()
	nlri := path.GetNlri()
	dst, _ := netlink.ParseIPNet(nlri.String())
	var route *netlink.Route

	// check if the neighbour is in same subnet
	if !nrc.nodeSubnet.Contains(nexthop) {
		tunnelName := generateTunnelName(nexthop.String())
		glog.Infof("Found node: " + nexthop.String() + " to be in different subnet.")

		// if overlay is not enabled then skip creating tunnels and adding route
		if !nrc.enableOverlays {
			glog.Infof("Found node: " + nexthop.String() + " to be in different subnet but overlays are " +
				"disabled so not creating any tunnel and injecting route for the node's pod CIDR.")
			glog.Infof("Cleaning up if there is any existing tunnel interface for the node")
			link, err := netlink.LinkByName(tunnelName)
			if err != nil {
				return nil
			}
			err = netlink.LinkDel(link)
			if err != nil {
				glog.Errorf("Failed to delete tunnel link for the node due to " + err.Error())
			}
			return nil
		}

		// create ip-in-ip tunnel and inject route as overlay is enabled
		var link netlink.Link
		var err error
		link, err = netlink.LinkByName(tunnelName)
		if err != nil {
			glog.Infof("Found node: " + nexthop.String() + " to be in different subnet. Creating tunnel: " + tunnelName)
			out, err := exec.Command("ip", "tunnel", "add", tunnelName, "mode", "ipip", "local", nrc.nodeIP.String(),
				"remote", nexthop.String(), "dev", nrc.nodeInterface).CombinedOutput()
			if err != nil {
				return fmt.Errorf("Route not injected for the route advertised by the node %s "+
					"Failed to create tunnel interface %s. error: %s, output: %s",
					nexthop.String(), tunnelName, err, string(out))
			}

			link, err = netlink.LinkByName(tunnelName)
			if err != nil {
				return fmt.Errorf("Route not injected for the route advertised by the node %s "+
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
			glog.Infof("Tunnel interface: " + tunnelName + " for the node " + nexthop.String() + " already exists.")
		}

		out, err := exec.Command("ip", "route", "list", "table", customRouteTableID).CombinedOutput()
		if err != nil {
			return fmt.Errorf("Failed to verify if route already exists in %s table: %s",
				customRouteTableName, err.Error())
		}
		if !strings.Contains(string(out), tunnelName) {
			if out, err = exec.Command("ip", "route", "add", nexthop.String(), "dev", tunnelName, "table",
				customRouteTableID).CombinedOutput(); err != nil {
				return fmt.Errorf("failed to add route in custom route table, err: %s, output: %s", err, string(out))
			}
		}

		route = &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
			Protocol:  0x11,
		}
	} else {
		route = &netlink.Route{
			Dst:      dst,
			Gw:       nexthop,
			Protocol: 0x11,
		}
	}

	if path.IsWithdraw {
		glog.V(2).Infof("Removing route: '%s via %s' from peer in the routing table", dst, nexthop)
		return netlink.RouteDel(route)
	}
	glog.V(2).Infof("Inject route: '%s via %s' from peer to routing table", dst, nexthop)
	return netlink.RouteReplace(route)
}

// Cleanup performs the cleanup of configurations done
func (nrc *NetworkRoutingController) Cleanup() {
	// Pod egress cleanup
	err := deletePodEgressRule()
	if err != nil {
		glog.Warningf("Error deleting Pod egress iptable rule: %s", err.Error())
	}

	err = deleteBadPodEgressRules()
	if err != nil {
		glog.Warningf("Error deleting Pod egress iptable rule: %s", err.Error())
	}

	err = nrc.ipSetHandler.DestroyAllWithin()
	if err != nil {
		glog.Warningf("Error deleting ipset: %s", err.Error())
	}
}

func (nrc *NetworkRoutingController) syncNodeIPSets() error {
	// Get the current list of the nodes from API server
	nodes, err := nrc.clientset.CoreV1().Nodes().List(metav1.ListOptions{})
	if err != nil {
		return errors.New("Failed to list nodes from API server: " + err.Error())
	}

	// Collect active PodCIDR(s) and NodeIPs from nodes
	currentPodCidrs := make([]string, 0)
	currentNodeIPs := make([]string, 0)
	for _, node := range nodes.Items {
		currentPodCidrs = append(currentPodCidrs, node.Spec.PodCIDR)
		nodeIP, err := utils.GetNodeIP(&node)
		if err != nil {
			return fmt.Errorf("Failed to find a node IP: %s", err)
		}
		currentNodeIPs = append(currentNodeIPs, nodeIP.String())
	}

	// Syncing Pod subnet ipset entries
	psSet := nrc.ipSetHandler.Get(podSubnetsIPSetName)
	if psSet == nil {
		glog.Infof("Creating missing ipset \"%s\"", podSubnetsIPSetName)
		_, err = nrc.ipSetHandler.Create(podSubnetsIPSetName, utils.OptionTimeout, "0")
		if err != nil {
			return fmt.Errorf("ipset \"%s\" not found in controller instance",
				podSubnetsIPSetName)
		}
	}
	err = psSet.Refresh(currentPodCidrs, psSet.Options...)
	if err != nil {
		return fmt.Errorf("Failed to sync Pod Subnets ipset: %s", err)
	}

	// Syncing Node Addresses ipset entries
	naSet := nrc.ipSetHandler.Get(nodeAddrsIPSetName)
	if naSet == nil {
		glog.Infof("Creating missing ipset \"%s\"", nodeAddrsIPSetName)
		_, err = nrc.ipSetHandler.Create(nodeAddrsIPSetName, utils.OptionTimeout, "0")
		if err != nil {
			return fmt.Errorf("ipset \"%s\" not found in controller instance",
				nodeAddrsIPSetName)
		}
	}
	err = naSet.Refresh(currentNodeIPs, naSet.Options...)
	if err != nil {
		return fmt.Errorf("Failed to sync Node Addresses ipset: %s", err)
	}

	return nil
}

// ensure there is rule in filter table and FORWARD chain to permit in/out traffic from pods
// this rules will be appended so that any iptable rules for network policies will take
// precedence
func (nrc *NetworkRoutingController) enableForwarding() error {

	iptablesCmdHandler, err := iptables.New()

	comment := "allow outbound traffic from pods"
	args := []string{"-m", "comment", "--comment", comment, "-i", "kube-bridge", "-j", "ACCEPT"}
	exists, err := iptablesCmdHandler.Exists("filter", "FORWARD", args...)
	if err != nil {
		return fmt.Errorf("Failed to run iptables command: %s", err.Error())
	}
	if !exists {
		err := iptablesCmdHandler.AppendUnique("filter", "FORWARD", args...)
		if err != nil {
			return fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
	}

	comment = "allow inbound traffic to pods"
	args = []string{"-m", "comment", "--comment", comment, "-o", "kube-bridge", "-j", "ACCEPT"}
	exists, err = iptablesCmdHandler.Exists("filter", "FORWARD", args...)
	if err != nil {
		return fmt.Errorf("Failed to run iptables command: %s", err.Error())
	}
	if !exists {
		err = iptablesCmdHandler.AppendUnique("filter", "FORWARD", args...)
		if err != nil {
			return fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
	}

	comment = "allow outbound node port traffic on node interface with which node ip is associated"
	args = []string{"-m", "comment", "--comment", comment, "-o", nrc.nodeInterface, "-j", "ACCEPT"}
	exists, err = iptablesCmdHandler.Exists("filter", "FORWARD", args...)
	if err != nil {
		return fmt.Errorf("Failed to run iptables command: %s", err.Error())
	}
	if !exists {
		err = iptablesCmdHandler.AppendUnique("filter", "FORWARD", args...)
		if err != nil {
			return fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
	}

	return nil
}

func (nrc *NetworkRoutingController) startBgpServer() error {
	var nodeAsnNumber uint32
	node, err := utils.GetNodeObject(nrc.clientset, nrc.hostnameOverride)
	if err != nil {
		return errors.New("Failed to get node object from api server: " + err.Error())
	}

	if nrc.bgpFullMeshMode {
		nodeAsnNumber = nrc.defaultNodeAsnNumber
	} else {
		nodeasn, ok := node.ObjectMeta.Annotations[nodeASNAnnotation]
		if !ok {
			return errors.New("Could not find ASN number for the node. " +
				"Node needs to be annotated with ASN number details to start BGP server.")
		}
		glog.Infof("Found ASN for the node to be %s from the node annotations", nodeasn)
		asnNo, err := strconv.ParseUint(nodeasn, 0, 32)
		if err != nil {
			return errors.New("Failed to parse ASN number specified for the the node")
		}
		nodeAsnNumber = uint32(asnNo)
		nrc.nodeAsnNumber = nodeAsnNumber
	}

	if clusterid, ok := node.ObjectMeta.Annotations[rrServerAnnotation]; ok {
		glog.Infof("Found rr.server for the node to be %s from the node annotation", clusterid)
		clusterID, err := strconv.ParseUint(clusterid, 0, 32)
		if err != nil {
			return errors.New("Failed to parse rr.server clusterId number specified for the the node")
		}
		nrc.bgpClusterID = uint32(clusterID)
		nrc.bgpRRServer = true
	} else if clusterid, ok := node.ObjectMeta.Annotations[rrClientAnnotation]; ok {
		glog.Infof("Found rr.client for the node to be %s from the node annotation", clusterid)
		clusterID, err := strconv.ParseUint(clusterid, 0, 32)
		if err != nil {
			return errors.New("Failed to parse rr.client clusterId number specified for the the node")
		}
		nrc.bgpClusterID = uint32(clusterID)
		nrc.bgpRRClient = true
	}

	nrc.bgpServer = gobgp.NewBgpServer()
	go nrc.bgpServer.Serve()

	g := bgpapi.NewGrpcServer(nrc.bgpServer, ":50051")
	go g.Serve()

	var localAddressList []string

	if ipv4IsEnabled() {
		localAddressList = append(localAddressList, nrc.nodeIP.String())
	}

	if ipv6IsEnabled() {
		localAddressList = append(localAddressList, "::")
	}

	global := &config.Global{
		Config: config.GlobalConfig{
			As:               nodeAsnNumber,
			RouterId:         nrc.nodeIP.String(),
			LocalAddressList: localAddressList,
		},
	}

	if err := nrc.bgpServer.Start(global); err != nil {
		return errors.New("Failed to start BGP server due to : " + err.Error())
	}

	go nrc.watchBgpUpdates()

	// If the global routing peer is configured then peer with it
	// else attempt to get peers from node specific BGP annotations.
	if len(nrc.globalPeerRouters) == 0 {
		// Get Global Peer Router ASN configs
		nodeBgpPeerAsnsAnnotation, ok := node.ObjectMeta.Annotations[peerASNAnnotation]
		if !ok {
			glog.Infof("Could not find BGP peer info for the node in the node annotations so skipping configuring peer.")
			return nil
		}

		asnStrings := stringToSlice(nodeBgpPeerAsnsAnnotation, ",")
		peerASNs, err := stringSliceToUInt32(asnStrings)
		if err != nil {
			nrc.bgpServer.Stop()
			return fmt.Errorf("Failed to parse node's Peer ASN Numbers Annotation: %s", err)
		}

		// Get Global Peer Router IP Address configs
		nodeBgpPeersAnnotation, ok := node.ObjectMeta.Annotations[peerIPAnnotation]
		if !ok {
			glog.Infof("Could not find BGP peer info for the node in the node annotations so skipping configuring peer.")
			return nil
		}
		ipStrings := stringToSlice(nodeBgpPeersAnnotation, ",")
		peerIPs, err := stringSliceToIPs(ipStrings)
		if err != nil {
			nrc.bgpServer.Stop()
			return fmt.Errorf("Failed to parse node's Peer Addresses Annotation: %s", err)
		}

		// Get Global Peer Router Password configs
		var peerPasswords []string
		nodeBGPPasswordsAnnotation, ok := node.ObjectMeta.Annotations[peerPasswordAnnotation]
		if !ok {
			glog.Infof("Could not find BGP peer password info in the node's annotations. Assuming no passwords.")
		} else {
			passStrings := stringToSlice(nodeBGPPasswordsAnnotation, ",")
			peerPasswords, err = stringSliceB64Decode(passStrings)
			if err != nil {
				nrc.bgpServer.Stop()
				return fmt.Errorf("Failed to parse node's Peer Passwords Annotation: %s", err)
			}
		}

		// Create and set Global Peer Router complete configs
		nrc.globalPeerRouters, err = newGlobalPeers(peerIPs, peerASNs, peerPasswords)
		if err != nil {
			nrc.bgpServer.Stop()
			return fmt.Errorf("Failed to process Global Peer Router configs: %s", err)
		}

		nrc.nodePeerRouters = ipStrings
	}

	if len(nrc.globalPeerRouters) != 0 {
		err := connectToExternalBGPPeers(nrc.bgpServer, nrc.globalPeerRouters, nrc.bgpGracefulRestart, nrc.peerMultihopTTL)
		if err != nil {
			nrc.bgpServer.Stop()
			return fmt.Errorf("Failed to peer with Global Peer Router(s): %s",
				err)
		}
	} else {
		glog.Infof("No Global Peer Routers configured. Peering skipped.")
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
		nrc.MetricsEnabled = true
	}

	nrc.bgpFullMeshMode = kubeRouterConfig.FullMeshMode
	nrc.bgpEnableInternal = kubeRouterConfig.EnableiBGP
	nrc.bgpGracefulRestart = kubeRouterConfig.BGPGracefulRestart
	nrc.peerMultihopTTL = kubeRouterConfig.PeerMultihopTtl
	nrc.enablePodEgress = kubeRouterConfig.EnablePodEgress
	nrc.syncPeriod = kubeRouterConfig.RoutesSyncPeriod
	nrc.clientset = clientset
	nrc.activeNodes = make(map[string]bool)
	nrc.bgpRRClient = false
	nrc.bgpRRServer = false
	nrc.bgpServerStarted = false
	nrc.initSrcDstCheckDone = false

	// lets start with assumption we hace necessary IAM creds to access EC2 api
	nrc.ec2IamAuthorized = true

	nrc.cniConfFile = os.Getenv("KUBE_ROUTER_CNI_CONF_FILE")
	if nrc.cniConfFile == "" {
		nrc.cniConfFile = "/etc/cni/net.d/10-kuberouter.conf"
	}
	if _, err := os.Stat(nrc.cniConfFile); os.IsNotExist(err) {
		return nil, errors.New("CNI conf file " + nrc.cniConfFile + " does not exist.")
	}

	nrc.ipSetHandler, err = utils.NewIPSet()
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
			return nil, errors.New("Invalid ASN number for cluster ASN")
		}
		nrc.defaultNodeAsnNumber = uint32(kubeRouterConfig.ClusterAsn)
	} else {
		nrc.defaultNodeAsnNumber = 64512 // this magic number is first of the private ASN range, use it as default
	}

	nrc.advertiseClusterIP = kubeRouterConfig.AdvertiseClusterIp
	nrc.advertiseExternalIP = kubeRouterConfig.AdvertiseExternalIp
	nrc.advertiseLoadBalancerIP = kubeRouterConfig.AdvertiseLoadBalancerIp
	nrc.advertisePodCidr = kubeRouterConfig.AdvertiseNodePodCidr

	nrc.enableOverlays = kubeRouterConfig.EnableOverlay

	// Convert ints to uint32s
	peerASNs := make([]uint32, 0)
	for _, i := range kubeRouterConfig.PeerASNs {
		peerASNs = append(peerASNs, uint32(i))
	}

	// Decode base64 passwords
	peerPasswords := make([]string, 0)
	if len(kubeRouterConfig.PeerPasswords) != 0 {
		peerPasswords, err = stringSliceB64Decode(kubeRouterConfig.PeerPasswords)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse CLI Peer Passwords flag: %s", err)
		}
	}

	nrc.globalPeerRouters, err = newGlobalPeers(kubeRouterConfig.PeerRouters,
		peerASNs, peerPasswords)
	if err != nil {
		return nil, fmt.Errorf("Error processing Global Peer Router configs: %s", err)
	}

	nrc.hostnameOverride = kubeRouterConfig.HostnameOverride
	node, err := utils.GetNodeObject(clientset, nrc.hostnameOverride)
	if err != nil {
		return nil, errors.New("Failed getting node object from API server: " + err.Error())
	}

	nrc.nodeName = node.Name

	nodeIP, err := utils.GetNodeIP(node)
	if err != nil {
		return nil, errors.New("Failed getting IP address from node object: " + err.Error())
	}
	nrc.nodeIP = nodeIP

	nrc.nodeSubnet, nrc.nodeInterface, err = getNodeSubnet(nodeIP)
	if err != nil {
		return nil, errors.New("Failed find the subnet of the node IP and interface on" +
			"which its configured: " + err.Error())
	}

	nrc.svcLister = svcInformer.GetIndexer()
	nrc.ServiceEventHandler = nrc.newServiceEventHandler()

	nrc.epLister = epInformer.GetIndexer()
	nrc.EndpointsEventHandler = nrc.newEndpointsEventHandler()

	nrc.nodeLister = nodeInformer.GetIndexer()
	nrc.NodeEventHandler = nrc.newNodeEventHandler()

	return &nrc, nil
}
