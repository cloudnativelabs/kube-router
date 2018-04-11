package controllers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/cloudnativelabs/kube-router/app/options"
	"github.com/cloudnativelabs/kube-router/utils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
	bgpapi "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	gobgp "github.com/osrg/gobgp/server"
	"github.com/osrg/gobgp/table"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"

	v1core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

var (
	podEgressArgs = []string{"-m", "set", "--match-set", podSubnetsIPSetName, "src",
		"-m", "set", "!", "--match-set", podSubnetsIPSetName, "dst",
		"-m", "set", "!", "--match-set", nodeAddrsIPSetName, "dst",
		"-j", "MASQUERADE"}
	podEgressArgsBad = [][]string{{"-m", "set", "--match-set", podSubnetsIPSetName, "src",
		"-m", "set", "!", "--match-set", podSubnetsIPSetName, "dst",
		"-j", "MASQUERADE"}}
)

const (
	customRouteTableID   = "77"
	customRouteTableName = "kube-router"
	podSubnetsIPSetName  = "kube-router-pod-subnets"
	nodeAddrsIPSetName   = "kube-router-node-ips"

	nodeASNAnnotation      = "kube-router.io/node.asn"
	peerASNAnnotation      = "kube-router.io/peer.asns"
	peerIPAnnotation       = "kube-router.io/peer.ips"
	peerPasswordAnnotation = "kube-router.io/peer.passwords"
	rrClientAnnotation     = "kube-router.io/rr.client"
	rrServerAnnotation     = "kube-router.io/rr.server"
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
	advertiseClusterIp      bool
	advertiseExternalIp     bool
	advertiseLoadBalancerIp bool
	defaultNodeAsnNumber    uint32
	nodeAsnNumber           uint32
	globalPeerRouters       []*config.NeighborConfig
	nodePeerRouters         []string
	bgpFullMeshMode         bool
	bgpEnableInternal       bool
	bgpGracefulRestart      bool
	ipSetHandler            *utils.IPSet
	enableOverlays          bool
	peerMultihopTtl         uint8
	MetricsEnabled          bool
	bgpServerStarted        bool
	bgpRRClient             bool
	bgpRRServer             bool
	bgpClusterId            uint32
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
func (nrc *NetworkRoutingController) Run(healthChan chan<- *ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) {
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
		toAdvertise, toWithdraw, err := nrc.getActiveUnicastRoutes(true)
		if err != nil {
			glog.Errorf("failed to get routes to advertise/withdraw %s", err)
		}

		nrc.advertiseIPs(toAdvertise)
		nrc.withdrawIPs(toWithdraw)

		glog.V(1).Info("Performing periodic sync of the routes")
		err = nrc.advertiseRoute()
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

		sendHeartBeat(healthChan, "NRC")

		select {
		case <-stopCh:
			glog.Infof("Shutting down network routes controller")
			return
		case <-t.C:
		}
	}
}

func createPodEgressRule() error {
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed create iptables handler:" + err.Error())
	}

	err = iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", podEgressArgs...)
	if err != nil {
		return errors.New("Failed to add iptable rule to masqurade outbound traffic from pods: " +
			err.Error() + "External connectivity will not work.")

	}

	glog.V(1).Infof("Added iptables rule to masqurade outbound traffic from pods.")
	return nil
}

func deletePodEgressRule() error {
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed create iptables handler:" + err.Error())
	}

	exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", podEgressArgs...)
	if err != nil {
		return errors.New("Failed to lookup iptable rule to masqurade outbound traffic from pods: " + err.Error())
	}

	if exists {
		err = iptablesCmdHandler.Delete("nat", "POSTROUTING", podEgressArgs...)
		if err != nil {
			return errors.New("Failed to delete iptable rule to masqurade outbound traffic from pods: " +
				err.Error() + ". Pod egress might still work...")
		}
		glog.Infof("Deleted iptables rule to masqurade outbound traffic from pods.")
	}

	return nil
}

func deleteBadPodEgressRules() error {
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed create iptables handler:" + err.Error())
	}

	for _, args := range podEgressArgsBad {
		exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", args...)
		if err != nil {
			return fmt.Errorf("Failed to lookup iptables rule: %s", err.Error())
		}

		if exists {
			err = iptablesCmdHandler.Delete("nat", "POSTROUTING", args...)
			if err != nil {
				return fmt.Errorf("Failed to delete old/bad iptable rule to "+
					"masqurade outbound traffic from pods: %s.\n"+
					"Pod egress might still work, or bugs may persist after upgrade...",
					err)
			}
			glog.Infof("Deleted old/bad iptables rule to masqurade outbound traffic from pods.")
		}
	}

	return nil
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
					controllerBGPadvertisementsReceived.WithLabelValues().Add(float64(1))
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

func (nrc *NetworkRoutingController) advertiseRoute() error {
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

func (nrc *NetworkRoutingController) getClusterIp(svc *v1core.Service) string {
	clusterIp := ""
	if svc.Spec.Type == "ClusterIP" || svc.Spec.Type == "NodePort" || svc.Spec.Type == "LoadBalancer" {

		// skip headless services
		if svc.Spec.ClusterIP != "None" && svc.Spec.ClusterIP != "" {
			clusterIp = svc.Spec.ClusterIP
		}
	}
	return clusterIp
}

func (nrc *NetworkRoutingController) getExternalIps(svc *v1core.Service) []string {
	externalIpList := make([]string, 0)
	if svc.Spec.Type == "ClusterIP" || svc.Spec.Type == "NodePort" {

		// skip headless services
		if svc.Spec.ClusterIP != "None" && svc.Spec.ClusterIP != "" {
			externalIpList = append(externalIpList, svc.Spec.ExternalIPs...)
		}
	}
	return externalIpList
}

func (nrc *NetworkRoutingController) getLoadBalancerIps(svc *v1core.Service) []string {
	loadBalancerIpList := make([]string, 0)
	if svc.Spec.Type == "LoadBalancer" {
		// skip headless services
		if svc.Spec.ClusterIP != "None" && svc.Spec.ClusterIP != "" {
			_, skiplbips := svc.ObjectMeta.Annotations["kube-router.io/service.skiplbips"]
			if !skiplbips {
				for _, lbIngress := range svc.Status.LoadBalancer.Ingress {
					if len(lbIngress.IP) > 0 {
						loadBalancerIpList = append(loadBalancerIpList, lbIngress.IP)
					}
				}
			}
		}
	}
	return loadBalancerIpList
}

func (nrc *NetworkRoutingController) getAllUnicastRoutes() ([]string, []string, error) {
	return getUnicastRoutes(false)
}

func (nrc *NetworkRoutingController) getActiveUnicastRoutes() ([]string, []string, error) {
	return getUnicastRoutes(true)
}

func (nrc *NetworkRoutingController) getUnicastRoutes(onlyActiveEndpoints bool) ([]string, []string, error) {
	toAdvertiseList := make([]string, 0)
	toWithdrawList := make([]string, 0)

	for _, obj := range nrc.svcLister.List() {
		svc := obj.(*v1core.Service)

		toAdvertise, toWithdraw, err = nrc.unicastRoutesForService(svc, onlyActiveEndpoints)
		if err != nil {
			return nil, nil, err
		}

		if len(toAdvertise) > 0 {
			toAdvertiseList = append(toAdvertiseList, toAdvertise...)
		}

		if len(toWithdraw) > 0 {
			toWithdrawList = append(toWithdrawList, toWithdraw...)
		}
	}

	return toAdvertiseList, toWithdrawList, nil
}

func (nrc *NetworkRoutingController) unicastRoutesForService(svc *v1core.Service, onlyActiveEndpoints bool) ([]string, []string, error) {
	ipList := make([]string, 0)
	var err error

	nodeHasEndpoints := true
	if onlyActiveEndpoints {
		if svc.Spec.ExternalTrafficPolicy == v1core.ServiceExternalTrafficPolicyTypeLocal {
			nodeHasEndpoints, err = nrc.nodeHasEndpointsForService(svc)
			if err != nil {
				return err
			}
		}
	}

	if nrc.advertiseClusterIp {
		clusterIp := nrc.getClusterIp(svc)
		if clusterIp != "" {
			ipList = append(ipList, clusterIp)
		}
	}
	if nrc.advertiseExternalIp {
		ipList = append(ipList, nrc.getExternalIps(svc)...)
	}
	if nrc.advertiseLoadBalancerIp {
		ipList = append(ipList, nrc.getLoadBalancerIps(svc)...)
	}

	if !nodeHasEndpoints {
		return nil, ipList, nil
	}

	return ipList, nil, nil
}

func (nrc *NetworkRoutingController) routesForEndpoints(ep *v1core.Endpoints) ([]string, []string, error) {
	return nil, nil, nil
}

func (nrc *NetworkRoutingController) advertiseIPs(toAdvertise []string) {
	for _, ip := range toAdvertise {
		err := nrc.AdvertiseClusterIp(ip)
		if err != nil {
			glog.Errorf("error advertising IP: %q, error: %v", ip, err)
		}
	}
}

func (nrc *NetworkRoutingController) withdrawIPs(toWithdraw []string) {
	for _, ip := range toWithdraw {
		err := nrc.WithdrawClusterIP(ip)
		if err != nil {
			glog.Errorf("error advertising IP: %q, error: %v", ip, err)
		}
	}
}

// nodeHasEndpointsForService will get the corresponding Endpoints resource for a given Service
// return true if any endpoint addresses has NodeName matching the node name of the route controller
func (nrc *NetworkRoutingController) nodeHasEndpointsForService(svc *v1core.Service) (bool, error) {
	// listers for endpoints and services should use the same keys since
	// endpoint and service resources share the same object name and namespace
	key, err := cache.MetaNamespaceKeyFunc(svc)
	if err != nil {
		return false, err
	}
	item, exists, err := nrc.epLister.GetByKey(key)
	if err != nil {
		return false, err
	}

	if !exists {
		return false, fmt.Errorf("endpoint resource doesn't exist for service: %q", svc.Name)
	}

	ep, ok := item.(*v1core.Endpoints)
	if !ok {
		return false, errors.New("failed to convert cache item to Endpoints type")
	}

	for _, subset := range ep.Subsets {
		for _, address := range subset.Addresses {
			if *address.NodeName == nrc.nodeName {
				return true, nil
			}
		}
	}

	return false, nil
}

// Used for processing Annotations that may contain multiple items
// Pass this the string and the delimiter
func stringToSlice(s, d string) []string {
	ss := make([]string, 0)
	if strings.Contains(s, d) {
		ss = strings.Split(s, d)
	} else {
		ss = append(ss, s)
	}
	return ss
}

func stringSliceToIPs(s []string) ([]net.IP, error) {
	ips := make([]net.IP, 0)
	for _, ipString := range s {
		ip := net.ParseIP(ipString)
		if ip == nil {
			return nil, fmt.Errorf("Could not parse \"%s\" as an IP", ipString)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func stringSliceToUInt32(s []string) ([]uint32, error) {
	ints := make([]uint32, 0)
	for _, intString := range s {
		newInt, err := strconv.ParseUint(intString, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("Could not parse \"%s\" as an integer", intString)
		}
		ints = append(ints, uint32(newInt))
	}
	return ints, nil
}

func stringSliceB64Decode(s []string) ([]string, error) {
	ss := make([]string, 0)
	for _, b64String := range s {
		decoded, err := base64.StdEncoding.DecodeString(b64String)
		if err != nil {
			return nil, fmt.Errorf("Could not parse \"%s\" as a base64 encoded string",
				b64String)
		}
		ss = append(ss, string(decoded))
	}
	return ss, nil
}

// Does validation and returns neighbor configs
func newGlobalPeers(ips []net.IP, asns []uint32, passwords []string) (
	[]*config.NeighborConfig, error) {
	peers := make([]*config.NeighborConfig, 0)

	// Validations
	if len(ips) != len(asns) {
		return nil, errors.New("Invalid peer router config. " +
			"The number of IPs and ASN numbers must be equal.")
	}

	if len(ips) != len(passwords) && len(passwords) != 0 {
		return nil, errors.New("Invalid peer router config. " +
			"The number of passwords should either be zero, or one per peer router." +
			" Use blank items if a router doesn't expect a password.\n" +
			"Example: \"pass,,pass\" OR [\"pass\",\"\",\"pass\"].")
	}

	for i := 0; i < len(ips); i++ {
		if !((asns[i] >= 64512 && asns[i] <= 65535) ||
			(asns[i] >= 4200000000 && asns[i] <= 4294967294)) {
			return nil, fmt.Errorf("Invalid ASN number \"%d\" for global BGP peer",
				asns[i])
		}

		peer := &config.NeighborConfig{
			NeighborAddress: ips[i].String(),
			PeerAs:          asns[i],
		}

		if len(passwords) != 0 {
			peer.AuthPassword = passwords[i]
		}

		peers = append(peers, peer)
	}

	return peers, nil
}

func connectToExternalBGPPeers(server *gobgp.BgpServer, peerConfigs []*config.NeighborConfig, bgpGracefulRestart bool, peerMultihopTtl uint8) error {
	for _, peerConfig := range peerConfigs {
		n := &config.Neighbor{
			Config: *peerConfig,
		}

		if bgpGracefulRestart {
			n.GracefulRestart = config.GracefulRestart{
				Config: config.GracefulRestartConfig{
					Enabled: true,
				},
				State: config.GracefulRestartState{
					LocalRestarting: true,
				},
			}

			n.AfiSafis = []config.AfiSafi{
				{
					Config: config.AfiSafiConfig{
						AfiSafiName: config.AFI_SAFI_TYPE_IPV4_UNICAST,
						Enabled:     true,
					},
					MpGracefulRestart: config.MpGracefulRestart{
						Config: config.MpGracefulRestartConfig{
							Enabled: true,
						},
					},
				},
			}
		}
		if peerMultihopTtl > 1 {
			n.EbgpMultihop = config.EbgpMultihop{
				Config: config.EbgpMultihopConfig{
					Enabled:     true,
					MultihopTtl: peerMultihopTtl,
				},
				State: config.EbgpMultihopState{
					Enabled:     true,
					MultihopTtl: peerMultihopTtl,
				},
			}
		}
		err := server.AddNeighbor(n)
		if err != nil {
			return fmt.Errorf("Error peering with peer router "+
				"\"%s\" due to: %s", peerConfig.NeighborAddress, err)
		}
		glog.V(2).Infof("Successfully configured %s in ASN %v as BGP peer to the node",
			peerConfig.NeighborAddress, peerConfig.PeerAs)
	}
	return nil
}

// AdvertiseClusterIp  advertises the service cluster ip the configured peers
func (nrc *NetworkRoutingController) AdvertiseClusterIp(clusterIp string) error {

	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop(nrc.nodeIP.String()),
	}

	glog.V(2).Infof("Advertising route: '%s/%s via %s' to peers", clusterIp, strconv.Itoa(32), nrc.nodeIP.String())

	_, err := nrc.bgpServer.AddPath("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(uint8(32),
		clusterIp), false, attrs, time.Now(), false)})

	return err
}

// UnadvertiseClusterIP  unadvertises the service cluster ip
func (nrc *NetworkRoutingController) WithdrawClusterIP(clusterIp string) error {
	glog.V(2).Infof("Unadvertising route: '%s/%s via %s' to peers", clusterIp, strconv.Itoa(32), nrc.nodeIP.String())

	pathList := []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(uint8(32),
		clusterIp), true, nil, time.Now(), false)}

	err := nrc.bgpServer.DeletePath([]byte(nil), 0, "", pathList)

	return err
}

// Each node advertises its pod CIDR to the nodes with same ASN (iBGP peers) and to the global BGP peer
// or per node BGP peer. Each node ends up advertising not only pod CIDR assigned to the self but other
// learned routes to the node pod CIDR's as well to global BGP peer or per node BGP peers. external BGP
// peer will randomly (since all path have equal selection attributes) select the routes from multiple
// routes to a pod CIDR which will result in extra hop. To prevent this behaviour this methods add
// defult export policy to reject everything and an explicit policy is added so that each node only
// advertised the pod CIDR assigned to it. Additionally export policy is added so that each node
// advertises cluster IP's ONLY to the external BGP peers (and not to iBGP peers).
func (nrc *NetworkRoutingController) addExportPolicies() error {

	// we are rr server do not add export policies
	if nrc.bgpRRServer {
		return nil
	}

	cidr, err := utils.GetPodCidrFromNodeSpec(nrc.clientset, nrc.hostnameOverride)
	if err != nil {
		return err
	}

	// creates prefix set to represent the assigned node's pod CIDR
	podCidrPrefixSet, err := table.NewPrefixSet(config.PrefixSet{
		PrefixSetName: "podcidrprefixset",
		PrefixList: []config.Prefix{
			{
				IpPrefix: cidr,
			},
		},
	})
	err = nrc.bgpServer.ReplaceDefinedSet(podCidrPrefixSet)
	if err != nil {
		nrc.bgpServer.AddDefinedSet(podCidrPrefixSet)
	}

	// creates prefix set to represent all the advertisable IP associated with the services
	advIpPrefixList := make([]config.Prefix, 0)
	advIps, _, _ := nrc.getAllUnicastRoutes()
	for _, ip := range advIps {
		advIpPrefixList = append(advIpPrefixList, config.Prefix{IpPrefix: ip + "/32"})
	}
	clusterIpPrefixSet, err := table.NewPrefixSet(config.PrefixSet{
		PrefixSetName: "clusteripprefixset",
		PrefixList:    advIpPrefixList,
	})
	err = nrc.bgpServer.ReplaceDefinedSet(clusterIpPrefixSet)
	if err != nil {
		nrc.bgpServer.AddDefinedSet(clusterIpPrefixSet)
	}

	statements := make([]config.Statement, 0)

	// statement to represent the export policy to permit advertising node's pod CIDR
	statements = append(statements,
		config.Statement{
			Conditions: config.Conditions{
				MatchPrefixSet: config.MatchPrefixSet{
					PrefixSet: "podcidrprefixset",
				},
			},
			Actions: config.Actions{
				RouteDisposition: config.ROUTE_DISPOSITION_ACCEPT_ROUTE,
			},
		})

	externalBgpPeers := make([]string, 0)
	if len(nrc.globalPeerRouters) != 0 {
		for _, peer := range nrc.globalPeerRouters {
			externalBgpPeers = append(externalBgpPeers, peer.NeighborAddress)
		}
	}
	if len(nrc.nodePeerRouters) != 0 {
		for _, peer := range nrc.nodePeerRouters {
			externalBgpPeers = append(externalBgpPeers, peer)
		}
	}
	if len(externalBgpPeers) > 0 {
		ns, _ := table.NewNeighborSet(config.NeighborSet{
			NeighborSetName:  "externalpeerset",
			NeighborInfoList: externalBgpPeers,
		})
		err = nrc.bgpServer.ReplaceDefinedSet(ns)
		if err != nil {
			nrc.bgpServer.AddDefinedSet(ns)
		}
		// statement to represent the export policy to permit advertising cluster IP's
		// only to the global BGP peer or node specific BGP peer
		statements = append(statements, config.Statement{
			Conditions: config.Conditions{
				MatchPrefixSet: config.MatchPrefixSet{
					PrefixSet: "clusteripprefixset",
				},
				MatchNeighborSet: config.MatchNeighborSet{
					NeighborSet: "externalpeerset",
				},
			},
			Actions: config.Actions{
				RouteDisposition: config.ROUTE_DISPOSITION_ACCEPT_ROUTE,
			},
		})
	}

	definition := config.PolicyDefinition{
		Name:       "kube_router",
		Statements: statements,
	}

	policy, err := table.NewPolicy(definition)
	if err != nil {
		return errors.New("Failed to create new policy: " + err.Error())
	}

	policyAlreadyExists := false
	policyList := nrc.bgpServer.GetPolicy()
	for _, existingPolicy := range policyList {
		if existingPolicy.Name == "kube_router" {
			policyAlreadyExists = true
		}
	}

	if !policyAlreadyExists {
		err = nrc.bgpServer.AddPolicy(policy, false)
		if err != nil {
			return errors.New("Failed to add policy: " + err.Error())
		}
	}

	policyAssignmentExists := false
	_, existingPolicyAssignments, err := nrc.bgpServer.GetPolicyAssignment("", table.POLICY_DIRECTION_EXPORT)
	if err == nil {
		for _, existingPolicyAssignment := range existingPolicyAssignments {
			if existingPolicyAssignment.Name == "kube_router" {
				policyAssignmentExists = true
			}
		}
	}

	if !policyAssignmentExists {
		err = nrc.bgpServer.AddPolicyAssignment("",
			table.POLICY_DIRECTION_EXPORT,
			[]*config.PolicyDefinition{&definition},
			table.ROUTE_TYPE_REJECT)
		if err != nil {
			return errors.New("Failed to add policy assignment: " + err.Error())
		}
	} else {
		// configure default BGP export policy to reject
		err = nrc.bgpServer.ReplacePolicyAssignment("",
			table.POLICY_DIRECTION_EXPORT,
			[]*config.PolicyDefinition{&definition},
			table.ROUTE_TYPE_REJECT)
		if err != nil {
			return errors.New("Failed to replace policy assignment: " + err.Error())
		}
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

func (nrc *NetworkRoutingController) disableSourceDestinationCheck() {
	nodes, err := nrc.clientset.CoreV1().Nodes().List(metav1.ListOptions{})
	if err != nil {
		glog.Errorf("Failed to list nodes from API server due to: %s. Can not perform BGP peer sync", err.Error())
		return
	}

	for _, node := range nodes.Items {
		if node.Spec.ProviderID == "" || !strings.HasPrefix(node.Spec.ProviderID, "aws") {
			return
		}
		providerID := strings.Replace(node.Spec.ProviderID, "///", "//", 1)
		URL, err := url.Parse(providerID)
		instanceID := URL.Path
		instanceID = strings.Trim(instanceID, "/")

		sess, _ := session.NewSession(aws.NewConfig().WithMaxRetries(5))
		metadataClient := ec2metadata.New(sess)
		region, err := metadataClient.Region()
		if err != nil {
			glog.Errorf("Failed to disable source destination check due to: " + err.Error())
			return
		}
		sess.Config.Region = aws.String(region)
		ec2Client := ec2.New(sess)
		_, err = ec2Client.ModifyInstanceAttribute(
			&ec2.ModifyInstanceAttributeInput{
				InstanceId: aws.String(instanceID),
				SourceDestCheck: &ec2.AttributeBooleanValue{
					Value: aws.Bool(false),
				},
			},
		)
		if err != nil {
			awserr := err.(awserr.Error)
			if awserr.Code() == "UnauthorizedOperation" {
				nrc.ec2IamAuthorized = false
				glog.Errorf("Node does not have necessary IAM creds to modify instance attribute. So skipping disabling src-dst check.")
				return
			}
			glog.Errorf("Failed to disable source destination check due to: %v", err.Error())
		} else {
			glog.Infof("Disabled source destination check for the instance: " + instanceID)
		}

		// to prevent EC2 rejecting API call due to API throttling give a delay between the calls
		time.Sleep(1000 * time.Millisecond)
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

// Refresh the peer relationship rest of the nodes in the cluster (iBGP peers). Node add/remove
// events should ensure peer relationship with only currently active nodes. In case
// we miss any events from API server this method which is called periodically
// ensure peer relationship with removed nodes is deleted. Also update Pod subnet ipset.
func (nrc *NetworkRoutingController) syncInternalPeers() {
	nrc.mu.Lock()
	defer nrc.mu.Unlock()

	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		controllerBGPInternalPeersSyncTime.WithLabelValues().Set(float64(endTime))
		glog.V(2).Infof("Syncing BGP peers for the node took %v", endTime)
	}()

	// get the current list of the nodes from API server
	nodes, err := nrc.clientset.CoreV1().Nodes().List(metav1.ListOptions{})
	if err != nil {
		glog.Errorf("Failed to list nodes from API server due to: %s. Can not perform BGP peer sync", err.Error())
		return
	}

	controllerBPGpeers.WithLabelValues().Set(float64(len(nodes.Items)))
	// establish peer and add Pod CIDRs with current set of nodes
	currentNodes := make([]string, 0)
	for _, node := range nodes.Items {
		nodeIP, _ := utils.GetNodeIP(&node)

		// skip self
		if nodeIP.String() == nrc.nodeIP.String() {
			continue
		}

		// we are rr-client peer only with rr-server
		if nrc.bgpRRClient {
			if _, ok := node.ObjectMeta.Annotations[rrServerAnnotation]; !ok {
				continue
			}
		}

		// if node full mesh is not requested then just peer with nodes with same ASN
		// (run iBGP among same ASN peers)
		if !nrc.bgpFullMeshMode {
			nodeasn, ok := node.ObjectMeta.Annotations[nodeASNAnnotation]
			if !ok {
				glog.Infof("Not peering with the Node %s as ASN number of the node is unknown.",
					nodeIP.String())
				continue
			}

			asnNo, err := strconv.ParseUint(nodeasn, 0, 32)
			if err != nil {
				glog.Infof("Not peering with the Node %s as ASN number of the node is invalid.",
					nodeIP.String())
				continue
			}

			// if the nodes ASN number is different from ASN number of current node skip peering
			if nrc.nodeAsnNumber != uint32(asnNo) {
				glog.Infof("Not peering with the Node %s as ASN number of the node is different.",
					nodeIP.String())
				continue
			}
		}

		currentNodes = append(currentNodes, nodeIP.String())
		nrc.activeNodes[nodeIP.String()] = true
		n := &config.Neighbor{
			Config: config.NeighborConfig{
				NeighborAddress: nodeIP.String(),
				PeerAs:          nrc.nodeAsnNumber,
			},
		}

		if nrc.bgpGracefulRestart {
			n.GracefulRestart = config.GracefulRestart{
				Config: config.GracefulRestartConfig{
					Enabled: true,
				},
				State: config.GracefulRestartState{
					LocalRestarting: true,
				},
			}

			n.AfiSafis = []config.AfiSafi{
				{
					Config: config.AfiSafiConfig{
						AfiSafiName: config.AFI_SAFI_TYPE_IPV4_UNICAST,
						Enabled:     true,
					},
					MpGracefulRestart: config.MpGracefulRestart{
						Config: config.MpGracefulRestartConfig{
							Enabled: true,
						},
					},
				},
			}
		}

		// we are rr-server peer with other rr-client with reflection enabled
		if nrc.bgpRRServer {
			if _, ok := node.ObjectMeta.Annotations[rrClientAnnotation]; ok {
				//add rr options with clusterId
				n.RouteReflector = config.RouteReflector{
					Config: config.RouteReflectorConfig{
						RouteReflectorClient:    true,
						RouteReflectorClusterId: config.RrClusterIdType(nrc.bgpClusterId),
					},
					State: config.RouteReflectorState{
						RouteReflectorClient:    true,
						RouteReflectorClusterId: config.RrClusterIdType(nrc.bgpClusterId),
					},
				}
			}
		}

		// TODO: check if a node is alredy added as nieighbour in a better way than add and catch error
		if err := nrc.bgpServer.AddNeighbor(n); err != nil {
			if !strings.Contains(err.Error(), "Can't overwrite the existing peer") {
				glog.Errorf("Failed to add node %s as peer due to %s", nodeIP.String(), err)
			}
		}
	}

	// find the list of the node removed, from the last known list of active nodes
	removedNodes := make([]string, 0)
	for ip := range nrc.activeNodes {
		stillActive := false
		for _, node := range currentNodes {
			if ip == node {
				stillActive = true
				break
			}
		}
		if !stillActive {
			removedNodes = append(removedNodes, ip)
		}
	}

	// delete the neighbor for the nodes that are removed
	for _, ip := range removedNodes {
		n := &config.Neighbor{
			Config: config.NeighborConfig{
				NeighborAddress: ip,
				PeerAs:          nrc.defaultNodeAsnNumber,
			},
		}
		if err := nrc.bgpServer.DeleteNeighbor(n); err != nil {
			glog.Errorf("Failed to remove node %s as peer due to %s", ip, err)
		}
		delete(nrc.activeNodes, ip)
	}
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

// setup a custom routing table that will be used for policy based routing to ensure traffic originating
// on tunnel interface only leaves through tunnel interface irrespective rp_filter enabled/disabled
func (nrc *NetworkRoutingController) enablePolicyBasedRouting() error {
	err := rtTablesAdd(customRouteTableID, customRouteTableName)
	if err != nil {
		return fmt.Errorf("Failed to update rt_tables file: %s", err)
	}

	cidr, err := utils.GetPodCidrFromNodeSpec(nrc.clientset, nrc.hostnameOverride)
	if err != nil {
		return fmt.Errorf("Failed to get the pod CIDR allocated for the node: %s", err.Error())
	}

	out, err := exec.Command("ip", "rule", "list").Output()
	if err != nil {
		return fmt.Errorf("Failed to verify if `ip rule` exists: %s", err.Error())
	}

	if !strings.Contains(string(out), cidr) {
		err = exec.Command("ip", "rule", "add", "from", cidr, "lookup", customRouteTableID).Run()
		if err != nil {
			return fmt.Errorf("Failed to add ip rule due to: %s", err.Error())
		}
	}

	return nil
}

func (nrc *NetworkRoutingController) disablePolicyBasedRouting() error {
	err := rtTablesAdd(customRouteTableID, customRouteTableName)
	if err != nil {
		return fmt.Errorf("Failed to update rt_tables file: %s", err)
	}

	cidr, err := utils.GetPodCidrFromNodeSpec(nrc.clientset, nrc.hostnameOverride)
	if err != nil {
		return fmt.Errorf("Failed to get the pod CIDR allocated for the node: %s",
			err.Error())
	}

	out, err := exec.Command("ip", "rule", "list").Output()
	if err != nil {
		return fmt.Errorf("Failed to verify if `ip rule` exists: %s",
			err.Error())
	}

	if strings.Contains(string(out), cidr) {
		err = exec.Command("ip", "rule", "del", "from", cidr, "table", customRouteTableID).Run()
		if err != nil {
			return fmt.Errorf("Failed to delete ip rule: %s", err.Error())
		}
	}

	return nil
}

func rtTablesAdd(tableNumber, tableName string) error {
	b, err := ioutil.ReadFile("/etc/iproute2/rt_tables")
	if err != nil {
		return fmt.Errorf("Failed to read: %s", err.Error())
	}

	if !strings.Contains(string(b), tableName) {
		f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("Failed to open: %s", err.Error())
		}
		defer f.Close()
		if _, err = f.WriteString(tableNumber + " " + tableName + "\n"); err != nil {
			return fmt.Errorf("Failed to write: %s", err.Error())
		}
	}

	return nil
}

// OnNodeUpdate Handle updates from Node watcher. Node watcher calls this method whenever there is
// new node is added or old node is deleted. So peer up with new node and drop peering
// from old node
func (nrc *NetworkRoutingController) OnNodeUpdate(obj interface{}) {
	if !nrc.bgpServerStarted {
		return
	}

	if nrc.bgpEnableInternal {
		nrc.syncInternalPeers()
	}

	// skip if first round of disableSourceDestinationCheck() is not done yet, this is to prevent
	// all the nodes for all the node add update trying to perfrom disableSourceDestinationCheck
	if nrc.initSrcDstCheckDone && nrc.ec2IamAuthorized {
		nrc.disableSourceDestinationCheck()
	}
}

func (nrc *NetworkRoutingController) OnServiceUpdate(obj interface{}) {
	if !nrc.bgpServerStarted {
		return
	}

	svc := obj.(*v1core.Service)

	toAdvertise, toWithdraw, err = nrc.unicastRoutesForService(svc, true)
	if err != nil {
		glog.Errorf("error getting routes for service: %s, err: %s", svc.Name, err)
	}

	if len(toAdvertise) > 0 {
		nrc.advertiseIPs(toAdvertise)
	}

	if len(toWithdraw) > 0 {
		nrc.withdrawIPs(toWithdraw)
	}
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
		clusterId, err := strconv.ParseUint(clusterid, 0, 32)
		if err != nil {
			return errors.New("Failed to parse rr.server clusterId number specified for the the node")
		}
		nrc.bgpClusterId = uint32(clusterId)
		nrc.bgpRRServer = true
	} else if clusterid, ok := node.ObjectMeta.Annotations[rrClientAnnotation]; ok {
		glog.Infof("Found rr.client for the node to be %s from the node annotation", clusterid)
		clusterId, err := strconv.ParseUint(clusterid, 0, 32)
		if err != nil {
			return errors.New("Failed to parse rr.client clusterId number specified for the the node")
		}
		nrc.bgpClusterId = uint32(clusterId)
		nrc.bgpRRClient = true
	}

	nrc.bgpServer = gobgp.NewBgpServer()
	go nrc.bgpServer.Serve()

	g := bgpapi.NewGrpcServer(nrc.bgpServer, ":50051")
	go g.Serve()

	var localAddressList []string

	if ipv4IsEnabled() {
		localAddressList = append(localAddressList, "0.0.0.0")
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
		err := connectToExternalBGPPeers(nrc.bgpServer, nrc.globalPeerRouters, nrc.bgpGracefulRestart, nrc.peerMultihopTtl)
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

func ipv4IsEnabled() bool {
	l, err := net.Listen("tcp4", "")
	if err != nil {
		return false
	}
	l.Close()

	return true
}

func ipv6IsEnabled() bool {
	l, err := net.Listen("tcp6", "")
	if err != nil {
		return false
	}
	l.Close()

	return true
}

func getNodeSubnet(nodeIp net.IP) (net.IPNet, string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return net.IPNet{}, "", errors.New("Failed to get list of links")
	}
	for _, link := range links {
		addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return net.IPNet{}, "", errors.New("Failed to get list of addr")
		}
		for _, addr := range addresses {
			if addr.IPNet.IP.Equal(nodeIp) {
				return *addr.IPNet, link.Attrs().Name, nil
			}
		}
	}
	return net.IPNet{}, "", errors.New("Failed to find interface with specified node ip")
}

// generateTunnelName will generate a name for a tunnel interface given a node IP
// for example, if the node IP is 10.0.0.1 the tunnel interface will be named tun-10001
// Since linux restricts interface names to 15 characters, if length of a node IP
// is greater than 12 (after removing "."), then the interface name is tunXYZ
// as opposed to tun-XYZ
func generateTunnelName(nodeIP string) string {
	hash := strings.Replace(nodeIP, ".", "", -1)

	if len(hash) < 12 {
		return "tun-" + hash
	}

	return "tun" + hash
}

func (nrc *NetworkRoutingController) newNodeEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*v1core.Node)
			nodeIP, _ := utils.GetNodeIP(node)

			glog.V(2).Infof("Received node %s added update from watch API so peer with new node", nodeIP)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			nrc.OnNodeUpdate(newObj)

		},
		DeleteFunc: func(obj interface{}) {
			node := obj.(*v1core.Node)
			nodeIP, _ := utils.GetNodeIP(node)

			glog.Infof("Received node %s removed update from watch API, so remove node from peer", nodeIP)

		},
	}
}

func (nrc *NetworkRoutingController) newServiceEventHandler() cache.ResourceEventHandler {
	return nil
}

func (nrc *NetworkRoutingController) newEndpointsEventHandler() cache.ResourceEventHandler {
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
		prometheus.MustRegister(controllerBGPadvertisementsReceived)
		prometheus.MustRegister(controllerBGPInternalPeersSyncTime)
		prometheus.MustRegister(controllerBPGpeers)
		nrc.MetricsEnabled = true
	}

	nrc.bgpFullMeshMode = kubeRouterConfig.FullMeshMode
	nrc.bgpEnableInternal = kubeRouterConfig.EnableiBGP
	nrc.bgpGracefulRestart = kubeRouterConfig.BGPGracefulRestart
	nrc.peerMultihopTtl = kubeRouterConfig.PeerMultihopTtl
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

	nrc.advertiseClusterIp = kubeRouterConfig.AdvertiseClusterIp
	nrc.advertiseExternalIp = kubeRouterConfig.AdvertiseExternalIp
	nrc.advertiseLoadBalancerIp = kubeRouterConfig.AdvertiseLoadBalancerIp

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
