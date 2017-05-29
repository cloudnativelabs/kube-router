package controllers

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/app/options"
	"github.com/cloudnativelabs/kube-router/app/watchers"
	"github.com/cloudnativelabs/kube-router/utils"
	"github.com/golang/glog"
	bgpapi "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	gobgp "github.com/osrg/gobgp/server"
	"github.com/osrg/gobgp/table"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type NetworkRoutingController struct {
	nodeIP             net.IP
	nodeHostName       string
	mu                 sync.Mutex
	clientset          *kubernetes.Clientset
	bgpServer          *gobgp.BgpServer
	syncPeriod         time.Duration
	advertiseClusterIp bool
	peerRouter         string
	asnNumber          uint32
	peerAsnNumber      uint32
}

func (nrc *NetworkRoutingController) Run(stopCh <-chan struct{}, wg *sync.WaitGroup) {

	cidr, err := utils.GetPodCidrFromCniSpec("/etc/cni/net.d/10-kuberouter.conf")
	if err != nil {
		glog.Errorf("Failed to get pod CIDR from CNI conf file: %s", err.Error())
	}
	cidrlen, _ := cidr.Mask.Size()
	oldCidr := cidr.IP.String() + "/" + strconv.Itoa(cidrlen)

	currentCidr, err := utils.GetPodCidrFromNodeSpec(nrc.clientset)
	if err != nil {
		glog.Errorf("Failed to get pod CIDR from node spec: %s", err.Error())
	}

	if len(cidr.IP) == 0 || strings.Compare(oldCidr, currentCidr) != 0 {
		err = utils.InsertPodCidrInCniSpec("/etc/cni/net.d/10-kuberouter.conf", currentCidr)
		if err != nil {
			glog.Errorf("Failed to insert pod CIDR into CNI conf file: %s", err.Error())
		}
	}

	t := time.NewTicker(nrc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	nodes, err := nrc.clientset.Core().Nodes().List(metav1.ListOptions{})
	if err != nil {
		glog.Errorf("Failed to list nodes: %s", err.Error())
		return
	}

	glog.Infof("Starting network route controller")

	// add the current set of nodes (excluding self) as BGP peers. Nodes form full mesh
	for _, node := range nodes.Items {
		nodeIP, _ := getNodeIP(&node)
		if nodeIP.String() == nrc.nodeIP.String() {
			continue
		}

		n := &config.Neighbor{
			Config: config.NeighborConfig{
				NeighborAddress: nodeIP.String(),
				PeerAs:          nrc.asnNumber,
			},
		}
		if err := nrc.bgpServer.AddNeighbor(n); err != nil {
			panic(err)
		}
	}

	// if the global routing peer is configured then peer with it
	if len(nrc.peerRouter) != 0 {
		n := &config.Neighbor{
			Config: config.NeighborConfig{
				NeighborAddress: nrc.peerRouter,
				PeerAs:          nrc.peerAsnNumber,
			},
		}
		if err := nrc.bgpServer.AddNeighbor(n); err != nil {
			glog.Errorf("Failed to peer with global peer routeri: %s", nrc.peerRouter)
		}
	}

	// loop forever till notified to stop on stopCh
	for {
		select {
		case <-stopCh:
			glog.Infof("Shutting down network routes controller")
			return
		default:
		}

		// advertise cluster IP for the service to be reachable via host
		if nrc.advertiseClusterIp {
			glog.Infof("Advertising cluster ips")
			for _, svc := range watchers.ServiceWatcher.List() {
				if svc.Spec.Type == "ClusterIP" || svc.Spec.Type == "NodePort" {
					glog.Infof("found a service of cluster ip type")
					nrc.AdvertiseClusterIp(svc.Spec.ClusterIP)
				}
			}
		}

		glog.Infof("Performing periodic syn of the routes")
		err := nrc.advertiseRoute()
		if err != nil {
			glog.Errorf("Failed to advertise route: %s", err.Error())
		}

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
				glog.Infof("Processing bgp route advertisement from peer")
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

	cidr, err := utils.GetPodCidrFromNodeSpec(nrc.clientset)
	if err != nil {
		return err
	}
	cidrStr := strings.Split(cidr, "/")
	subnet := cidrStr[0]
	cidrLen, err := strconv.Atoi(cidrStr[1])
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop(nrc.nodeIP.String()),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{4000, 400000, 300000, 40001})}),
	}
	glog.Infof("Advertising route: '%s/%s via %s' to peers", subnet, strconv.Itoa(cidrLen), nrc.nodeIP.String())
	if _, err := nrc.bgpServer.AddPath("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(uint8(cidrLen),
		subnet), false, attrs, time.Now(), false)}); err != nil {
		return fmt.Errorf(err.Error())
	}
	return nil
}

func (nrc *NetworkRoutingController) AdvertiseClusterIp(clusterIp string) error {

	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop(nrc.nodeIP.String()),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{4000, 400000, 300000, 40001})}),
	}
	glog.Infof("Advertising route: '%s/%s via %s' to peers", clusterIp, strconv.Itoa(32), nrc.nodeIP.String())
	if _, err := nrc.bgpServer.AddPath("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(uint8(32),
		clusterIp), false, attrs, time.Now(), false)}); err != nil {
		return fmt.Errorf(err.Error())
	}
	return nil
}

func (nrc *NetworkRoutingController) injectRoute(path *table.Path) error {
	nexthop := path.GetNexthop()
	nlri := path.GetNlri()
	dst, _ := netlink.ParseIPNet(nlri.String())
	route := &netlink.Route{
		Dst:      dst,
		Gw:       nexthop,
		Protocol: 0x11,
	}

	glog.Infof("Inject route: '%s via %s' from peer to routing table", dst, nexthop)
	return netlink.RouteReplace(route)
}

func (nrc *NetworkRoutingController) Cleanup() {

}

func NewNetworkRoutingController(clientset *kubernetes.Clientset, kubeRouterConfig *options.KubeRouterConfig) (*NetworkRoutingController, error) {

	nrc := NetworkRoutingController{}

	nrc.syncPeriod = kubeRouterConfig.RoutesSyncPeriod
	nrc.clientset = clientset

	if len(kubeRouterConfig.ClusterAsn) != 0 {
		asn, err := strconv.ParseUint(kubeRouterConfig.ClusterAsn, 0, 32)
		if err != nil {
			panic("Invalid cluster ASN: " + err.Error())
		}
		if asn > 65534 || asn < 64512 {
			panic("Invalid ASN number for cluster ASN")
		}
		nrc.asnNumber = uint32(asn)
	} else {
		nrc.asnNumber = 64512 // this magic number is first of the private ASN range, use it as default
	}

	nrc.advertiseClusterIp = kubeRouterConfig.AdvertiseClusterIp

	if len(kubeRouterConfig.PeerRouter) != 0 {
		if net.ParseIP(kubeRouterConfig.PeerRouter) == nil {
			panic("Invalid peer router ip: " + nrc.peerRouter)
		}

		nrc.peerRouter = kubeRouterConfig.PeerRouter

		if len(kubeRouterConfig.PeerAsn) == 0 {
			panic("ASN number for peer router must be specified")
		}
		asn, err := strconv.ParseUint(kubeRouterConfig.PeerAsn, 0, 32)
		if err != nil {
			panic("Invalid BGP peer ASN: " + err.Error())
		}
		if asn > 65534 {
			panic("Invalid ASN number for cluster ASN")
		}
		nrc.peerAsnNumber = uint32(asn)
	}

	nodeHostName, err := os.Hostname()
	if err != nil {
		panic(err.Error())
	}
	nodeFqdnHostName := utils.GetFqdn()

	node, err := clientset.Core().Nodes().Get(nodeHostName, metav1.GetOptions{})
	if err != nil {
		node, err = clientset.Core().Nodes().Get(nodeFqdnHostName, metav1.GetOptions{})
		if err != nil {
			panic(err.Error())
		}
		nrc.nodeHostName = nodeFqdnHostName
	} else {
		nrc.nodeHostName = nodeHostName
	}

	nodeIP, err := getNodeIP(node)
	if err != nil {
		panic(err.Error())
	}
	nrc.nodeIP = nodeIP

	nrc.bgpServer = gobgp.NewBgpServer()
	go nrc.bgpServer.Serve()

	g := bgpapi.NewGrpcServer(nrc.bgpServer, ":50051")
	go g.Serve()

	global := &config.Global{
		Config: config.GlobalConfig{
			As:       nrc.asnNumber,
			RouterId: nrc.nodeIP.String(),
		},
	}

	if err := nrc.bgpServer.Start(global); err != nil {
		panic(err)
	}

	go nrc.watchBgpUpdates()

	return &nrc, nil
}
