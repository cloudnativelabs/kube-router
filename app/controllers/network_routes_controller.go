package controllers

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/app/options"
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
	nodeIP       net.IP
	nodeHostName string
	mu           sync.Mutex
	clientset    *kubernetes.Clientset
	bgpServer    *gobgp.BgpServer
	cniConfFile  string
	syncPeriod   time.Duration
}

func (nrc *NetworkRoutingController) Run(stopCh <-chan struct{}, wg *sync.WaitGroup) {

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
				PeerAs:          65000,
			},
		}
		if err := nrc.bgpServer.AddNeighbor(n); err != nil {
			panic(err)
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

	subnet, cidrlen, err := utils.GetPodCidrDetails(nrc.cniConfFile)
	if err != nil {
		return err
	}
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop(nrc.nodeIP.String()),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{4000, 400000, 300000, 40001})}),
	}
	glog.Infof("Advertising route: '%s/%s via %s' to peers", subnet, strconv.Itoa(cidrlen), nrc.nodeIP.String())
	if _, err := nrc.bgpServer.AddPath("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(uint8(cidrlen),
		subnet), false, attrs, time.Now(), false)}); err != nil {
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
	nrc.cniConfFile = kubeRouterConfig.CniConfFile

	if kubeRouterConfig.CniConfFile == "" {
		panic("Please specify a valid CNF conf file path in the command line parameter --cni-conf-file ")
	}

	if _, err := os.Stat(nrc.cniConfFile); os.IsNotExist(err) {
		panic("Specified CNI conf file does not exist. Conf file: " + nrc.cniConfFile)
	}
	_, _, err := utils.GetPodCidrDetails(nrc.cniConfFile)
	if err != nil {
		panic("Failed to read IPAM conf from the CNI conf file: " + nrc.cniConfFile + " due to " + err.Error())
	}

	nodeHostName, err := os.Hostname()
	if err != nil {
		panic(err.Error())
	}
	nrc.nodeHostName = nodeHostName

	node, err := clientset.Core().Nodes().Get(nodeHostName, metav1.GetOptions{})
	if err != nil {
		panic(err.Error())
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
			As:       65000,
			RouterId: nrc.nodeIP.String(),
		},
	}

	if err := nrc.bgpServer.Start(global); err != nil {
		panic(err)
	}

	go nrc.watchBgpUpdates()

	return &nrc, nil
}
