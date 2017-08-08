package controllers

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/cloudnativelabs/kube-router/app/options"
	"github.com/cloudnativelabs/kube-router/app/watchers"
	"github.com/cloudnativelabs/kube-router/utils"
	"github.com/coreos/go-iptables/iptables"
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
	nodeIP               net.IP
	nodeHostName         string
	nodeSubnet           net.IPNet
	nodeInterface        string
	mu                   sync.Mutex
	clientset            *kubernetes.Clientset
	bgpServer            *gobgp.BgpServer
	syncPeriod           time.Duration
	enablePodEgress      bool
	hostnameOverride     string
	advertiseClusterIp   bool
	defaultNodeAsnNumber uint32
	nodeAsnNumber        uint32
	globalPeerRouters    []string
	nodePeerRouters      []string
	globalPeerAsnNumber  uint32
	bgpFullMeshMode      bool
}

var (
	activeNodes = make(map[string]bool)
)

const (
	clustetNieghboursSet = "clusterneighboursset"
)

func (nrc *NetworkRoutingController) Run(stopCh <-chan struct{}, wg *sync.WaitGroup) {

	cidr, err := utils.GetPodCidrFromCniSpec("/etc/cni/net.d/10-kuberouter.conf")
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
		glog.Infof("cidr.IP not found, or oldCidr/currentCidr don't match.")
		glog.Infof("cidr.IP is %s\noldCidr is %s\ncurrentCidr is %s\n", cidr.IP.String(), oldCidr, currentCidr)
		err = utils.InsertPodCidrInCniSpec("/etc/cni/net.d/10-kuberouter.conf", currentCidr)
		if err != nil {
			glog.Errorf("Failed to insert pod CIDR into CNI conf file: %s", err.Error())
		}
	}

	// In case of cluster provisioned on AWS disable source-destination check
	nrc.disableSourceDestinationCheck()

	t := time.NewTicker(nrc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	glog.Infof("Starting network route controller")

	// Handle Pod egress masquerading configuration
	args := []string{"-s", currentCidr, "!", "-d", currentCidr, "-j", "MASQUERADE"}
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		glog.Errorf("Failed create iptables handler due to %s.", err.Error())
	}
	if nrc.enablePodEgress {
		err = iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", args...)
		if err != nil {
			glog.Errorf("Failed to add iptable rule to masqurade outbound traffic from pods due to %s. External connectivity will not work.", err.Error())
		}
		glog.Infof("Added iptables rule to masqurade outbound traffic from pods.")
	} else {
		exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", args...)
		if err != nil {
			glog.Errorf("Failed to lookup iptable rule to masqurade outbound traffic from pods due to %s.", err.Error())
		}
		if exists {
			err = iptablesCmdHandler.Delete("nat", "POSTROUTING", args...)
			if err != nil {
				glog.Errorf("Failed to delete iptable rule to masqurade outbound traffic from pods due to %s. Pod egress might still work...", err.Error())
			}
			glog.Infof("Deleted iptables rule to masqurade outbound traffic from pods.")
		}
	}

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

	// loop forever till notified to stop on stopCh
	for {
		select {
		case <-stopCh:
			glog.Infof("Shutting down network routes controller")
			return
		default:
		}

		// add the current set of nodes (excluding self) as BGP peers. Nodes form full mesh
		nrc.syncPeers()

		// advertise cluster IP for the service to be reachable via host
		if nrc.advertiseClusterIp {
			glog.Infof("Advertising cluster ips")
			for _, svc := range watchers.ServiceWatcher.List() {
				if svc.Spec.Type == "ClusterIP" || svc.Spec.Type == "NodePort" || svc.Spec.Type == "LoadBalancer" {

					// skip headless services
					if svc.Spec.ClusterIP == "None" || svc.Spec.ClusterIP == "" {
						continue
					}

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

		err = nrc.addExportPolicies()
		if err != nil {
			glog.Errorf("Failed to add BGP export policies due to %s", err.Error())
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

	cidr, err := utils.GetPodCidrFromNodeSpec(nrc.clientset, nrc.hostnameOverride)
	if err != nil {
		return err
	}

	cidrStr := strings.Split(cidr, "/")
	subnet := cidrStr[0]
	cidrLen, err := strconv.Atoi(cidrStr[1])
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop(nrc.nodeIP.String()),
	}
	glog.Infof("Advertising route: '%s/%s via %s' to peers", subnet, strconv.Itoa(cidrLen), nrc.nodeIP.String())
	if _, err := nrc.bgpServer.AddPath("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(uint8(cidrLen),
		subnet), false, attrs, time.Now(), false)}); err != nil {
		return fmt.Errorf(err.Error())
	}
	return nil
}

func (nrc *NetworkRoutingController) getClusterIps() ([]string, error) {
	clusterIpList := make([]string, 0)
	for _, svc := range watchers.ServiceWatcher.List() {
		if svc.Spec.Type == "ClusterIP" || svc.Spec.Type == "NodePort" || svc.Spec.Type == "LoadBalancer" {

			// skip headless services
			if svc.Spec.ClusterIP == "None" || svc.Spec.ClusterIP == "" {
				continue
			}
			clusterIpList = append(clusterIpList, svc.Spec.ClusterIP)
		}
	}
	return clusterIpList, nil
}

func (nrc *NetworkRoutingController) AdvertiseClusterIp(clusterIp string) error {

	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeNextHop(nrc.nodeIP.String()),
	}
	glog.Infof("Advertising route: '%s/%s via %s' to peers", clusterIp, strconv.Itoa(32), nrc.nodeIP.String())
	if _, err := nrc.bgpServer.AddPath("", []*table.Path{table.NewPath(nil, bgp.NewIPAddrPrefix(uint8(32),
		clusterIp), false, attrs, time.Now(), false)}); err != nil {
		return fmt.Errorf(err.Error())
	}
	return nil
}

// Each node advertises its pod CIDR to the nodes with same ASN (iBGP peers) and to the global BGP peer
// or per node BGP peer. Each node ends up advertising not only pod CIDR assigned to the self but other
// routers learned to the node pod CIDR's as well to global BGP peer or per node BGP peers. external BGP
// peer will randomly (since all path have equal selection atributes) select the routes from multiple
// routes to a pod CIDR which will result in extra hop. To prevent this behaviour this methods add
// defult export policy to reject. and explicit policy is added so that each node only advertised the
// pod CIDR assigned to it. Additionally export policy is added so that a node advertises cluster IP's
// only to the external BGP peers.
func (nrc *NetworkRoutingController) addExportPolicies() error {

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

	// creates prefix set to represent all the cluster IP associated with the services
	clusterIpPrefixList := make([]config.Prefix, 0)
	clusterIps, _ := nrc.getClusterIps()
	for _, ip := range clusterIps {
		clusterIpPrefixList = append(clusterIpPrefixList, config.Prefix{IpPrefix: ip + "/32"})
	}
	clusterIpPrefixSet, err := table.NewPrefixSet(config.PrefixSet{
		PrefixSetName: "clusteripprefixset",
		PrefixList:    clusterIpPrefixList,
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
		externalBgpPeers = append(externalBgpPeers, nrc.globalPeerRouters...)
	}
	if len(nrc.nodePeerRouters) != 0 {
		externalBgpPeers = append(externalBgpPeers, nrc.nodePeerRouters...)
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
		return err
	}
	if err = nrc.bgpServer.AddPolicy(policy, false); err != nil {
		return err
	}
	err = nrc.bgpServer.AddPolicyAssignment("",
		table.POLICY_DIRECTION_EXPORT,
		[]*config.PolicyDefinition{&definition},
		table.ROUTE_TYPE_ACCEPT)
	if err != nil {
		return err
	}

	// configure default BGP export policy to reject
	pd := make([]*config.PolicyDefinition, 0)
	pd = append(pd, &definition)
	nrc.bgpServer.ReplacePolicyAssignment("", table.POLICY_DIRECTION_EXPORT, pd, table.ROUTE_TYPE_REJECT)

	return nil
}

func (nrc *NetworkRoutingController) injectRoute(path *table.Path) error {
	nexthop := path.GetNexthop()
	nlri := path.GetNlri()
	dst, _ := netlink.ParseIPNet(nlri.String())
	var route *netlink.Route

	// check if the neighbour is in same subnet
	if !nrc.nodeSubnet.Contains(nexthop) {
		tunnelName := "tun-" + strings.Replace(nexthop.String(), ".", "", -1)
		glog.Infof("Found node: " + nexthop.String() + " to be in different subnet.")
		var link netlink.Link
		var err error
		link, err = netlink.LinkByName(tunnelName)
		if err != nil {
			glog.Infof("Found node: " + nexthop.String() + " to be in different subnet. Creating tunnel: " + tunnelName)
			cmd := exec.Command("ip", "tunnel", "add", tunnelName, "mode", "ipip", "local", nrc.nodeIP.String(),
				"remote", nexthop.String(), "dev", nrc.nodeInterface)
			err = cmd.Run()
			if err != nil {
				return errors.New("Route not injected for the route advertised by the node " + nexthop.String() +
					". Failed to create tunnel interface " + tunnelName)
			}
			link, err = netlink.LinkByName(tunnelName)
			if err != nil {
				return errors.New("Route not injected for the route advertised by the node " + nexthop.String() +
					". Failed to create tunnel interface " + tunnelName)
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
		glog.Infof("Removing route: '%s via %s' from peer in the routing table", dst, nexthop)
		return netlink.RouteDel(route)
	}
	glog.Infof("Inject route: '%s via %s' from peer to routing table", dst, nexthop)
	return netlink.RouteReplace(route)
}

func (nrc *NetworkRoutingController) Cleanup() {
}

func (nrc *NetworkRoutingController) disableSourceDestinationCheck() {

	nodes, err := nrc.clientset.Core().Nodes().List(metav1.ListOptions{})
	if err != nil {
		glog.Errorf("Failed to list nodes from API server due to: %s. Can not perform BGP peer sync", err.Error())
		return
	}

	for _, node := range nodes.Items {
		if node.Spec.ProviderID == "" || !strings.HasPrefix(node.Spec.ProviderID, "aws") {
			return
		}
		providerID := strings.Replace(node.Spec.ProviderID, "///", "//", 1)
		url, err := url.Parse(providerID)
		instanceID := url.Path
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
			glog.Errorf("Failed to disable source destination check due to: " + err.Error())
		} else {
			glog.Infof("Disabled source destination check for the instance: " + instanceID)
		}
	}
}

// Refresh the peer relationship rest of the nodes in the cluster. Node add/remove
// events should ensure peer relationship with only currently active nodes. In case
// we miss any events from API server this method which is called periodically
// ensure peer relationship with removed nodes is deleted.
func (nrc *NetworkRoutingController) syncPeers() {

	glog.Infof("Syncing BGP peers for the node.")

	// get the current list of the nodes from API server
	nodes, err := nrc.clientset.Core().Nodes().List(metav1.ListOptions{})
	if err != nil {
		glog.Errorf("Failed to list nodes from API server due to: %s. Can not perform BGP peer sync", err.Error())
		return
	}

	// establish peer with current set of nodes
	currentNodes := make([]string, 0)
	for _, node := range nodes.Items {
		nodeIP, _ := getNodeIP(&node)

		// skip self
		if nodeIP.String() == nrc.nodeIP.String() {
			continue
		}

		// if node full mesh is not requested then just peer with nodes with same ASN (run iBGP among same ASN peers)
		if !nrc.bgpFullMeshMode {
			// if the node is not annotated with ASN number or with invalid ASN skip peering
			nodeasn, ok := node.ObjectMeta.Annotations["net.kuberouter.nodeasn"]
			if !ok {
				glog.Infof("Not peering with the Node %s as ASN number of the node is unknown.", nodeIP.String())
				continue
			}

			asnNo, err := strconv.ParseUint(nodeasn, 0, 32)
			if err != nil {
				glog.Infof("Not peering with the Node %s as ASN number of the node is invalid.", nodeIP.String())
				continue
			}

			// if the nodes ASN number is different from ASN number of current node skipp peering
			if nrc.nodeAsnNumber != uint32(asnNo) {
				glog.Infof("Not peering with the Node %s as ASN number of the node is different.", nodeIP.String())
				continue
			}
		}

		currentNodes = append(currentNodes, nodeIP.String())
		activeNodes[nodeIP.String()] = true
		n := &config.Neighbor{
			Config: config.NeighborConfig{
				NeighborAddress: nodeIP.String(),
				PeerAs:          nrc.defaultNodeAsnNumber,
			},
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
	for ip := range activeNodes {
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

	// delete the neighbor for the node that is removed
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
		delete(activeNodes, ip)
	}
}

// Handle updates from Node watcher. Node watcher calls this method whenever there is
// new node is added or old node is deleted. So peer up with new node and drop peering
// from old node
func (nrc *NetworkRoutingController) OnNodeUpdate(nodeUpdate *watchers.NodeUpdate) {
	nrc.mu.Lock()
	defer nrc.mu.Unlock()

	node := nodeUpdate.Node
	nodeIP, _ := getNodeIP(node)
	if nodeUpdate.Op == watchers.ADD {
		glog.Infof("Received node %s added update from watch API so peer with new node", nodeIP)
		n := &config.Neighbor{
			Config: config.NeighborConfig{
				NeighborAddress: nodeIP.String(),
				PeerAs:          nrc.defaultNodeAsnNumber,
			},
		}
		if err := nrc.bgpServer.AddNeighbor(n); err != nil {
			glog.Errorf("Failed to add node %s as peer due to %s", nodeIP, err)
		}
		activeNodes[nodeIP.String()] = true
	} else if nodeUpdate.Op == watchers.REMOVE {
		glog.Infof("Received node %s removed update from watch API, so remove node from peer", nodeIP)
		n := &config.Neighbor{
			Config: config.NeighborConfig{
				NeighborAddress: nodeIP.String(),
				PeerAs:          nrc.defaultNodeAsnNumber,
			},
		}
		if err := nrc.bgpServer.DeleteNeighbor(n); err != nil {
			glog.Errorf("Failed to remove node %s as peer due to %s", nodeIP, err)
		}
		delete(activeNodes, nodeIP.String())
	}
	nrc.disableSourceDestinationCheck()
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
		nodeasn, ok := node.ObjectMeta.Annotations["net.kuberouter.nodeasn"]
		if !ok {
			return errors.New("Could not find ASN number for the node. Node need to be annotated with ASN number details to start BGP server.")
		} else {
			glog.Infof("Found ASN for the node to be %s from the node annotations", nodeasn)
			asnNo, err := strconv.ParseUint(nodeasn, 0, 32)
			if err != nil {
				return errors.New("Failed to parse ASN number specified for the the node")
			}
			nodeAsnNumber = uint32(asnNo)
		}
		nrc.nodeAsnNumber = nodeAsnNumber
	}

	nrc.bgpServer = gobgp.NewBgpServer()
	go nrc.bgpServer.Serve()

	g := bgpapi.NewGrpcServer(nrc.bgpServer, ":50051")
	go g.Serve()

	global := &config.Global{
		Config: config.GlobalConfig{
			As:       nodeAsnNumber,
			RouterId: nrc.nodeIP.String(),
		},
	}

	if err := nrc.bgpServer.Start(global); err != nil {
		return errors.New("Failed to start BGP server due to : " + err.Error())
	}

	go nrc.watchBgpUpdates()

	// if the global routing peer is configured then peer with it
	// else peer with node specific BGP peer
	if len(nrc.globalPeerRouters) != 0 && nrc.globalPeerAsnNumber != 0 {
		for _, peer := range nrc.globalPeerRouters {
			n := &config.Neighbor{
				Config: config.NeighborConfig{
					NeighborAddress: peer,
					PeerAs:          nrc.globalPeerAsnNumber,
				},
			}
			if err := nrc.bgpServer.AddNeighbor(n); err != nil {
				return errors.New("Failed to peer with global peer router \"" + peer + "\" due to: " + err.Error())
			}
		}
	} else {
		nodeBgpPeerAsn, ok := node.ObjectMeta.Annotations["net.kuberouter.node.bgppeer.asn"]
		if !ok {
			glog.Infof("Could not find BGP peer info for the node in the node annotations so skipping configuring peer.")
			return nil
		}
		asnNo, err := strconv.ParseUint(nodeBgpPeerAsn, 0, 32)
		if err != nil {
			return errors.New("Failed to parse ASN number specified for the the node in the annotations")
		}
		peerAsnNo := uint32(asnNo)

		nodeBgpPeersAnnotation, ok := node.ObjectMeta.Annotations["net.kuberouter.node.bgppeer.address"]
		if !ok {
			glog.Infof("Could not find BGP peer info for the node in the node annotations so skipping configuring peer.")
			return nil
		}
		nodePeerRouters := make([]string, 0)
		if strings.Contains(nodeBgpPeersAnnotation, ",") {
			ips := strings.Split(nodeBgpPeersAnnotation, ",")
			for _, ip := range ips {
				if net.ParseIP(ip) == nil {
					return errors.New("Invalid node BGP peer router ip in the annotation: " + ip)
				}
			}
			nodePeerRouters = append(nodePeerRouters, ips...)
		} else {
			if net.ParseIP(nodeBgpPeersAnnotation) == nil {
				return errors.New("Invalid node BGP peer router ip: " + nodeBgpPeersAnnotation)
			}
			nodePeerRouters = append(nodePeerRouters, nodeBgpPeersAnnotation)
		}
		for _, peer := range nodePeerRouters {
			glog.Infof("Node is configured to peer with %s in ASN %v from the node annotations", peer, peerAsnNo)
			n := &config.Neighbor{
				Config: config.NeighborConfig{
					NeighborAddress: peer,
					PeerAs:          peerAsnNo,
				},
			}
			if err := nrc.bgpServer.AddNeighbor(n); err != nil {
				return errors.New("Failed to peer with node specific BGP peer router: " + peer + " due to " + err.Error())
			}
		}

		nrc.nodePeerRouters = nodePeerRouters
		glog.Infof("Successfully configured  %s in ASN %v as BGP peer to the node", nodeBgpPeersAnnotation, peerAsnNo)
	}

	return nil
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

func NewNetworkRoutingController(clientset *kubernetes.Clientset, kubeRouterConfig *options.KubeRouterConfig) (*NetworkRoutingController, error) {

	nrc := NetworkRoutingController{}

	nrc.bgpFullMeshMode = kubeRouterConfig.FullMeshMode
	nrc.enablePodEgress = kubeRouterConfig.EnablePodEgress
	nrc.syncPeriod = kubeRouterConfig.RoutesSyncPeriod
	nrc.clientset = clientset

	if len(kubeRouterConfig.ClusterAsn) != 0 {
		asn, err := strconv.ParseUint(kubeRouterConfig.ClusterAsn, 0, 32)
		if err != nil {
			return nil, errors.New("Invalid cluster ASN: " + err.Error())
		}
		if asn > 65534 || asn < 64512 {
			return nil, errors.New("Invalid ASN number for cluster ASN")
		}
		nrc.defaultNodeAsnNumber = uint32(asn)
	} else {
		nrc.defaultNodeAsnNumber = 64512 // this magic number is first of the private ASN range, use it as default
	}

	nrc.advertiseClusterIp = kubeRouterConfig.AdvertiseClusterIp

	if (len(kubeRouterConfig.PeerRouter) != 0 && len(kubeRouterConfig.PeerAsn) == 0) ||
		(len(kubeRouterConfig.PeerRouter) == 0 && len(kubeRouterConfig.PeerAsn) != 0) {
		return nil, errors.New("Either both or none of the params --peer-asn, --peer-router must be specified")
	}

	if len(kubeRouterConfig.PeerRouter) != 0 && len(kubeRouterConfig.PeerAsn) != 0 {

		if strings.Contains(kubeRouterConfig.PeerRouter, ",") {
			ips := strings.Split(kubeRouterConfig.PeerRouter, ",")
			for _, ip := range ips {
				if net.ParseIP(ip) == nil {
					return nil, errors.New("Invalid global BGP peer router ip: " + kubeRouterConfig.PeerRouter)
				}
			}
			nrc.globalPeerRouters = append(nrc.globalPeerRouters, ips...)

		} else {
			if net.ParseIP(kubeRouterConfig.PeerRouter) == nil {
				return nil, errors.New("Invalid global BGP peer router ip: " + kubeRouterConfig.PeerRouter)
			}
			nrc.globalPeerRouters = append(nrc.globalPeerRouters, kubeRouterConfig.PeerRouter)
		}

		asn, err := strconv.ParseUint(kubeRouterConfig.PeerAsn, 0, 32)
		if err != nil {
			return nil, errors.New("Invalid global BGP peer ASN: " + err.Error())
		}
		if asn > 65534 {
			return nil, errors.New("Invalid ASN number for global BGP peer")
		}
		nrc.globalPeerAsnNumber = uint32(asn)
	}

	nrc.hostnameOverride = kubeRouterConfig.HostnameOverride
	node, err := utils.GetNodeObject(clientset, nrc.hostnameOverride)
	if err != nil {
		return nil, errors.New("Failed getting node object from API server: " + err.Error())
	}

	nrc.nodeHostName = node.Name

	nodeIP, err := getNodeIP(node)
	if err != nil {
		return nil, errors.New("Failed getting IP address from node object: " + err.Error())
	}
	nrc.nodeIP = nodeIP

	nrc.nodeSubnet, nrc.nodeInterface, err = getNodeSubnet(nodeIP)
	if err != nil {
		return nil, errors.New("Failed find the subnet of the node IP and interface on" +
			"which its configured: " + err.Error())
	}

	watchers.NodeWatcher.RegisterHandler(&nrc)

	return &nrc, nil
}
