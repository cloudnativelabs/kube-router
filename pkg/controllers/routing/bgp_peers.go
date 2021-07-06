package routing

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	gobgpapi "github.com/osrg/gobgp/api"
	gobgp "github.com/osrg/gobgp/pkg/server"
	v1core "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// Refresh the peer relationship with rest of the nodes in the cluster (iBGP peers). Node add/remove
// events should ensure peer relationship with only currently active nodes. In case
// we miss any events from API server this method which is called periodically
// ensures peer relationship with removed nodes is deleted.
func (nrc *NetworkRoutingController) syncInternalPeers() {
	nrc.mu.Lock()
	defer nrc.mu.Unlock()

	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		if nrc.MetricsEnabled {
			metrics.ControllerBGPInternalPeersSyncTime.Observe(endTime.Seconds())
		}
		klog.V(2).Infof("Syncing BGP peers for the node took %v", endTime)
	}()

	// get the current list of the nodes from API server
	nodes := nrc.nodeLister.List()

	if nrc.MetricsEnabled {
		metrics.ControllerBPGpeers.Set(float64(len(nodes)))
	}
	// establish peer and add Pod CIDRs with current set of nodes
	currentNodes := make([]string, 0)
	for _, obj := range nodes {
		node := obj.(*v1core.Node)
		nodeIP, err := utils.GetNodeIP(node)
		if err != nil {
			klog.Errorf("Failed to find a node IP and therefore cannot sync internal BGP Peer: %v", err)
			continue
		}

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
				klog.Infof("Not peering with the Node %s as ASN number of the node is unknown.",
					nodeIP.String())
				continue
			}

			asnNo, err := strconv.ParseUint(nodeasn, 0, 32)
			if err != nil {
				klog.Infof("Not peering with the Node %s as ASN number of the node is invalid.",
					nodeIP.String())
				continue
			}

			// if the nodes ASN number is different from ASN number of current node skip peering
			if nrc.nodeAsnNumber != uint32(asnNo) {
				klog.Infof("Not peering with the Node %s as ASN number of the node is different.",
					nodeIP.String())
				continue
			}
		}

		currentNodes = append(currentNodes, nodeIP.String())
		nrc.activeNodes[nodeIP.String()] = true
		// explicitly set neighbors.transport.config.local-address with nodeIP which is configured
		// as their neighbor address at the remote peers.
		// this prevents the controller from initiating connection to its peers with a different IP address
		// when multiple L3 interfaces are active.
		n := &gobgpapi.Peer{
			Conf: &gobgpapi.PeerConf{
				NeighborAddress: nodeIP.String(),
				PeerAs:          nrc.nodeAsnNumber,
			},
			Transport: &gobgpapi.Transport{
				LocalAddress: nrc.nodeIP.String(),
				RemotePort:   nrc.bgpPort,
			},
		}

		if nrc.bgpGracefulRestart {
			n.GracefulRestart = &gobgpapi.GracefulRestart{
				Enabled:         true,
				RestartTime:     uint32(nrc.bgpGracefulRestartTime.Seconds()),
				DeferralTime:    uint32(nrc.bgpGracefulRestartDeferralTime.Seconds()),
				LocalRestarting: true,
			}

			n.AfiSafis = []*gobgpapi.AfiSafi{
				{
					Config: &gobgpapi.AfiSafiConfig{
						Family:  &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP, Safi: gobgpapi.Family_SAFI_UNICAST},
						Enabled: true,
					},
					MpGracefulRestart: &gobgpapi.MpGracefulRestart{
						Config: &gobgpapi.MpGracefulRestartConfig{
							Enabled: true,
						},
						State: &gobgpapi.MpGracefulRestartState{},
					},
				},
				{
					Config: &gobgpapi.AfiSafiConfig{
						Family:  &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP6, Safi: gobgpapi.Family_SAFI_UNICAST},
						Enabled: true,
					},
					MpGracefulRestart: &gobgpapi.MpGracefulRestart{
						Config: &gobgpapi.MpGracefulRestartConfig{
							Enabled: true,
						},
						State: &gobgpapi.MpGracefulRestartState{},
					},
				},
			}
		}

		// we are rr-server peer with other rr-client with reflection enabled
		if nrc.bgpRRServer {
			if _, ok := node.ObjectMeta.Annotations[rrClientAnnotation]; ok {
				//add rr options with clusterId
				n.RouteReflector = &gobgpapi.RouteReflector{
					RouteReflectorClient:    true,
					RouteReflectorClusterId: fmt.Sprint(nrc.bgpClusterID),
				}
			}
		}

		// TODO: check if a node is already added as neighbor in a better way than add and catch error
		if err := nrc.bgpServer.AddPeer(context.Background(), &gobgpapi.AddPeerRequest{
			Peer: n,
		}); err != nil {
			if !strings.Contains(err.Error(), "can't overwrite the existing peer") {
				klog.Errorf("Failed to add node %s as peer due to %s", nodeIP.String(), err)
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
		if err := nrc.bgpServer.DeletePeer(context.Background(), &gobgpapi.DeletePeerRequest{Address: ip}); err != nil {
			klog.Errorf("Failed to remove node %s as peer due to %s", ip, err)
		}
		delete(nrc.activeNodes, ip)
	}
}

// connectToExternalBGPPeers adds all the configured eBGP peers (global or node specific) as neighbours
func connectToExternalBGPPeers(server *gobgp.BgpServer, peerNeighbors []*gobgpapi.Peer, bgpGracefulRestart bool, bgpGracefulRestartDeferralTime time.Duration,
	bgpGracefulRestartTime time.Duration, peerMultihopTTL uint8) error {
	for _, n := range peerNeighbors {

		if bgpGracefulRestart {
			n.GracefulRestart = &gobgpapi.GracefulRestart{
				Enabled:         true,
				RestartTime:     uint32(bgpGracefulRestartTime.Seconds()),
				DeferralTime:    uint32(bgpGracefulRestartDeferralTime.Seconds()),
				LocalRestarting: true,
			}

			n.AfiSafis = []*gobgpapi.AfiSafi{
				{
					Config: &gobgpapi.AfiSafiConfig{
						Family:  &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP, Safi: gobgpapi.Family_SAFI_UNICAST},
						Enabled: true,
					},
					MpGracefulRestart: &gobgpapi.MpGracefulRestart{
						Config: &gobgpapi.MpGracefulRestartConfig{
							Enabled: true,
						},
					},
				},
				{
					Config: &gobgpapi.AfiSafiConfig{
						Family:  &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP6, Safi: gobgpapi.Family_SAFI_UNICAST},
						Enabled: true,
					},
					MpGracefulRestart: &gobgpapi.MpGracefulRestart{
						Config: &gobgpapi.MpGracefulRestartConfig{
							Enabled: true,
						},
					},
				},
			}
		}
		if peerMultihopTTL > 1 {
			n.EbgpMultihop = &gobgpapi.EbgpMultihop{
				Enabled:     true,
				MultihopTtl: uint32(peerMultihopTTL),
			}
		}
		err := server.AddPeer(context.Background(), &gobgpapi.AddPeerRequest{Peer: n})
		if err != nil {
			return fmt.Errorf("error peering with peer router "+
				"%q due to: %s", n.Conf.NeighborAddress, err)
		}
		klog.V(2).Infof("Successfully configured %s in ASN %v as BGP peer to the node",
			n.Conf.NeighborAddress, n.Conf.PeerAs)
	}
	return nil
}

// Does validation and returns neighbor configs
func newGlobalPeers(ips []net.IP, ports []uint32, asns []uint32, passwords []string, holdtime float64, localAddress string) (
	[]*gobgpapi.Peer, error) {
	peers := make([]*gobgpapi.Peer, 0)

	// Validations
	if len(ips) != len(asns) {
		return nil, errors.New("invalid peer router config, the number of IPs and ASN numbers must be equal")
	}

	if len(ips) != len(passwords) && len(passwords) != 0 {
		return nil, errors.New("Invalid peer router config. " +
			"The number of passwords should either be zero, or one per peer router." +
			" Use blank items if a router doesn't expect a password.\n" +
			"Example: \"pass,,pass\" OR [\"pass\",\"\",\"pass\"].")
	}

	if len(ips) != len(ports) && len(ports) != 0 {
		return nil, errors.New("Invalid peer router config. " +
			"The number of ports should either be zero, or one per peer router." +
			" If blank items are used, it will default to standard BGP port, " +
			strconv.Itoa(options.DefaultBgpPort) + "\n" +
			"Example: \"port,,port\" OR [\"port\",\"\",\"port\"].")
	}

	for i := 0; i < len(ips); i++ {
		if !((asns[i] >= 1 && asns[i] <= 23455) ||
			(asns[i] >= 23457 && asns[i] <= 63999) ||
			(asns[i] >= 64512 && asns[i] <= 65534) ||
			(asns[i] >= 131072 && asns[i] <= 4199999999) ||
			(asns[i] >= 4200000000 && asns[i] <= 4294967294)) {
			return nil, fmt.Errorf("reserved ASN number \"%d\" for global BGP peer",
				asns[i])
		}

		// explicitly set neighbors.transport.config.local-address with nodeIP which is configured
		// as their neighbor address at the remote peers.
		// this prevents the controller from initiating connection to its peers with a different IP address
		// when multiple L3 interfaces are active.
		peer := &gobgpapi.Peer{
			Conf: &gobgpapi.PeerConf{
				NeighborAddress: ips[i].String(),
				PeerAs:          asns[i],
			},
			Timers: &gobgpapi.Timers{Config: &gobgpapi.TimersConfig{HoldTime: uint64(holdtime)}},
			Transport: &gobgpapi.Transport{
				LocalAddress: localAddress,
				RemotePort:   options.DefaultBgpPort,
			},
		}

		if len(ports) != 0 {
			peer.Transport.RemotePort = ports[i]
		}

		if len(passwords) != 0 {
			peer.Conf.AuthPassword = passwords[i]
		}

		peers = append(peers, peer)
	}

	return peers, nil
}

func (nrc *NetworkRoutingController) newNodeEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*v1core.Node)
			nodeIP, err := utils.GetNodeIP(node)
			if err != nil {
				klog.Errorf("New node received, but we were unable to add it as we were couldn't find it's node IP: %v", err)
				return
			}

			klog.V(2).Infof("Received node %s added update from watch API so peer with new node", nodeIP)
			nrc.OnNodeUpdate(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			// we are only interested in node add/delete, so skip update
		},
		DeleteFunc: func(obj interface{}) {
			node, ok := obj.(*v1core.Node)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					klog.Errorf("unexpected object type: %v", obj)
					return
				}
				if node, ok = tombstone.Obj.(*v1core.Node); !ok {
					klog.Errorf("unexpected object type: %v", obj)
					return
				}
			}
			nodeIP, err := utils.GetNodeIP(node)
			// In this case even if we can't get the NodeIP that's alright as the node is being removed anyway and
			// future node lister operations that happen in OnNodeUpdate won't be affected as the node won't be returned
			if err == nil {
				klog.Infof("Received node %s removed update from watch API, so remove node from peer", nodeIP)
			} else {
				klog.Infof("Received node (IP unavailable) removed update from watch API, so remove node from peer")
			}

			nrc.OnNodeUpdate(obj)
		},
	}
}

// OnNodeUpdate Handle updates from Node watcher. Node watcher calls this method whenever there is
// new node is added or old node is deleted. So peer up with new node and drop peering
// from old node
func (nrc *NetworkRoutingController) OnNodeUpdate(_ interface{}) {
	if !nrc.bgpServerStarted {
		return
	}

	// update export policies so that NeighborSet gets updated with new set of nodes
	err := nrc.AddPolicies()
	if err != nil {
		klog.Errorf("Error adding BGP policies: %s", err.Error())
	}

	if nrc.bgpEnableInternal {
		nrc.syncInternalPeers()
	}

	// skip if first round of disableSourceDestinationCheck() is not done yet, this is to prevent
	// all the nodes for all the node add update trying to perfrom disableSourceDestinationCheck
	if nrc.disableSrcDstCheck && nrc.initSrcDstCheckDone && nrc.ec2IamAuthorized {
		nrc.disableSourceDestinationCheck()
	}
}
