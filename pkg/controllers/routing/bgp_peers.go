package routing

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/bgp"
	"github.com/cloudnativelabs/kube-router/v2/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	gobgpapi "github.com/osrg/gobgp/v3/api"
	gobgp "github.com/osrg/gobgp/v3/pkg/server"
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
		targetNode, err := utils.NewRemoteKRNode(node)
		if err != nil {
			klog.Errorf("failed to create KRNode from node object: %v", err)
			continue
		}

		// skip self
		if targetNode.GetPrimaryNodeIP().Equal(nrc.krNode.GetPrimaryNodeIP()) {
			continue
		}

		// we are rr-client peer only with rr-server
		if nrc.bgpRRClient {
			if _, ok := node.Annotations[rrServerAnnotation]; !ok {
				continue
			}
		}

		// if node full mesh is not requested then just peer with nodes with same ASN
		// (run iBGP among same ASN peers)
		if !nrc.bgpFullMeshMode {
			nodeasn, ok := node.Annotations[nodeASNAnnotation]
			if !ok {
				klog.Infof("Not peering with the Node %s as ASN number of the node is unknown.",
					targetNode.GetPrimaryNodeIP().String())
				continue
			}

			asnNo, err := strconv.ParseUint(nodeasn, 0, asnMaxBitSize)
			if err != nil {
				klog.Infof("Not peering with the Node %s as ASN number of the node is invalid.",
					targetNode.GetPrimaryNodeIP().String())
				continue
			}

			// if the nodes ASN number is different from ASN number of current node skip peering
			if nrc.nodeAsnNumber != uint32(asnNo) {
				klog.Infof("Not peering with the Node %s as ASN number of the node is different.",
					targetNode.GetPrimaryNodeIP().String())
				continue
			}
		}

		targetNodeIsIPv4 := targetNode.GetPrimaryNodeIP().To4() != nil
		sourceNodeIsIPv4 := nrc.krNode.GetPrimaryNodeIP().To4() != nil

		if targetNodeIsIPv4 != sourceNodeIsIPv4 {
			klog.Warningf(
				"Not peering with Node %s as it's primary IP (%s) uses a different protocol than "+
					"our primary IP (%s)",
				node.Name,
				targetNode.GetPrimaryNodeIP(),
				nrc.krNode.GetPrimaryNodeIP(),
			)
			continue
		}

		currentNodes = append(currentNodes, targetNode.GetPrimaryNodeIP().String())
		nrc.activeNodes[targetNode.GetPrimaryNodeIP().String()] = true
		// explicitly set neighbors.transport.config.local-address with primaryIP which is configured
		// as their neighbor address at the remote peers.
		// this prevents the controller from initiating connection to its peers with a different IP address
		// when multiple L3 interfaces are active.
		n := &gobgpapi.Peer{
			Conf: &gobgpapi.PeerConf{
				NeighborAddress: targetNode.GetPrimaryNodeIP().String(),
				PeerAsn:         nrc.nodeAsnNumber,
			},
			Transport: &gobgpapi.Transport{
				LocalAddress: nrc.krNode.GetPrimaryNodeIP().String(),
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

			// We choose to only peer using the protocol of the node's primary IP
			if targetNode.IsIPv4Capable() {
				afiSafi := gobgpapi.AfiSafi{
					Config: &gobgpapi.AfiSafiConfig{
						Family: &gobgpapi.Family{
							Afi:  gobgpapi.Family_AFI_IP,
							Safi: gobgpapi.Family_SAFI_UNICAST,
						},
						Enabled: true,
					},
					MpGracefulRestart: &gobgpapi.MpGracefulRestart{
						Config: &gobgpapi.MpGracefulRestartConfig{
							Enabled: true,
						},
						State: &gobgpapi.MpGracefulRestartState{},
					},
				}
				n.AfiSafis = append(n.AfiSafis, &afiSafi)
			}
			if targetNode.IsIPv6Capable() {
				afiSafi := gobgpapi.AfiSafi{
					Config: &gobgpapi.AfiSafiConfig{
						Family: &gobgpapi.Family{
							Afi:  gobgpapi.Family_AFI_IP6,
							Safi: gobgpapi.Family_SAFI_UNICAST,
						},
						Enabled: true,
					},
					MpGracefulRestart: &gobgpapi.MpGracefulRestart{
						Config: &gobgpapi.MpGracefulRestartConfig{
							Enabled: true,
						},
						State: &gobgpapi.MpGracefulRestartState{},
					},
				}
				n.AfiSafis = append(n.AfiSafis, &afiSafi)
			}
		}

		// we are rr-server peer with other rr-client with reflection enabled
		if nrc.bgpRRServer {
			if _, ok := node.Annotations[rrClientAnnotation]; ok {
				// add rr options with clusterId
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
				klog.Errorf(
					"Failed to add node %s as peer due to %s",
					targetNode.GetPrimaryNodeIP(),
					err,
				)
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
func (nrc *NetworkRoutingController) connectToExternalBGPPeers(
	server *gobgp.BgpServer,
	peerNeighbors []*gobgpapi.Peer,
	bgpGracefulRestart bool,
	bgpGracefulRestartDeferralTime time.Duration,
	bgpGracefulRestartTime time.Duration,
	peerMultihopTTL uint8,
) error {
	for _, n := range peerNeighbors {
		neighborIPStr := n.Conf.NeighborAddress
		neighborIP := net.ParseIP(neighborIPStr)
		if neighborIP == nil {
			klog.Errorf("unable to parse CIDR of global peer (%s), not peering with this peer",
				neighborIPStr)
			continue
		}
		peeringAddressForNeighbor := net.ParseIP(n.Transport.LocalAddress)
		if peeringAddressForNeighbor == nil {
			klog.Errorf(
				"unable to parse our local address for peer (%s), not peering with this peer (%s)",
				n.Transport.LocalAddress,
				neighborIPStr,
			)
		}

		neighborIsIPv4 := neighborIP.To4() != nil
		peeringAddressIsIPv4 := peeringAddressForNeighbor.To4() != nil
		if neighborIsIPv4 != peeringAddressIsIPv4 {
			klog.Warningf(
				"Not peering with configured peer as it's primary IP (%s) uses a different "+
					"protocol than our configured local-address (%s). Its possible that this can be resolved by setting "+
					"the local address appropriately",
				neighborIP,
				peeringAddressForNeighbor,
			)
			continue
		}

		if bgpGracefulRestart {
			n.GracefulRestart = &gobgpapi.GracefulRestart{
				Enabled:         true,
				RestartTime:     uint32(bgpGracefulRestartTime.Seconds()),
				DeferralTime:    uint32(bgpGracefulRestartDeferralTime.Seconds()),
				LocalRestarting: true,
			}

			if nrc.krNode.IsIPv4Capable() {
				n.AfiSafis = []*gobgpapi.AfiSafi{
					{
						Config: &gobgpapi.AfiSafiConfig{
							Family: &gobgpapi.Family{
								Afi:  gobgpapi.Family_AFI_IP,
								Safi: gobgpapi.Family_SAFI_UNICAST,
							},
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
			if nrc.krNode.IsIPv6Capable() {
				afiSafi := gobgpapi.AfiSafi{
					Config: &gobgpapi.AfiSafiConfig{
						Family: &gobgpapi.Family{
							Afi:  gobgpapi.Family_AFI_IP6,
							Safi: gobgpapi.Family_SAFI_UNICAST,
						},
						Enabled: true,
					},
					MpGracefulRestart: &gobgpapi.MpGracefulRestart{
						Config: &gobgpapi.MpGracefulRestartConfig{
							Enabled: true,
						},
					},
				}
				n.AfiSafis = append(n.AfiSafis, &afiSafi)
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
			n.Conf.NeighborAddress, n.Conf.PeerAsn)
	}
	return nil
}

// Does validation and returns neighbor configs
func newGlobalPeers(
	peerConfigs bgp.PeerConfigs,
	holdtime float64,
	localAddress string,
) []*gobgpapi.Peer {
	peers := make([]*gobgpapi.Peer, 0)

	ips := peerConfigs.RemoteIPs()
	asns := peerConfigs.RemoteASNs()
	passwords := peerConfigs.Passwords()
	ports := peerConfigs.Ports()
	localips := peerConfigs.LocalIPs()

	for i := 0; i < len(ips); i++ {
		// explicitly set neighbors.transport.config.local-address with primaryIP which is configured
		// as their neighbor address at the remote peers.
		// this prevents the controller from initiating connection to its peers with a different IP address
		// when multiple L3 interfaces are active.
		peer := &gobgpapi.Peer{
			Conf: &gobgpapi.PeerConf{
				NeighborAddress: ips[i].String(),
				PeerAsn:         asns[i],
			},
			Timers: &gobgpapi.Timers{Config: &gobgpapi.TimersConfig{HoldTime: uint64(holdtime)}},
			Transport: &gobgpapi.Transport{
				// localAddress defaults to the node's primary IP, but can be overridden below on a peer-by-peer basis
				// below via the kube-router.io/peer.localips annotation
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

		// if localip is set and is non-blank for BGP configuration override primaryIP choice set for peer above
		if len(localips) != 0 && localips[i] != "" {
			peer.Transport.LocalAddress = localips[i]
		}

		peers = append(peers, peer)
	}

	return peers
}

func (nrc *NetworkRoutingController) newNodeEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*v1core.Node)
			targetNode, err := utils.NewRemoteKRNode(node)
			if err != nil {
				klog.Errorf("failed to create KRNode from node object: %v", err)
				return
			}

			klog.V(2).Infof("Received node %s added update from watch API so peer with new node",
				targetNode.GetPrimaryNodeIP())
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
			targetNode, err := utils.NewRemoteKRNode(node)
			// In this case even if we can't get the NodeIP that's alright as the node is being removed anyway and
			// future node lister operations that happen in OnNodeUpdate won't be affected as the node won't be returned
			if err == nil && targetNode != nil {
				klog.Infof(
					"Received node %s removed update from watch API, so remove node from peer",
					targetNode.GetPrimaryNodeIP(),
				)
			} else {
				klog.Infof("Received node (IP unavailable) removed update from watch API, so remove node " +
					"from peer")
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
