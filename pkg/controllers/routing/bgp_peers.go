package routing

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/golang/glog"
	"github.com/osrg/gobgp/config"
	gobgp "github.com/osrg/gobgp/server"
	v1core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
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
		metrics.ControllerBGPInternalPeersSyncTime.WithLabelValues().Set(float64(endTime))
		glog.V(2).Infof("Syncing BGP peers for the node took %v", endTime)
	}()

	// get the current list of the nodes from API server
	nodes, err := nrc.clientset.CoreV1().Nodes().List(metav1.ListOptions{})
	if err != nil {
		glog.Errorf("Failed to list nodes from API server due to: %s. Can not perform BGP peer sync", err.Error())
		return
	}

	metrics.ControllerBPGpeers.WithLabelValues().Set(float64(len(nodes.Items)))
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
						RouteReflectorClusterId: config.RrClusterIdType(nrc.bgpClusterID),
					},
					State: config.RouteReflectorState{
						RouteReflectorClient:    true,
						RouteReflectorClusterId: config.RrClusterIdType(nrc.bgpClusterID),
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

// connectToExternalBGPPeers adds all the configured eBGP peers (global or node specific) as neighbours
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

func (nrc *NetworkRoutingController) newNodeEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*v1core.Node)
			nodeIP, _ := utils.GetNodeIP(node)

			glog.V(2).Infof("Received node %s added update from watch API so peer with new node", nodeIP)
			nrc.OnNodeUpdate(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			// we are interested only node add/delete, so skip update
			return

		},
		DeleteFunc: func(obj interface{}) {
			node := obj.(*v1core.Node)
			nodeIP, _ := utils.GetNodeIP(node)

			glog.Infof("Received node %s removed update from watch API, so remove node from peer", nodeIP)
			nrc.OnNodeUpdate(obj)
		},
	}
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
