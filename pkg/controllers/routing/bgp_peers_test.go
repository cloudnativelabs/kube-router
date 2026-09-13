package routing

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	gobgpapi "github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	v1core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/klog/v2"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
)

// mockNode implements utils.NodeFamilyAware for testing purposes
type mockNode struct {
	ipv4Capable bool
	ipv6Capable bool
}

func (m *mockNode) IsIPv4Capable() bool {
	return m.ipv4Capable
}

func (m *mockNode) IsIPv6Capable() bool {
	return m.ipv6Capable
}

// Additional methods to satisfy broader interfaces if needed in future tests
func (m *mockNode) GetPrimaryNodeIP() net.IP {
	if m.ipv4Capable {
		return net.IPv4(10, 0, 0, 1)
	}
	if m.ipv6Capable {
		return net.ParseIP("2001:db8::1")
	}
	return nil
}

func (m *mockNode) FindBestIPv4NodeAddress() net.IP {
	if m.ipv4Capable {
		return net.IPv4(10, 0, 0, 1)
	}
	return nil
}

func (m *mockNode) FindBestIPv6NodeAddress() net.IP {
	if m.ipv6Capable {
		return net.ParseIP("2001:db8::1")
	}
	return nil
}

func (m *mockNode) GetNodeIPv4Addrs() []net.IP {
	if m.ipv4Capable {
		return []net.IP{net.IPv4(10, 0, 0, 1)}
	}
	return nil
}

func (m *mockNode) GetNodeIPv6Addrs() []net.IP {
	if m.ipv6Capable {
		return []net.IP{net.ParseIP("2001:db8::1")}
	}
	return nil
}

func (m *mockNode) GetNodeIPAddrs() []net.IP {
	var addrs []net.IP
	addrs = append(addrs, m.GetNodeIPv4Addrs()...)
	addrs = append(addrs, m.GetNodeIPv6Addrs()...)
	return addrs
}

func (m *mockNode) AddressesMatch(_ *v1core.Node) bool {
	return true
}

func TestConfigurePeerAfiSafis(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                    string
		node                    *mockNode
		gracefulRestartEnabled  bool
		expectedAfiSafiCount    int
		expectIPv4AfiSafi       bool
		expectIPv6AfiSafi       bool
		expectMpGracefulRestart bool
	}{
		{
			name: "IPv4 only node without graceful restart",
			node: &mockNode{
				ipv4Capable: true,
				ipv6Capable: false,
			},
			gracefulRestartEnabled:  false,
			expectedAfiSafiCount:    1,
			expectIPv4AfiSafi:       true,
			expectIPv6AfiSafi:       false,
			expectMpGracefulRestart: false,
		},
		{
			name: "IPv4 only node with graceful restart",
			node: &mockNode{
				ipv4Capable: true,
				ipv6Capable: false,
			},
			gracefulRestartEnabled:  true,
			expectedAfiSafiCount:    1,
			expectIPv4AfiSafi:       true,
			expectIPv6AfiSafi:       false,
			expectMpGracefulRestart: true,
		},
		{
			name: "IPv6 only node without graceful restart",
			node: &mockNode{
				ipv4Capable: false,
				ipv6Capable: true,
			},
			gracefulRestartEnabled:  false,
			expectedAfiSafiCount:    1,
			expectIPv4AfiSafi:       false,
			expectIPv6AfiSafi:       true,
			expectMpGracefulRestart: false,
		},
		{
			name: "IPv6 only node with graceful restart",
			node: &mockNode{
				ipv4Capable: false,
				ipv6Capable: true,
			},
			gracefulRestartEnabled:  true,
			expectedAfiSafiCount:    1,
			expectIPv4AfiSafi:       false,
			expectIPv6AfiSafi:       true,
			expectMpGracefulRestart: true,
		},
		{
			name: "dual-stack node without graceful restart",
			node: &mockNode{
				ipv4Capable: true,
				ipv6Capable: true,
			},
			gracefulRestartEnabled:  false,
			expectedAfiSafiCount:    2,
			expectIPv4AfiSafi:       true,
			expectIPv6AfiSafi:       true,
			expectMpGracefulRestart: false,
		},
		{
			name: "dual-stack node with graceful restart",
			node: &mockNode{
				ipv4Capable: true,
				ipv6Capable: true,
			},
			gracefulRestartEnabled:  true,
			expectedAfiSafiCount:    2,
			expectIPv4AfiSafi:       true,
			expectIPv6AfiSafi:       true,
			expectMpGracefulRestart: true,
		},
		{
			name: "node with no IP capabilities",
			node: &mockNode{
				ipv4Capable: false,
				ipv6Capable: false,
			},
			gracefulRestartEnabled:  false,
			expectedAfiSafiCount:    0,
			expectIPv4AfiSafi:       false,
			expectIPv6AfiSafi:       false,
			expectMpGracefulRestart: false,
		},
		{
			name: "node with no IP capabilities and graceful restart enabled",
			node: &mockNode{
				ipv4Capable: false,
				ipv6Capable: false,
			},
			gracefulRestartEnabled:  true,
			expectedAfiSafiCount:    0,
			expectIPv4AfiSafi:       false,
			expectIPv6AfiSafi:       false,
			expectMpGracefulRestart: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			peer := &gobgpapi.Peer{
				Conf: &gobgpapi.PeerConf{
					NeighborAddress: "192.168.1.1",
					PeerAsn:         65000,
				},
			}

			configurePeerAfiSafis(peer, tt.node, tt.gracefulRestartEnabled)

			// Verify the number of AFI-SAFIs
			assert.Equal(t, tt.expectedAfiSafiCount, len(peer.AfiSafis),
				"unexpected number of AFI-SAFIs")

			// Check for IPv4 AFI-SAFI presence
			hasIPv4 := false
			hasIPv6 := false
			for _, afiSafi := range peer.AfiSafis {
				assert.NotNil(t, afiSafi.Config, "AfiSafi.Config should not be nil")
				assert.NotNil(t, afiSafi.Config.Family, "AfiSafi.Config.Family should not be nil")
				assert.True(t, afiSafi.Config.Enabled, "AfiSafi should be enabled")

				if afiSafi.Config.Family.Afi == gobgpapi.Family_AFI_IP &&
					afiSafi.Config.Family.Safi == gobgpapi.Family_SAFI_UNICAST {
					hasIPv4 = true

					// Check MpGracefulRestart for IPv4
					if tt.expectMpGracefulRestart {
						assert.NotNil(t, afiSafi.MpGracefulRestart,
							"MpGracefulRestart should be set for IPv4 when graceful restart is enabled")
						assert.NotNil(t, afiSafi.MpGracefulRestart.Config,
							"MpGracefulRestart.Config should not be nil")
						assert.True(t, afiSafi.MpGracefulRestart.Config.Enabled,
							"MpGracefulRestart should be enabled")
						assert.NotNil(t, afiSafi.MpGracefulRestart.State,
							"MpGracefulRestart.State should not be nil")
					} else {
						assert.Nil(t, afiSafi.MpGracefulRestart,
							"MpGracefulRestart should not be set when graceful restart is disabled")
					}
				}

				if afiSafi.Config.Family.Afi == gobgpapi.Family_AFI_IP6 &&
					afiSafi.Config.Family.Safi == gobgpapi.Family_SAFI_UNICAST {
					hasIPv6 = true

					// Check MpGracefulRestart for IPv6
					if tt.expectMpGracefulRestart {
						assert.NotNil(t, afiSafi.MpGracefulRestart,
							"MpGracefulRestart should be set for IPv6 when graceful restart is enabled")
						assert.NotNil(t, afiSafi.MpGracefulRestart.Config,
							"MpGracefulRestart.Config should not be nil")
						assert.True(t, afiSafi.MpGracefulRestart.Config.Enabled,
							"MpGracefulRestart should be enabled")
						assert.NotNil(t, afiSafi.MpGracefulRestart.State,
							"MpGracefulRestart.State should not be nil")
					} else {
						assert.Nil(t, afiSafi.MpGracefulRestart,
							"MpGracefulRestart should not be set when graceful restart is disabled")
					}
				}
			}

			assert.Equal(t, tt.expectIPv4AfiSafi, hasIPv4,
				"IPv4 AFI-SAFI presence mismatch")
			assert.Equal(t, tt.expectIPv6AfiSafi, hasIPv6,
				"IPv6 AFI-SAFI presence mismatch")
		})
	}
}

func TestConfigurePeerAfiSafis_AppendsToExistingAfiSafis(t *testing.T) {
	t.Parallel()

	// Create a peer with pre-existing AFI-SAFIs
	existingAfiSafi := &gobgpapi.AfiSafi{
		Config: &gobgpapi.AfiSafiConfig{
			Family:  &gobgpapi.Family{Afi: gobgpapi.Family_AFI_L2VPN, Safi: gobgpapi.Family_SAFI_EVPN},
			Enabled: true,
		},
	}

	peer := &gobgpapi.Peer{
		Conf: &gobgpapi.PeerConf{
			NeighborAddress: "192.168.1.1",
			PeerAsn:         65000,
		},
		AfiSafis: []*gobgpapi.AfiSafi{existingAfiSafi},
	}

	node := &mockNode{
		ipv4Capable: true,
		ipv6Capable: true,
	}

	configurePeerAfiSafis(peer, node, false)

	// Should have 3 AFI-SAFIs: 1 existing + 2 added (IPv4 + IPv6)
	assert.Equal(t, 3, len(peer.AfiSafis), "should append to existing AFI-SAFIs")

	// First one should be the existing L2VPN EVPN
	assert.Equal(t, gobgpapi.Family_AFI_L2VPN, peer.AfiSafis[0].Config.Family.Afi)
	assert.Equal(t, gobgpapi.Family_SAFI_EVPN, peer.AfiSafis[0].Config.Family.Safi)

	// Second should be IPv4 Unicast
	assert.Equal(t, gobgpapi.Family_AFI_IP, peer.AfiSafis[1].Config.Family.Afi)
	assert.Equal(t, gobgpapi.Family_SAFI_UNICAST, peer.AfiSafis[1].Config.Family.Safi)

	// Third should be IPv6 Unicast
	assert.Equal(t, gobgpapi.Family_AFI_IP6, peer.AfiSafis[2].Config.Family.Afi)
	assert.Equal(t, gobgpapi.Family_SAFI_UNICAST, peer.AfiSafis[2].Config.Family.Safi)
}

func TestConfigurePeerAfiSafis_OrderConsistency(t *testing.T) {
	t.Parallel()

	// When both IPv4 and IPv6 are capable, IPv4 should come before IPv6
	node := &mockNode{
		ipv4Capable: true,
		ipv6Capable: true,
	}

	peer := &gobgpapi.Peer{
		Conf: &gobgpapi.PeerConf{
			NeighborAddress: "192.168.1.1",
			PeerAsn:         65000,
		},
	}

	configurePeerAfiSafis(peer, node, true)

	assert.Equal(t, 2, len(peer.AfiSafis), "should have 2 AFI-SAFIs for dual-stack")

	// IPv4 should be first
	assert.Equal(t, gobgpapi.Family_AFI_IP, peer.AfiSafis[0].Config.Family.Afi,
		"IPv4 AFI-SAFI should be first")

	// IPv6 should be second
	assert.Equal(t, gobgpapi.Family_AFI_IP6, peer.AfiSafis[1].Config.Family.Afi,
		"IPv6 AFI-SAFI should be second")
}

func TestConfigurePeerAfiSafis_DoesNotModifyOtherPeerFields(t *testing.T) {
	t.Parallel()

	node := &mockNode{
		ipv4Capable: true,
		ipv6Capable: true,
	}

	peer := &gobgpapi.Peer{
		Conf: &gobgpapi.PeerConf{
			NeighborAddress: "192.168.1.1",
			PeerAsn:         65000,
			AuthPassword:    "secret",
		},
		Transport: &gobgpapi.Transport{
			LocalAddress: "10.0.0.1",
			RemotePort:   179,
		},
		GracefulRestart: &gobgpapi.GracefulRestart{
			Enabled:     true,
			RestartTime: 120,
		},
	}

	configurePeerAfiSafis(peer, node, true)

	// Verify other fields are unchanged
	assert.Equal(t, "192.168.1.1", peer.Conf.NeighborAddress)
	assert.Equal(t, uint32(65000), peer.Conf.PeerAsn)
	assert.Equal(t, "secret", peer.Conf.AuthPassword)
	assert.Equal(t, "10.0.0.1", peer.Transport.LocalAddress)
	assert.Equal(t, uint32(179), peer.Transport.RemotePort)
	assert.True(t, peer.GracefulRestart.Enabled)
	assert.Equal(t, uint32(120), peer.GracefulRestart.RestartTime)
}

func TestConfigurePeerAfiSafis_NilPeerAfiSafisSlice(t *testing.T) {
	t.Parallel()

	node := &mockNode{
		ipv4Capable: true,
		ipv6Capable: false,
	}

	// Peer with nil AfiSafis slice (not just empty)
	peer := &gobgpapi.Peer{
		Conf: &gobgpapi.PeerConf{
			NeighborAddress: "192.168.1.1",
			PeerAsn:         65000,
		},
		AfiSafis: nil,
	}

	// Should not panic
	configurePeerAfiSafis(peer, node, false)

	assert.Equal(t, 1, len(peer.AfiSafis), "should create AFI-SAFI slice")
	assert.Equal(t, gobgpapi.Family_AFI_IP, peer.AfiSafis[0].Config.Family.Afi)
}

func TestConfigurePeerAfiSafis_MpGracefulRestartStateInitialization(t *testing.T) {
	t.Parallel()

	node := &mockNode{
		ipv4Capable: true,
		ipv6Capable: true,
	}

	peer := &gobgpapi.Peer{
		Conf: &gobgpapi.PeerConf{
			NeighborAddress: "192.168.1.1",
			PeerAsn:         65000,
		},
	}

	configurePeerAfiSafis(peer, node, true)

	// Both AFI-SAFIs should have MpGracefulRestart.State initialized
	for _, afiSafi := range peer.AfiSafis {
		assert.NotNil(t, afiSafi.MpGracefulRestart, "MpGracefulRestart should be set")
		assert.NotNil(t, afiSafi.MpGracefulRestart.State,
			"MpGracefulRestart.State should be initialized (not nil)")
	}
}

func TestConfigurePeerAfiSafis_IPv6OnlyWithGracefulRestart(t *testing.T) {
	t.Parallel()

	// This test specifically covers the bug scenario from issue #1992
	// where IPv6 routes weren't advertised when BGP Graceful Restart was disabled
	node := &mockNode{
		ipv4Capable: false,
		ipv6Capable: true,
	}

	peer := &gobgpapi.Peer{
		Conf: &gobgpapi.PeerConf{
			NeighborAddress: "2001:db8::2",
			PeerAsn:         65000,
		},
	}

	// Without graceful restart - this was the failing case
	configurePeerAfiSafis(peer, node, false)

	assert.Equal(t, 1, len(peer.AfiSafis), "should have IPv6 AFI-SAFI even without graceful restart")
	assert.Equal(t, gobgpapi.Family_AFI_IP6, peer.AfiSafis[0].Config.Family.Afi)
	assert.Equal(t, gobgpapi.Family_SAFI_UNICAST, peer.AfiSafis[0].Config.Family.Safi)
	assert.True(t, peer.AfiSafis[0].Config.Enabled)
	assert.Nil(t, peer.AfiSafis[0].MpGracefulRestart,
		"MpGracefulRestart should not be set when graceful restart is disabled")
}

func TestConfigurePeerAfiSafis_DualStackWithoutGracefulRestart(t *testing.T) {
	t.Parallel()

	// This test covers the main fix scenario: dual-stack nodes should get both
	// IPv4 and IPv6 AFI-SAFIs configured even when graceful restart is disabled
	node := &mockNode{
		ipv4Capable: true,
		ipv6Capable: true,
	}

	peer := &gobgpapi.Peer{
		Conf: &gobgpapi.PeerConf{
			NeighborAddress: "192.168.1.1",
			PeerAsn:         65000,
		},
	}

	configurePeerAfiSafis(peer, node, false)

	assert.Equal(t, 2, len(peer.AfiSafis),
		"dual-stack node should have both IPv4 and IPv6 AFI-SAFIs without graceful restart")

	// Verify both AFI-SAFIs are properly configured
	var hasIPv4, hasIPv6 bool
	for _, afiSafi := range peer.AfiSafis {
		if afiSafi.Config.Family.Afi == gobgpapi.Family_AFI_IP {
			hasIPv4 = true
			assert.Nil(t, afiSafi.MpGracefulRestart)
		}
		if afiSafi.Config.Family.Afi == gobgpapi.Family_AFI_IP6 {
			hasIPv6 = true
			assert.Nil(t, afiSafi.MpGracefulRestart)
		}
	}

	assert.True(t, hasIPv4, "should have IPv4 AFI-SAFI")
	assert.True(t, hasIPv6, "should have IPv6 AFI-SAFI")
}

func nodeWithAddresses(name string, addrs ...v1core.NodeAddress) *v1core.Node {
	return &v1core.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     v1core.NodeStatus{Addresses: addrs},
	}
}

func internalIP(address string) v1core.NodeAddress {
	return v1core.NodeAddress{Type: v1core.NodeInternalIP, Address: address}
}

func externalIP(address string) v1core.NodeAddress {
	return v1core.NodeAddress{Type: v1core.NodeExternalIP, Address: address}
}

const (
	localNodeName = "node-local"
	localNodeIP   = "10.0.0.100"
)

// We leave bgpServerStarted false so that a worker-driven OnNodeUpdate() never touches the nil BGP server. The local
// node is deliberately not any of the node-N fixtures the handler tests feed in, so those all count as remote.
func newNodeSyncTestNRC() *NetworkRoutingController {
	return &NetworkRoutingController{
		krNode: &utils.LocalKRNode{
			KRNode: utils.KRNode{
				NodeName:  localNodeName,
				PrimaryIP: net.ParseIP(localNodeIP),
				NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{
					v1core.NodeInternalIP: {net.ParseIP(localNodeIP)},
				},
			},
		},
		nodeSyncRequestChan: make(chan struct{}, 1),
		nodeSyncLimiter:     rate.NewLimiter(nodeSyncQPS, nodeSyncBurst),
	}
}

func TestNodeUpdateIsRelevant(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		oldNode  *v1core.Node
		newNode  *v1core.Node
		expected bool
	}{
		{
			name:     "identical nodes are not relevant",
			oldNode:  nodeWithAddresses("node-1", internalIP("10.0.0.1")),
			newNode:  nodeWithAddresses("node-1", internalIP("10.0.0.1")),
			expected: false,
		},
		{
			// This is the cloud controller manager sequence that motivated the whole change
			name:     "addresses appearing on a previously uninitialized node is relevant",
			oldNode:  nodeWithAddresses("node-1"),
			newNode:  nodeWithAddresses("node-1", internalIP("10.0.0.1")),
			expected: true,
		},
		{
			name:     "addresses disappearing is relevant",
			oldNode:  nodeWithAddresses("node-1", internalIP("10.0.0.1")),
			newNode:  nodeWithAddresses("node-1"),
			expected: true,
		},
		{
			name:     "a changed address value is relevant",
			oldNode:  nodeWithAddresses("node-1", internalIP("10.0.0.1")),
			newNode:  nodeWithAddresses("node-1", internalIP("10.0.0.2")),
			expected: true,
		},
		{
			name:     "a changed address type is relevant",
			oldNode:  nodeWithAddresses("node-1", internalIP("10.0.0.1")),
			newNode:  nodeWithAddresses("node-1", externalIP("10.0.0.1")),
			expected: true,
		},
		{
			name:     "an additional address is relevant",
			oldNode:  nodeWithAddresses("node-1", internalIP("10.0.0.1")),
			newNode:  nodeWithAddresses("node-1", internalIP("10.0.0.1"), externalIP("1.1.1.1")),
			expected: true,
		},
		{
			name:     "reordered addresses are relevant, since the first internal IP is the primary IP",
			oldNode:  nodeWithAddresses("node-1", internalIP("10.0.0.1"), internalIP("10.0.0.2")),
			newNode:  nodeWithAddresses("node-1", internalIP("10.0.0.2"), internalIP("10.0.0.1")),
			expected: true,
		},
		{
			// kube-router doesn't support changing a node's pod CIDR on a running cluster, and syncInternalPeers()
			// doesn't consume pod CIDRs anyway, so a change here shouldn't spend a sync.
			name: "a changed pod CIDR is not relevant",
			oldNode: &v1core.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
				Spec: v1core.NodeSpec{
					PodCIDR:  "10.244.0.0/24",
					PodCIDRs: []string{"10.244.0.0/24"},
				},
			},
			newNode: &v1core.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
				Spec: v1core.NodeSpec{
					PodCIDR:  "10.244.1.0/24",
					PodCIDRs: []string{"10.244.1.0/24", "2001:db8::/64"},
				},
			},
			expected: false,
		},
		{
			// Annotations aren't re-read on sync yet, so a change to one shouldn't spend a sync either
			name: "an annotation change alone is not relevant",
			oldNode: &v1core.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
			},
			newNode: &v1core.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "node-1",
					Annotations: map[string]string{rrClientAnnotation: "1"},
				},
			},
			expected: false,
		},
		{
			// Heartbeats and resource pressure conditions are the bulk of real node update traffic
			name: "a status condition change alone is not relevant",
			oldNode: &v1core.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
				Status: v1core.NodeStatus{
					Addresses: []v1core.NodeAddress{internalIP("10.0.0.1")},
					Conditions: []v1core.NodeCondition{
						{Type: v1core.NodeReady, Status: v1core.ConditionFalse},
					},
				},
			},
			newNode: &v1core.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
				Status: v1core.NodeStatus{
					Addresses: []v1core.NodeAddress{internalIP("10.0.0.1")},
					Conditions: []v1core.NodeCondition{
						{Type: v1core.NodeReady, Status: v1core.ConditionTrue},
					},
				},
			},
			expected: false,
		},
		{
			name: "a resource version bump alone is not relevant",
			oldNode: &v1core.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-1", ResourceVersion: "1"},
			},
			newNode: &v1core.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-1", ResourceVersion: "2"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, nodeUpdateIsRelevant(tt.oldNode, tt.newNode))
		})
	}
}

// We need a sync both when the kubelet registers a node and when CCM supplies its addresses
func TestNodeEventHandlerCCMSequence(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		nrc := newNodeSyncTestNRC()

		clientset := fake.NewSimpleClientset()
		informerFactory := informers.NewSharedInformerFactory(clientset, 0)
		nodeInformer := informerFactory.Core().V1().Nodes().Informer()
		_, err := nodeInformer.AddEventHandler(nrc.newNodeEventHandler())
		require.NoError(t, err)

		stopCh := make(chan struct{})
		informerFactory.Start(stopCh)
		informerFactory.WaitForCacheSync(stopCh)
		defer func() {
			close(stopCh)
			informerFactory.Shutdown()
		}()

		uninitialized := &v1core.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}}
		_, err = clientset.CoreV1().Nodes().Create(context.Background(), uninitialized, metav1.CreateOptions{})
		require.NoError(t, err)
		synctest.Wait()
		require.Len(t, nrc.nodeSyncRequestChan, 1, "node add should request a sync")

		// Drain, so that the add event can't be mistaken for the update event below
		<-nrc.nodeSyncRequestChan

		initialized := uninitialized.DeepCopy()
		initialized.Status.Addresses = []v1core.NodeAddress{internalIP("10.0.0.1")}
		_, err = clientset.CoreV1().Nodes().UpdateStatus(context.Background(), initialized, metav1.UpdateOptions{})
		require.NoError(t, err)
		synctest.Wait()
		require.Len(t, nrc.nodeSyncRequestChan, 1, "node address update should request a sync")
	})
}

func TestNodeEventHandlerIgnoresIrrelevantUpdates(t *testing.T) {
	t.Parallel()

	nrc := newNodeSyncTestNRC()

	handler := nrc.newNodeEventHandler()
	oldNode := nodeWithAddresses("node-1", internalIP("10.0.0.1"))
	newNode := oldNode.DeepCopy()
	newNode.ResourceVersion = "2"
	newNode.Status.Conditions = []v1core.NodeCondition{
		{Type: v1core.NodeReady, Status: v1core.ConditionTrue},
	}

	handler.OnUpdate(oldNode, newNode)

	assert.Equal(t, 0, len(nrc.nodeSyncRequestChan), "a heartbeat-only update should not request a sync")
}

// A change to our own node's addresses can't be applied by a peer sync, so it must never spend one. Whether the
// addresses actually drifted is covered by Test_AddressesMatch in pkg/utils.
func TestNodeEventHandlerLocalNodeUpdateDoesNotSync(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		newNode *v1core.Node
	}{
		{
			name:    "local node addresses drifted from the startup snapshot",
			newNode: nodeWithAddresses(localNodeName, internalIP("10.0.0.200")),
		},
		{
			// Addresses changed relative to the previous event, but ended up back at what we started with
			name:    "local node addresses still match the startup snapshot",
			newNode: nodeWithAddresses(localNodeName, internalIP(localNodeIP)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			nrc := newNodeSyncTestNRC()
			handler := nrc.newNodeEventHandler()
			oldNode := nodeWithAddresses(localNodeName, internalIP("10.0.0.1"))

			handler.OnUpdate(oldNode, tt.newNode)

			assert.Empty(t, nrc.nodeSyncRequestChan)
		})
	}
}

func TestNodeEventHandlerLocalNodeInitialAdd(t *testing.T) {
	// We keep this test serial because capturing klog output changes global logging settings
	state := klog.CaptureState()
	t.Cleanup(state.Restore)
	klog.LogToStderr(false)

	for _, tt := range []struct {
		name string
		ip   string
		warn bool
	}{
		{name: "drifted snapshot", ip: "10.0.0.200", warn: true},
		{name: "matching snapshot", ip: localNodeIP},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			klog.SetOutput(&logs)
			nrc := newNodeSyncTestNRC()
			handler := nrc.newNodeEventHandler()
			node := nodeWithAddresses(localNodeName, internalIP(tt.ip))

			handler.OnAdd(node, true)
			klog.Flush()
			warning := "The addresses on node " + localNodeName + " no longer match"
			assert.Equal(t, tt.warn, bytes.Contains(logs.Bytes(), []byte(warning)))
			require.Len(t, nrc.nodeSyncRequestChan, 1, "initial add must still request reconciliation")
			<-nrc.nodeSyncRequestChan

			logs.Reset()
			updated := node.DeepCopy()
			updated.ResourceVersion = "2"
			updated.Status.Conditions = []v1core.NodeCondition{
				{Type: v1core.NodeReady, Status: v1core.ConditionTrue},
			}
			handler.OnUpdate(node, updated)
			klog.Flush()
			assert.NotContains(t, logs.String(), warning, "heartbeats must not repeat the warning")
			assert.Empty(t, nrc.nodeSyncRequestChan)
		})
	}
}

func TestNodeSyncRequestsCoalesceBursts(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		nrc := newNodeSyncTestNRC()
		handler := nrc.newNodeEventHandler()
		const eventCount = 50
		for i := range eventCount {
			oldNode := nodeWithAddresses("node-1", internalIP("10.0.0.1"))
			newNode := nodeWithAddresses("node-1", internalIP(fmt.Sprintf("10.0.0.%d", i+2)))
			handler.OnUpdate(oldNode, newNode)
		}

		assert.Equal(t, 1, len(nrc.nodeSyncRequestChan))
		// We charge execution rather than event arrival so that coalesced events don't accrue limiter debt
		assert.Equal(t, float64(nodeSyncBurst), nrc.nodeSyncLimiter.Tokens())

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var wg sync.WaitGroup
		wg.Add(1)
		go nrc.runNodeSyncWorker(ctx, &wg)
		synctest.Wait()

		assert.Empty(t, nrc.nodeSyncRequestChan)
		assert.Equal(t, float64(nodeSyncBurst-1), nrc.nodeSyncLimiter.Tokens())
		nrc.requestNodeSync()
		synctest.Wait()
		assert.Empty(t, nrc.nodeSyncRequestChan)
		assert.Equal(t, float64(nodeSyncBurst-2), nrc.nodeSyncLimiter.Tokens())

		cancel()
		wg.Wait()
	})
}

func TestRunNodeSyncWorkerShutdown(t *testing.T) {
	t.Parallel()

	nrc := newNodeSyncTestNRC()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go nrc.runNodeSyncWorker(ctx, &wg)

	nrc.requestNodeSync()
	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("node sync worker did not exit and decrement the WaitGroup after the context was cancelled")
	}
}

func TestRunNodeSyncWorkerExitsWhileThrottled(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		nrc := newNodeSyncTestNRC()
		require.True(t, nrc.nodeSyncLimiter.AllowN(time.Now(), nodeSyncBurst))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var wg sync.WaitGroup
		wg.Add(1)
		go nrc.runNodeSyncWorker(ctx, &wg)
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		nrc.requestNodeSync()
		synctest.Wait()
		// A negative balance confirms the worker reserved a token and is waiting for its refill
		require.Equal(t, float64(-1), nrc.nodeSyncLimiter.Tokens())
		select {
		case <-done:
			t.Fatal("node sync worker exited before cancellation")
		default:
		}

		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("node sync worker did not exit while blocked in the limiter")
		}
	})
}
