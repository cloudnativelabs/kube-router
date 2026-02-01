package routing

import (
	"net"
	"testing"

	gobgpapi "github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
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
