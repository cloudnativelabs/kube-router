package routing

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/v2/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"

	gobgpapi "github.com/osrg/gobgp/v4/api"
	gobgp "github.com/osrg/gobgp/v4/pkg/server"
)

// These exist because advertiseVIPs, withdrawVIPs and syncInternalPeers used to log and drop their
// failures, letting the controller report a successful sync with no VIP advertised and no peer up

// newNRCWithStoppedBGP returns a controller whose BGP server still runs its management loop but has
// been stopped, which is how we get a deterministic failure out of AddPath, DeletePath and AddPeer
func newNRCWithStoppedBGP(t *testing.T) *NetworkRoutingController {
	t.Helper()

	server := gobgp.NewBgpServer()
	go server.Serve()
	err := server.StartBgp(context.Background(), &gobgpapi.StartBgpRequest{
		Global: &gobgpapi.Global{Asn: 1, RouterId: testNodeIPv4, ListenPort: -1},
	})
	if err != nil {
		t.Fatalf("failed to start BGP server: %v", err)
	}
	if err = server.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{}); err != nil {
		t.Fatalf("failed to stop BGP server: %v", err)
	}

	return &NetworkRoutingController{
		bgpServer:       server,
		bgpFullMeshMode: true,
		clientset:       fake.NewSimpleClientset(),
		activeNodes:     make(map[string]bool),
		krNode: &utils.LocalKRNode{
			KRNode: utils.KRNode{
				NodeName:      "node-1",
				PrimaryIP:     net.ParseIP(testNodeIPv4),
				NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
			},
		},
	}
}

func Test_advertiseVIPsReportsFailures(t *testing.T) {
	t.Run("every failed advertisement is reported", func(t *testing.T) {
		nrc := newNRCWithStoppedBGP(t)

		err := nrc.advertiseVIPs([]string{"10.96.0.1", "10.96.0.2"})

		require.Error(t, err, "advertising over an unusable BGP server has to be reported")
		assert.ErrorContains(t, err, "advertise 10.96.0.1")
		assert.ErrorContains(t, err, "advertise 10.96.0.2")
	})

	t.Run("every failed withdrawal is reported", func(t *testing.T) {
		nrc := newNRCWithStoppedBGP(t)

		err := nrc.withdrawVIPs([]string{"10.96.0.1", "10.96.0.2"})

		require.Error(t, err)
		assert.ErrorContains(t, err, "withdraw 10.96.0.1")
		assert.ErrorContains(t, err, "withdraw 10.96.0.2")
	})

	t.Run("a VIP with no usable nexthop is reported rather than skipped", func(t *testing.T) {
		// An IPv6 VIP on an IPv4 only node fails while building the path, before BGP is involved
		nrc := newNRCWithStoppedBGP(t)

		assert.ErrorContains(t, nrc.advertiseVIPs([]string{testNodeIPv6}), "unable to advertise VIP")
		assert.ErrorContains(t, nrc.withdrawVIPs([]string{testNodeIPv6}), "unable to withdraw VIP")
	})

	t.Run("nothing to do is not a failure", func(t *testing.T) {
		nrc := newNRCWithStoppedBGP(t)

		assert.NoError(t, nrc.advertiseVIPs(nil))
		assert.NoError(t, nrc.withdrawVIPs([]string{}))
	})
}

func Test_syncInternalPeersReportsFailures(t *testing.T) {
	nrc := newNRCWithStoppedBGP(t)
	startInformersForRoutes(t, nrc, nrc.clientset)

	nodes := []*v1core.Node{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "node-2"},
			Status: v1core.NodeStatus{
				Addresses: []v1core.NodeAddress{{Type: v1core.NodeInternalIP, Address: "10.0.0.2"}},
			},
		},
	}
	if err := createNodes(nrc.clientset, nodes); err != nil {
		t.Fatalf("failed to create existing nodes: %v", err)
	}
	waitForListerWithTimeout(nrc.nodeLister, time.Second*10, t)

	err := nrc.syncInternalPeers()

	require.Error(t, err, "a peer we could not add has to be reported")
	assert.ErrorContains(t, err, "add peer 10.0.0.2")
}

func Test_syncInternalPeersRetriesFailedDeletions(t *testing.T) {
	nrc := newNRCWithStoppedBGP(t)
	startInformersForRoutes(t, nrc, nrc.clientset)

	// No Node backs this entry, so the sync tries to delete the peer, which the stopped BGP
	// server refuses with an error that is not the peer-already-gone sentinel
	nrc.activeNodes["10.0.0.9"] = true

	err := nrc.syncInternalPeers()

	require.Error(t, err, "a peer we could not delete has to be reported")
	assert.ErrorContains(t, err, "delete peer 10.0.0.9")
	assert.True(t, nrc.activeNodes["10.0.0.9"],
		"a failed deletion must stay in activeNodes so the next sync retries it")
}

func Test_syncInternalPeersPreservesPeersWhenNodeCannotBeParsed(t *testing.T) {
	nrc := newNRCWithStoppedBGP(t)
	startInformersForRoutes(t, nrc, nrc.clientset)

	const peerIP = "10.0.0.9"
	nrc.activeNodes[peerIP] = true
	_, err := nrc.clientset.CoreV1().Nodes().Create(t.Context(), &v1core.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-without-an-address"},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	waitForListerWithTimeout(nrc.nodeLister, time.Second*10, t)

	err = nrc.syncInternalPeers()

	require.Error(t, err)
	assert.ErrorContains(t, err, "evaluate node node-without-an-address")
	assert.True(t, nrc.activeNodes[peerIP],
		"peer deletion must wait until every Node can be evaluated")
}

func Test_startBgpServerWithRetryReportsFailures(t *testing.T) {
	metrics.ControllerSyncFailures.Reset()
	metrics.ControllerSyncLastSuccess.Reset()
	healthChan := make(chan *healthcheck.ControllerHeartbeat, 2)
	stopCh := make(chan struct{})
	retry := make(chan time.Time, 2)
	retry <- time.Now()
	retry <- time.Now()

	attempts := 0
	started := startBgpServerWithRetry(healthChan, stopCh, retry, func() error {
		attempts++
		if attempts < 3 {
			return errors.New("invalid BGP configuration")
		}
		return nil
	})

	assert.True(t, started)
	assert.Equal(t, 3, attempts)
	assert.Len(t, healthChan, 2, "each failed startup attempt must send a heartbeat")
	assert.Equal(t, float64(2), testutil.ToFloat64(
		metrics.ControllerSyncFailures.WithLabelValues("NetworkRoutesController")))
	assert.Zero(t, testutil.ToFloat64(
		metrics.ControllerSyncLastSuccess.WithLabelValues("NetworkRoutesController")),
		"a failed startup attempt must not stamp a successful routing sync")
}

// Test_routingSyncFailuresReachTheMetric ties the helpers above back to the exported metric
func Test_routingSyncFailuresReachTheMetric(t *testing.T) {
	metrics.ControllerSyncFailures.Reset()
	metrics.ControllerSyncLastSuccess.Reset()

	nrc := newNRCWithStoppedBGP(t)
	syncErr := nrc.advertiseVIPs([]string{"10.96.0.1"})
	require.Error(t, syncErr)

	metrics.RecordSyncResult(healthcheck.NetworkRoutesController, syncErr)

	assert.Equal(t, float64(1), testutil.ToFloat64(
		metrics.ControllerSyncFailures.WithLabelValues("NetworkRoutesController")))
	assert.Zero(t, testutil.ToFloat64(
		metrics.ControllerSyncLastSuccess.WithLabelValues("NetworkRoutesController")),
		"a failed VIP advertisement must not stamp a successful sync")
}
