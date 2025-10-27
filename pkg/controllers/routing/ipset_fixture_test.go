package routing

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/pkg/controllers/testhelpers"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/stretchr/testify/require"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNetworkRoutingFixtureIPSets(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "..", "testdata", "ipset_test_1")

	nodes := testhelpers.LoadNodeList(t, filepath.Join(fixtureDir, "nodes.yaml"))

	client := fake.NewSimpleClientset()
	for i := range nodes.Items {
		_, err := client.CoreV1().Nodes().Create(context.Background(), nodes.Items[i].DeepCopy(), metav1.CreateOptions{})
		require.NoError(t, err)
	}

	informerFactory := informers.NewSharedInformerFactory(client, 0)
	nodeInformer := informerFactory.Core().V1().Nodes().Informer()
	indexer := nodeInformer.GetIndexer()
	for i := range nodes.Items {
		node := nodes.Items[i].DeepCopy()
		node.SetResourceVersion("1")
		require.NoError(t, indexer.Add(node))
	}

	ipv4Handler := testhelpers.NewFakeIPSetHandler(false)
	ipv6Handler := testhelpers.NewFakeIPSetHandler(true)

	controller := &NetworkRoutingController{
		ipSetHandlers: map[v1.IPFamily]utils.IPSetHandler{
			v1.IPv4Protocol: ipv4Handler,
			v1.IPv6Protocol: ipv6Handler,
		},
		ipsetMutex: &sync.Mutex{},
		nodeLister: indexer,
	}

	err := controller.syncNodeIPSets()
	require.NoError(t, err)

	actual := testhelpers.MergeExpectations(
		testhelpers.ParseRestoreScript(ipv4Handler.Restored()),
		testhelpers.ParseRestoreScript(ipv6Handler.Restored()),
	)

	include := func(name string) bool {
		// Exclude netpol ipsets
		if strings.Contains(name, "KUBE-DST") || strings.Contains(name, "KUBE-SRC") {
			return false
		}
		// Exclude proxy ipsets
		if strings.Contains(name, "svip") || strings.Contains(name, "local-ips") {
			return false
		}
		return true
	}

	expected := testhelpers.ParseSnapshotWithFilter(
		t,
		filepath.Join(fixtureDir, "ipset_save.txt"),
		include,
	)

	require.NotEmpty(t, expected, "expected snapshot should not be empty")
	require.Equal(t, testhelpers.ExpectedKeys(expected), testhelpers.ExpectedKeys(actual))

	for name, exp := range expected {
		act := actual[name]
		require.Equal(t, exp.SetType, act.SetType, "set type mismatch for %s", name)
		require.Equal(t, exp.Entries, act.Entries, "entries mismatch for %s", name)
	}
}
