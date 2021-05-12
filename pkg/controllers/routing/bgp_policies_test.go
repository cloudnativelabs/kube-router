package routing

import (
	"context"
	"reflect"
	"testing"
	"time"

	v1core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	gobgpapi "github.com/osrg/gobgp/api"
	gobgp "github.com/osrg/gobgp/pkg/server"
)

type PolicyTestCase struct {
	name                   string
	nrc                    *NetworkRoutingController
	existingNodes          []*v1core.Node
	existingServices       []*v1core.Service
	podDefinedSet          *gobgpapi.DefinedSet
	clusterIPDefinedSet    *gobgpapi.DefinedSet
	externalPeerDefinedSet *gobgpapi.DefinedSet
	allPeerDefinedSet      *gobgpapi.DefinedSet
	exportPolicyStatements []*gobgpapi.Statement
	importPolicyStatements []*gobgpapi.Statement
	err                    error
}

func Test_AddPolicies(t *testing.T) {
	testcases := []PolicyTestCase{
		{
			"has nodes and services",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				bgpFullMeshMode:   false,
				bgpEnableInternal: true,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				nodeAsnNumber:     100,
				podCidr:           "172.20.0.0/24",
			},
			[]*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
						Annotations: map[string]string{
							"kube-router.io/node.asn": "100",
						},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{
								Type:    v1core.NodeInternalIP,
								Address: "10.0.0.1",
							},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR: "172.20.0.0/24",
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:        "ClusterIP",
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1"},
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_PREFIX,
				Name:        "podcidrdefinedset",
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "172.20.0.0/24",
						MaskLengthMin: 24,
						MaskLengthMax: 24,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_PREFIX,
				Name:        "servicevipsdefinedset",
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "1.1.1.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
					{
						IpPrefix:      "10.0.0.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
				},
			},
			&gobgpapi.DefinedSet{},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_NEIGHBOR,
				Name:        "allpeerset",
				List:        []string{},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "podcidrdefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "iBGPpeerset",
						},
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ACCEPT,
					},
				},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "servicevipsdefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "allpeerset",
						},
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
			},
			nil,
		},
		{
			"has nodes, services with external peers",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				bgpFullMeshMode:   false,
				bgpEnableInternal: true,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				podCidr:           "172.20.0.0/24",
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.10.0.1",
						},
					},
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.10.0.2",
						},
					},
				},
				nodeAsnNumber: 100,
			},
			[]*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
						Annotations: map[string]string{
							"kube-router.io/node.asn": "100",
						},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{
								Type:    v1core.NodeInternalIP,
								Address: "10.0.0.1",
							},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR: "172.20.0.0/24",
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:        "ClusterIP",
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1"},
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_PREFIX,
				Name:        "podcidrdefinedset",
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "172.20.0.0/24",
						MaskLengthMin: 24,
						MaskLengthMax: 24,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_PREFIX,
				Name:        "servicevipsdefinedset",
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "1.1.1.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
					{
						IpPrefix:      "10.0.0.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_NEIGHBOR,
				Name:        "externalpeerset",
				List:        []string{"10.10.0.1/32", "10.10.0.2/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_NEIGHBOR,
				Name:        "allpeerset",
				List:        []string{"10.10.0.1/32", "10.10.0.2/32"},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "podcidrdefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "iBGPpeerset",
						},
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "servicevipsdefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "externalpeerset",
						},
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ACCEPT,
					},
				},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "servicevipsdefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "allpeerset",
						},
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
			},
			nil,
		},
		{
			"has nodes, services with external peers and iBGP disabled",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				bgpFullMeshMode:   false,
				bgpEnableInternal: false,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				podCidr:           "172.20.0.0/24",
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.10.0.1",
						},
					},
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.10.0.2",
						},
					},
				},
				nodeAsnNumber: 100,
			},
			[]*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
						Annotations: map[string]string{
							"kube-router.io/node.asn": "100",
						},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{
								Type:    v1core.NodeInternalIP,
								Address: "10.0.0.1",
							},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR: "172.20.0.0/24",
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:        "ClusterIP",
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1"},
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_PREFIX,
				Name:        "podcidrdefinedset",
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "172.20.0.0/24",
						MaskLengthMin: 24,
						MaskLengthMax: 24,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_PREFIX,
				Name:        "servicevipsdefinedset",
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "1.1.1.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
					{
						IpPrefix:      "10.0.0.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_NEIGHBOR,
				Name:        "externalpeerset",
				List:        []string{"10.10.0.1/32", "10.10.0.2/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_NEIGHBOR,
				Name:        "allpeerset",
				List:        []string{"10.10.0.1/32", "10.10.0.2/32"},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "servicevipsdefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "externalpeerset",
						},
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ACCEPT,
					},
				},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "servicevipsdefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "allpeerset",
						},
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
			},
			nil,
		},
		{
			"prepends AS with external peers",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				bgpEnableInternal: true,
				bgpFullMeshMode:   false,
				pathPrepend:       true,
				pathPrependCount:  5,
				pathPrependAS:     "65100",
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				podCidr:           "172.20.0.0/24",
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.10.0.1",
						},
					},
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.10.0.2",
						},
					},
				},
				nodeAsnNumber: 100,
			},
			[]*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
						Annotations: map[string]string{
							"kube-router.io/node.asn": "100",
						},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{
								Type:    v1core.NodeInternalIP,
								Address: "10.0.0.1",
							},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR: "172.20.0.0/24",
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:        "ClusterIP",
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1"},
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_PREFIX,
				Name:        "podcidrdefinedset",
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "172.20.0.0/24",
						MaskLengthMin: 24,
						MaskLengthMax: 24,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_PREFIX,
				Name:        "servicevipsdefinedset",
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "1.1.1.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
					{
						IpPrefix:      "10.0.0.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_NEIGHBOR,
				Name:        "externalpeerset",
				List:        []string{"10.10.0.1/32", "10.10.0.2/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_NEIGHBOR,
				Name:        "allpeerset",
				List:        []string{"10.10.0.1/32", "10.10.0.2/32"},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "podcidrdefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "iBGPpeerset",
						},
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "servicevipsdefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "externalpeerset",
						},
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ACCEPT,
						AsPrepend: &gobgpapi.AsPrependAction{
							Asn:    65100,
							Repeat: 5,
						},
					},
				},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "servicevipsdefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "allpeerset",
						},
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
			},
			nil,
		},
		{
			"only prepends AS when both node annotations are present",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				bgpEnableInternal: true,
				bgpFullMeshMode:   false,
				pathPrepend:       false,
				pathPrependAS:     "65100",
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				podCidr:           "172.20.0.0/24",
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.10.0.1",
						},
					},
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.10.0.2",
						},
					},
				},
				nodeAsnNumber: 100,
			},
			[]*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
						Annotations: map[string]string{
							"kube-router.io/node.asn": "100",
						},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{
								Type:    v1core.NodeInternalIP,
								Address: "10.0.0.1",
							},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR: "172.20.0.0/24",
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:        "ClusterIP",
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1"},
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_PREFIX,
				Name:        "podcidrdefinedset",
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "172.20.0.0/24",
						MaskLengthMin: 24,
						MaskLengthMax: 24,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_PREFIX,
				Name:        "servicevipsdefinedset",
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "1.1.1.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
					{
						IpPrefix:      "10.0.0.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_NEIGHBOR,
				Name:        "externalpeerset",
				List:        []string{"10.10.0.1/32", "10.10.0.2/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_NEIGHBOR,
				Name:        "allpeerset",
				List:        []string{"10.10.0.1/32", "10.10.0.2/32"},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "podcidrdefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "iBGPpeerset",
						},
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "servicevipsdefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "externalpeerset",
						},
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ACCEPT,
						AsPrepend: &gobgpapi.AsPrependAction{
							Asn:    65100,
							Repeat: 5,
						},
					},
				},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "servicevipsdefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "allpeerset",
						},
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
			},
			nil,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			go testcase.nrc.bgpServer.Serve()
			global := &gobgpapi.Global{
				As:         1,
				RouterId:   "10.0.0.0",
				ListenPort: 10000,
			}
			err := testcase.nrc.bgpServer.StartBgp(context.Background(), &gobgpapi.StartBgpRequest{Global: global})
			if err != nil {
				t.Fatalf("failed to start BGP server: %v", err)
			}
			defer func() {
				if err := testcase.nrc.bgpServer.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{}); err != nil {
					t.Fatalf("failed to stop BGP server : %s", err)
				}
			}()

			startInformersForRoutes(testcase.nrc, testcase.nrc.clientset)

			if err = createNodes(testcase.nrc.clientset, testcase.existingNodes); err != nil {
				t.Errorf("failed to create existing nodes: %v", err)
			}

			if err = createServices(testcase.nrc.clientset, testcase.existingServices); err != nil {
				t.Errorf("failed to create existing nodes: %v", err)
			}

			// ClusterIPs and ExternalIPs
			waitForListerWithTimeout(testcase.nrc.svcLister, time.Second*10, t)

			testcase.nrc.advertiseClusterIP = true
			testcase.nrc.advertiseExternalIP = true
			testcase.nrc.advertiseLoadBalancerIP = false

			informerFactory := informers.NewSharedInformerFactory(testcase.nrc.clientset, 0)
			nodeInformer := informerFactory.Core().V1().Nodes().Informer()
			testcase.nrc.nodeLister = nodeInformer.GetIndexer()
			err = testcase.nrc.AddPolicies()
			if !reflect.DeepEqual(err, testcase.err) {
				t.Logf("expected err %v", testcase.err)
				t.Logf("actual err %v", err)
				t.Error("unexpected error")
			}

			err = testcase.nrc.bgpServer.ListDefinedSet(context.Background(), &gobgpapi.ListDefinedSetRequest{
				DefinedType: gobgpapi.DefinedType_PREFIX,
				Name:        "podcidrdefinedset"}, func(podDefinedSet *gobgpapi.DefinedSet) {
				if !reflect.DeepEqual(podDefinedSet, testcase.podDefinedSet) {
					t.Logf("expected pod defined set: %+v", testcase.podDefinedSet)
					t.Logf("actual pod defined set: %+v", podDefinedSet)
					t.Error("unexpected pod defined set")
				}
			})
			if err != nil {
				t.Fatalf("error validating defined sets: %v", err)
			}

			err = testcase.nrc.bgpServer.ListDefinedSet(context.Background(), &gobgpapi.ListDefinedSetRequest{
				DefinedType: gobgpapi.DefinedType_PREFIX,
				Name:        "servicevipsdefinedset"}, func(clusterIPDefinedSet *gobgpapi.DefinedSet) {
				if !reflect.DeepEqual(clusterIPDefinedSet, testcase.clusterIPDefinedSet) {
					t.Logf("expected pod defined set: %+v", testcase.clusterIPDefinedSet)
					t.Logf("actual pod defined set: %+v", clusterIPDefinedSet)
					t.Error("unexpected pod defined set")
				}
			})
			if err != nil {
				t.Fatalf("error validating defined sets: %v", err)
			}

			err = testcase.nrc.bgpServer.ListDefinedSet(context.Background(), &gobgpapi.ListDefinedSetRequest{
				DefinedType: gobgpapi.DefinedType_NEIGHBOR,
				Name:        "externalpeerset"}, func(externalPeerDefinedSet *gobgpapi.DefinedSet) {
				if !reflect.DeepEqual(externalPeerDefinedSet, testcase.externalPeerDefinedSet) {
					t.Logf("expected external peer defined set: %+v", testcase.externalPeerDefinedSet.List)
					t.Logf("actual external peer defined set: %+v", externalPeerDefinedSet.List)
					t.Error("unexpected external peer defined set")
				}
			})
			if err != nil {
				t.Fatalf("error validating defined sets: %v", err)
			}

			err = testcase.nrc.bgpServer.ListDefinedSet(context.Background(), &gobgpapi.ListDefinedSetRequest{
				DefinedType: gobgpapi.DefinedType_NEIGHBOR,
				Name:        "allpeerset"}, func(allPeerDefinedSet *gobgpapi.DefinedSet) {
				if !reflect.DeepEqual(allPeerDefinedSet, testcase.allPeerDefinedSet) {
					t.Logf("expected all peer defined set: %+v", testcase.allPeerDefinedSet.List)
					t.Logf("actual all peer defined set: %+v", allPeerDefinedSet.List)
					t.Error("unexpected all peer defined set")
				}
			})
			if err != nil {
				t.Fatalf("error validating defined sets: %v", err)
			}

			checkPolicies(t, testcase, gobgpapi.PolicyDirection_EXPORT, gobgpapi.RouteAction_REJECT, testcase.exportPolicyStatements)
			checkPolicies(t, testcase, gobgpapi.PolicyDirection_IMPORT, gobgpapi.RouteAction_ACCEPT, testcase.importPolicyStatements)
		})
	}
}

func checkPolicies(t *testing.T, testcase PolicyTestCase, gobgpDirection gobgpapi.PolicyDirection, defaultPolicy gobgpapi.RouteAction,
	policyStatements []*gobgpapi.Statement) {
	policyExists := false

	var direction string
	if gobgpDirection.String() == "EXPORT" {
		direction = "export"
	} else if gobgpDirection.String() == "IMPORT" {
		direction = "import"
	}

	err := testcase.nrc.bgpServer.ListPolicy(context.Background(), &gobgpapi.ListPolicyRequest{}, func(policy *gobgpapi.Policy) {
		if policy.Name == "kube_router_"+direction {
			policyExists = true
		}
	})
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if !policyExists {
		t.Errorf("policy 'kube_router_%v' was not added", direction)
	}

	policyAssignmentExists := false
	err = testcase.nrc.bgpServer.ListPolicyAssignment(context.Background(), &gobgpapi.ListPolicyAssignmentRequest{}, func(policyAssignment *gobgpapi.PolicyAssignment) {
		if policyAssignment.Name == "global" && policyAssignment.Direction == gobgpDirection {
			for _, policy := range policyAssignment.Policies {
				if policy.Name == "kube_router_"+direction {
					policyAssignmentExists = true
				}
			}
		}
	})
	if err != nil {
		t.Fatalf("failed to get policy assignments: %v", err)
	}

	if !policyAssignmentExists {
		t.Errorf("export policy assignment 'kube_router_%v' was not added", direction)
	}
	/*
		statements := testcase.nrc.bgpServer.GetStatement()
		for _, expectedStatement := range policyStatements {
			found := false
			for _, statement := range statements {
				if reflect.DeepEqual(statement, expectedStatement) {
					found = true
				}
			}

			if !found {
				t.Errorf("statement %v not found", expectedStatement)
			}
		}
	*/
}
