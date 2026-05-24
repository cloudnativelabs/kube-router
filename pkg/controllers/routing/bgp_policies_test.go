package routing

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	v1core "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	gobgpapi "github.com/osrg/gobgp/v4/api"
	gobgp "github.com/osrg/gobgp/v4/pkg/server"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

type PolicyTestCase struct {
	name                         string
	nrc                          *NetworkRoutingController
	existingNodes                []*v1core.Node
	existingServices             []*v1core.Service
	existingEndpoints            []*discoveryv1.EndpointSlice
	podDefinedSet                *gobgpapi.DefinedSet
	clusterIPDefinedSet          *gobgpapi.DefinedSet
	externalPeerDefinedSet       *gobgpapi.DefinedSet
	allPeerDefinedSet            *gobgpapi.DefinedSet
	customImportRejectDefinedSet *gobgpapi.DefinedSet
	exportPolicyStatements       []*gobgpapi.Statement
	importPolicyStatements       []*gobgpapi.Statement
	startBGPServerErr            error
}

func Test_AddPolicies(t *testing.T) {
	ipv4CapableKRNode := &utils.LocalKRNode{
		KRNode: utils.KRNode{
			NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.IPv4(10, 10, 10, 10)}},
		},
	}
	testcases := []PolicyTestCase{
		{
			"has nodes and services",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.0.0.1",
				localAddressList:  []string{"0.0.0.0"},
				bgpPort:           10000,
				bgpFullMeshMode:   false,
				bgpEnableInternal: true,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				nodeAsnNumber:     100,
				podCidr:           "172.20.0.0/24",
				krNode:            ipv4CapableKRNode,
				podIPv4CIDRs:      []string{"172.20.0.0/24"},
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
								Address: "10.0.0.2",
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
						Name:      "svc-1",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "10.1.0.1",
						ExternalIPs:           []string{"1.1.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
			},
			[]*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-1",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "172.20.0.0/24",
						MaskLengthMin: 24,
						MaskLengthMax: 24,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "1.1.1.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
					{
						IpPrefix:      "10.1.0.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
				},
			},
			&gobgpapi.DefinedSet{},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet,
				List:        []string{},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSet,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: podCIDRSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: iBGPPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
			},
			[]*gobgpapi.Statement{},
			nil,
		},
		{
			"has nodes and services with custom import reject annotation",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.1.0.1",
				localAddressList:  []string{"0.0.0.0"},
				bgpPort:           10000,
				bgpFullMeshMode:   false,
				bgpEnableInternal: true,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				nodeAsnNumber:     100,
				podCidr:           "172.21.0.0/24",
				krNode:            ipv4CapableKRNode,
				podIPv4CIDRs:      []string{"172.21.0.0/24"},
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.11.0.1",
						},
						Transport: &gobgpapi.Transport{
							LocalAddress: "10.1.0.1",
						},
					},
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.11.0.2",
						},
						Transport: &gobgpapi.Transport{
							LocalAddress: "10.1.0.1",
						},
					},
				},
			},
			[]*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
						Annotations: map[string]string{
							"kube-router.io/node.asn":                    "100",
							"kube-router.io/node.bgp.customimportreject": "192.168.11.0/24,192.168.13.0/24,192.168.12.0/25, 10.1.0.0/16",
						},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{
								Type:    v1core.NodeInternalIP,
								Address: "10.1.0.2",
							},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR: "172.21.0.0/24",
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  "ClusterIP",
						ClusterIP:             "10.11.0.1",
						ExternalIPs:           []string{"1.11.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
			},
			[]*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-1",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "172.21.0.0/24",
						MaskLengthMin: 24,
						MaskLengthMax: 24,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "1.11.1.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
					{
						IpPrefix:      "10.11.0.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSet,
				List:        []string{"10.11.0.1/32", "10.11.0.2/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet,
				List:        []string{"10.11.0.1/32", "10.11.0.2/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "10.1.0.0/16",
						MaskLengthMin: 16,
						MaskLengthMax: ipv4MaskMinBits,
					},
					{
						IpPrefix:      "192.168.11.0/24",
						MaskLengthMin: 24,
						MaskLengthMax: ipv4MaskMinBits,
					},
					{
						IpPrefix:      "192.168.12.0/25",
						MaskLengthMin: 25,
						MaskLengthMax: ipv4MaskMinBits,
					},
					{
						IpPrefix:      "192.168.13.0/24",
						MaskLengthMin: 24,
						MaskLengthMax: ipv4MaskMinBits,
					},
				},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: podCIDRSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: iBGPPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				// V6 default-route cross-family reject statement (kube-router unconditionally
				// generates this for any peer set since defaultRouteSetV6 is always populated).
				{
					Name: "kube_router_import_stmt2",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt3",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: customImportRejectSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
			},
			nil,
		},
		{
			"has dual-stack nodes with V4+V6 custom import reject annotation",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.10.0.1",
				localAddressList:  []string{"0.0.0.0", "::"},
				bgpPort:           10000,
				bgpFullMeshMode:   false,
				bgpEnableInternal: true,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				nodeAsnNumber:     100,
				podCidr:           "172.30.0.0/24",
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP("10.10.0.2"),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP("10.10.0.2")}},
						NodeIPv6Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP("2001:db8:42:a::2")}},
					},
				},
				podIPv4CIDRs: []string{"172.30.0.0/24"},
				podIPv6CIDRs: []string{"2001:db8:42:1e::/64"},
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf:      &gobgpapi.PeerConf{NeighborAddress: "10.20.0.1"},
						Transport: &gobgpapi.Transport{LocalAddress: "10.10.0.2"},
					},
					{
						Conf:      &gobgpapi.PeerConf{NeighborAddress: "2001:db8:42:14::1"},
						Transport: &gobgpapi.Transport{LocalAddress: "2001:db8:42:a::2"},
					},
				},
			},
			[]*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
						Annotations: map[string]string{
							"kube-router.io/node.asn":                    "100",
							"kube-router.io/node.bgp.customimportreject": "192.168.11.0/24,2001:db8:cafe::/48,10.1.0.0/16,2001:db8:dead::/48",
						},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{Type: v1core.NodeInternalIP, Address: "10.10.0.2"},
							{Type: v1core.NodeInternalIP, Address: "2001:db8:42:a::2"},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR:  "172.30.0.0/24",
						PodCIDRs: []string{"172.30.0.0/24", "2001:db8:42:1e::/64"},
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-1", Namespace: "default"},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "10.20.0.5",
						ClusterIPs:            []string{"10.20.0.5", "2001:db8:42:14::5"},
						ExternalIPs:           []string{"1.20.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
			},
			[]*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels:    map[string]string{"kubernetes.io/service-name": "svc-1"},
					},
					Endpoints: []discoveryv1.Endpoint{{Addresses: []string{testNodeIPv4}}},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "172.30.0.0/24", MaskLengthMin: 24, MaskLengthMax: 24},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "1.20.1.1/32", MaskLengthMin: 32, MaskLengthMax: 32},
					{IpPrefix: "10.20.0.5/32", MaskLengthMin: 32, MaskLengthMax: 32},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSet,
				List:        []string{"10.20.0.1/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet,
				List:        []string{"10.20.0.1/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "10.1.0.0/16", MaskLengthMin: 16, MaskLengthMax: ipv4MaskMinBits},
					{IpPrefix: "192.168.11.0/24", MaskLengthMin: 24, MaskLengthMax: ipv4MaskMinBits},
				},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: podCIDRSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: iBGPPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: podCIDRSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: iBGPPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt2",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt3",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt4",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt5",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt2",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt3",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt4",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: customImportRejectSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt5",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: customImportRejectSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt6",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt7",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt8",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt9",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt10",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: customImportRejectSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt11",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: customImportRejectSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
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
				routerID:          "10.2.0.1",
				localAddressList:  []string{"0.0.0.0"},
				bgpPort:           10000,
				bgpFullMeshMode:   false,
				bgpEnableInternal: true,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				podCidr:           "172.22.0.0/24",
				krNode:            ipv4CapableKRNode,
				podIPv4CIDRs:      []string{"172.22.0.0/24"},
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.12.0.1",
						},
						Transport: &gobgpapi.Transport{
							LocalAddress: "10.2.0.1",
						},
					},
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.12.0.2",
						},
						Transport: &gobgpapi.Transport{
							LocalAddress: "10.2.0.1",
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
								Address: "10.2.0.2",
							},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR: "172.22.0.0/24",
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "10.12.0.1",
						ExternalIPs:           []string{"1.12.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
			},
			[]*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-1",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "172.22.0.0/24",
						MaskLengthMin: 24,
						MaskLengthMax: 24,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "1.12.1.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
					{
						IpPrefix:      "10.12.0.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSet,
				List:        []string{"10.12.0.1/32", "10.12.0.2/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet,
				List:        []string{"10.12.0.1/32", "10.12.0.2/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSet,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: podCIDRSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: iBGPPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				// V6 default-route cross-family reject statement (kube-router unconditionally
				// generates this for any peer set since defaultRouteSetV6 is always populated).
				{
					Name: "kube_router_import_stmt2",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
			},
			nil,
		},
		{
			"has dual-stack nodes and services with external peers",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.3.0.1",
				localAddressList:  []string{"0.0.0.0", "::"},
				bgpPort:           10000,
				bgpFullMeshMode:   false,
				bgpEnableInternal: true,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				podCidr:           "172.23.0.0/24",
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP("10.3.0.2"),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP("10.3.0.2")}},
						NodeIPv6Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP("2001:db8:42:3::2")}},
					},
				},
				podIPv4CIDRs: []string{"172.23.0.0/24"},
				podIPv6CIDRs: []string{"2001:db8:42:23::/64"},
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.13.0.1",
						},
						Transport: &gobgpapi.Transport{
							LocalAddress: "10.3.0.2",
						},
					},
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "2001:db8:42:13::1",
						},
						Transport: &gobgpapi.Transport{
							LocalAddress: "2001:db8:42:3::2",
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
								Address: "10.3.0.2",
							},
							{
								Type:    v1core.NodeInternalIP,
								Address: "2001:db8:42:3::2",
							},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR: "172.23.0.0/24",
						PodCIDRs: []string{
							"172.23.0.0/24",
							"2001:db8:42:23::/64",
						},
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "10.13.0.5",
						ClusterIPs:            []string{"10.13.0.5", "2001:db8:42:13::5"},
						ExternalIPs:           []string{"1.13.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
			},
			[]*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-1",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "172.23.0.0/24",
						MaskLengthMin: 24,
						MaskLengthMax: 24,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "1.13.1.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
					{
						IpPrefix:      "10.13.0.5/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSet,
				List:        []string{"10.13.0.1/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet,
				List:        []string{"10.13.0.1/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSet,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: podCIDRSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: iBGPPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: podCIDRSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: iBGPPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt2",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt3",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt4",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt5",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt2",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt3",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt4",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt5",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt6",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt7",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
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
				routerID:          "10.3.0.1",
				localAddressList:  []string{"0.0.0.0"},
				bgpPort:           10000,
				bgpFullMeshMode:   false,
				bgpEnableInternal: false,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				podCidr:           "172.23.0.0/24",
				krNode:            ipv4CapableKRNode,
				podIPv4CIDRs:      []string{"172.23.0.0/24"},
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.13.0.1",
						},
						Transport: &gobgpapi.Transport{
							LocalAddress: "10.3.0.1",
						},
					},
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.13.0.2",
						},
						Transport: &gobgpapi.Transport{
							LocalAddress: "10.3.0.1",
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
								Address: "10.3.0.2",
							},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR: "172.23.0.0/24",
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "10.13.0.1",
						ExternalIPs:           []string{"1.13.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
			},
			[]*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-1",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "172.23.0.0/24",
						MaskLengthMin: 24,
						MaskLengthMax: 24,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "1.13.1.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
					{
						IpPrefix:      "10.13.0.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSet,
				List:        []string{"10.13.0.1/32", "10.13.0.2/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet,
				List:        []string{"10.13.0.1/32", "10.13.0.2/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSet,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				// V6 default-route cross-family reject statement (kube-router unconditionally
				// generates this for any peer set since defaultRouteSetV6 is always populated).
				{
					Name: "kube_router_import_stmt2",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
			},
			nil,
		},
		{
			"has dual-stack nodes, services with external peers and iBGP disabled",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.7.0.1",
				localAddressList:  []string{"0.0.0.0", "::"},
				bgpPort:           10000,
				bgpFullMeshMode:   false,
				bgpEnableInternal: false,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				podCidr:           "172.27.0.0/24",
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP("10.7.0.2"),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP("10.7.0.2")}},
						NodeIPv6Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP("2001:db8:42:7::2")}},
					},
				},
				podIPv4CIDRs: []string{"172.27.0.0/24"},
				podIPv6CIDRs: []string{"2001:db8:42:27::/64"},
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf:      &gobgpapi.PeerConf{NeighborAddress: "10.17.0.1"},
						Transport: &gobgpapi.Transport{LocalAddress: "10.7.0.2"},
					},
					{
						Conf:      &gobgpapi.PeerConf{NeighborAddress: "2001:db8:42:17::1"},
						Transport: &gobgpapi.Transport{LocalAddress: "2001:db8:42:7::2"},
					},
				},
				nodeAsnNumber: 100,
			},
			[]*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "node-1",
						Annotations: map[string]string{"kube-router.io/node.asn": "100"},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{Type: v1core.NodeInternalIP, Address: "10.7.0.2"},
							{Type: v1core.NodeInternalIP, Address: "2001:db8:42:7::2"},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR:  "172.27.0.0/24",
						PodCIDRs: []string{"172.27.0.0/24", "2001:db8:42:27::/64"},
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-1", Namespace: "default"},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "10.17.0.5",
						ClusterIPs:            []string{"10.17.0.5", "2001:db8:42:17::5"},
						ExternalIPs:           []string{"1.17.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
			},
			[]*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels:    map[string]string{"kubernetes.io/service-name": "svc-1"},
					},
					Endpoints: []discoveryv1.Endpoint{{Addresses: []string{testNodeIPv4}}},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "172.27.0.0/24", MaskLengthMin: 24, MaskLengthMax: 24},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "1.17.1.1/32", MaskLengthMin: 32, MaskLengthMax: 32},
					{IpPrefix: "10.17.0.5/32", MaskLengthMin: 32, MaskLengthMax: 32},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSet,
				List:        []string{"10.17.0.1/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet,
				List:        []string{"10.17.0.1/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSet,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt2",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt3",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt2",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt3",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt4",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt5",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt6",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt7",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
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
				routerID:          "10.4.0.1",
				localAddressList:  []string{"0.0.0.0"},
				bgpPort:           10000,
				bgpEnableInternal: true,
				bgpFullMeshMode:   false,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				podCidr:           "172.24.0.0/24",
				krNode:            ipv4CapableKRNode,
				podIPv4CIDRs:      []string{"172.24.0.0/24"},
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.14.0.1",
						},
						Transport: &gobgpapi.Transport{
							LocalAddress: "10.4.0.1",
						},
					},
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.14.0.2",
						},
						Transport: &gobgpapi.Transport{
							LocalAddress: "10.4.0.1",
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
							"kube-router.io/node.asn":              "100",
							"kube-router.io/path-prepend.as":       "65100",
							"kube-router.io/path-prepend.repeat-n": "5",
						},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{
								Type:    v1core.NodeInternalIP,
								Address: "10.4.0.2",
							},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR: "172.24.0.0/24",
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "10.14.0.1",
						ExternalIPs:           []string{"1.14.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
			},
			[]*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-1",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "172.24.0.0/24",
						MaskLengthMin: 24,
						MaskLengthMax: 24,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "1.14.1.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
					{
						IpPrefix:      "10.14.0.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSet,
				List:        []string{"10.14.0.1/32", "10.14.0.2/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet,
				List:        []string{"10.14.0.1/32", "10.14.0.2/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSet,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: podCIDRSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: iBGPPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
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
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				// V6 default-route cross-family reject statement (kube-router unconditionally
				// generates this for any peer set since defaultRouteSetV6 is always populated).
				{
					Name: "kube_router_import_stmt2",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
			},
			nil,
		},
		{
			"prepends AS with dual-stack external peers",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.8.0.1",
				localAddressList:  []string{"0.0.0.0", "::"},
				bgpPort:           10000,
				bgpEnableInternal: true,
				bgpFullMeshMode:   false,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				podCidr:           "172.28.0.0/24",
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP("10.8.0.2"),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP("10.8.0.2")}},
						NodeIPv6Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP("2001:db8:42:8::2")}},
					},
				},
				podIPv4CIDRs: []string{"172.28.0.0/24"},
				podIPv6CIDRs: []string{"2001:db8:42:28::/64"},
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf:      &gobgpapi.PeerConf{NeighborAddress: "10.18.0.1"},
						Transport: &gobgpapi.Transport{LocalAddress: "10.8.0.2"},
					},
					{
						Conf:      &gobgpapi.PeerConf{NeighborAddress: "2001:db8:42:18::1"},
						Transport: &gobgpapi.Transport{LocalAddress: "2001:db8:42:8::2"},
					},
				},
				nodeAsnNumber: 100,
			},
			[]*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
						Annotations: map[string]string{
							"kube-router.io/node.asn":              "100",
							"kube-router.io/path-prepend.as":       "65100",
							"kube-router.io/path-prepend.repeat-n": "5",
						},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{Type: v1core.NodeInternalIP, Address: "10.8.0.2"},
							{Type: v1core.NodeInternalIP, Address: "2001:db8:42:8::2"},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR:  "172.28.0.0/24",
						PodCIDRs: []string{"172.28.0.0/24", "2001:db8:42:28::/64"},
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-1", Namespace: "default"},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "10.18.0.5",
						ClusterIPs:            []string{"10.18.0.5", "2001:db8:42:18::5"},
						ExternalIPs:           []string{"1.18.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
			},
			[]*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels:    map[string]string{"kubernetes.io/service-name": "svc-1"},
					},
					Endpoints: []discoveryv1.Endpoint{{Addresses: []string{testNodeIPv4}}},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "172.28.0.0/24", MaskLengthMin: 24, MaskLengthMax: 24},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "1.18.1.1/32", MaskLengthMin: 32, MaskLengthMax: 32},
					{IpPrefix: "10.18.0.5/32", MaskLengthMin: 32, MaskLengthMax: 32},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSet,
				List:        []string{"10.18.0.1/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet,
				List:        []string{"10.18.0.1/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSet,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: podCIDRSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: iBGPPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: podCIDRSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: iBGPPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt2",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
						AsPrepend: &gobgpapi.AsPrependAction{
							Asn:    65100,
							Repeat: 5,
						},
					},
				},
				{
					Name: "kube_router_export_stmt3",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
						AsPrepend: &gobgpapi.AsPrependAction{
							Asn:    65100,
							Repeat: 5,
						},
					},
				},
				{
					Name: "kube_router_export_stmt4",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
						AsPrepend: &gobgpapi.AsPrependAction{
							Asn:    65100,
							Repeat: 5,
						},
					},
				},
				{
					Name: "kube_router_export_stmt5",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
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
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt2",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt3",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt4",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt5",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt6",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt7",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
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
				routerID:          "10.5.0.1",
				localAddressList:  []string{"0.0.0.0"},
				bgpPort:           10000,
				bgpEnableInternal: true,
				bgpFullMeshMode:   false,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				podCidr:           "172.25.0.0/24",
				krNode:            ipv4CapableKRNode,
				podIPv4CIDRs:      []string{"172.25.0.0/24"},
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.15.0.1",
						},
						Transport: &gobgpapi.Transport{
							LocalAddress: "10.5.0.1",
						},
					},
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.15.0.2",
						},
						Transport: &gobgpapi.Transport{
							LocalAddress: "10.5.0.1",
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
							"kube-router.io/node.asn":        "100",
							"kube-router.io/path-prepend.as": "65100",
						},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{
								Type:    v1core.NodeInternalIP,
								Address: "10.5.0.2",
							},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR: "172.25.0.0/24",
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "10.15.0.1",
						ExternalIPs:           []string{"1.15.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
			},
			[]*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-1",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "172.25.0.0/24",
						MaskLengthMin: 24,
						MaskLengthMax: 24,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "1.15.1.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
					{
						IpPrefix:      "10.15.0.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSet,
				List:        []string{"10.15.0.1/32", "10.15.0.2/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet,
				List:        []string{"10.15.0.1/32", "10.15.0.2/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSet,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: podCIDRSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: iBGPPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
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
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
			},
			fmt.Errorf("both %s and %s must be set", pathPrependASNAnnotation, pathPrependRepeatNAnnotation),
		},
		{
			"has nodes with communities defined",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.6.0.1",
				localAddressList:  []string{"0.0.0.0"},
				bgpPort:           10000,
				bgpFullMeshMode:   false,
				bgpEnableInternal: false,
				bgpServer:         gobgp.NewBgpServer(),
				advertisePodCidr:  true,
				activeNodes:       make(map[string]bool),
				podCidr:           "172.26.0.0/24",
				krNode:            ipv4CapableKRNode,
				podIPv4CIDRs:      []string{"172.26.0.0/24"},
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.16.0.1",
						},
						Transport: &gobgpapi.Transport{
							LocalAddress: "10.6.0.1",
						},
					},
					{
						Conf: &gobgpapi.PeerConf{
							NeighborAddress: "10.16.0.2",
						},
						Transport: &gobgpapi.Transport{
							LocalAddress: "10.6.0.1",
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
							"kube-router.io/node.asn":             "100",
							"kube-router.io/node.bgp.communities": "no-export",
						},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{
								Type:    v1core.NodeInternalIP,
								Address: "10.6.0.2",
							},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR: "172.26.0.0/24",
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "10.16.0.1",
						ExternalIPs:           []string{"1.16.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
			},
			[]*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-1",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "172.26.0.0/24",
						MaskLengthMin: 24,
						MaskLengthMax: 24,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet,
				Prefixes: []*gobgpapi.Prefix{
					{
						IpPrefix:      "1.16.1.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
					{
						IpPrefix:      "10.16.0.1/32",
						MaskLengthMin: 32,
						MaskLengthMax: 32,
					},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSet,
				List:        []string{"10.16.0.1/32", "10.16.0.2/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet,
				List:        []string{"10.16.0.1/32", "10.16.0.2/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSet,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						Community: &gobgpapi.CommunityAction{
							Type:        gobgpapi.CommunityAction_TYPE_ADD,
							Communities: []string{"65535:65281"}, // corresponds to no-export
						},
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: podCIDRSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						Community: &gobgpapi.CommunityAction{
							Type:        gobgpapi.CommunityAction_TYPE_ADD,
							Communities: []string{"65535:65281"}, // corresponds to no-export
						},
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				// V6 default-route cross-family reject statement (kube-router unconditionally
				// generates this for any peer set since defaultRouteSetV6 is always populated).
				{
					Name: "kube_router_import_stmt2",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
			},
			nil,
		},
		{
			"has dual-stack nodes with communities defined",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.9.0.1",
				localAddressList:  []string{"0.0.0.0", "::"},
				bgpPort:           10000,
				bgpFullMeshMode:   false,
				bgpEnableInternal: false,
				bgpServer:         gobgp.NewBgpServer(),
				advertisePodCidr:  true,
				activeNodes:       make(map[string]bool),
				podCidr:           "172.29.0.0/24",
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP("10.9.0.2"),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP("10.9.0.2")}},
						NodeIPv6Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP("2001:db8:42:9::2")}},
					},
				},
				podIPv4CIDRs: []string{"172.29.0.0/24"},
				podIPv6CIDRs: []string{"2001:db8:42:29::/64"},
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf:      &gobgpapi.PeerConf{NeighborAddress: "10.19.0.1"},
						Transport: &gobgpapi.Transport{LocalAddress: "10.9.0.2"},
					},
					{
						Conf:      &gobgpapi.PeerConf{NeighborAddress: "2001:db8:42:19::1"},
						Transport: &gobgpapi.Transport{LocalAddress: "2001:db8:42:9::2"},
					},
				},
				nodeAsnNumber: 100,
			},
			[]*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
						Annotations: map[string]string{
							"kube-router.io/node.asn":             "100",
							"kube-router.io/node.bgp.communities": "no-export",
						},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{Type: v1core.NodeInternalIP, Address: "10.9.0.2"},
							{Type: v1core.NodeInternalIP, Address: "2001:db8:42:9::2"},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR:  "172.29.0.0/24",
						PodCIDRs: []string{"172.29.0.0/24", "2001:db8:42:29::/64"},
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-1", Namespace: "default"},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "10.19.0.5",
						ClusterIPs:            []string{"10.19.0.5", "2001:db8:42:19::5"},
						ExternalIPs:           []string{"1.19.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
			},
			[]*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels:    map[string]string{"kubernetes.io/service-name": "svc-1"},
					},
					Endpoints: []discoveryv1.Endpoint{{Addresses: []string{testNodeIPv4}}},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "172.29.0.0/24", MaskLengthMin: 24, MaskLengthMax: 24},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "1.19.1.1/32", MaskLengthMin: 32, MaskLengthMax: 32},
					{IpPrefix: "10.19.0.5/32", MaskLengthMin: 32, MaskLengthMax: 32},
				},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSet,
				List:        []string{"10.19.0.1/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet,
				List:        []string{"10.19.0.1/32"},
			},
			&gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSet,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						Community: &gobgpapi.CommunityAction{
							Type:        gobgpapi.CommunityAction_TYPE_ADD,
							Communities: []string{"65535:65281"}, // corresponds to no-export
						},
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						Community: &gobgpapi.CommunityAction{
							Type:        gobgpapi.CommunityAction_TYPE_ADD,
							Communities: []string{"65535:65281"}, // corresponds to no-export
						},
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt2",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: podCIDRSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						Community: &gobgpapi.CommunityAction{
							Type:        gobgpapi.CommunityAction_TYPE_ADD,
							Communities: []string{"65535:65281"}, // corresponds to no-export
						},
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt3",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: podCIDRSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						Community: &gobgpapi.CommunityAction{
							Type:        gobgpapi.CommunityAction_TYPE_ADD,
							Communities: []string{"65535:65281"}, // corresponds to no-export
						},
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt4",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						Community: &gobgpapi.CommunityAction{
							Type:        gobgpapi.CommunityAction_TYPE_ADD,
							Communities: []string{"65535:65281"}, // corresponds to no-export
						},
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt5",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						Community: &gobgpapi.CommunityAction{
							Type:        gobgpapi.CommunityAction_TYPE_ADD,
							Communities: []string{"65535:65281"}, // corresponds to no-export
						},
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt6",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: podCIDRSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						Community: &gobgpapi.CommunityAction{
							Type:        gobgpapi.CommunityAction_TYPE_ADD,
							Communities: []string{"65535:65281"}, // corresponds to no-export
						},
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt7",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: podCIDRSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: externalPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						Community: &gobgpapi.CommunityAction{
							Type:        gobgpapi.CommunityAction_TYPE_ADD,
							Communities: []string{"65535:65281"}, // corresponds to no-export
						},
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_ACCEPT,
					},
				},
			},
			[]*gobgpapi.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt2",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt3",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSet,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt4",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt5",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: serviceVIPsSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt6",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSet,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt7",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: defaultRouteSetV6,
						},
						NeighborSet: &gobgpapi.MatchSet{
							Type: gobgpapi.MatchSet_TYPE_ANY,
							Name: allPeerSetV6,
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_ROUTE_ACTION_REJECT,
					},
				},
			},
			nil,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			startInformersForRoutes(t, testcase.nrc, testcase.nrc.clientset)

			if err := createNodes(testcase.nrc.clientset, testcase.existingNodes); err != nil {
				t.Errorf("failed to create existing nodes: %v", err)
			}

			if err := createServices(testcase.nrc.clientset, testcase.existingServices); err != nil {
				t.Errorf("failed to create existing services: %v", err)
			}

			if err := createEndpointSlices(testcase.nrc.clientset, testcase.existingEndpoints); err != nil {
				t.Errorf("failed to create existing endpoints: %v", err)
			}

			err := testcase.nrc.startBgpServer(false)
			if testcase.startBGPServerErr != nil && err == nil {
				t.Errorf("expected error when starting BGP server, got nil on testcase: %s", testcase.name)
			}
			if err != nil {
				assert.EqualError(t, testcase.startBGPServerErr, err.Error())
			}
			// If the server was not expected to start we should stop here as the rest of the tests are unimportant
			if testcase.startBGPServerErr != nil {
				return
			}
			defer func() {
				if err := testcase.nrc.bgpServer.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{}); err != nil {
					t.Fatalf("failed to stop BGP server : %s", err)
				}
			}()

			// ClusterIPs and ExternalIPs
			waitForListerWithTimeout(testcase.nrc.svcLister, time.Second*10, t)

			testcase.nrc.advertiseClusterIP = true
			testcase.nrc.advertiseExternalIP = true
			testcase.nrc.advertiseLoadBalancerIP = false

			informerFactory := informers.NewSharedInformerFactory(testcase.nrc.clientset, 0)
			nodeInformer := informerFactory.Core().V1().Nodes().Informer()
			testcase.nrc.nodeLister = nodeInformer.GetIndexer()
			if err := testcase.nrc.AddPolicies(); err != nil {
				// If AddPolicies() failed we should stop here as there is no point in further evaluating policies
				t.Fatalf("unexpected error when invoking AddPolicies(): %v", err)
			}

			err = testcase.nrc.bgpServer.ListDefinedSet(context.Background(),
				&gobgpapi.ListDefinedSetRequest{DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX, Name: podCIDRSet},
				func(podDefinedSet *gobgpapi.DefinedSet) {
					if !reflect.DeepEqual(podDefinedSet, testcase.podDefinedSet) {
						t.Logf("expected pod defined set: %+v", testcase.podDefinedSet)
						t.Logf("actual pod defined set: %+v", podDefinedSet)
						t.Error("unexpected pod defined set")
					}
				})
			if err != nil {
				t.Fatalf("error validating defined sets: %v", err)
			}

			err = testcase.nrc.bgpServer.ListDefinedSet(context.Background(),
				&gobgpapi.ListDefinedSetRequest{DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX, Name: customImportRejectSet},
				func(customImportRejectDefinedSet *gobgpapi.DefinedSet) {
					if !reflect.DeepEqual(customImportRejectDefinedSet, testcase.customImportRejectDefinedSet) {
						t.Logf("expected customimportreject defined set: %+v", testcase.customImportRejectDefinedSet)
						t.Logf("actual customimportreject defined set: %+v", customImportRejectDefinedSet)
						t.Error("unexpected customimportreject defined set")
					}
				})
			if err != nil {
				t.Fatalf("error validating defined sets: %v", err)
			}

			err = testcase.nrc.bgpServer.ListDefinedSet(context.Background(), &gobgpapi.ListDefinedSetRequest{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet}, func(clusterIPDefinedSet *gobgpapi.DefinedSet) {
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
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSet}, func(externalPeerDefinedSet *gobgpapi.DefinedSet) {
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
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet}, func(allPeerDefinedSet *gobgpapi.DefinedSet) {
				if !reflect.DeepEqual(allPeerDefinedSet, testcase.allPeerDefinedSet) {
					t.Logf("expected all peer defined set: %+v", testcase.allPeerDefinedSet.List)
					t.Logf("actual all peer defined set: %+v", allPeerDefinedSet.List)
					t.Error("unexpected all peer defined set")
				}
			})
			if err != nil {
				t.Fatalf("error validating defined sets: %v", err)
			}

			checkPolicies(t, testcase, gobgpapi.PolicyDirection_POLICY_DIRECTION_EXPORT, testcase.exportPolicyStatements)
			checkPolicies(t, testcase, gobgpapi.PolicyDirection_POLICY_DIRECTION_IMPORT, testcase.importPolicyStatements)
		})
	}
}

func checkPolicies(t *testing.T, testcase PolicyTestCase, gobgpDirection gobgpapi.PolicyDirection, policyStatements []*gobgpapi.Statement) {
	t.Helper()

	var direction string
	if gobgpDirection.String() == "POLICY_DIRECTION_EXPORT" {
		direction = "export"
	} else if gobgpDirection.String() == "POLICY_DIRECTION_IMPORT" {
		direction = "import"
	}

	// Discover the version-suffixed name (e.g. "kube_router_import1") rather than reconstructing
	// it, so the helper still works if AddPolicies is ever called more than once on the same server.
	policyExists := false
	actualPolicyName := ""
	expectedPolicyPrefix := "kube_router_" + direction
	err := testcase.nrc.bgpServer.ListPolicy(context.Background(), &gobgpapi.ListPolicyRequest{}, func(policy *gobgpapi.Policy) {
		if strings.HasPrefix(policy.Name, expectedPolicyPrefix) {
			policyExists = true
			actualPolicyName = policy.Name
		}
	})
	if err != nil {
		t.Fatalf("failed to get policy: %v", err)
	}
	if !policyExists {
		t.Errorf("policy with prefix %q was not added", expectedPolicyPrefix)
	}

	policyAssignmentExists := false
	err = testcase.nrc.bgpServer.ListPolicyAssignment(context.Background(), &gobgpapi.ListPolicyAssignmentRequest{}, func(policyAssignment *gobgpapi.PolicyAssignment) {
		if policyAssignment.Name == "global" && policyAssignment.Direction == gobgpDirection {
			for _, policy := range policyAssignment.Policies {
				if policy.Name == actualPolicyName {
					policyAssignmentExists = true
				}
			}
		}
	})
	if err != nil {
		t.Fatalf("failed to get policy assignments: %v", err)
	}

	if !policyAssignmentExists {
		t.Errorf("%s policy assignment 'kube_router_%s' was not added", direction, direction)
	}

	// Bail before the next ListPolicy call: an empty Name filter would match every policy and
	// produce a misleading secondary failure.
	if actualPolicyName == "" {
		return
	}

	// GoBGP's ListPolicy does exact name matching, so we must pass the full versioned name.
	policyFound := false
	err = testcase.nrc.bgpServer.ListPolicy(context.Background(), &gobgpapi.ListPolicyRequest{Name: actualPolicyName}, func(foundPolicy *gobgpapi.Policy) {
		policyFound = true
		for _, expectedStatement := range policyStatements {
			found := false
			for _, statement := range foundPolicy.Statements {
				if statementsEquivalent(statement, expectedStatement) {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("statement %v not found", expectedStatement)
			}
		}
		if len(policyStatements) != len(foundPolicy.Statements) {
			t.Errorf("expected %d statements, found %d: %v",
				len(policyStatements), len(foundPolicy.Statements), foundPolicy.Statements)
		}
	})
	if err != nil {
		t.Fatalf("ListPolicy failed: %v", err)
	}
	if !policyFound {
		t.Fatalf("expected to find policy %q, but none matched", actualPolicyName)
	}
}

// statementsEquivalent compares two BGP policy statements by their semantically meaningful fields
// (Conditions and Actions), ignoring implementation-detail fields whose values are stable but not
// what the test author intends to assert:
//
//   - Name: GoBGP preserves the kube-router-generated name (e.g. "servicevipsdefinedsetallpeerset"),
//     not a sequential index like "kube_router_import_stmt0" that several test cases use. Comparing
//     by Name would require either rewriting every expected entry or coupling the tests to the
//     internal naming scheme.
//   - Conditions.RpkiResult: production code never sets this field, so the actual value is always
//     the proto default (0). Several test cases pre-fill it as -1, which would never match.
//
// What actually matters for these tests is *what* the statement matches (PrefixSet, NeighborSet)
// and *what* it does (Actions), both of which are compared via proto.Equal (which understands
// protobuf semantics and ignores internal MessageState — unlike reflect.DeepEqual).
func statementsEquivalent(a, b *gobgpapi.Statement) bool {
	if !proto.Equal(a.GetActions(), b.GetActions()) {
		return false
	}
	return proto.Equal(normalizeConditions(a.GetConditions()), normalizeConditions(b.GetConditions()))
}

// normalizeConditions returns a copy of the given Conditions with RpkiResult zeroed out, so the
// proto.Equal comparison ignores it. Uses proto.Clone to avoid copying the embedded sync.Mutex
// in protoimpl.MessageState (which `go vet` flags via copylocks).
func normalizeConditions(c *gobgpapi.Conditions) *gobgpapi.Conditions {
	if c == nil {
		return nil
	}
	cp, _ := proto.Clone(c).(*gobgpapi.Conditions)
	cp.RpkiResult = 0
	return cp
}

// DefinedSetContentsTestCase exercises the *contents* of the named GoBGP defined sets that AddPolicies()
// constructs. It is intentionally separate from PolicyTestCase: PolicyTestCase verifies that policy
// statements reference the right named sets (wiring), this verifies that those named sets actually
// contain the right prefixes/neighbors (data).
//
// A nil expected field is treated as "do not assert this set". To assert that a set is absent from
// GoBGP (callback never fires), pass &gobgpapi.DefinedSet{} (zero value).
type DefinedSetContentsTestCase struct {
	name              string
	nrc               *NetworkRoutingController
	existingNodes     []*v1core.Node
	existingServices  []*v1core.Service
	existingEndpoints []*discoveryv1.EndpointSlice

	// Prefix-typed defined sets
	expectedPodCIDRSet              *gobgpapi.DefinedSet
	expectedPodCIDRSetV6            *gobgpapi.DefinedSet
	expectedServiceVIPsSet          *gobgpapi.DefinedSet
	expectedServiceVIPsSetV6        *gobgpapi.DefinedSet
	expectedDefaultRouteSet         *gobgpapi.DefinedSet
	expectedDefaultRouteSetV6       *gobgpapi.DefinedSet
	expectedCustomImportRejectSet   *gobgpapi.DefinedSet
	expectedCustomImportRejectSetV6 *gobgpapi.DefinedSet

	// Neighbor-typed defined sets
	expectedExternalPeerSet   *gobgpapi.DefinedSet
	expectedExternalPeerSetV6 *gobgpapi.DefinedSet
	expectedAllPeerSet        *gobgpapi.DefinedSet
	expectedAllPeerSetV6      *gobgpapi.DefinedSet
}

// Test_AddDefinedSetContents verifies that AddPolicies() populates the GoBGP defined sets with the
// correct prefixes and neighbor lists for the IPv4-only, IPv6-only, and dual-stack scenarios.
//
// This complements Test_AddPolicies, which only verifies that policy *statements* reference the
// named sets correctly; here we assert the named sets actually contain the expected values. In
// particular, this is the only place that confirms defaultRouteSetV6 actually contains "::/0".
func Test_AddDefinedSetContents(t *testing.T) {
	ipv4KRNode := &utils.LocalKRNode{
		KRNode: utils.KRNode{
			NodeName:      "node-1",
			PrimaryIP:     net.ParseIP("10.40.0.2"),
			NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP("10.40.0.2")}},
		},
	}
	ipv6KRNode := &utils.LocalKRNode{
		KRNode: utils.KRNode{
			NodeName:      "node-1",
			PrimaryIP:     net.ParseIP("2001:db8:42:40::2"),
			NodeIPv6Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP("2001:db8:42:40::2")}},
		},
	}
	dualStackKRNode := &utils.LocalKRNode{
		KRNode: utils.KRNode{
			NodeName:      "node-1",
			PrimaryIP:     net.ParseIP("10.41.0.2"),
			NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP("10.41.0.2")}},
			NodeIPv6Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP("2001:db8:42:41::2")}},
		},
	}

	testcases := []DefinedSetContentsTestCase{
		{
			name: "IPv4-only populates V4 sets and leaves V6 sets empty",
			nrc: &NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.40.0.1",
				localAddressList:  []string{"0.0.0.0"},
				bgpPort:           10000,
				bgpFullMeshMode:   false,
				bgpEnableInternal: true,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				nodeAsnNumber:     100,
				podCidr:           "172.40.0.0/24",
				krNode:            ipv4KRNode,
				podIPv4CIDRs:      []string{"172.40.0.0/24"},
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf:      &gobgpapi.PeerConf{NeighborAddress: "10.140.0.1"},
						Transport: &gobgpapi.Transport{LocalAddress: "10.40.0.2"},
					},
				},
			},
			existingNodes: []*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "node-1",
						Annotations: map[string]string{"kube-router.io/node.asn": "100"},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{Type: v1core.NodeInternalIP, Address: "10.40.0.2"},
						},
					},
					Spec: v1core.NodeSpec{PodCIDR: "172.40.0.0/24"},
				},
			},
			existingServices: []*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-1", Namespace: "default"},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "10.140.0.5",
						ExternalIPs:           []string{"1.40.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
			},
			existingEndpoints: []*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels:    map[string]string{"kubernetes.io/service-name": "svc-1"},
					},
					Endpoints: []discoveryv1.Endpoint{{Addresses: []string{testNodeIPv4}}},
				},
			},

			expectedPodCIDRSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "172.40.0.0/24", MaskLengthMin: 24, MaskLengthMax: 24},
				},
			},
			expectedPodCIDRSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSetV6,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			expectedServiceVIPsSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "1.40.1.1/32", MaskLengthMin: 32, MaskLengthMax: 32},
					{IpPrefix: "10.140.0.5/32", MaskLengthMin: 32, MaskLengthMax: 32},
				},
			},
			expectedServiceVIPsSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSetV6,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			expectedDefaultRouteSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        defaultRouteSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "0.0.0.0/0", MaskLengthMin: 0, MaskLengthMax: 0},
				},
			},
			expectedDefaultRouteSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        defaultRouteSetV6,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "::/0", MaskLengthMin: 0, MaskLengthMax: 0},
				},
			},
			expectedCustomImportRejectSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSet,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			expectedCustomImportRejectSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSetV6,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			expectedExternalPeerSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSet,
				List:        []string{"10.140.0.1/32"},
			},
			expectedExternalPeerSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSetV6,
				List:        []string{},
			},
			expectedAllPeerSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet,
				List:        []string{"10.140.0.1/32"},
			},
			expectedAllPeerSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSetV6,
				List:        []string{},
			},
		},
		{
			name: "IPv6-only populates V6 sets and leaves V4 sets empty",
			nrc: &NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.40.0.1",
				localAddressList:  []string{"::"},
				bgpPort:           10000,
				bgpFullMeshMode:   false,
				bgpEnableInternal: true,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				nodeAsnNumber:     100,
				podCidr:           "2001:db8:42:40::/64",
				krNode:            ipv6KRNode,
				podIPv6CIDRs:      []string{"2001:db8:42:40::/64"},
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf:      &gobgpapi.PeerConf{NeighborAddress: "2001:db8:42:140::1"},
						Transport: &gobgpapi.Transport{LocalAddress: "2001:db8:42:40::2"},
					},
				},
			},
			existingNodes: []*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "node-1",
						Annotations: map[string]string{"kube-router.io/node.asn": "100"},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{Type: v1core.NodeInternalIP, Address: "2001:db8:42:40::2"},
						},
					},
					Spec: v1core.NodeSpec{PodCIDR: "2001:db8:42:40::/64"},
				},
			},
			existingServices: []*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-1", Namespace: "default"},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "2001:db8:42:140::5",
						ClusterIPs:            []string{"2001:db8:42:140::5"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
			},
			existingEndpoints: []*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels:    map[string]string{"kubernetes.io/service-name": "svc-1"},
					},
					Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"2001:db8:42:40::2"}}},
				},
			},

			expectedPodCIDRSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSet,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			expectedPodCIDRSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSetV6,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "2001:db8:42:40::/64", MaskLengthMin: 64, MaskLengthMax: 64},
				},
			},
			expectedServiceVIPsSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			expectedServiceVIPsSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSetV6,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "2001:db8:42:140::5/128", MaskLengthMin: 128, MaskLengthMax: 128},
				},
			},
			expectedDefaultRouteSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        defaultRouteSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "0.0.0.0/0", MaskLengthMin: 0, MaskLengthMax: 0},
				},
			},
			expectedDefaultRouteSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        defaultRouteSetV6,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "::/0", MaskLengthMin: 0, MaskLengthMax: 0},
				},
			},
			expectedCustomImportRejectSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSet,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			expectedCustomImportRejectSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSetV6,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			expectedExternalPeerSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSet,
				List:        []string{},
			},
			expectedExternalPeerSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSetV6,
				List:        []string{"2001:db8:42:140::1/128"},
			},
			expectedAllPeerSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet,
				List:        []string{},
			},
			expectedAllPeerSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSetV6,
				List:        []string{"2001:db8:42:140::1/128"},
			},
		},
		{
			name: "dual-stack populates both V4 and V6 sets",
			nrc: &NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.41.0.1",
				localAddressList:  []string{"0.0.0.0", "::"},
				bgpPort:           10000,
				bgpFullMeshMode:   false,
				bgpEnableInternal: true,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				nodeAsnNumber:     100,
				podCidr:           "172.41.0.0/24",
				krNode:            dualStackKRNode,
				podIPv4CIDRs:      []string{"172.41.0.0/24"},
				podIPv6CIDRs:      []string{"2001:db8:42:41::/64"},
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf:      &gobgpapi.PeerConf{NeighborAddress: "10.141.0.1"},
						Transport: &gobgpapi.Transport{LocalAddress: "10.41.0.2"},
					},
					{
						Conf:      &gobgpapi.PeerConf{NeighborAddress: "2001:db8:42:141::1"},
						Transport: &gobgpapi.Transport{LocalAddress: "2001:db8:42:41::2"},
					},
				},
			},
			existingNodes: []*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "node-1",
						Annotations: map[string]string{"kube-router.io/node.asn": "100"},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{Type: v1core.NodeInternalIP, Address: "10.41.0.2"},
							{Type: v1core.NodeInternalIP, Address: "2001:db8:42:41::2"},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR:  "172.41.0.0/24",
						PodCIDRs: []string{"172.41.0.0/24", "2001:db8:42:41::/64"},
					},
				},
			},
			existingServices: []*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-1", Namespace: "default"},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "10.141.0.5",
						ClusterIPs:            []string{"10.141.0.5", "2001:db8:42:141::5"},
						ExternalIPs:           []string{"1.41.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
			},
			existingEndpoints: []*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels:    map[string]string{"kubernetes.io/service-name": "svc-1"},
					},
					Endpoints: []discoveryv1.Endpoint{{Addresses: []string{testNodeIPv4}}},
				},
			},

			expectedPodCIDRSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "172.41.0.0/24", MaskLengthMin: 24, MaskLengthMax: 24},
				},
			},
			expectedPodCIDRSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSetV6,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "2001:db8:42:41::/64", MaskLengthMin: 64, MaskLengthMax: 64},
				},
			},
			expectedServiceVIPsSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "1.41.1.1/32", MaskLengthMin: 32, MaskLengthMax: 32},
					{IpPrefix: "10.141.0.5/32", MaskLengthMin: 32, MaskLengthMax: 32},
				},
			},
			expectedServiceVIPsSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSetV6,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "2001:db8:42:141::5/128", MaskLengthMin: 128, MaskLengthMax: 128},
				},
			},
			expectedDefaultRouteSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        defaultRouteSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "0.0.0.0/0", MaskLengthMin: 0, MaskLengthMax: 0},
				},
			},
			expectedDefaultRouteSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        defaultRouteSetV6,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "::/0", MaskLengthMin: 0, MaskLengthMax: 0},
				},
			},
			expectedCustomImportRejectSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSet,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			expectedCustomImportRejectSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSetV6,
				Prefixes:    []*gobgpapi.Prefix{},
			},
			expectedExternalPeerSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSet,
				List:        []string{"10.141.0.1/32"},
			},
			expectedExternalPeerSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSetV6,
				List:        []string{"2001:db8:42:141::1/128"},
			},
			expectedAllPeerSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet,
				List:        []string{"10.141.0.1/32"},
			},
			expectedAllPeerSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSetV6,
				List:        []string{"2001:db8:42:141::1/128"},
			},
		},
		{
			name: "dual-stack with V4+V6 customImportReject annotation populates both sets",
			nrc: &NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.42.0.1",
				localAddressList:  []string{"0.0.0.0", "::"},
				bgpPort:           10000,
				bgpFullMeshMode:   false,
				bgpEnableInternal: true,
				bgpServer:         gobgp.NewBgpServer(),
				activeNodes:       make(map[string]bool),
				nodeAsnNumber:     100,
				podCidr:           "172.42.0.0/24",
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP("10.42.0.2"),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP("10.42.0.2")}},
						NodeIPv6Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP("2001:db8:42:42::2")}},
					},
				},
				podIPv4CIDRs: []string{"172.42.0.0/24"},
				podIPv6CIDRs: []string{"2001:db8:42:42::/64"},
				globalPeerRouters: []*gobgpapi.Peer{
					{
						Conf:      &gobgpapi.PeerConf{NeighborAddress: "10.142.0.1"},
						Transport: &gobgpapi.Transport{LocalAddress: "10.42.0.2"},
					},
					{
						Conf:      &gobgpapi.PeerConf{NeighborAddress: "2001:db8:42:142::1"},
						Transport: &gobgpapi.Transport{LocalAddress: "2001:db8:42:42::2"},
					},
				},
			},
			existingNodes: []*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
						Annotations: map[string]string{
							"kube-router.io/node.asn":                    "100",
							"kube-router.io/node.bgp.customimportreject": "192.168.11.0/24,2001:db8:cafe::/48,10.1.0.0/16,2001:db8:dead::/48",
						},
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{Type: v1core.NodeInternalIP, Address: "10.42.0.2"},
							{Type: v1core.NodeInternalIP, Address: "2001:db8:42:42::2"},
						},
					},
					Spec: v1core.NodeSpec{
						PodCIDR:  "172.42.0.0/24",
						PodCIDRs: []string{"172.42.0.0/24", "2001:db8:42:42::/64"},
					},
				},
			},
			existingServices: []*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-1", Namespace: "default"},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "10.142.0.5",
						ClusterIPs:            []string{"10.142.0.5", "2001:db8:42:142::5"},
						ExternalIPs:           []string{"1.42.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
			},
			existingEndpoints: []*discoveryv1.EndpointSlice{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels:    map[string]string{"kubernetes.io/service-name": "svc-1"},
					},
					Endpoints: []discoveryv1.Endpoint{{Addresses: []string{testNodeIPv4}}},
				},
			},

			expectedPodCIDRSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "172.42.0.0/24", MaskLengthMin: 24, MaskLengthMax: 24},
				},
			},
			expectedPodCIDRSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        podCIDRSetV6,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "2001:db8:42:42::/64", MaskLengthMin: 64, MaskLengthMax: 64},
				},
			},
			expectedServiceVIPsSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "1.42.1.1/32", MaskLengthMin: 32, MaskLengthMax: 32},
					{IpPrefix: "10.142.0.5/32", MaskLengthMin: 32, MaskLengthMax: 32},
				},
			},
			expectedServiceVIPsSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        serviceVIPsSetV6,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "2001:db8:42:142::5/128", MaskLengthMin: 128, MaskLengthMax: 128},
				},
			},
			expectedDefaultRouteSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        defaultRouteSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "0.0.0.0/0", MaskLengthMin: 0, MaskLengthMax: 0},
				},
			},
			expectedDefaultRouteSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        defaultRouteSetV6,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "::/0", MaskLengthMin: 0, MaskLengthMax: 0},
				},
			},
			expectedCustomImportRejectSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSet,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "10.1.0.0/16", MaskLengthMin: 16, MaskLengthMax: 32},
					{IpPrefix: "192.168.11.0/24", MaskLengthMin: 24, MaskLengthMax: 32},
				},
			},
			expectedCustomImportRejectSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_PREFIX,
				Name:        customImportRejectSetV6,
				Prefixes: []*gobgpapi.Prefix{
					{IpPrefix: "2001:db8:cafe::/48", MaskLengthMin: 48, MaskLengthMax: 128},
					{IpPrefix: "2001:db8:dead::/48", MaskLengthMin: 48, MaskLengthMax: 128},
				},
			},
			expectedExternalPeerSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSet,
				List:        []string{"10.142.0.1/32"},
			},
			expectedExternalPeerSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        externalPeerSetV6,
				List:        []string{"2001:db8:42:142::1/128"},
			},
			expectedAllPeerSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSet,
				List:        []string{"10.142.0.1/32"},
			},
			expectedAllPeerSetV6: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR,
				Name:        allPeerSetV6,
				List:        []string{"2001:db8:42:142::1/128"},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			startInformersForRoutes(t, tc.nrc, tc.nrc.clientset)

			if err := createNodes(tc.nrc.clientset, tc.existingNodes); err != nil {
				t.Fatalf("failed to create existing nodes: %v", err)
			}
			if err := createServices(tc.nrc.clientset, tc.existingServices); err != nil {
				t.Fatalf("failed to create existing services: %v", err)
			}
			if err := createEndpointSlices(tc.nrc.clientset, tc.existingEndpoints); err != nil {
				t.Fatalf("failed to create existing endpoints: %v", err)
			}

			if err := tc.nrc.startBgpServer(false); err != nil {
				t.Fatalf("failed to start BGP server: %v", err)
			}
			defer func() {
				if err := tc.nrc.bgpServer.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{}); err != nil {
					t.Fatalf("failed to stop BGP server: %s", err)
				}
			}()

			waitForListerWithTimeout(tc.nrc.svcLister, time.Second*10, t)

			tc.nrc.advertiseClusterIP = true
			tc.nrc.advertiseExternalIP = true
			tc.nrc.advertiseLoadBalancerIP = false

			informerFactory := informers.NewSharedInformerFactory(tc.nrc.clientset, 0)
			tc.nrc.nodeLister = informerFactory.Core().V1().Nodes().Informer().GetIndexer()
			if err := tc.nrc.AddPolicies(); err != nil {
				t.Fatalf("unexpected error from AddPolicies(): %v", err)
			}

			checkDefinedSet(t, tc.nrc, podCIDRSet, gobgpapi.DefinedType_DEFINED_TYPE_PREFIX, tc.expectedPodCIDRSet)
			checkDefinedSet(t, tc.nrc, podCIDRSetV6, gobgpapi.DefinedType_DEFINED_TYPE_PREFIX, tc.expectedPodCIDRSetV6)
			checkDefinedSet(t, tc.nrc, serviceVIPsSet, gobgpapi.DefinedType_DEFINED_TYPE_PREFIX, tc.expectedServiceVIPsSet)
			checkDefinedSet(t, tc.nrc, serviceVIPsSetV6, gobgpapi.DefinedType_DEFINED_TYPE_PREFIX, tc.expectedServiceVIPsSetV6)
			checkDefinedSet(t, tc.nrc, defaultRouteSet, gobgpapi.DefinedType_DEFINED_TYPE_PREFIX, tc.expectedDefaultRouteSet)
			checkDefinedSet(t, tc.nrc, defaultRouteSetV6, gobgpapi.DefinedType_DEFINED_TYPE_PREFIX, tc.expectedDefaultRouteSetV6)
			checkDefinedSet(t, tc.nrc, customImportRejectSet, gobgpapi.DefinedType_DEFINED_TYPE_PREFIX, tc.expectedCustomImportRejectSet)
			checkDefinedSet(t, tc.nrc, customImportRejectSetV6, gobgpapi.DefinedType_DEFINED_TYPE_PREFIX, tc.expectedCustomImportRejectSetV6)
			checkDefinedSet(t, tc.nrc, externalPeerSet, gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR, tc.expectedExternalPeerSet)
			checkDefinedSet(t, tc.nrc, externalPeerSetV6, gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR, tc.expectedExternalPeerSetV6)
			checkDefinedSet(t, tc.nrc, allPeerSet, gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR, tc.expectedAllPeerSet)
			checkDefinedSet(t, tc.nrc, allPeerSetV6, gobgpapi.DefinedType_DEFINED_TYPE_NEIGHBOR, tc.expectedAllPeerSetV6)
		})
	}
}

// checkDefinedSet asserts that the named defined set in GoBGP matches `expected`. A nil `expected`
// skips the check. If the set is absent from GoBGP (callback never fires), the actual value is
// treated as &gobgpapi.DefinedSet{} (zero value) so absence can be expressed by passing the same.
func checkDefinedSet(t *testing.T, nrc *NetworkRoutingController, name string,
	defType gobgpapi.DefinedType, expected *gobgpapi.DefinedSet) {
	t.Helper()
	if expected == nil {
		return
	}
	var actual *gobgpapi.DefinedSet
	err := nrc.bgpServer.ListDefinedSet(context.Background(),
		&gobgpapi.ListDefinedSetRequest{DefinedType: defType, Name: name},
		func(ds *gobgpapi.DefinedSet) {
			actual = ds
		})
	if err != nil {
		t.Fatalf("error listing defined set %s: %v", name, err)
	}
	if actual == nil {
		actual = &gobgpapi.DefinedSet{}
	}
	// proto.Equal compares by field semantics and ignores protobuf internal state (MessageState,
	// sizeCache) that reflect.DeepEqual would treat as a real difference.
	if !proto.Equal(actual, expected) {
		t.Logf("expected %s defined set: %+v", name, expected)
		t.Logf("actual %s defined set: %+v", name, actual)
		t.Errorf("unexpected %s defined set contents", name)
	}
}
