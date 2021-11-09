package routing

import (
	"context"
	"fmt"
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
	addPolicyErr           error
	startBGPServerErr      error
}

func Test_AddPolicies(t *testing.T) {
	testcases := []PolicyTestCase{
		{
			"has nodes and services",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.0.0.0",
				bgpPort:           10000,
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
						Type:        v1core.ServiceTypeClusterIP,
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
						RpkiResult: -1,
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
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "defaultroutedefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "allpeerset",
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
			},
			nil,
			nil,
		},
		{
			"has nodes, services with external peers",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.0.0.0",
				bgpPort:           10000,
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
						Type:        v1core.ServiceTypeClusterIP,
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
						RpkiResult: -1,
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
						RpkiResult: -1,
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
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "defaultroutedefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "allpeerset",
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
			},
			nil,
			nil,
		},
		{
			"has nodes, services with external peers and iBGP disabled",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.0.0.0",
				bgpPort:           10000,
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
						Type:        v1core.ServiceTypeClusterIP,
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
						RpkiResult: -1,
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
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "defaultroutedefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "allpeerset",
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
			},
			nil,
			nil,
		},
		{
			"prepends AS with external peers",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.0.0.0",
				bgpPort:           10000,
				bgpEnableInternal: true,
				bgpFullMeshMode:   false,
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
							"kube-router.io/node.asn":              "100",
							"kube-router.io/path-prepend.as":       "65100",
							"kube-router.io/path-prepend.repeat-n": "5",
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
						Type:        v1core.ServiceTypeClusterIP,
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
						RpkiResult: -1,
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
						RpkiResult: -1,
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
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "defaultroutedefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "allpeerset",
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
			},
			nil,
			nil,
		},
		{
			"only prepends AS when both node annotations are present",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.0.0.0",
				bgpPort:           10000,
				bgpEnableInternal: true,
				bgpFullMeshMode:   false,
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
							"kube-router.io/node.asn":        "100",
							"kube-router.io/path-prepend.as": "65100",
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
						Type:        v1core.ServiceTypeClusterIP,
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
						RpkiResult: -1,
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
						RpkiResult: -1,
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
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "defaultroutedefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "allpeerset",
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
			},
			nil,
			fmt.Errorf("both %s and %s must be set", pathPrependASNAnnotation, pathPrependRepeatNAnnotation),
		},
		{
			"has nodes with communities defined",
			&NetworkRoutingController{
				clientset:         fake.NewSimpleClientset(),
				hostnameOverride:  "node-1",
				routerID:          "10.0.0.0",
				bgpPort:           10000,
				bgpFullMeshMode:   false,
				bgpEnableInternal: false,
				bgpServer:         gobgp.NewBgpServer(),
				advertisePodCidr:  true,
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
							"kube-router.io/node.asn":             "100",
							"kube-router.io/node.bgp.communities": "no-export",
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
						Type:        v1core.ServiceTypeClusterIP,
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
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						Community: &gobgpapi.CommunityAction{
							ActionType:  gobgpapi.CommunityActionType_COMMUNITY_ADD,
							Communities: []string{"65535:65281"}, // corresponds to no-export
						},
						RouteAction: gobgpapi.RouteAction_ACCEPT,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "podcidrdefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "externalpeerset",
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						Community: &gobgpapi.CommunityAction{
							ActionType:  gobgpapi.CommunityActionType_COMMUNITY_ADD,
							Communities: []string{"65535:65281"}, // corresponds to no-export
						},
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
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
				{
					Name: "kube_router_import_stmt1",
					Conditions: &gobgpapi.Conditions{
						PrefixSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "defaultroutedefinedset",
						},
						NeighborSet: &gobgpapi.MatchSet{
							MatchType: gobgpapi.MatchType_ANY,
							Name:      "allpeerset",
						},
						RpkiResult: -1,
					},
					Actions: &gobgpapi.Actions{
						RouteAction: gobgpapi.RouteAction_REJECT,
					},
				},
			},
			nil,
			nil,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			startInformersForRoutes(testcase.nrc, testcase.nrc.clientset)

			if err := createNodes(testcase.nrc.clientset, testcase.existingNodes); err != nil {
				t.Errorf("failed to create existing nodes: %v", err)
			}

			if err := createServices(testcase.nrc.clientset, testcase.existingServices); err != nil {
				t.Errorf("failed to create existing nodes: %v", err)
			}

			err := testcase.nrc.startBgpServer(false)
			if !reflect.DeepEqual(err, testcase.startBGPServerErr) {
				t.Logf("expected err when invoking startBGPServer(): %v", testcase.startBGPServerErr)
				t.Logf("actual err from startBGPServer() received: %v", err)
				t.Error("unexpected error")
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
			err = testcase.nrc.AddPolicies()
			if !reflect.DeepEqual(err, testcase.addPolicyErr) {
				t.Logf("expected err when invoking AddPolicies(): %v", testcase.addPolicyErr)
				t.Logf("actual err from AddPolicies() received: %v", err)
				t.Error("unexpected error")
			}
			// If we expect AddPolicies() to fail we should stop here as there is no point in further evaluating policies
			if testcase.addPolicyErr != nil {
				return
			}

			err = testcase.nrc.bgpServer.ListDefinedSet(context.Background(),
				&gobgpapi.ListDefinedSetRequest{DefinedType: gobgpapi.DefinedType_PREFIX, Name: "podcidrdefinedset"},
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

			checkPolicies(t, testcase, gobgpapi.PolicyDirection_EXPORT, testcase.exportPolicyStatements)
			checkPolicies(t, testcase, gobgpapi.PolicyDirection_IMPORT, testcase.importPolicyStatements)
		})
	}
}

func checkPolicies(t *testing.T, testcase PolicyTestCase, gobgpDirection gobgpapi.PolicyDirection, policyStatements []*gobgpapi.Statement) {
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
		t.Errorf("%s policy assignment 'kube_router_%s' was not added", direction, direction)
	}
	err = testcase.nrc.bgpServer.ListPolicy(context.Background(), &gobgpapi.ListPolicyRequest{Name: fmt.Sprintf("kube_router_%s", direction)}, func(foundPolicy *gobgpapi.Policy) {
		for _, expectedStatement := range policyStatements {
			found := false
			for _, statement := range foundPolicy.Statements {
				if reflect.DeepEqual(statement, expectedStatement) {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("statement %v not found", expectedStatement)
			}
		}
		if len(policyStatements) != len(foundPolicy.Statements) {
			t.Errorf("unexpected statement found: %v", foundPolicy.Statements)
		}
	})
	if err != nil {
		t.Fatalf("expected to find a policy, but none were returned")
	}
}
