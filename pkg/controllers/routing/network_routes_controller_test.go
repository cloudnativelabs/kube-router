package routing

import (
	"context"
	"fmt"
	"net"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/internal/testutils"
	"github.com/cloudnativelabs/kube-router/v2/pkg/bgp"
	"github.com/cloudnativelabs/kube-router/v2/pkg/k8s/indexers"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	. "github.com/onsi/ginkgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1core "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	gobgp "github.com/osrg/gobgp/v3/pkg/server"
)

func Test_advertiseClusterIPs(t *testing.T) {
	testcases := []struct {
		name              string
		nrc               *NetworkRoutingController
		existingServices  []*v1core.Service
		existingEndpoints []*discoveryv1.EndpointSlice
		// the key is the subnet from the watch event
		watchEvents map[string]bool
	}{
		{
			"add bgp path for service with ClusterIP",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
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
						ClusterIP:             "10.0.0.1",
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
			map[string]bool{
				"10.0.0.1/32": true,
			},
		},
		{
			"add bgp path for service with ClusterIP/NodePort/LoadBalancer",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
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
						ClusterIP:             "10.0.0.1",
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  LoadBalancerST,
						ClusterIP:             "10.0.0.2",
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-3",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  NodePortST,
						ClusterIP:             "10.0.0.3",
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
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-2",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-3",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-3",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			map[string]bool{
				"10.0.0.1/32": true,
				"10.0.0.2/32": true,
				"10.0.0.3/32": true,
			},
		},
		{
			"add bgp path for invalid service type",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
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
						ClusterIP:             "10.0.0.1",
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-2",
					},
					Spec: v1core.ServiceSpec{
						Type:                  "AnotherType",
						ClusterIP:             "10.0.0.2",
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
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-2",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			map[string]bool{
				"10.0.0.1/32": true,
			},
		},
		{
			"add bgp path for headless service",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
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
						ClusterIP:             "10.0.0.1",
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "None",
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-3",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "",
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
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-2",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-3",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-3",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			map[string]bool{
				"10.0.0.1/32": true,
			},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			go testcase.nrc.bgpServer.Serve()
			global := &gobgpapi.Global{
				Asn:        1,
				RouterId:   testNodeIPv4,
				ListenPort: 10000,
			}
			err := testcase.nrc.bgpServer.StartBgp(context.Background(), &gobgpapi.StartBgpRequest{Global: global})
			if err != nil {
				t.Fatalf("failed to start BGP server: %v", err)
			}
			defer func() {
				if err = testcase.nrc.bgpServer.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{}); err != nil {
					t.Fatalf("failed to stop BGP server : %s", err)
				}
			}()

			clientset := fake.NewSimpleClientset()
			startInformersForRoutes(testcase.nrc, clientset)

			err = createServices(clientset, testcase.existingServices)
			if err != nil {
				t.Fatalf("failed to create existing services: %v", err)
			}

			err = createEndpointSlices(clientset, testcase.existingEndpoints)
			if err != nil {
				t.Fatalf("failed to create existing endpoint slices: %v", err)
			}

			waitForListerWithTimeout(testcase.nrc.svcLister, time.Second*10, t)

			eventMu := sync.Mutex{}
			var events []*gobgpapi.Path
			pathWatch := func(r *gobgpapi.WatchEventResponse) {
				if table := r.GetTable(); table != nil {
					for _, p := range table.Paths {
						if p.Family.Afi == gobgpapi.Family_AFI_IP || p.Family.Safi == gobgpapi.Family_SAFI_UNICAST {
							func() {
								defer eventMu.Unlock()
								eventMu.Lock()
								events = append(events, p)
							}()
						}
					}
				}
			}
			err = testcase.nrc.bgpServer.WatchEvent(context.Background(), &gobgpapi.WatchEventRequest{
				Table: &gobgpapi.WatchEventRequest_Table{
					Filters: []*gobgpapi.WatchEventRequest_Table_Filter{
						{
							Type: gobgpapi.WatchEventRequest_Table_Filter_BEST,
						},
					},
				},
			}, pathWatch)
			if err != nil {
				t.Fatalf("failed to register callback to mortor global routing table: %v", err)
			}
			// ClusterIPs
			testcase.nrc.advertiseClusterIP = true
			testcase.nrc.advertiseExternalIP = false
			testcase.nrc.advertiseLoadBalancerIP = false

			toAdvertise, toWithdraw, _ := testcase.nrc.getVIPs()
			testcase.nrc.advertiseVIPs(toAdvertise)
			testcase.nrc.withdrawVIPs(toWithdraw)

			timeoutCh := time.After(time.Second * 10)
			ticker := time.NewTicker(100 * time.Millisecond)
		L:
			for {
				select {
				case <-timeoutCh:
					t.Fatalf("timeout exceeded waiting for %d watch events, got %d", len(testcase.watchEvents), len(events))
				case <-ticker.C:
					stopLoop := func() bool {
						defer eventMu.Unlock()
						eventMu.Lock()
						return len(events) == len(testcase.watchEvents)
					}()
					if stopLoop {
						break L
					}
				}
			}

			defer eventMu.Unlock()
			eventMu.Lock()
			for _, path := range events {
				nlri := path.GetNlri()
				var prefix gobgpapi.IPAddressPrefix
				err = nlri.UnmarshalTo(&prefix)
				if err != nil {
					t.Fatalf("Invalid nlri in advertised path")
				}
				advertisedPrefix := prefix.Prefix + "/" + fmt.Sprint(prefix.PrefixLen)
				if _, ok := testcase.watchEvents[advertisedPrefix]; !ok {
					t.Errorf("got unexpected path: %v", advertisedPrefix)
				}
			}
		})
	}
}

func Test_advertiseExternalIPs(t *testing.T) {
	testcases := []struct {
		name              string
		nrc               *NetworkRoutingController
		existingServices  []*v1core.Service
		existingEndpoints []*discoveryv1.EndpointSlice
		// the key is the subnet from the watch event
		watchEvents map[string]bool
	}{
		{
			"add bgp path for service with external IPs",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						PrimaryIP:     net.ParseIP("10.0.0.1"),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
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
						ClusterIP:             "10.0.0.1",
						ExternalIPs:           []string{"1.1.1.1", "2.2.2.2"},
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
			map[string]bool{
				"1.1.1.1/32": true,
				"2.2.2.2/32": true,
			},
		},
		{
			"add bgp path for services with external IPs of type ClusterIP/NodePort/LoadBalancer",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
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
						ClusterIP:             "10.0.0.1",
						ExternalIPs:           []string{"1.1.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  LoadBalancerST,
						ClusterIP:             "10.0.0.2",
						ExternalIPs:           []string{"2.2.2.2"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-3",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  NodePortST,
						ClusterIP:             "10.0.0.3",
						ExternalIPs:           []string{"3.3.3.3", "4.4.4.4"},
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
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-2",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-3",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-3",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			map[string]bool{
				"1.1.1.1/32": true,
				"2.2.2.2/32": true,
				"3.3.3.3/32": true,
				"4.4.4.4/32": true,
			},
		},
		{
			"add bgp path for invalid service type",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
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
						ClusterIP:             "10.0.0.1",
						ExternalIPs:           []string{"1.1.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  "AnotherType",
						ClusterIP:             "10.0.0.2",
						ExternalIPs:           []string{"2.2.2.2"},
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
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-2",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			map[string]bool{
				"1.1.1.1/32": true,
			},
		},
		{
			"add bgp path for headless service",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
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
						ClusterIP:             "10.0.0.1",
						ExternalIPs:           []string{"1.1.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "None",
						ExternalIPs:           []string{"2.2.2.2"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-3",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "",
						ExternalIPs:           []string{"3.3.3.3"},
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
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-2",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-3",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-3",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			map[string]bool{
				"1.1.1.1/32": true,
			},
		},
		{
			"skip bgp path to loadbalancerIP for service without LoadBalancer IP",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
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
						Type:                  LoadBalancerST,
						ClusterIP:             "10.0.0.1",
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
					Status: v1core.ServiceStatus{
						LoadBalancer: v1core.LoadBalancerStatus{
							Ingress: []v1core.LoadBalancerIngress{
								{
									Hostname: "foo-bar.zone.elb.example.com",
								},
							},
						},
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
			map[string]bool{},
		},
		{
			"add bgp path to loadbalancerIP for service with LoadBalancer IP",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
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
						Type:                  LoadBalancerST,
						ClusterIP:             "10.0.0.1",
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
					Status: v1core.ServiceStatus{
						LoadBalancer: v1core.LoadBalancerStatus{
							Ingress: []v1core.LoadBalancerIngress{
								{
									IP: "10.0.255.1",
								},
								{
									IP: "10.0.255.2",
								},
							},
						},
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
			map[string]bool{
				"10.0.255.1/32": true,
				"10.0.255.2/32": true,
			},
		},
		{
			"no bgp path to nil loadbalancerIPs for service with LoadBalancer",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
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
						Type:                  LoadBalancerST,
						ClusterIP:             "10.0.0.1",
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
					Status: v1core.ServiceStatus{
						LoadBalancer: v1core.LoadBalancerStatus{
							Ingress: []v1core.LoadBalancerIngress{},
						},
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
			map[string]bool{},
		},
		{
			"no bgp path to loadbalancerIPs for service with LoadBalancer and skiplbips annotation",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Annotations: map[string]string{
							svcSkipLbIpsAnnotation: "true",
						},
					},
					Spec: v1core.ServiceSpec{
						Type:                  LoadBalancerST,
						ClusterIP:             "10.0.0.1",
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
					Status: v1core.ServiceStatus{
						LoadBalancer: v1core.LoadBalancerStatus{
							Ingress: []v1core.LoadBalancerIngress{
								{
									IP: "10.0.255.1",
								},
								{
									IP: "10.0.255.2",
								},
							},
						},
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
			map[string]bool{},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			go testcase.nrc.bgpServer.Serve()
			global := &gobgpapi.Global{
				Asn:        1,
				RouterId:   testNodeIPv4,
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

			var events []*gobgpapi.Path
			eventMu := sync.Mutex{}
			pathWatch := func(r *gobgpapi.WatchEventResponse) {
				if table := r.GetTable(); table != nil {
					for _, p := range table.Paths {
						if p.Family.Afi == gobgpapi.Family_AFI_IP || p.Family.Safi == gobgpapi.Family_SAFI_UNICAST {
							func() {
								defer eventMu.Unlock()
								eventMu.Lock()
								events = append(events, p)
							}()
						}
					}
				}
			}
			err = testcase.nrc.bgpServer.WatchEvent(context.Background(), &gobgpapi.WatchEventRequest{
				Table: &gobgpapi.WatchEventRequest_Table{
					Filters: []*gobgpapi.WatchEventRequest_Table_Filter{
						{
							Type: gobgpapi.WatchEventRequest_Table_Filter_BEST,
						},
					},
				},
			}, pathWatch)
			if err != nil {
				t.Fatalf("failed to register callback to mortor global routing table: %v", err)
			}
			clientset := fake.NewSimpleClientset()
			startInformersForRoutes(testcase.nrc, clientset)

			err = createServices(clientset, testcase.existingServices)
			if err != nil {
				t.Fatalf("failed to create existing services: %v", err)
			}

			err = createEndpointSlices(clientset, testcase.existingEndpoints)
			if err != nil {
				t.Fatalf("failed to create existing endpoint slices: %v", err)
			}

			waitForListerWithTimeout(testcase.nrc.svcLister, time.Second*10, t)

			// ExternalIPs
			testcase.nrc.advertiseClusterIP = false
			testcase.nrc.advertiseExternalIP = true
			testcase.nrc.advertiseLoadBalancerIP = true

			toAdvertise, toWithdraw, _ := testcase.nrc.getVIPs()
			testcase.nrc.advertiseVIPs(toAdvertise)
			testcase.nrc.withdrawVIPs(toWithdraw)
			timeoutCh := time.After(time.Second * 10)
			ticker := time.NewTicker(500 * time.Millisecond)

		L:
			for {
				select {
				case <-timeoutCh:
					t.Fatalf("timeout exceeded waiting for %d watch events, got %d", len(testcase.watchEvents), len(events))
				case <-ticker.C:
					stopLoop := func() bool {
						defer eventMu.Unlock()
						eventMu.Lock()
						return len(events) == len(testcase.watchEvents)
					}()
					if stopLoop {
						break L
					}
				}
			}

			defer eventMu.Unlock()
			eventMu.Lock()
			for _, path := range events {
				nlri := path.GetNlri()
				var prefix gobgpapi.IPAddressPrefix
				err = nlri.UnmarshalTo(&prefix)
				if err != nil {
					t.Fatalf("Invalid nlri in advertised path")
				}
				advertisedPrefix := prefix.Prefix + "/" + fmt.Sprint(prefix.PrefixLen)
				if _, ok := testcase.watchEvents[advertisedPrefix]; !ok {
					t.Errorf("got unexpected path: %v", advertisedPrefix)
				}
			}
		})
	}
}

func Test_advertiseAnnotationOptOut(t *testing.T) {
	testcases := []struct {
		name              string
		nrc               *NetworkRoutingController
		existingServices  []*v1core.Service
		existingEndpoints []*discoveryv1.EndpointSlice
		// the key is the subnet from the watch event
		watchEvents map[string]bool
	}{
		{
			"add bgp paths for all service IPs",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
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
						ClusterIP:             "10.0.0.1",
						ExternalIPs:           []string{"1.1.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  NodePortST,
						ClusterIP:             "10.0.0.2",
						ExternalIPs:           []string{"2.2.2.2", "3.3.3.3"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-3",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  LoadBalancerST,
						ClusterIP:             "10.0.0.3",
						ExternalIPs:           []string{"4.4.4.4"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
					Status: v1core.ServiceStatus{
						LoadBalancer: v1core.LoadBalancerStatus{
							Ingress: []v1core.LoadBalancerIngress{
								{
									IP: "10.0.255.1",
								},
								{
									IP: "10.0.255.2",
								},
							},
						},
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
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-2",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-3",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-3",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			map[string]bool{
				"10.0.0.1/32":   true,
				"10.0.0.2/32":   true,
				"10.0.0.3/32":   true,
				"1.1.1.1/32":    true,
				"2.2.2.2/32":    true,
				"3.3.3.3/32":    true,
				"4.4.4.4/32":    true,
				"10.0.255.1/32": true,
				"10.0.255.2/32": true,
			},
		},
		{
			"opt out to advertise any IPs via annotations",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Annotations: map[string]string{
							svcAdvertiseClusterAnnotation:      "false",
							svcAdvertiseExternalAnnotation:     "false",
							svcAdvertiseLoadBalancerAnnotation: "false",
						},
					},
					Spec: v1core.ServiceSpec{
						Type:                  LoadBalancerST,
						ClusterIP:             "10.0.0.1",
						ExternalIPs:           []string{"1.1.1.1", "2.2.2.2"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
					Status: v1core.ServiceStatus{
						LoadBalancer: v1core.LoadBalancerStatus{
							Ingress: []v1core.LoadBalancerIngress{
								{
									IP: "10.0.255.1",
								},
								{
									IP: "10.0.255.2",
								},
							},
						},
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
			map[string]bool{},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			go testcase.nrc.bgpServer.Serve()
			global := &gobgpapi.Global{
				Asn:        1,
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

			var events []*gobgpapi.Path
			eventMu := sync.Mutex{}
			pathWatch := func(r *gobgpapi.WatchEventResponse) {
				if table := r.GetTable(); table != nil {
					for _, p := range table.Paths {
						if p.Family.Afi == gobgpapi.Family_AFI_IP || p.Family.Safi == gobgpapi.Family_SAFI_UNICAST {
							func() {
								defer eventMu.Unlock()
								eventMu.Lock()
								events = append(events, p)
							}()
						}
					}
				}
			}
			err = testcase.nrc.bgpServer.WatchEvent(context.Background(), &gobgpapi.WatchEventRequest{
				Table: &gobgpapi.WatchEventRequest_Table{
					Filters: []*gobgpapi.WatchEventRequest_Table_Filter{
						{
							Type: gobgpapi.WatchEventRequest_Table_Filter_BEST,
						},
					},
				},
			}, pathWatch)
			if err != nil {
				t.Fatalf("failed to register callback to mortor global routing table: %v", err)
			}

			clientset := fake.NewSimpleClientset()
			startInformersForRoutes(testcase.nrc, clientset)

			err = createServices(clientset, testcase.existingServices)
			if err != nil {
				t.Fatalf("failed to create existing services: %v", err)
			}

			err = createEndpointSlices(clientset, testcase.existingEndpoints)
			if err != nil {
				t.Fatalf("failed to create existing endpoints: %v", err)
			}

			waitForListerWithTimeout(testcase.nrc.svcLister, time.Second*10, t)

			// By default advertise all IPs
			testcase.nrc.advertiseClusterIP = true
			testcase.nrc.advertiseExternalIP = true
			testcase.nrc.advertiseLoadBalancerIP = true

			toAdvertise, toWithdraw, _ := testcase.nrc.getVIPs()
			testcase.nrc.advertiseVIPs(toAdvertise)
			testcase.nrc.withdrawVIPs(toWithdraw)
			timeoutCh := time.After(time.Second * 10)
			ticker := time.NewTicker(100 * time.Millisecond)

		L:
			for {
				select {
				case <-timeoutCh:
					t.Fatalf("timeout exceeded waiting for %d watch events, got %d", len(testcase.watchEvents), len(events))
				case <-ticker.C:
					stopLoop := func() bool {
						defer eventMu.Unlock()
						eventMu.Lock()
						return len(events) == len(testcase.watchEvents)
					}()
					if stopLoop {
						break L
					}
				}
			}

			defer eventMu.Unlock()
			eventMu.Lock()
			for _, path := range events {
				nlri := path.GetNlri()
				var prefix gobgpapi.IPAddressPrefix
				err = nlri.UnmarshalTo(&prefix)
				if err != nil {
					t.Fatalf("Invalid nlri in advertised path")
				}
				advertisedPrefix := prefix.Prefix + "/" + fmt.Sprint(prefix.PrefixLen)
				if _, ok := testcase.watchEvents[advertisedPrefix]; !ok {
					t.Errorf("got unexpected path: %v", advertisedPrefix)
				}
			}
		})
	}
}

func Test_advertiseAnnotationOptIn(t *testing.T) {
	testcases := []struct {
		name              string
		nrc               *NetworkRoutingController
		existingServices  []*v1core.Service
		existingEndpoints []*discoveryv1.EndpointSlice
		// the key is the subnet from the watch event
		watchEvents map[string]bool
	}{
		{
			"no bgp paths for any service IPs",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
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
						ClusterIP:             "10.0.0.1",
						ExternalIPs:           []string{"1.1.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:                  NodePortST,
						ClusterIP:             "10.0.0.2",
						ExternalIPs:           []string{"2.2.2.2", "3.3.3.3"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-3",
						Namespace: "default",
					},
					Spec: v1core.ServiceSpec{
						Type:      LoadBalancerST,
						ClusterIP: "10.0.0.3",
						// ignored since LoadBalancer services don't
						// advertise external IPs.
						ExternalIPs:           []string{"4.4.4.4"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
					Status: v1core.ServiceStatus{
						LoadBalancer: v1core.LoadBalancerStatus{
							Ingress: []v1core.LoadBalancerIngress{
								{
									IP: "10.0.255.1",
								},
								{
									IP: "10.0.255.2",
								},
							},
						},
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
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-2",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-3",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-3",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			map[string]bool{},
		},
		{
			"opt in to advertise all IPs via annotations",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Annotations: map[string]string{
							svcAdvertiseClusterAnnotation:      "true",
							svcAdvertiseExternalAnnotation:     "true",
							svcAdvertiseLoadBalancerAnnotation: "true",
						},
					},
					Spec: v1core.ServiceSpec{
						Type:                  ClusterIPST,
						ClusterIP:             "10.0.0.1",
						ExternalIPs:           []string{"1.1.1.1"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
						Annotations: map[string]string{
							svcAdvertiseClusterAnnotation:      "true",
							svcAdvertiseExternalAnnotation:     "true",
							svcAdvertiseLoadBalancerAnnotation: "true",
						},
					},
					Spec: v1core.ServiceSpec{
						Type:                  NodePortST,
						ClusterIP:             "10.0.0.2",
						ExternalIPs:           []string{"2.2.2.2", "3.3.3.3"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-3",
						Namespace: "default",
						Annotations: map[string]string{
							svcAdvertiseClusterAnnotation:      "true",
							svcAdvertiseExternalAnnotation:     "true",
							svcAdvertiseLoadBalancerAnnotation: "true",
						},
					},
					Spec: v1core.ServiceSpec{
						Type:                  LoadBalancerST,
						ClusterIP:             "10.0.0.3",
						ExternalIPs:           []string{"4.4.4.4"},
						InternalTrafficPolicy: &testClusterIntTrafPol,
						ExternalTrafficPolicy: testClusterExtTrafPol,
					},
					Status: v1core.ServiceStatus{
						LoadBalancer: v1core.LoadBalancerStatus{
							Ingress: []v1core.LoadBalancerIngress{
								{
									IP: "10.0.255.1",
								},
								{
									IP: "10.0.255.2",
								},
							},
						},
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
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-2",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-3",
						Namespace: "default",
						Labels: map[string]string{
							"kubernetes.io/service-name": "svc-3",
						},
					},
					Endpoints: []discoveryv1.Endpoint{
						{
							Addresses: []string{testNodeIPv4},
						},
					},
				},
			},
			map[string]bool{
				"10.0.0.1/32":   true,
				"10.0.0.2/32":   true,
				"10.0.0.3/32":   true,
				"1.1.1.1/32":    true,
				"2.2.2.2/32":    true,
				"3.3.3.3/32":    true,
				"4.4.4.4/32":    true,
				"10.0.255.1/32": true,
				"10.0.255.2/32": true,
			},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			go testcase.nrc.bgpServer.Serve()
			global := &gobgpapi.Global{
				Asn:        1,
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

			var events []*gobgpapi.Path
			eventMu := sync.Mutex{}
			pathWatch := func(r *gobgpapi.WatchEventResponse) {
				if table := r.GetTable(); table != nil {
					for _, p := range table.Paths {
						if p.Family.Afi == gobgpapi.Family_AFI_IP || p.Family.Safi == gobgpapi.Family_SAFI_UNICAST {
							func() {
								defer eventMu.Unlock()
								eventMu.Lock()
								events = append(events, p)
							}()
						}
					}
				}
			}
			err = testcase.nrc.bgpServer.WatchEvent(context.Background(), &gobgpapi.WatchEventRequest{
				Table: &gobgpapi.WatchEventRequest_Table{
					Filters: []*gobgpapi.WatchEventRequest_Table_Filter{
						{
							Type: gobgpapi.WatchEventRequest_Table_Filter_BEST,
						},
					},
				},
			}, pathWatch)
			if err != nil {
				t.Fatalf("failed to register callback to mortor global routing table: %v", err)
			}

			clientset := fake.NewSimpleClientset()
			startInformersForRoutes(testcase.nrc, clientset)

			err = createServices(clientset, testcase.existingServices)
			if err != nil {
				t.Fatalf("failed to create existing services: %v", err)
			}

			err = createEndpointSlices(clientset, testcase.existingEndpoints)
			if err != nil {
				t.Fatalf("failed to create existing endpoint slices: %v", err)
			}

			waitForListerWithTimeout(testcase.nrc.svcLister, time.Second*10, t)

			// By default do not advertise any IPs
			testcase.nrc.advertiseClusterIP = false
			testcase.nrc.advertiseExternalIP = false
			testcase.nrc.advertiseLoadBalancerIP = false

			toAdvertise, toWithdraw, _ := testcase.nrc.getVIPs()
			testcase.nrc.advertiseVIPs(toAdvertise)
			testcase.nrc.withdrawVIPs(toWithdraw)

			timeoutCh := time.After(time.Second * 10)
			ticker := time.NewTicker(100 * time.Millisecond)

		L:
			for {
				select {
				case <-timeoutCh:
					t.Fatalf("timeout exceeded waiting for %d watch events, got %d", len(testcase.watchEvents), len(events))
				case <-ticker.C:
					stopLoop := func() bool {
						defer eventMu.Unlock()
						eventMu.Lock()
						return len(events) == len(testcase.watchEvents)
					}()
					if stopLoop {
						break L
					}
				}
			}

			defer eventMu.Unlock()
			eventMu.Lock()
			for _, path := range events {
				nlri := path.GetNlri()
				var prefix gobgpapi.IPAddressPrefix
				err = nlri.UnmarshalTo(&prefix)
				if err != nil {
					t.Fatalf("Invalid nlri in advertised path")
				}
				advertisedPrefix := prefix.Prefix + "/" + fmt.Sprint(prefix.PrefixLen)
				if _, ok := testcase.watchEvents[advertisedPrefix]; !ok {
					t.Errorf("got unexpected path: %v", advertisedPrefix)
				}
			}
		})
	}
}

func Test_nodeHasEndpointsForService(t *testing.T) {
	testcases := []struct {
		name             string
		nrc              *NetworkRoutingController
		existingService  *v1core.Service
		existingEndpoint *discoveryv1.EndpointSlice
		nodeHasEndpoints bool
	}{
		{
			"node has endpoints for service",
			&NetworkRoutingController{
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
			},
			&v1core.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc-1",
					Namespace: "default",
				},
				Spec: v1core.ServiceSpec{
					Type:                  ClusterIPST,
					ClusterIP:             "10.0.0.1",
					ExternalIPs:           []string{"1.1.1.1", "2.2.2.2"},
					InternalTrafficPolicy: &testClusterIntTrafPol,
					ExternalTrafficPolicy: testClusterExtTrafPol,
				},
			},
			&discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc-1",
					Namespace: "default",
					Labels: map[string]string{
						"kubernetes.io/service-name": "svc-1",
					},
				},
				Endpoints: []discoveryv1.Endpoint{
					{
						Addresses: []string{"172.20.1.1"},
						NodeName:  testutils.ValToPtr("node-1"),
					},
					{
						Addresses: []string{"172.20.1.2"},
						NodeName:  testutils.ValToPtr("node-2"),
					},
				},
			},
			true,
		},
		{
			"node has no endpoints for service",
			&NetworkRoutingController{
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
			},
			&v1core.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc-1",
					Namespace: "default",
				},
				Spec: v1core.ServiceSpec{
					Type:                  ClusterIPST,
					ClusterIP:             "10.0.0.1",
					ExternalIPs:           []string{"1.1.1.1", "2.2.2.2"},
					InternalTrafficPolicy: &testClusterIntTrafPol,
					ExternalTrafficPolicy: testClusterExtTrafPol,
				},
			},
			&discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc-1",
					Namespace: "default",
					Labels: map[string]string{
						"kubernetes.io/service-name": "svc-1",
					},
				},
				Endpoints: []discoveryv1.Endpoint{
					{
						Addresses: []string{"172.20.1.1"},
						NodeName:  testutils.ValToPtr("node-2"),
					},
					{
						Addresses: []string{"172.20.1.2"},
						NodeName:  testutils.ValToPtr("node-3"),
					},
				},
			},
			false,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset()
			startInformersForRoutes(testcase.nrc, clientset)

			_, err := clientset.DiscoveryV1().EndpointSlices("default").Create(context.Background(), testcase.existingEndpoint, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("failed to create existing endpoints: %v", err)
			}

			_, err = clientset.CoreV1().Services("default").Create(context.Background(), testcase.existingService, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("failed to create existing services: %v", err)
			}

			waitForListerWithTimeout(testcase.nrc.svcLister, time.Second*10, t)
			waitForListerWithTimeout(testcase.nrc.epSliceLister, time.Second*10, t)

			nodeHasEndpoints, err := testcase.nrc.nodeHasEndpointsForService(testcase.existingService)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if nodeHasEndpoints != testcase.nodeHasEndpoints {
				t.Logf("expected nodeHasEndpoints: %v", testcase.nodeHasEndpoints)
				t.Logf("actual nodeHasEndpoints: %v", nodeHasEndpoints)
				t.Error("unexpected nodeHasEndpoints")
			}
		})
	}
}

func Test_advertisePodRoute(t *testing.T) {
	testcases := []struct {
		name        string
		nrc         *NetworkRoutingController
		envNodeName string
		node        *v1core.Node
		// the key is the subnet from the watch event
		watchEvents map[string]bool
	}{
		{
			"add bgp path for pod cidr using NODE_NAME",
			&NetworkRoutingController{
				bgpServer:    gobgp.NewBgpServer(),
				podCidr:      "172.20.0.0/24",
				podIPv4CIDRs: []string{"172.20.0.0/24"},
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
			},
			"node-1",
			&v1core.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node-1",
				},
				Spec: v1core.NodeSpec{
					PodCIDR: "172.20.0.0/24",
					PodCIDRs: []string{
						"172.20.0.0/24",
					},
				},
			},
			map[string]bool{
				"172.20.0.0/24": true,
			},
		},
		{
			"add bgp path for pod cidr using hostname override",
			&NetworkRoutingController{
				bgpServer:        gobgp.NewBgpServer(),
				hostnameOverride: "node-1",
				podCidr:          "172.20.0.0/24",
				podIPv4CIDRs:     []string{"172.20.0.0/24"},
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
			},
			"",
			&v1core.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node-1",
				},
				Spec: v1core.NodeSpec{
					PodCIDR: "172.20.0.0/24",
					PodCIDRs: []string{
						"172.20.0.0/24",
					},
				},
			},
			map[string]bool{
				"172.20.0.0/24": true,
			},
		},
		{
			"advertise IPv6 Address when enabled",
			&NetworkRoutingController{
				bgpServer:        gobgp.NewBgpServer(),
				hostnameOverride: "node-1",
				podCidr:          "2001:db8:42:2::/64",
				podIPv6CIDRs:     []string{"2001:db8:42:2::/64"},
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
						NodeIPv6Addrs: map[v1core.NodeAddressType][]net.IP{
							v1core.NodeInternalIP: {net.IPv6loopback},
						},
					},
				},
			},
			"",
			&v1core.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node-1",
				},
				Spec: v1core.NodeSpec{
					PodCIDR: "2001:db8:42:2::/64",
					PodCIDRs: []string{
						"2001:db8:42:2::/64",
					},
				},
			},
			map[string]bool{
				"2001:db8:42:2::/64": true,
			},
		},
		/* disabling tests for now, as node POD cidr is read just once at the starting of the program
		   Tests needs to be adopted to catch the errors when NetworkRoutingController starts
			{
				"add bgp path for pod cidr without NODE_NAME or hostname override",
				&NetworkRoutingController{
					bgpServer: gobgp.NewBgpServer(),
				},
				"",
				&v1core.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v1core.NodeSpec{
						PodCIDR: "172.20.0.0/24",
					},
				},
				map[string]bool{},
				errors.New("Failed to get pod CIDR allocated for the node due to: Failed to identify the node by NODE_NAME, hostname or --hostname-override"),
			},
			{
				"node does not have pod cidr set",
				&NetworkRoutingController{
					bgpServer: gobgp.NewBgpServer(),
				},
				"node-1",
				&v1core.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
					},
					Spec: v1core.NodeSpec{
						PodCIDR: "",
					},
				},
				map[string]bool{},
				errors.New("node.Spec.PodCIDR not set for node: node-1"),
			},
		*/
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			go testcase.nrc.bgpServer.Serve()
			global := &gobgpapi.Global{
				Asn:        1,
				RouterId:   testNodeIPv4,
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

			var events []*gobgpapi.Path
			eventMu := sync.Mutex{}
			pathWatch := func(r *gobgpapi.WatchEventResponse) {
				if table := r.GetTable(); table != nil {
					for _, p := range table.Paths {
						if p.Family.Afi == gobgpapi.Family_AFI_IP || p.Family.Safi == gobgpapi.Family_SAFI_UNICAST {
							func() {
								defer eventMu.Unlock()
								eventMu.Lock()
								events = append(events, p)
							}()
						}
					}
				}
			}
			err = testcase.nrc.bgpServer.WatchEvent(context.Background(), &gobgpapi.WatchEventRequest{
				Table: &gobgpapi.WatchEventRequest_Table{
					Filters: []*gobgpapi.WatchEventRequest_Table_Filter{
						{
							Type: gobgpapi.WatchEventRequest_Table_Filter_BEST,
						},
					},
				},
			}, pathWatch)
			if err != nil {
				t.Fatalf("failed to register callback to mortor global routing table: %v", err)
			}

			clientset := fake.NewSimpleClientset()
			_, err = clientset.CoreV1().Nodes().Create(context.Background(), testcase.node, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("failed to create node: %v", err)
			}
			testcase.nrc.clientset = clientset

			_ = os.Setenv("NODE_NAME", testcase.envNodeName)
			defer func() { _ = os.Unsetenv("NODE_NAME") }()

			if err := testcase.nrc.advertisePodRoute(); err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			timeoutCh := time.After(time.Second * 10)
			ticker := time.NewTicker(100 * time.Millisecond)

		waitForEvents:
			for {
				select {
				case <-timeoutCh:
					t.Fatalf("timeout exceeded waiting for %d watch events, got %d", len(testcase.watchEvents), len(events))
				case <-ticker.C:
					stopLoop := func() bool {
						defer eventMu.Unlock()
						eventMu.Lock()
						return len(events) == len(testcase.watchEvents)
					}()
					if stopLoop {
						break waitForEvents
					}
				}
			}

			defer eventMu.Unlock()
			eventMu.Lock()
			for _, path := range events {
				nlri := path.GetNlri()
				var prefix gobgpapi.IPAddressPrefix
				err = nlri.UnmarshalTo(&prefix)
				if err != nil {
					t.Fatalf("Invalid nlri in advertised path")
				}
				advertisedPrefix := prefix.Prefix + "/" + fmt.Sprint(prefix.PrefixLen)
				if _, ok := testcase.watchEvents[advertisedPrefix]; !ok {
					t.Errorf("got unexpected path: %v", advertisedPrefix)
				}
			}
		})
	}
}

func Test_syncInternalPeers(t *testing.T) {
	testcases := []struct {
		name          string
		nrc           *NetworkRoutingController
		existingNodes []*v1core.Node
		neighbors     map[string]bool
	}{
		{
			"sync 1 peer",
			&NetworkRoutingController{
				bgpFullMeshMode: true,
				clientset:       fake.NewSimpleClientset(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
				bgpServer:   gobgp.NewBgpServer(),
				activeNodes: make(map[string]bool),
			},
			[]*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{
								Type:    v1core.NodeInternalIP,
								Address: "10.0.0.1",
							},
						},
					},
				},
			},
			map[string]bool{
				"10.0.0.1": true,
			},
		},
		{
			"sync multiple peers",
			&NetworkRoutingController{
				bgpFullMeshMode: true,
				clientset:       fake.NewSimpleClientset(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
				bgpServer:   gobgp.NewBgpServer(),
				activeNodes: make(map[string]bool),
			},
			[]*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{
								Type:    v1core.NodeInternalIP,
								Address: "10.0.0.1",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-2",
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{
								Type:    v1core.NodeInternalIP,
								Address: "10.0.0.2",
							},
						},
					},
				},
			},
			map[string]bool{
				"10.0.0.1": true,
				"10.0.0.2": true,
			},
		},
		{
			"sync peer with removed nodes",
			&NetworkRoutingController{
				bgpFullMeshMode: true,
				clientset:       fake.NewSimpleClientset(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
				bgpServer: gobgp.NewBgpServer(),
				activeNodes: map[string]bool{
					"10.0.0.2": true,
				},
			},
			[]*v1core.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-1",
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{
								Type:    v1core.NodeInternalIP,
								Address: "10.0.0.1",
							},
						},
					},
				},
			},
			map[string]bool{
				"10.0.0.1": true,
			},
		},
		{
			"sync multiple peers with full mesh disabled",
			&NetworkRoutingController{
				bgpFullMeshMode: false,
				clientset:       fake.NewSimpleClientset(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
				bgpServer:     gobgp.NewBgpServer(),
				activeNodes:   make(map[string]bool),
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
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-2",
					},
					Status: v1core.NodeStatus{
						Addresses: []v1core.NodeAddress{
							{
								Type:    v1core.NodeInternalIP,
								Address: "10.0.0.2",
							},
						},
					},
				},
			},
			map[string]bool{
				"10.0.0.1": true,
			},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			go testcase.nrc.bgpServer.Serve()
			global := &gobgpapi.Global{
				Asn:        1,
				RouterId:   testNodeIPv4,
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
			waitForListerWithTimeout(testcase.nrc.nodeLister, time.Second*10, t)

			testcase.nrc.syncInternalPeers()

			neighbors := make(map[string]bool)
			err = testcase.nrc.bgpServer.ListPeer(context.Background(), &gobgpapi.ListPeerRequest{}, func(peer *gobgpapi.Peer) {
				if peer.Conf.NeighborAddress == "" {
					return
				}
				neighbors[peer.Conf.NeighborAddress] = true
			})
			if err != nil {
				t.Errorf("error listing BGP peers: %v", err)
			}
			if !reflect.DeepEqual(testcase.neighbors, neighbors) {
				t.Logf("actual neighbors: %v", neighbors)
				t.Logf("expected neighbors: %v", testcase.neighbors)
				t.Errorf("did not get expected neighbors")
			}

			if !reflect.DeepEqual(testcase.nrc.activeNodes, testcase.neighbors) {
				t.Logf("actual active nodes: %v", testcase.nrc.activeNodes)
				t.Logf("expected active nodes: %v", testcase.neighbors)
				t.Errorf("did not get expected activeNodes")
			}
		})
	}
}

func Test_routeReflectorConfiguration(t *testing.T) {
	testcases := []struct {
		name               string
		nrc                *NetworkRoutingController
		node               *v1core.Node
		expectedRRServer   bool
		expectedRRClient   bool
		expectedClusterID  string
		expectedBgpToStart bool
	}{
		{
			"RR server with int cluster id",
			&NetworkRoutingController{
				bgpFullMeshMode: false,
				bgpPort:         10000,
				clientset:       fake.NewSimpleClientset(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
				routerID:         testNodeIPv4,
				bgpServer:        gobgp.NewBgpServer(),
				activeNodes:      make(map[string]bool),
				nodeAsnNumber:    100,
				hostnameOverride: "node-1",
			},
			&v1core.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node-1",
					Annotations: map[string]string{
						"kube-router.io/node.asn": "100",
						rrServerAnnotation:        "1",
					},
				},
			},
			true,
			false,
			"1",
			true,
		},
		{
			"RR server with IPv4 cluster id",
			&NetworkRoutingController{
				bgpFullMeshMode: false,
				bgpPort:         10000,
				clientset:       fake.NewSimpleClientset(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
				routerID:         testNodeIPv4,
				bgpServer:        gobgp.NewBgpServer(),
				activeNodes:      make(map[string]bool),
				nodeAsnNumber:    100,
				hostnameOverride: "node-1",
			},
			&v1core.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node-1",
					Annotations: map[string]string{
						"kube-router.io/node.asn": "100",
						rrServerAnnotation:        "10.0.0.1",
					},
				},
			},
			true,
			false,
			"10.0.0.1",
			true,
		},
		{
			"RR client with int cluster id",
			&NetworkRoutingController{
				bgpFullMeshMode: false,
				bgpPort:         10000,
				clientset:       fake.NewSimpleClientset(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
				routerID:         testNodeIPv4,
				bgpServer:        gobgp.NewBgpServer(),
				activeNodes:      make(map[string]bool),
				nodeAsnNumber:    100,
				hostnameOverride: "node-1",
			},
			&v1core.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node-1",
					Annotations: map[string]string{
						"kube-router.io/node.asn": "100",
						rrClientAnnotation:        "1",
					},
				},
			},
			false,
			true,
			"1",
			true,
		},
		{
			"RR client with IPv4 cluster id",
			&NetworkRoutingController{
				bgpFullMeshMode: false,
				bgpPort:         10000,
				clientset:       fake.NewSimpleClientset(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
				routerID:         testNodeIPv4,
				bgpServer:        gobgp.NewBgpServer(),
				activeNodes:      make(map[string]bool),
				nodeAsnNumber:    100,
				hostnameOverride: "node-1",
			},
			&v1core.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node-1",
					Annotations: map[string]string{
						"kube-router.io/node.asn": "100",
						rrClientAnnotation:        "10.0.0.1",
					},
				},
			},
			false,
			true,
			"10.0.0.1",
			true,
		},
		{
			"RR server with unparseable cluster id",
			&NetworkRoutingController{
				bgpFullMeshMode: false,
				bgpPort:         10000,
				clientset:       fake.NewSimpleClientset(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
				bgpServer:        gobgp.NewBgpServer(),
				activeNodes:      make(map[string]bool),
				nodeAsnNumber:    100,
				hostnameOverride: "node-1",
			},
			&v1core.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node-1",
					Annotations: map[string]string{
						"kube-router.io/node.asn": "100",
						rrServerAnnotation:        "hello world",
					},
				},
			},
			false,
			false,
			"",
			false,
		},
		{
			"RR client with unparseable cluster id",
			&NetworkRoutingController{
				bgpFullMeshMode: false,
				bgpPort:         10000,
				clientset:       fake.NewSimpleClientset(),
				krNode: &utils.LocalKRNode{
					KRNode: utils.KRNode{
						NodeName:      "node-1",
						PrimaryIP:     net.ParseIP(testNodeIPv4),
						NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
					},
				},
				bgpServer:        gobgp.NewBgpServer(),
				activeNodes:      make(map[string]bool),
				nodeAsnNumber:    100,
				hostnameOverride: "node-1",
			},
			&v1core.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node-1",
					Annotations: map[string]string{
						"kube-router.io/node.asn": "100",
						rrClientAnnotation:        "hello world",
					},
				},
			},
			false,
			false,
			"",
			false,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			if err := createNodes(testcase.nrc.clientset, []*v1core.Node{testcase.node}); err != nil {
				t.Errorf("failed to create existing nodes: %v", err)
			}

			err := testcase.nrc.startBgpServer(false)
			if err == nil {
				defer func() {
					if err := testcase.nrc.bgpServer.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{}); err != nil {
						t.Fatalf("failed to stop BGP server : %s", err)
					}
				}()
			}

			if testcase.expectedBgpToStart {
				if err != nil {
					t.Fatalf("failed to start BGP server: %v", err)
				}
				if testcase.expectedRRServer != testcase.nrc.bgpRRServer {
					t.Error("Node suppose to be RR server")
				}
				if testcase.expectedRRClient != testcase.nrc.bgpRRClient {
					t.Error("Node suppose to be RR client")
				}
				if testcase.expectedClusterID != testcase.nrc.bgpClusterID {
					t.Errorf("Node suppose to have cluster id '%s' but got %s", testcase.expectedClusterID, testcase.nrc.bgpClusterID)
				}
			} else if err == nil {
				t.Fatal("mis-configured BGP server is not supposed to start")
			}
		})
	}
}

func Test_bgpPeerConfigsFromAnnotations(t *testing.T) {
	testCases := []struct {
		name                   string
		nodeAnnotations        map[string]string
		expectedBgpPeerConfigs bgp.PeerConfigs
		expectError            bool
	}{
		{
			"node annotations are empty",
			map[string]string{},
			nil,
			false,
		},
		{
			"combined bgp peers config annotation",
			map[string]string{
				peersAnnotation: `- remoteip: 10.0.0.1
  remoteasn: 64640
  password: cGFzc3dvcmQ=
  localip: 192.168.0.1
- remoteip: 10.0.0.2
  remoteasn: 64641
  password: cGFzc3dvcmQ=
  localip: 192.168.0.2`,
			},
			bgp.PeerConfigs{
				bgp.PeerConfig{
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.1")),
					RemoteASN: testutils.ValToPtr(uint32(64640)),
					Password:  testutils.ValToPtr(utils.Base64String("password")),
					LocalIP:   testutils.ValToPtr("192.168.0.1"),
				},
				bgp.PeerConfig{
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.2")),
					RemoteASN: testutils.ValToPtr(uint32(64641)),
					Password:  testutils.ValToPtr(utils.Base64String("password")),
					LocalIP:   testutils.ValToPtr("192.168.0.2"),
				},
			},
			false,
		},
		{
			"combined bgp peers config annotation without matching number of peer config fields set",
			map[string]string{
				peersAnnotation: `- remoteip: 10.0.0.1
  remoteasn: 64640
- remoteip: 10.0.0.2
  remoteasn: 64641
  password: cGFzc3dvcmQ=
  localip: 192.168.0.2`,
			},
			bgp.PeerConfigs{
				bgp.PeerConfig{
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.1")),
					RemoteASN: testutils.ValToPtr(uint32(64640)),
				},
				bgp.PeerConfig{
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.2")),
					RemoteASN: testutils.ValToPtr(uint32(64641)),
					Password:  testutils.ValToPtr(utils.Base64String("password")),
					LocalIP:   testutils.ValToPtr("192.168.0.2"),
				},
			},
			true,
		},
		{
			"individual bgp peers config annotations",
			map[string]string{
				peerIPAnnotation:       "10.0.0.1,10.0.0.2",
				peerASNAnnotation:      "64640,64641",
				peerPasswordAnnotation: "cGFzc3dvcmQ=,cGFzc3dvcmQ=",
				peerLocalIPAnnotation:  "192.168.0.1,192.168.0.2",
			},
			bgp.PeerConfigs{
				bgp.PeerConfig{
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.1")),
					RemoteASN: testutils.ValToPtr(uint32(64640)),
					Password:  testutils.ValToPtr(utils.Base64String("password")),
					LocalIP:   testutils.ValToPtr("192.168.0.1"),
				},
				bgp.PeerConfig{
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.2")),
					RemoteASN: testutils.ValToPtr(uint32(64641)),
					Password:  testutils.ValToPtr(utils.Base64String("password")),
					LocalIP:   testutils.ValToPtr("192.168.0.2"),
				},
			},
			false,
		},
		{
			"individual bgp peers config annotations without matching number of peer config fields set",
			map[string]string{
				peerIPAnnotation:       "10.0.0.1,10.0.0.2",
				peerASNAnnotation:      "64640,64641",
				peerPasswordAnnotation: "cGFzc3dvcmQ=",
				peerLocalIPAnnotation:  "192.168.0.2",
			},
			bgp.PeerConfigs{
				bgp.PeerConfig{
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.1")),
					RemoteASN: testutils.ValToPtr(uint32(64640)),
					Password:  testutils.ValToPtr(utils.Base64String("password")),
					LocalIP:   testutils.ValToPtr("192.168.0.1"),
				},
				bgp.PeerConfig{
					RemoteIP:  testutils.ValToPtr(net.ParseIP("10.0.0.2")),
					RemoteASN: testutils.ValToPtr(uint32(64641)),
					Password:  testutils.ValToPtr(utils.Base64String("password")),
					LocalIP:   testutils.ValToPtr("192.168.0.2"),
				},
			},
			true,
		},
		{
			"individual bgp peers config annotations without peer ASN annotation",
			map[string]string{
				peerASNAnnotation:      "64640,64641",
				peerPasswordAnnotation: "cGFzc3dvcmQ=,cGFzc3dvcmQ=",
				peerLocalIPAnnotation:  "192.168.0.1,192.168.0.2",
			},
			nil,
			false,
		},
		{
			"individual bgp peers config annotations without peer IP annotation",
			map[string]string{
				peerIPAnnotation:       "10.0.0.1,10.0.0.2",
				peerPasswordAnnotation: "cGFzc3dvcmQ=,cGFzc3dvcmQ=",
				peerLocalIPAnnotation:  "192.168.0.1,192.168.0.2",
			},
			nil,
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bgpPeerCfgs, err := bgpPeerConfigsFromAnnotations(tc.nodeAnnotations, "")
			if tc.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if !cmp.Equal(tc.expectedBgpPeerConfigs, bgpPeerCfgs, cmpopts.IgnoreUnexported(bgp.PeerConfig{})) {
				diff := cmp.Diff(tc.expectedBgpPeerConfigs, bgpPeerCfgs, cmpopts.IgnoreUnexported(bgp.PeerConfig{}))
				t.Errorf("BGP peer config mismatch:\n%s", diff)
			}
		})
	}
}

/* Disabling test for now. OnNodeUpdate() behaviour is changed. test needs to be adopted.
func Test_OnNodeUpdate(t *testing.T) {
	testcases := []struct {
		name        string
		nrc         *NetworkRoutingController
		nodeEvents  []*watchers.NodeUpdate
		activeNodes map[string]bool
	}{
		{
			"node add event",
			&NetworkRoutingController{
				activeNodes:          make(map[string]bool),
				bgpServer:            gobgp.NewBgpServer(),
				defaultNodeAsnNumber: 1,
				clientset:            fake.NewSimpleClientset(),
			},
			[]*watchers.NodeUpdate{
				{
					Node: &v1core.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: "node-1",
						},
						Status: v1core.NodeStatus{
							Addresses: []v1core.NodeAddress{
								{
									Type:    v1core.NodeInternalIP,
									Address: "10.0.0.1",
								},
							},
						},
					},
					Op: watchers.ADD,
				},
			},
			map[string]bool{
				"10.0.0.1": true,
			},
		},
		{
			"add multiple nodes",
			&NetworkRoutingController{
				activeNodes:          make(map[string]bool),
				bgpServer:            gobgp.NewBgpServer(),
				defaultNodeAsnNumber: 1,
				clientset:            fake.NewSimpleClientset(),
			},
			[]*watchers.NodeUpdate{
				{
					Node: &v1core.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: "node-1",
						},
						Status: v1core.NodeStatus{
							Addresses: []v1core.NodeAddress{
								{
									Type:    v1core.NodeInternalIP,
									Address: "10.0.0.1",
								},
							},
						},
					},
					Op: watchers.ADD,
				},
				{
					Node: &v1core.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: "node-2",
						},
						Status: v1core.NodeStatus{
							Addresses: []v1core.NodeAddress{
								{
									Type:    v1core.NodeExternalIP,
									Address: "1.1.1.1",
								},
							},
						},
					},
					Op: watchers.ADD,
				},
			},
			map[string]bool{
				"10.0.0.1": true,
				"1.1.1.1":  true,
			},
		},
		{
			"add and then delete nodes",
			&NetworkRoutingController{
				activeNodes:          make(map[string]bool),
				bgpServer:            gobgp.NewBgpServer(),
				defaultNodeAsnNumber: 1,
				clientset:            fake.NewSimpleClientset(),
			},
			[]*watchers.NodeUpdate{
				{
					Node: &v1core.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: "node-1",
						},
						Status: v1core.NodeStatus{
							Addresses: []v1core.NodeAddress{
								{
									Type:    v1core.NodeInternalIP,
									Address: "10.0.0.1",
								},
							},
						},
					},
					Op: watchers.ADD,
				},
				{
					Node: &v1core.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: "node-1",
						},
						Status: v1core.NodeStatus{
							Addresses: []v1core.NodeAddress{
								{
									Type:    v1core.NodeInternalIP,
									Address: "10.0.0.1",
								},
							},
						},
					},
					Op: watchers.REMOVE,
				},
			},
			map[string]bool{},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			go testcase.nrc.bgpServer.Serve()
			err := testcase.nrc.bgpServer.Start(&config.Global{
				Config: config.GlobalConfig{
					As:       1,
					RouterId: "10.0.0.0",
					Port:     10000,
				},
			})
			testcase.nrc.bgpServerStarted = true
			if err != nil {
				t.Fatalf("failed to start BGP server: %v", err)
			}
			defer testcase.nrc.bgpServer.Stop()

			for _, nodeEvent := range testcase.nodeEvents {
				testcase.nrc.OnNodeUpdate(nodeEvent)
			}

			neighbors := testcase.nrc.bgpServer.GetNeighbor("", false)
			for _, neighbor := range neighbors {
				_, exists := testcase.activeNodes[neighbor.Config.NeighborAddress]
				if !exists {
					t.Errorf("expected neighbor: %v doesn't exist", neighbor.Config.NeighborAddress)
				}
			}

			if !reflect.DeepEqual(testcase.nrc.activeNodes, testcase.activeNodes) {
				t.Logf("actual active nodes: %v", testcase.nrc.activeNodes)
				t.Logf("expected active nodes: %v", testcase.activeNodes)
				t.Errorf("did not get expected activeNodes")
			}
		})
	}
}
*/

func createServices(clientset kubernetes.Interface, svcs []*v1core.Service) error {
	for _, svc := range svcs {
		_, err := clientset.CoreV1().Services(svc.ObjectMeta.Namespace).Create(context.Background(), svc, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

func createNodes(clientset kubernetes.Interface, nodes []*v1core.Node) error {
	for _, node := range nodes {
		_, err := clientset.CoreV1().Nodes().Create(context.Background(), node, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

func createEndpointSlices(clientset kubernetes.Interface, endpointSlices []*discoveryv1.EndpointSlice) error {
	for _, es := range endpointSlices {
		_, err := clientset.DiscoveryV1().EndpointSlices(es.ObjectMeta.Namespace).Create(
			context.Background(), es, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}

func fatalf(format string, a ...interface{}) {
	msg := fmt.Sprintf("FATAL: "+format+"\n", a...)
	Fail(msg)
}

func startInformersForRoutes(nrc *NetworkRoutingController, clientset kubernetes.Interface) {
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)
	svcInformer := informerFactory.Core().V1().Services().Informer()
	epSliceInformer := informerFactory.Discovery().V1().EndpointSlices().Informer()
	nodeInformer := informerFactory.Core().V1().Nodes().Informer()

	err := epSliceInformer.AddIndexers(map[string]cache.IndexFunc{
		indexers.ServiceNameIndex: indexers.ServiceNameIndexFunc,
	})
	if err != nil {
		fatalf("failed to add indexers to endpoint slice informer: %v", err)
	}

	go informerFactory.Start(nil)
	informerFactory.WaitForCacheSync(nil)

	nrc.svcLister = svcInformer.GetIndexer()
	nrc.epSliceLister = epSliceInformer.GetIndexer()
	nrc.nodeLister = nodeInformer.GetIndexer()
}

//nolint:unparam // it doesn't hurt anything to leave timeout here, and increases future flexibility for testing
func waitForListerWithTimeout(lister cache.Indexer, timeout time.Duration, t *testing.T) {
	tick := time.Tick(100 * time.Millisecond)
	timeoutCh := time.After(timeout)
	for {
		select {
		case <-timeoutCh:
			t.Fatal("timeout exceeded waiting for service lister to fill cache")
		case <-tick:
			if len(lister.List()) != 0 {
				return
			}
		}
	}
}
