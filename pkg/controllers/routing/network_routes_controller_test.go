package routing

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1core "k8s.io/api/core/v1"
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
		name             string
		nrc              *NetworkRoutingController
		existingServices []*v1core.Service
		// the key is the subnet from the watch event
		watchEvents map[string]bool
	}{

		{
			"add bgp path for service with ClusterIP",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				primaryIP: net.ParseIP("10.0.0.1"),
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:      ClusterIPST,
						ClusterIP: "10.0.0.1",
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
				primaryIP: net.ParseIP("10.0.0.1"),
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:      ClusterIPST,
						ClusterIP: "10.0.0.1",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-2",
					},
					Spec: v1core.ServiceSpec{
						Type:      LoadBalancerST,
						ClusterIP: "10.0.0.2",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-3",
					},
					Spec: v1core.ServiceSpec{
						Type:      NodePortST,
						ClusterIP: "10.0.0.3",
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
				primaryIP: net.ParseIP("10.0.0.1"),
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:      ClusterIPST,
						ClusterIP: "10.0.0.1",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-2",
					},
					Spec: v1core.ServiceSpec{
						Type:      "AnotherType",
						ClusterIP: "10.0.0.2",
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
				primaryIP: net.ParseIP("10.0.0.1"),
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:      ClusterIPST,
						ClusterIP: "10.0.0.1",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-2",
					},
					Spec: v1core.ServiceSpec{
						Type:      ClusterIPST,
						ClusterIP: "None",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-3",
					},
					Spec: v1core.ServiceSpec{
						Type:      ClusterIPST,
						ClusterIP: "",
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
				RouterId:   "10.0.0.0",
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

			waitForListerWithTimeout(testcase.nrc.svcLister, time.Second*10, t)

			var events []*gobgpapi.Path
			pathWatch := func(r *gobgpapi.WatchEventResponse) {
				if table := r.GetTable(); table != nil {
					for _, p := range table.Paths {
						if p.Family.Afi == gobgpapi.Family_AFI_IP || p.Family.Safi == gobgpapi.Family_SAFI_UNICAST {
							events = append(events, p)
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

			toAdvertise, toWithdraw, _ := testcase.nrc.getActiveVIPs()
			testcase.nrc.advertiseVIPs(toAdvertise)
			testcase.nrc.withdrawVIPs(toWithdraw)

			timeoutCh := time.After(time.Second * 10)
		L:
			for {
				select {
				case <-timeoutCh:
					t.Fatalf("timeout exceeded waiting for %d watch events, got %d", len(testcase.watchEvents), len(events))
				default:
					if len(events) == len(testcase.watchEvents) {
						break L
					}
				}
			}

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
		name             string
		nrc              *NetworkRoutingController
		existingServices []*v1core.Service
		// the key is the subnet from the watch event
		watchEvents map[string]bool
	}{
		{
			"add bgp path for service with external IPs",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				primaryIP: net.ParseIP("10.0.0.1"),
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:        ClusterIPST,
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1", "2.2.2.2"},
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
				primaryIP: net.ParseIP("10.0.0.1"),
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:        ClusterIPST,
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-2",
					},
					Spec: v1core.ServiceSpec{
						Type:        LoadBalancerST,
						ClusterIP:   "10.0.0.2",
						ExternalIPs: []string{"2.2.2.2"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-3",
					},
					Spec: v1core.ServiceSpec{
						Type:        NodePortST,
						ClusterIP:   "10.0.0.3",
						ExternalIPs: []string{"3.3.3.3", "4.4.4.4"},
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
				primaryIP: net.ParseIP("10.0.0.1"),
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:        ClusterIPST,
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-2",
					},
					Spec: v1core.ServiceSpec{
						Type:        "AnotherType",
						ClusterIP:   "10.0.0.2",
						ExternalIPs: []string{"2.2.2.2"},
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
				primaryIP: net.ParseIP("10.0.0.1"),
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:        ClusterIPST,
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-2",
					},
					Spec: v1core.ServiceSpec{
						Type:        ClusterIPST,
						ClusterIP:   "None",
						ExternalIPs: []string{"2.2.2.2"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-3",
					},
					Spec: v1core.ServiceSpec{
						Type:        ClusterIPST,
						ClusterIP:   "",
						ExternalIPs: []string{"3.3.3.3"},
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
				primaryIP: net.ParseIP("10.0.0.1"),
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:      LoadBalancerST,
						ClusterIP: "10.0.0.1",
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
			map[string]bool{},
		},
		{
			"add bgp path to loadbalancerIP for service with LoadBalancer IP",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				primaryIP: net.ParseIP("10.0.0.1"),
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:      LoadBalancerST,
						ClusterIP: "10.0.0.1",
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
			map[string]bool{
				"10.0.255.1/32": true,
				"10.0.255.2/32": true,
			},
		},
		{
			"no bgp path to nil loadbalancerIPs for service with LoadBalancer",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				primaryIP: net.ParseIP("10.0.0.1"),
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:      LoadBalancerST,
						ClusterIP: "10.0.0.1",
					},
					Status: v1core.ServiceStatus{
						LoadBalancer: v1core.LoadBalancerStatus{
							Ingress: []v1core.LoadBalancerIngress{},
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
				primaryIP: net.ParseIP("10.0.0.1"),
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
						Annotations: map[string]string{
							svcSkipLbIpsAnnotation: "true",
						},
					},
					Spec: v1core.ServiceSpec{
						Type:      LoadBalancerST,
						ClusterIP: "10.0.0.1",
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
			map[string]bool{},
		},
	}

	//nolint:dupl // There is no need to spend a lot of time de-duplicating test code
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
			pathWatch := func(r *gobgpapi.WatchEventResponse) {
				if table := r.GetTable(); table != nil {
					for _, p := range table.Paths {
						if p.Family.Afi == gobgpapi.Family_AFI_IP || p.Family.Safi == gobgpapi.Family_SAFI_UNICAST {
							events = append(events, p)
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

			waitForListerWithTimeout(testcase.nrc.svcLister, time.Second*10, t)

			// ExternalIPs
			testcase.nrc.advertiseClusterIP = false
			testcase.nrc.advertiseExternalIP = true
			testcase.nrc.advertiseLoadBalancerIP = true

			toAdvertise, toWithdraw, _ := testcase.nrc.getActiveVIPs()
			testcase.nrc.advertiseVIPs(toAdvertise)
			testcase.nrc.withdrawVIPs(toWithdraw)
			timeoutCh := time.After(time.Second * 10)

		L:
			for {
				select {
				case <-timeoutCh:
					t.Fatalf("timeout exceeded waiting for %d watch events, got %d", len(testcase.watchEvents), len(events))
				default:
					if len(events) == len(testcase.watchEvents) {
						break L
					}
				}
			}

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
		name             string
		nrc              *NetworkRoutingController
		existingServices []*v1core.Service
		// the key is the subnet from the watch event
		watchEvents map[string]bool
	}{
		{
			"add bgp paths for all service IPs",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				primaryIP: net.ParseIP("10.0.1.1"),
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:        ClusterIPST,
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-2",
					},
					Spec: v1core.ServiceSpec{
						Type:        NodePortST,
						ClusterIP:   "10.0.0.2",
						ExternalIPs: []string{"2.2.2.2", "3.3.3.3"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-3",
					},
					Spec: v1core.ServiceSpec{
						Type:        LoadBalancerST,
						ClusterIP:   "10.0.0.3",
						ExternalIPs: []string{"4.4.4.4"},
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
				primaryIP: net.ParseIP("10.0.1.1"),
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
						Annotations: map[string]string{
							svcAdvertiseClusterAnnotation:      "false",
							svcAdvertiseExternalAnnotation:     "false",
							svcAdvertiseLoadBalancerAnnotation: "false",
						},
					},
					Spec: v1core.ServiceSpec{
						Type:        LoadBalancerST,
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1", "2.2.2.2"},
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
			map[string]bool{},
		},
	}

	//nolint:dupl // There is no need to spend a lot of time de-duplicating test code
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
			pathWatch := func(r *gobgpapi.WatchEventResponse) {
				if table := r.GetTable(); table != nil {
					for _, p := range table.Paths {
						if p.Family.Afi == gobgpapi.Family_AFI_IP || p.Family.Safi == gobgpapi.Family_SAFI_UNICAST {
							events = append(events, p)
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

			waitForListerWithTimeout(testcase.nrc.svcLister, time.Second*10, t)

			// By default advertise all IPs
			testcase.nrc.advertiseClusterIP = true
			testcase.nrc.advertiseExternalIP = true
			testcase.nrc.advertiseLoadBalancerIP = true

			toAdvertise, toWithdraw, _ := testcase.nrc.getActiveVIPs()
			testcase.nrc.advertiseVIPs(toAdvertise)
			testcase.nrc.withdrawVIPs(toWithdraw)
			timeoutCh := time.After(time.Second * 10)

		L:
			for {
				select {
				case <-timeoutCh:
					t.Fatalf("timeout exceeded waiting for %d watch events, got %d", len(testcase.watchEvents), len(events))
				default:
					if len(events) == len(testcase.watchEvents) {
						break L
					}
				}
			}

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
		name             string
		nrc              *NetworkRoutingController
		existingServices []*v1core.Service
		// the key is the subnet from the watch event
		watchEvents map[string]bool
	}{
		{
			"no bgp paths for any service IPs",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				primaryIP: net.ParseIP("10.0.1.1"),
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:        ClusterIPST,
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-2",
					},
					Spec: v1core.ServiceSpec{
						Type:        NodePortST,
						ClusterIP:   "10.0.0.2",
						ExternalIPs: []string{"2.2.2.2", "3.3.3.3"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-3",
					},
					Spec: v1core.ServiceSpec{
						Type:      LoadBalancerST,
						ClusterIP: "10.0.0.3",
						// ignored since LoadBalancer services don't
						// advertise external IPs.
						ExternalIPs: []string{"4.4.4.4"},
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
			map[string]bool{},
		},
		{
			"opt in to advertise all IPs via annotations",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
				primaryIP: net.ParseIP("10.0.1.1"),
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
						Annotations: map[string]string{
							svcAdvertiseClusterAnnotation:      "true",
							svcAdvertiseExternalAnnotation:     "true",
							svcAdvertiseLoadBalancerAnnotation: "true",
						},
					},
					Spec: v1core.ServiceSpec{
						Type:        ClusterIPST,
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-2",
						Annotations: map[string]string{
							svcAdvertiseClusterAnnotation:      "true",
							svcAdvertiseExternalAnnotation:     "true",
							svcAdvertiseLoadBalancerAnnotation: "true",
						},
					},
					Spec: v1core.ServiceSpec{
						Type:        NodePortST,
						ClusterIP:   "10.0.0.2",
						ExternalIPs: []string{"2.2.2.2", "3.3.3.3"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-3",
						Annotations: map[string]string{
							svcAdvertiseClusterAnnotation:      "true",
							svcAdvertiseExternalAnnotation:     "true",
							svcAdvertiseLoadBalancerAnnotation: "true",
						},
					},
					Spec: v1core.ServiceSpec{
						Type:        LoadBalancerST,
						ClusterIP:   "10.0.0.3",
						ExternalIPs: []string{"4.4.4.4"},
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

	//nolint:dupl // There is no need to spend a lot of time de-duplicating test code
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
			pathWatch := func(r *gobgpapi.WatchEventResponse) {
				if table := r.GetTable(); table != nil {
					for _, p := range table.Paths {
						if p.Family.Afi == gobgpapi.Family_AFI_IP || p.Family.Safi == gobgpapi.Family_SAFI_UNICAST {
							events = append(events, p)
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

			waitForListerWithTimeout(testcase.nrc.svcLister, time.Second*10, t)

			// By default do not advertise any IPs
			testcase.nrc.advertiseClusterIP = false
			testcase.nrc.advertiseExternalIP = false
			testcase.nrc.advertiseLoadBalancerIP = false

			toAdvertise, toWithdraw, _ := testcase.nrc.getActiveVIPs()
			testcase.nrc.advertiseVIPs(toAdvertise)
			testcase.nrc.withdrawVIPs(toWithdraw)

			timeoutCh := time.After(time.Second * 10)

		L:
			for {
				select {
				case <-timeoutCh:
					t.Fatalf("timeout exceeded waiting for %d watch events, got %d", len(testcase.watchEvents), len(events))
				default:
					if len(events) == len(testcase.watchEvents) {
						break L
					}
				}
			}

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
		existingEndpoint *v1core.Endpoints
		nodeHasEndpoints bool
		err              error
	}{
		{
			"node has endpoints for service",
			&NetworkRoutingController{
				nodeName: "node-1",
			},
			&v1core.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc-1",
					Namespace: "default",
				},
				Spec: v1core.ServiceSpec{
					Type:        ClusterIPST,
					ClusterIP:   "10.0.0.1",
					ExternalIPs: []string{"1.1.1.1", "2.2.2.2"},
				},
			},
			&v1core.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc-1",
					Namespace: "default",
				},
				Subsets: []v1core.EndpointSubset{
					{
						Addresses: []v1core.EndpointAddress{
							{
								IP:       "172.20.1.1",
								NodeName: ptrToString("node-1"),
							},
							{
								IP:       "172.20.1.2",
								NodeName: ptrToString("node-2"),
							},
						},
					},
				},
			},
			true,
			nil,
		},
		{
			"node has no endpoints for service",
			&NetworkRoutingController{
				nodeName: "node-1",
			},
			&v1core.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc-1",
					Namespace: "default",
				},
				Spec: v1core.ServiceSpec{
					Type:        ClusterIPST,
					ClusterIP:   "10.0.0.1",
					ExternalIPs: []string{"1.1.1.1", "2.2.2.2"},
				},
			},
			&v1core.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc-1",
					Namespace: "default",
				},
				Subsets: []v1core.EndpointSubset{
					{
						Addresses: []v1core.EndpointAddress{
							{
								IP:       "172.20.1.1",
								NodeName: ptrToString("node-2"),
							},
							{
								IP:       "172.20.1.2",
								NodeName: ptrToString("node-3"),
							},
						},
					},
				},
			},
			false,
			nil,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset()
			startInformersForRoutes(testcase.nrc, clientset)

			_, err := clientset.CoreV1().Endpoints("default").Create(context.Background(), testcase.existingEndpoint, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("failed to create existing endpoints: %v", err)
			}

			_, err = clientset.CoreV1().Services("default").Create(context.Background(), testcase.existingService, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("failed to create existing services: %v", err)
			}

			waitForListerWithTimeout(testcase.nrc.svcLister, time.Second*10, t)
			waitForListerWithTimeout(testcase.nrc.epLister, time.Second*10, t)

			nodeHasEndpoints, err := testcase.nrc.nodeHasEndpointsForService(testcase.existingService)
			if !reflect.DeepEqual(err, testcase.err) {
				t.Logf("actual err: %v", err)
				t.Logf("expected err: %v", testcase.err)
				t.Error("unexpected error")
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
	cniConfFile := "/tmp/kube-router-cni"
	validCniConfFileContent := `{"bridge":"kube-bridge","ipam":{"subnet":"172.20.0.0/24","type":"host-local"},"isDefaultGateway":true,"name":"kubernetes","type":"bridge"}`
	invalidCniConfFileContent := ``

	testcases := []struct {
		name        string
		nrc         *NetworkRoutingController
		envNodeName string
		node        *v1core.Node
		// the key is the subnet from the watch event
		watchEvents        map[string]bool
		err                error
		cniConfFile        string
		cniConfFileContent string
	}{
		{
			"add bgp path for pod cidr using NODE_NAME",
			&NetworkRoutingController{
				bgpServer:     gobgp.NewBgpServer(),
				podCidr:       "172.20.0.0/24",
				isIPv4Capable: true,
				podIPv4CIDRs:  []string{"172.20.0.0/24"},
				primaryIP:     net.ParseIP("10.0.0.1"),
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
			nil,
			cniConfFile,
			invalidCniConfFileContent,
		},
		{
			"add bgp path for pod cidr using hostname override",
			&NetworkRoutingController{
				bgpServer:        gobgp.NewBgpServer(),
				hostnameOverride: "node-1",
				podCidr:          "172.20.0.0/24",
				isIPv4Capable:    true,
				podIPv4CIDRs:     []string{"172.20.0.0/24"},
				primaryIP:        net.ParseIP("10.0.0.1"),
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
			nil,
			cniConfFile,
			invalidCniConfFileContent,
		},
		{
			"advertise IPv6 Address when enabled",
			&NetworkRoutingController{
				bgpServer:        gobgp.NewBgpServer(),
				hostnameOverride: "node-1",
				podCidr:          "2001:db8:42:2::/64",
				podIPv6CIDRs:     []string{"2001:db8:42:2::/64"},
				nodeIPv6Addrs: map[v1core.NodeAddressType][]net.IP{
					v1core.NodeInternalIP: {net.IPv6loopback},
				},
				isIPv6Capable: true,
				primaryIP:     net.ParseIP("10.0.0.1"),
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
			nil,
			cniConfFile,
			invalidCniConfFileContent,
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
				cniConfFile,
				invalidCniConfFileContent,
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
			map[string]bool{
				"172.20.0.0/24": true,
			},
			nil,
			cniConfFile,
			validCniConfFileContent,
		},
		{
			"add bgp path for pod cidr using cni config if apiserver call fails",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
			},
			"node-1",
			nil,
			map[string]bool{
				"172.20.0.0/24": true,
			},
			nil,
			cniConfFile,
			validCniConfFileContent,
		},
		{
			"add bgp path for pod cidr using cni config if apiserver call fails and cni config file parsing fails",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
			},
			"node-1",
			nil,
			nil,
			errors.New("Failed to load CNI conf file: error parsing configuration: unexpected end of JSON input"),
			cniConfFile,
			invalidCniConfFileContent,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			file, err := createFile(testcase.cniConfFileContent, testcase.cniConfFile)
			if err != nil {
				t.Fatalf("Failed to create temporary CNI config file: %v", err)
			}
			defer os.Remove(file.Name())
			testcase.nrc.cniConfFile = testcase.cniConfFile

			go testcase.nrc.bgpServer.Serve()
			global := &gobgpapi.Global{
				Asn:        1,
				RouterId:   "10.0.0.0",
				ListenPort: 10000,
			}
			err = testcase.nrc.bgpServer.StartBgp(context.Background(), &gobgpapi.StartBgpRequest{Global: global})
			if err != nil {
				t.Fatalf("failed to start BGP server: %v", err)
			}
			defer func() {
				if err := testcase.nrc.bgpServer.StopBgp(context.Background(), &gobgpapi.StopBgpRequest{}); err != nil {
					t.Fatalf("failed to stop BGP server : %s", err)
				}
			}()

			var events []*gobgpapi.Path
			pathWatch := func(r *gobgpapi.WatchEventResponse) {
				if table := r.GetTable(); table != nil {
					for _, p := range table.Paths {
						if p.Family.Afi == gobgpapi.Family_AFI_IP || p.Family.Safi == gobgpapi.Family_SAFI_UNICAST {
							events = append(events, p)
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
			if testcase.node != nil {
				_, err = clientset.CoreV1().Nodes().Create(context.TODO(), testcase.node, metav1.CreateOptions{})
				if err != nil {
					t.Fatalf("failed to create node: %v", err)
				}
			}
			testcase.nrc.clientset = clientset

			_ = os.Setenv("NODE_NAME", testcase.envNodeName)
			defer func() { _ = os.Unsetenv("NODE_NAME") }()

			err = testcase.nrc.advertisePodRoute()
			if !reflect.DeepEqual(testcase.err, err) && (testcase.err == nil || err == nil || err.Error() != testcase.err.Error()) {
				t.Logf("actual error: %v", err)
				t.Logf("expected error: %v", testcase.err)
				t.Error("did not get expected error")
			}

			timeoutCh := time.After(time.Second * 10)

		waitForEvents:
			for {
				select {
				case <-timeoutCh:
					t.Fatalf("timeout exceeded waiting for %d watch events, got %d", len(testcase.watchEvents), len(events))
				default:
					if len(events) == len(testcase.watchEvents) {
						break waitForEvents
					}
				}
			}

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
				primaryIP:       net.ParseIP("10.0.0.0"),
				bgpServer:       gobgp.NewBgpServer(),
				activeNodes:     make(map[string]bool),
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
				primaryIP:       net.ParseIP("10.0.0.0"),
				bgpServer:       gobgp.NewBgpServer(),
				activeNodes:     make(map[string]bool),
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
				primaryIP:       net.ParseIP("10.0.0.0"),
				bgpServer:       gobgp.NewBgpServer(),
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
				primaryIP:       net.ParseIP("10.0.0.0"),
				bgpServer:       gobgp.NewBgpServer(),
				activeNodes:     make(map[string]bool),
				nodeAsnNumber:   100,
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
				bgpFullMeshMode:  false,
				bgpPort:          10000,
				clientset:        fake.NewSimpleClientset(),
				primaryIP:        net.ParseIP("10.0.0.0"),
				routerID:         "10.0.0.0",
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
				bgpFullMeshMode:  false,
				bgpPort:          10000,
				clientset:        fake.NewSimpleClientset(),
				primaryIP:        net.ParseIP("10.0.0.0"),
				routerID:         "10.0.0.0",
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
				bgpFullMeshMode:  false,
				bgpPort:          10000,
				clientset:        fake.NewSimpleClientset(),
				primaryIP:        net.ParseIP("10.0.0.0"),
				routerID:         "10.0.0.0",
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
				bgpFullMeshMode:  false,
				bgpPort:          10000,
				clientset:        fake.NewSimpleClientset(),
				primaryIP:        net.ParseIP("10.0.0.0"),
				routerID:         "10.0.0.0",
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
				bgpFullMeshMode:  false,
				bgpPort:          10000,
				clientset:        fake.NewSimpleClientset(),
				primaryIP:        net.ParseIP("10.0.0.0"),
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
				bgpFullMeshMode:  false,
				bgpPort:          10000,
				clientset:        fake.NewSimpleClientset(),
				primaryIP:        net.ParseIP("10.0.0.0"),
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

func Test_generateTunnelName(t *testing.T) {
	testcases := []struct {
		name       string
		nodeIP     string
		tunnelName string
	}{
		{
			"IP less than 12 characters after removing '.'",
			"10.0.0.1",
			"tun-e443169117a",
		},
		{
			"IP has 12 characters after removing '.'",
			"100.200.300.400",
			"tun-9033d7906c7",
		},
		{
			"IPv6 tunnel names are properly handled and consistent",
			"2001:db8:42:2::/64",
			"tun-ba56986ef05",
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			tunnelName := generateTunnelName(testcase.nodeIP)
			assert.Lessf(t, len(tunnelName), 16, "the maximum length of the tunnel name should never exceed"+
				"15 characters as 16 characters is the maximum length of a Unix interface name")
			assert.Equal(t, testcase.tunnelName, tunnelName, "did not get expected tunnel interface name")
		})
	}
}

func createServices(clientset kubernetes.Interface, svcs []*v1core.Service) error {
	for _, svc := range svcs {
		_, err := clientset.CoreV1().Services("default").Create(context.Background(), svc, metav1.CreateOptions{})
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

func startInformersForRoutes(nrc *NetworkRoutingController, clientset kubernetes.Interface) {
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)
	svcInformer := informerFactory.Core().V1().Services().Informer()
	epInformer := informerFactory.Core().V1().Endpoints().Informer()
	nodeInformer := informerFactory.Core().V1().Nodes().Informer()

	go informerFactory.Start(nil)
	informerFactory.WaitForCacheSync(nil)

	nrc.svcLister = svcInformer.GetIndexer()
	nrc.epLister = epInformer.GetIndexer()
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

func ptrToString(str string) *string {
	return &str
}

func createFile(content, filename string) (*os.File, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot create file: %v", err)
	}

	if _, err = file.Write([]byte(content)); err != nil {
		return nil, fmt.Errorf("cannot write to file: %v", err)
	}

	fmt.Println("File is ", file.Name())
	return file, nil
}
