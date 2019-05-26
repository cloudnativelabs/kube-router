package routing

import (
	"errors"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/osrg/gobgp/config"
	gobgp "github.com/osrg/gobgp/server"
	"github.com/osrg/gobgp/table"

	v1core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
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
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:      "ClusterIP",
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
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:      "ClusterIP",
						ClusterIP: "10.0.0.1",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-2",
					},
					Spec: v1core.ServiceSpec{
						Type:      "LoadBalancer",
						ClusterIP: "10.0.0.2",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-3",
					},
					Spec: v1core.ServiceSpec{
						Type:      "NodePort",
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
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:      "ClusterIP",
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
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:      "ClusterIP",
						ClusterIP: "10.0.0.1",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-2",
					},
					Spec: v1core.ServiceSpec{
						Type:      "ClusterIP",
						ClusterIP: "None",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-3",
					},
					Spec: v1core.ServiceSpec{
						Type:      "ClusterIP",
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
			err := testcase.nrc.bgpServer.Start(&config.Global{
				Config: config.GlobalConfig{
					As:       1,
					RouterId: "10.0.0.0",
					Port:     10000,
				},
			})
			if err != nil {
				t.Fatalf("failed to start BGP server: %v", err)
			}
			defer testcase.nrc.bgpServer.Stop()
			w := testcase.nrc.bgpServer.Watch(gobgp.WatchBestPath(false))

			clientset := fake.NewSimpleClientset()
			startInformersForRoutes(testcase.nrc, clientset)

			err = createServices(clientset, testcase.existingServices)
			if err != nil {
				t.Fatalf("failed to create existing services: %v", err)
			}

			waitForListerWithTimeout(testcase.nrc.svcLister, time.Second*10, t)

			// ClusterIPs
			testcase.nrc.advertiseClusterIP = true
			testcase.nrc.advertiseExternalIP = false
			testcase.nrc.advertiseLoadBalancerIP = false

			toAdvertise, toWithdraw, _ := testcase.nrc.getActiveVIPs()
			testcase.nrc.advertiseVIPs(toAdvertise)
			testcase.nrc.withdrawVIPs(toWithdraw)

			watchEvents := waitForBGPWatchEventWithTimeout(time.Second*10, len(testcase.watchEvents), w, t)
			for _, watchEvent := range watchEvents {
				for _, path := range watchEvent.PathList {
					if _, ok := testcase.watchEvents[path.GetNlri().String()]; ok {
						continue
					} else {
						t.Errorf("got unexpected path: %v", path.GetNlri().String())
					}
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
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:        "ClusterIP",
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
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-2",
					},
					Spec: v1core.ServiceSpec{
						Type:      "LoadBalancer",
						ClusterIP: "10.0.0.2",
						// ignored since LoadBalancer services don't
						// advertise external IPs.
						ExternalIPs: []string{"2.2.2.2"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-3",
					},
					Spec: v1core.ServiceSpec{
						Type:        "NodePort",
						ClusterIP:   "10.0.0.3",
						ExternalIPs: []string{"3.3.3.3", "4.4.4.4"},
					},
				},
			},
			map[string]bool{
				"1.1.1.1/32": true,
				"3.3.3.3/32": true,
				"4.4.4.4/32": true,
			},
		},
		{
			"add bgp path for invalid service type",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
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
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-2",
					},
					Spec: v1core.ServiceSpec{
						Type:        "ClusterIP",
						ClusterIP:   "None",
						ExternalIPs: []string{"2.2.2.2"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-3",
					},
					Spec: v1core.ServiceSpec{
						Type:        "ClusterIP",
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
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:      "LoadBalancer",
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
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:      "LoadBalancer",
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
			},
			[]*v1core.Service{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:      "LoadBalancer",
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
						Type:      "LoadBalancer",
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
			if err != nil {
				t.Fatalf("failed to start BGP server: %v", err)
			}
			defer testcase.nrc.bgpServer.Stop()
			w := testcase.nrc.bgpServer.Watch(gobgp.WatchBestPath(false))

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

			watchEvents := waitForBGPWatchEventWithTimeout(time.Second*10, len(testcase.watchEvents), w, t)
			for _, watchEvent := range watchEvents {
				for _, path := range watchEvent.PathList {
					if _, ok := testcase.watchEvents[path.GetNlri().String()]; ok {
						continue
					} else {
						t.Errorf("got unexpected path: %v", path.GetNlri().String())
					}
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
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-2",
					},
					Spec: v1core.ServiceSpec{
						Type:        "NodePort",
						ClusterIP:   "10.0.0.2",
						ExternalIPs: []string{"2.2.2.2", "3.3.3.3"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-3",
					},
					Spec: v1core.ServiceSpec{
						Type:      "LoadBalancer",
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
			map[string]bool{
				"10.0.0.1/32":   true,
				"10.0.0.2/32":   true,
				"10.0.0.3/32":   true,
				"1.1.1.1/32":    true,
				"2.2.2.2/32":    true,
				"3.3.3.3/32":    true,
				"10.0.255.1/32": true,
				"10.0.255.2/32": true,
			},
		},
		{
			"opt out to advertise any IPs via annotations",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
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
						Type:        "LoadBalancer",
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
			if err != nil {
				t.Fatalf("failed to start BGP server: %v", err)
			}
			defer testcase.nrc.bgpServer.Stop()
			w := testcase.nrc.bgpServer.Watch(gobgp.WatchBestPath(false))

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

			watchEvents := waitForBGPWatchEventWithTimeout(time.Second*10, len(testcase.watchEvents), w, t)
			for _, watchEvent := range watchEvents {
				for _, path := range watchEvent.PathList {
					if _, ok := testcase.watchEvents[path.GetNlri().String()]; ok {
						continue
					} else {
						t.Errorf("got unexpected path: %v", path.GetNlri().String())
					}
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
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-2",
					},
					Spec: v1core.ServiceSpec{
						Type:        "NodePort",
						ClusterIP:   "10.0.0.2",
						ExternalIPs: []string{"2.2.2.2", "3.3.3.3"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-3",
					},
					Spec: v1core.ServiceSpec{
						Type:      "LoadBalancer",
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
						Type:        "ClusterIP",
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
						Type:        "NodePort",
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
						Type:      "LoadBalancer",
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
			map[string]bool{
				"10.0.0.1/32":   true,
				"10.0.0.2/32":   true,
				"10.0.0.3/32":   true,
				"1.1.1.1/32":    true,
				"2.2.2.2/32":    true,
				"3.3.3.3/32":    true,
				"10.0.255.1/32": true,
				"10.0.255.2/32": true,
			},
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
			if err != nil {
				t.Fatalf("failed to start BGP server: %v", err)
			}
			defer testcase.nrc.bgpServer.Stop()
			w := testcase.nrc.bgpServer.Watch(gobgp.WatchBestPath(false))

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

			watchEvents := waitForBGPWatchEventWithTimeout(time.Second*10, len(testcase.watchEvents), w, t)
			for _, watchEvent := range watchEvents {
				for _, path := range watchEvent.PathList {
					if _, ok := testcase.watchEvents[path.GetNlri().String()]; ok {
						continue
					} else {
						t.Errorf("got unexpected path: %v", path.GetNlri().String())
					}
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
					Type:        "ClusterIP",
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
					Type:        "ClusterIP",
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

			_, err := clientset.CoreV1().Endpoints("default").Create(testcase.existingEndpoint)
			if err != nil {
				t.Fatalf("failed to create existing endpoints: %v", err)
			}

			_, err = clientset.CoreV1().Services("default").Create(testcase.existingService)
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
	testcases := []struct {
		name        string
		nrc         *NetworkRoutingController
		envNodeName string
		node        *v1core.Node
		// the key is the subnet from the watch event
		watchEvents map[string]bool
		err         error
	}{
		{
			"add bgp path for pod cidr using NODE_NAME",
			&NetworkRoutingController{
				bgpServer: gobgp.NewBgpServer(),
			},
			"node-1",
			&v1core.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node-1",
				},
				Spec: v1core.NodeSpec{
					PodCIDR: "172.20.0.0/24",
				},
			},
			map[string]bool{
				"172.20.0.0/24": true,
			},
			nil,
		},
		{
			"add bgp path for pod cidr using hostname override",
			&NetworkRoutingController{
				bgpServer:        gobgp.NewBgpServer(),
				hostnameOverride: "node-1",
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
			map[string]bool{
				"172.20.0.0/24": true,
			},
			nil,
		},
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
			if err != nil {
				t.Fatalf("failed to start BGP server: %v", err)
			}
			defer testcase.nrc.bgpServer.Stop()
			w := testcase.nrc.bgpServer.Watch(gobgp.WatchBestPath(false))

			clientset := fake.NewSimpleClientset()
			_, err = clientset.CoreV1().Nodes().Create(testcase.node)
			if err != nil {
				t.Fatalf("failed to create node: %v", err)
			}
			testcase.nrc.clientset = clientset

			os.Setenv("NODE_NAME", testcase.envNodeName)
			defer os.Unsetenv("NODE_NAME")

			err = testcase.nrc.advertisePodRoute()
			if !reflect.DeepEqual(err, testcase.err) {
				t.Logf("actual error: %v", err)
				t.Logf("expected error: %v", testcase.err)
				t.Error("did not get expected error")
			}

			watchEvents := waitForBGPWatchEventWithTimeout(time.Second*10, len(testcase.watchEvents), w, t)
			for _, watchEvent := range watchEvents {
				for _, path := range watchEvent.PathList {
					if _, ok := testcase.watchEvents[path.GetNlri().String()]; ok {
						continue
					} else {
						t.Errorf("got unexpected path: %v", path.GetNlri().String())
					}
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
				nodeIP:          net.ParseIP("10.0.0.0"),
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
				nodeIP:          net.ParseIP("10.0.0.0"),
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
				nodeIP:          net.ParseIP("10.0.0.0"),
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
				nodeIP:          net.ParseIP("10.0.0.0"),
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
			err := testcase.nrc.bgpServer.Start(&config.Global{
				Config: config.GlobalConfig{
					As:       1,
					RouterId: "10.0.0.0",
					Port:     10000,
				},
			})
			if err != nil {
				t.Fatalf("failed to start BGP server: %v", err)
			}
			defer testcase.nrc.bgpServer.Stop()

			if err = createNodes(testcase.nrc.clientset, testcase.existingNodes); err != nil {
				t.Errorf("failed to create existing nodes: %v", err)
			}

			testcase.nrc.syncInternalPeers()

			neighbors := testcase.nrc.bgpServer.GetNeighbor("", false)
			for _, neighbor := range neighbors {
				_, exists := testcase.neighbors[neighbor.Config.NeighborAddress]
				if !exists {
					t.Errorf("expected neighbor: %v doesn't exist", neighbor.Config.NeighborAddress)
				}
			}

			if !reflect.DeepEqual(testcase.nrc.activeNodes, testcase.neighbors) {
				t.Logf("actual active nodes: %v", testcase.nrc.activeNodes)
				t.Logf("expected active nodes: %v", testcase.neighbors)
				t.Errorf("did not get expected activeNodes")
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

type PolicyTestCase struct {
	name                   string
	nrc                    *NetworkRoutingController
	existingNodes          []*v1core.Node
	existingServices       []*v1core.Service
	podDefinedSet          *config.DefinedSets
	clusterIPDefinedSet    *config.DefinedSets
	externalPeerDefinedSet *config.DefinedSets
	exportPolicyStatements []*config.Statement
	importPolicyStatements []*config.Statement
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
			&config.DefinedSets{
				PrefixSets: []config.PrefixSet{
					{
						PrefixSetName: "podcidrprefixset",
						PrefixList: []config.Prefix{
							{
								IpPrefix:        "172.20.0.0/24",
								MasklengthRange: "24..24",
							},
						},
					},
				},
				NeighborSets:   []config.NeighborSet{},
				TagSets:        []config.TagSet{},
				BgpDefinedSets: config.BgpDefinedSets{},
			},
			&config.DefinedSets{
				PrefixSets: []config.PrefixSet{
					{
						PrefixSetName: "clusteripprefixset",
						PrefixList: []config.Prefix{
							{
								IpPrefix:        "1.1.1.1/32",
								MasklengthRange: "32..32",
							},
							{
								IpPrefix:        "10.0.0.1/32",
								MasklengthRange: "32..32",
							},
						},
					},
				},
				NeighborSets:   []config.NeighborSet{},
				TagSets:        []config.TagSet{},
				BgpDefinedSets: config.BgpDefinedSets{},
			},
			&config.DefinedSets{},
			[]*config.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: config.Conditions{
						MatchPrefixSet: config.MatchPrefixSet{
							PrefixSet:       "podcidrprefixset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
						MatchNeighborSet: config.MatchNeighborSet{
							NeighborSet:     "iBGPpeerset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
					},
					Actions: config.Actions{
						RouteDisposition: config.ROUTE_DISPOSITION_ACCEPT_ROUTE,
					},
				},
			},
			[]*config.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: config.Conditions{
						MatchPrefixSet: config.MatchPrefixSet{
							PrefixSet:       "clusteripprefixset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
					},
					Actions: config.Actions{
						RouteDisposition: config.ROUTE_DISPOSITION_REJECT_ROUTE,
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
				globalPeerRouters: []*config.Neighbor{
					{
						Config: config.NeighborConfig{NeighborAddress: "10.10.0.1"},
					},
					{
						Config: config.NeighborConfig{NeighborAddress: "10.10.0.2"},
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
			&config.DefinedSets{
				PrefixSets: []config.PrefixSet{
					{
						PrefixSetName: "podcidrprefixset",
						PrefixList: []config.Prefix{
							{
								IpPrefix:        "172.20.0.0/24",
								MasklengthRange: "24..24",
							},
						},
					},
				},
				NeighborSets:   []config.NeighborSet{},
				TagSets:        []config.TagSet{},
				BgpDefinedSets: config.BgpDefinedSets{},
			},
			&config.DefinedSets{
				PrefixSets: []config.PrefixSet{
					{
						PrefixSetName: "clusteripprefixset",
						PrefixList: []config.Prefix{
							{
								IpPrefix:        "1.1.1.1/32",
								MasklengthRange: "32..32",
							},
							{
								IpPrefix:        "10.0.0.1/32",
								MasklengthRange: "32..32",
							},
						},
					},
				},
				NeighborSets:   []config.NeighborSet{},
				TagSets:        []config.TagSet{},
				BgpDefinedSets: config.BgpDefinedSets{},
			},
			&config.DefinedSets{
				PrefixSets: []config.PrefixSet{},
				NeighborSets: []config.NeighborSet{
					{
						NeighborSetName:  "externalpeerset",
						NeighborInfoList: []string{"10.10.0.1/32", "10.10.0.2/32"},
					},
				},
				TagSets:        []config.TagSet{},
				BgpDefinedSets: config.BgpDefinedSets{},
			},
			[]*config.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: config.Conditions{
						MatchPrefixSet: config.MatchPrefixSet{
							PrefixSet:       "podcidrprefixset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
						MatchNeighborSet: config.MatchNeighborSet{
							NeighborSet:     "iBGPpeerset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
					},
					Actions: config.Actions{
						RouteDisposition: config.ROUTE_DISPOSITION_ACCEPT_ROUTE,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: config.Conditions{
						MatchPrefixSet: config.MatchPrefixSet{
							PrefixSet:       "clusteripprefixset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
						MatchNeighborSet: config.MatchNeighborSet{
							NeighborSet:     "externalpeerset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
					},
					Actions: config.Actions{
						RouteDisposition: config.ROUTE_DISPOSITION_ACCEPT_ROUTE,
					},
				},
			},
			[]*config.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: config.Conditions{
						MatchPrefixSet: config.MatchPrefixSet{
							PrefixSet:       "clusteripprefixset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
					},
					Actions: config.Actions{
						RouteDisposition: config.ROUTE_DISPOSITION_REJECT_ROUTE,
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
				globalPeerRouters: []*config.Neighbor{
					{
						Config: config.NeighborConfig{NeighborAddress: "10.10.0.1"},
					},
					{
						Config: config.NeighborConfig{NeighborAddress: "10.10.0.2"},
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
			&config.DefinedSets{
				PrefixSets: []config.PrefixSet{
					{
						PrefixSetName: "podcidrprefixset",
						PrefixList: []config.Prefix{
							{
								IpPrefix:        "172.20.0.0/24",
								MasklengthRange: "24..24",
							},
						},
					},
				},
				NeighborSets:   []config.NeighborSet{},
				TagSets:        []config.TagSet{},
				BgpDefinedSets: config.BgpDefinedSets{},
			},
			&config.DefinedSets{
				PrefixSets: []config.PrefixSet{
					{
						PrefixSetName: "clusteripprefixset",
						PrefixList: []config.Prefix{
							{
								IpPrefix:        "1.1.1.1/32",
								MasklengthRange: "32..32",
							},
							{
								IpPrefix:        "10.0.0.1/32",
								MasklengthRange: "32..32",
							},
						},
					},
				},
				NeighborSets:   []config.NeighborSet{},
				TagSets:        []config.TagSet{},
				BgpDefinedSets: config.BgpDefinedSets{},
			},
			&config.DefinedSets{
				PrefixSets: []config.PrefixSet{},
				NeighborSets: []config.NeighborSet{
					{
						NeighborSetName:  "externalpeerset",
						NeighborInfoList: []string{"10.10.0.1/32", "10.10.0.2/32"},
					},
				},
				TagSets:        []config.TagSet{},
				BgpDefinedSets: config.BgpDefinedSets{},
			},
			[]*config.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: config.Conditions{
						MatchPrefixSet: config.MatchPrefixSet{
							PrefixSet:       "clusteripprefixset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
						MatchNeighborSet: config.MatchNeighborSet{
							NeighborSet:     "externalpeerset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
					},
					Actions: config.Actions{
						RouteDisposition: config.ROUTE_DISPOSITION_ACCEPT_ROUTE,
					},
				},
			},
			[]*config.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: config.Conditions{
						MatchPrefixSet: config.MatchPrefixSet{
							PrefixSet:       "clusteripprefixset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
					},
					Actions: config.Actions{
						RouteDisposition: config.ROUTE_DISPOSITION_REJECT_ROUTE,
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
				globalPeerRouters: []*config.Neighbor{
					{
						Config: config.NeighborConfig{NeighborAddress: "10.10.0.1"},
					},
					{
						Config: config.NeighborConfig{NeighborAddress: "10.10.0.2"},
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
			&config.DefinedSets{
				PrefixSets: []config.PrefixSet{
					{
						PrefixSetName: "podcidrprefixset",
						PrefixList: []config.Prefix{
							{
								IpPrefix:        "172.20.0.0/24",
								MasklengthRange: "24..24",
							},
						},
					},
				},
				NeighborSets:   []config.NeighborSet{},
				TagSets:        []config.TagSet{},
				BgpDefinedSets: config.BgpDefinedSets{},
			},
			&config.DefinedSets{
				PrefixSets: []config.PrefixSet{
					{
						PrefixSetName: "clusteripprefixset",
						PrefixList: []config.Prefix{
							{
								IpPrefix:        "1.1.1.1/32",
								MasklengthRange: "32..32",
							},
							{
								IpPrefix:        "10.0.0.1/32",
								MasklengthRange: "32..32",
							},
						},
					},
				},
				NeighborSets:   []config.NeighborSet{},
				TagSets:        []config.TagSet{},
				BgpDefinedSets: config.BgpDefinedSets{},
			},
			&config.DefinedSets{
				PrefixSets: []config.PrefixSet{},
				NeighborSets: []config.NeighborSet{
					{
						NeighborSetName:  "externalpeerset",
						NeighborInfoList: []string{"10.10.0.1/32", "10.10.0.2/32"},
					},
				},
				TagSets:        []config.TagSet{},
				BgpDefinedSets: config.BgpDefinedSets{},
			},
			[]*config.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: config.Conditions{
						MatchPrefixSet: config.MatchPrefixSet{
							PrefixSet:       "podcidrprefixset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
						MatchNeighborSet: config.MatchNeighborSet{
							NeighborSet:     "iBGPpeerset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
					},
					Actions: config.Actions{
						RouteDisposition: config.ROUTE_DISPOSITION_ACCEPT_ROUTE,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: config.Conditions{
						MatchPrefixSet: config.MatchPrefixSet{
							PrefixSet:       "clusteripprefixset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
						MatchNeighborSet: config.MatchNeighborSet{
							NeighborSet:     "externalpeerset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
					},
					Actions: config.Actions{
						RouteDisposition: config.ROUTE_DISPOSITION_ACCEPT_ROUTE,
						BgpActions: config.BgpActions{
							SetAsPathPrepend: config.SetAsPathPrepend{
								As:      "65100",
								RepeatN: 5,
							},
						},
					},
				},
			},
			[]*config.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: config.Conditions{
						MatchPrefixSet: config.MatchPrefixSet{
							PrefixSet:       "clusteripprefixset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
					},
					Actions: config.Actions{
						RouteDisposition: config.ROUTE_DISPOSITION_REJECT_ROUTE,
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
				globalPeerRouters: []*config.Neighbor{
					{
						Config: config.NeighborConfig{NeighborAddress: "10.10.0.1"},
					},
					{
						Config: config.NeighborConfig{NeighborAddress: "10.10.0.2"},
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
			&config.DefinedSets{
				PrefixSets: []config.PrefixSet{
					{
						PrefixSetName: "podcidrprefixset",
						PrefixList: []config.Prefix{
							{
								IpPrefix:        "172.20.0.0/24",
								MasklengthRange: "24..24",
							},
						},
					},
				},
				NeighborSets:   []config.NeighborSet{},
				TagSets:        []config.TagSet{},
				BgpDefinedSets: config.BgpDefinedSets{},
			},
			&config.DefinedSets{
				PrefixSets: []config.PrefixSet{
					{
						PrefixSetName: "clusteripprefixset",
						PrefixList: []config.Prefix{
							{
								IpPrefix:        "1.1.1.1/32",
								MasklengthRange: "32..32",
							},
							{
								IpPrefix:        "10.0.0.1/32",
								MasklengthRange: "32..32",
							},
						},
					},
				},
				NeighborSets:   []config.NeighborSet{},
				TagSets:        []config.TagSet{},
				BgpDefinedSets: config.BgpDefinedSets{},
			},
			&config.DefinedSets{
				PrefixSets: []config.PrefixSet{},
				NeighborSets: []config.NeighborSet{
					{
						NeighborSetName:  "externalpeerset",
						NeighborInfoList: []string{"10.10.0.1/32", "10.10.0.2/32"},
					},
				},
				TagSets:        []config.TagSet{},
				BgpDefinedSets: config.BgpDefinedSets{},
			},
			[]*config.Statement{
				{
					Name: "kube_router_export_stmt0",
					Conditions: config.Conditions{
						MatchPrefixSet: config.MatchPrefixSet{
							PrefixSet:       "podcidrprefixset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
						MatchNeighborSet: config.MatchNeighborSet{
							NeighborSet:     "iBGPpeerset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
					},
					Actions: config.Actions{
						RouteDisposition: config.ROUTE_DISPOSITION_ACCEPT_ROUTE,
					},
				},
				{
					Name: "kube_router_export_stmt1",
					Conditions: config.Conditions{
						MatchPrefixSet: config.MatchPrefixSet{
							PrefixSet:       "clusteripprefixset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
						MatchNeighborSet: config.MatchNeighborSet{
							NeighborSet:     "externalpeerset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
					},
					Actions: config.Actions{
						RouteDisposition: config.ROUTE_DISPOSITION_ACCEPT_ROUTE,
					},
				},
			},
			[]*config.Statement{
				{
					Name: "kube_router_import_stmt0",
					Conditions: config.Conditions{
						MatchPrefixSet: config.MatchPrefixSet{
							PrefixSet:       "clusteripprefixset",
							MatchSetOptions: config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY,
						},
					},
					Actions: config.Actions{
						RouteDisposition: config.ROUTE_DISPOSITION_REJECT_ROUTE,
					},
				},
			},
			nil,
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
			if err != nil {
				t.Fatalf("failed to start BGP server: %v", err)
			}
			defer testcase.nrc.bgpServer.Stop()

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

			podDefinedSet, err := testcase.nrc.bgpServer.GetDefinedSet(table.DEFINED_TYPE_PREFIX, "podcidrprefixset")
			if err != nil {
				t.Fatalf("error validating defined sets: %v", err)
			}

			if !podDefinedSet.Equal(testcase.podDefinedSet) {
				t.Logf("expected pod defined set: %+v", testcase.podDefinedSet.PrefixSets)
				t.Logf("actual pod defined set: %+v", podDefinedSet.PrefixSets)
				t.Error("unexpected pod defined set")
			}

			clusterIPDefinedSet, err := testcase.nrc.bgpServer.GetDefinedSet(table.DEFINED_TYPE_PREFIX, "clusteripprefixset")
			if err != nil {
				t.Fatalf("error validating defined sets: %v", err)
			}

			if !clusterIPDefinedSet.Equal(testcase.clusterIPDefinedSet) {
				t.Logf("expected cluster ip defined set: %+v", testcase.clusterIPDefinedSet.PrefixSets)
				t.Logf("actual cluster ip defined set: %+v", clusterIPDefinedSet.PrefixSets)
				t.Error("unexpected cluster ip defined set")
			}

			externalPeerDefinedSet, err := testcase.nrc.bgpServer.GetDefinedSet(table.DEFINED_TYPE_NEIGHBOR, "externalpeerset")
			if err != nil {
				t.Fatalf("error validating defined sets: %v", err)
			}

			if !externalPeerDefinedSet.Equal(testcase.externalPeerDefinedSet) {
				t.Logf("expected external peer defined set: %+v", testcase.externalPeerDefinedSet.NeighborSets)
				t.Logf("actual external peer defined set: %+v", externalPeerDefinedSet.NeighborSets)
				t.Error("unexpected external peer defined set")
			}

			checkPolicies(t, testcase, table.POLICY_DIRECTION_EXPORT, table.ROUTE_TYPE_REJECT, testcase.exportPolicyStatements)
			checkPolicies(t, testcase, table.POLICY_DIRECTION_IMPORT, table.ROUTE_TYPE_ACCEPT, testcase.importPolicyStatements)
		})
	}
}

func checkPolicies(t *testing.T, testcase PolicyTestCase, direction table.PolicyDirection, defaultPolicy table.RouteType,
	policyStatements []*config.Statement) {
	policies := testcase.nrc.bgpServer.GetPolicy()
	policyExists := false
	for _, policy := range policies {
		if policy.Name == "kube_router_"+direction.String() {
			policyExists = true
			break
		}
	}
	if !policyExists {
		t.Errorf("policy 'kube_router_%v' was not added", direction)
	}

	routeType, policyAssignments, err := testcase.nrc.bgpServer.GetPolicyAssignment("", direction)
	if routeType != defaultPolicy {
		t.Errorf("expected route type '%v' for %v policy assignment, but got %v", defaultPolicy, direction, routeType)
	}
	if err != nil {
		t.Fatalf("failed to get policy assignments: %v", err)
	}

	policyAssignmentExists := false
	for _, policyAssignment := range policyAssignments {
		if policyAssignment.Name == "kube_router_"+direction.String() {
			policyAssignmentExists = true
		}
	}

	if !policyAssignmentExists {
		t.Errorf("export policy assignment 'kube_router_%v' was not added", direction)
	}

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
}

func Test_generateTunnelName(t *testing.T) {
	testcases := []struct {
		name       string
		nodeIP     string
		tunnelName string
	}{
		{
			"IP less than 12 characters after removing '.'",
			"10.0.0.1",
			"tun-10001",
		},
		{
			"IP has 12 characters after removing '.'",
			"100.200.300.400",
			"tun100200300400",
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			tunnelName := generateTunnelName(testcase.nodeIP)
			if tunnelName != testcase.tunnelName {
				t.Logf("actual tunnel interface name: %s", tunnelName)
				t.Logf("expected tunnel interface name: %s", testcase.tunnelName)
				t.Error("did not get expected tunnel interface name")
			}
		})
	}
}

func createServices(clientset kubernetes.Interface, svcs []*v1core.Service) error {
	for _, svc := range svcs {
		_, err := clientset.CoreV1().Services("default").Create(svc)
		if err != nil {
			return err
		}
	}

	return nil
}

func createNodes(clientset kubernetes.Interface, nodes []*v1core.Node) error {
	for _, node := range nodes {
		_, err := clientset.CoreV1().Nodes().Create(node)
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

	go informerFactory.Start(nil)
	informerFactory.WaitForCacheSync(nil)

	nrc.svcLister = svcInformer.GetIndexer()
	nrc.epLister = epInformer.GetIndexer()
}

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

func waitForBGPWatchEventWithTimeout(timeout time.Duration, expectedNumEvents int, w *gobgp.Watcher, t *testing.T) []*gobgp.WatchEventBestPath {
	timeoutCh := time.After(timeout)
	var events []*gobgp.WatchEventBestPath
	for {
		select {
		case <-timeoutCh:
			t.Fatalf("timeout exceeded waiting for %d watch events, got %d", expectedNumEvents, len(events))
		case event := <-w.Event():
			events = append(events, event.(*gobgp.WatchEventBestPath))
		default:
			if len(events) == expectedNumEvents {
				return events
			}
		}
	}
}

func ptrToString(str string) *string {
	return &str
}
