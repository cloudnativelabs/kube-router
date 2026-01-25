package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/k8s/indexers"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/moby/ipvs"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
	v1core "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

// mockIPVSState holds stateful IPVS data for tests that need to track services
type mockIPVSState struct {
	services []*ipvs.Service
}

func newMockIPVSState() *mockIPVSState {
	return &mockIPVSState{
		services: make([]*ipvs.Service, 0, 64),
	}
}

// addService adds an IPVS service to the mock state and returns the created service
func (m *mockIPVSState) addService(vip net.IP, protocol, port uint16) *ipvs.Service {
	svc := &ipvs.Service{
		Address:  vip,
		Protocol: protocol,
		Port:     port,
	}
	m.services = append(m.services, svc)
	return svc
}

func waitForListerWithTimeout(t *testing.T, lister cache.Indexer, timeout time.Duration) {
	t.Helper()
	tick := time.Tick(100 * time.Millisecond)
	timeoutCh := time.After(timeout)
	for {
		select {
		case <-timeoutCh:
			t.Fatalf("timeout exceeded waiting for lister to fill cache")
		case <-tick:
			if len(lister.List()) != 0 {
				return
			}
		}
	}
}

func startInformersForServiceProxy(t *testing.T, nsc *NetworkServicesController, clientset kubernetes.Interface) {
	t.Helper()
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)
	svcInformer := informerFactory.Core().V1().Services().Informer()
	epSliceInformer := informerFactory.Discovery().V1().EndpointSlices().Informer()
	podInformer := informerFactory.Core().V1().Pods().Informer()

	err := epSliceInformer.AddIndexers(map[string]cache.IndexFunc{
		indexers.ServiceNameIndex: indexers.ServiceNameIndexFunc,
	})
	if err != nil {
		t.Fatalf("failed to add indexers to endpoint slice informer: %v", err)
	}

	go informerFactory.Start(nil)
	informerFactory.WaitForCacheSync(nil)

	nsc.svcLister = svcInformer.GetIndexer()
	nsc.epSliceLister = epSliceInformer.GetIndexer()
	nsc.podLister = podInformer.GetIndexer()
}

func stringToPtr(str string) *string {
	return &str
}

func int32ToPtr(i int32) *int32 {
	return &i
}

func protoToPtr(proto v1core.Protocol) *v1core.Protocol {
	return &proto
}

func boolToPtr(b bool) *bool {
	return &b
}

// setupTestController creates and initializes a NetworkServicesController for testing.
// It returns the mock IPVS state (for injecting pre-existing services), the LinuxNetworkingMock
// (for verifying calls), and the controller.
func setupTestController(t *testing.T, service *v1core.Service, endpointSlice *discoveryv1.EndpointSlice) (
	*mockIPVSState, *LinuxNetworkingMock, *NetworkServicesController) {
	t.Helper()

	ipvsState := newMockIPVSState()

	// Create the mock using moq-generated LinuxNetworkingMock with inline implementations
	mock := &LinuxNetworkingMock{
		getKubeDummyInterfaceFunc: func() (netlink.Link, error) {
			return netlink.LinkByName("lo")
		},
		ipAddrAddFunc: func(iface netlink.Link, ip string, nodeIP string, addRoute bool) error {
			return nil
		},
		ipAddrDelFunc: func(iface netlink.Link, ip string, nodeIP string) error {
			return nil
		},
		ipvsAddServerFunc: func(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error {
			return nil
		},
		ipvsAddServiceFunc: func(svcs []*ipvs.Service, vip net.IP, protocol uint16, port uint16,
			persistent bool, persistentTimeout int32, scheduler string,
			flags schedFlags) ([]*ipvs.Service, *ipvs.Service, error) {
			svc := &ipvs.Service{
				Address:  vip,
				Protocol: protocol,
				Port:     port,
			}
			ipvsState.services = append(ipvsState.services, svc)
			return svcs, svc, nil
		},
		ipvsDelServiceFunc: func(ipvsSvc *ipvs.Service) error {
			for idx, svc := range ipvsState.services {
				if svc.Address.Equal(ipvsSvc.Address) && svc.Protocol == ipvsSvc.Protocol &&
					svc.Port == ipvsSvc.Port {
					ipvsState.services = append(ipvsState.services[:idx], ipvsState.services[idx+1:]...)
					break
				}
			}
			return nil
		},
		ipvsGetDestinationsFunc: func(ipvsSvc *ipvs.Service) ([]*ipvs.Destination, error) {
			return []*ipvs.Destination{}, nil
		},
		ipvsGetServicesFunc: func() ([]*ipvs.Service, error) {
			// Return a copy to avoid mutation issues during iteration
			svcsCopy := make([]*ipvs.Service, len(ipvsState.services))
			copy(svcsCopy, ipvsState.services)
			return svcsCopy, nil
		},
		setupPolicyRoutingForDSRFunc: func(setupIPv4 bool, setupIPv6 bool) error {
			return nil
		},
		setupRoutesForExternalIPForDSRFunc: func(serviceInfo serviceInfoMap, setupIPv4 bool, setupIPv6 bool) error {
			return nil
		},
	}

	clientset := fake.NewSimpleClientset()

	if endpointSlice != nil && endpointSlice.Name != "" {
		_, err := clientset.DiscoveryV1().EndpointSlices("default").Create(
			context.Background(), endpointSlice, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("failed to create endpoint slice: %v", err)
		}
	}

	_, err := clientset.CoreV1().Services("default").Create(
		context.Background(), service, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	krNode := &utils.LocalKRNode{
		KRNode: utils.KRNode{
			NodeName:  "node-1",
			PrimaryIP: net.ParseIP("10.0.0.0"),
		},
	}
	nsc := &NetworkServicesController{
		krNode:     krNode,
		ln:         mock,
		nphc:       NewNodePortHealthCheck(),
		ipsetMutex: &sync.Mutex{},
	}

	startInformersForServiceProxy(t, nsc, clientset)
	waitForListerWithTimeout(t, nsc.svcLister, time.Second*10)

	nsc.setServiceMap(nsc.buildServicesInfo())
	nsc.endpointsMap = nsc.buildEndpointSliceInfo()

	return ipvsState, mock, nsc
}

// getIPsFromAddrAddCalls extracts IP addresses from ipAddrAdd mock calls
func getIPsFromAddrAddCalls(mock *LinuxNetworkingMock) []string {
	var ips []string
	for _, call := range mock.ipAddrAddCalls() {
		ips = append(ips, call.IP)
	}
	return ips
}

// getServicesFromAddServiceCalls formats ipvsAddService calls as strings for comparison
func getServicesFromAddServiceCalls(mock *LinuxNetworkingMock) []string {
	var services []string
	for _, args := range mock.ipvsAddServiceCalls() {
		services = append(services, fmt.Sprintf("%v:%v:%v:%v:%v",
			args.Vip, args.Protocol, args.Port, args.Persistent, args.Scheduler))
	}
	return services
}

// getEndpointsFromAddServerCalls formats ipvsAddServer calls as strings for comparison
func getEndpointsFromAddServerCalls(mock *LinuxNetworkingMock) []string {
	var endpoints []string
	for _, args := range mock.ipvsAddServerCalls() {
		svc := args.IpvsSvc
		dst := args.IpvsDst
		endpoints = append(endpoints, fmt.Sprintf("%v:%v->%v:%v",
			svc.Address, svc.Port, dst.Address, dst.Port))
	}
	return endpoints
}

func TestNetworkServicesController_syncIpvsServices(t *testing.T) {
	// Default traffic policies used in tests
	intTrafficPolicyCluster := v1core.ServiceInternalTrafficPolicyCluster
	extTrafficPolicyCluster := v1core.ServiceExternalTrafficPolicyCluster

	tests := []struct {
		name                     string
		service                  *v1core.Service
		endpointSlice            *discoveryv1.EndpointSlice
		injectPreExistingIpvsSvc bool
		expectedIPs              []string
		expectedServices         []string
		expectedEndpoints        []string
		verifyDSRSetup           bool // whether to verify DSR-related mock calls
		verifyPreExistingDeleted bool // whether to verify pre-existing services were deleted
	}{
		{
			name: "service with externalIPs and no endpoints",
			service: &v1core.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "svc-1"},
				Spec: v1core.ServiceSpec{
					Type:                  "ClusterIP",
					ClusterIP:             "10.0.0.1",
					ExternalIPs:           []string{"1.1.1.1", "2.2.2.2"},
					InternalTrafficPolicy: &intTrafficPolicyCluster,
					ExternalTrafficPolicy: extTrafficPolicyCluster,
					Ports: []v1core.ServicePort{
						{Name: "port-1", Port: 8080, Protocol: "TCP"},
					},
				},
			},
			endpointSlice:            &discoveryv1.EndpointSlice{},
			injectPreExistingIpvsSvc: true,
			expectedIPs:              []string{"10.0.0.1", "1.1.1.1", "2.2.2.2"},
			expectedServices: []string{
				"10.0.0.1:6:8080:false:rr",
				"1.1.1.1:6:8080:false:rr",
				"2.2.2.2:6:8080:false:rr",
			},
			verifyDSRSetup:           true,
			verifyPreExistingDeleted: true,
		},
		{
			name: "service with loadbalancer IPs",
			service: &v1core.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "svc-1"},
				Spec: v1core.ServiceSpec{
					Type:                  "LoadBalancer",
					ClusterIP:             "10.0.0.1",
					ExternalIPs:           []string{"1.1.1.1", "2.2.2.2"},
					InternalTrafficPolicy: &intTrafficPolicyCluster,
					ExternalTrafficPolicy: extTrafficPolicyCluster,
					Ports: []v1core.ServicePort{
						{Name: "port-1", Protocol: "TCP", Port: 8080},
					},
				},
				Status: v1core.ServiceStatus{
					LoadBalancer: v1core.LoadBalancerStatus{
						Ingress: []v1core.LoadBalancerIngress{
							{IP: "10.255.0.1"},
							{IP: "10.255.0.2"},
						},
					},
				},
			},
			endpointSlice: &discoveryv1.EndpointSlice{},
			expectedIPs:   []string{"10.0.0.1", "1.1.1.1", "2.2.2.2", "10.255.0.1", "10.255.0.2"},
			expectedServices: []string{
				"10.0.0.1:6:8080:false:rr",
				"1.1.1.1:6:8080:false:rr",
				"2.2.2.2:6:8080:false:rr",
				"10.255.0.1:6:8080:false:rr",
				"10.255.0.2:6:8080:false:rr",
			},
		},
		{
			name: "service with loadbalancer IPs and skiplbips annotation",
			service: &v1core.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					Annotations: map[string]string{
						"kube-router.io/service.skiplbips": "true",
					},
				},
				Spec: v1core.ServiceSpec{
					Type:                  "LoadBalancer",
					ClusterIP:             "10.0.0.1",
					ExternalIPs:           []string{"1.1.1.1", "2.2.2.2"},
					InternalTrafficPolicy: &intTrafficPolicyCluster,
					ExternalTrafficPolicy: extTrafficPolicyCluster,
					Ports: []v1core.ServicePort{
						{Name: "port-1", Protocol: "TCP", Port: 8080},
					},
				},
				Status: v1core.ServiceStatus{
					LoadBalancer: v1core.LoadBalancerStatus{
						Ingress: []v1core.LoadBalancerIngress{
							{IP: "10.255.0.1"},
							{IP: "10.255.0.2"},
						},
					},
				},
			},
			endpointSlice: &discoveryv1.EndpointSlice{},
			expectedIPs:   []string{"10.0.0.1", "1.1.1.1", "2.2.2.2"},
			expectedServices: []string{
				"10.0.0.1:6:8080:false:rr",
				"1.1.1.1:6:8080:false:rr",
				"2.2.2.2:6:8080:false:rr",
			},
		},
		{
			name: "service with loadbalancer hostname only (no IPs)",
			service: &v1core.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "svc-1"},
				Spec: v1core.ServiceSpec{
					Type:                  "LoadBalancer",
					ClusterIP:             "10.0.0.1",
					ExternalIPs:           []string{"1.1.1.1", "2.2.2.2"},
					InternalTrafficPolicy: &intTrafficPolicyCluster,
					ExternalTrafficPolicy: extTrafficPolicyCluster,
					Ports: []v1core.ServicePort{
						{Name: "port-1", Protocol: "TCP", Port: 8080},
					},
				},
				Status: v1core.ServiceStatus{
					LoadBalancer: v1core.LoadBalancerStatus{
						Ingress: []v1core.LoadBalancerIngress{
							{Hostname: "foo-bar.zone.elb.example.com"},
						},
					},
				},
			},
			endpointSlice: &discoveryv1.EndpointSlice{},
			expectedIPs:   []string{"10.0.0.1", "1.1.1.1", "2.2.2.2"},
			expectedServices: []string{
				"10.0.0.1:6:8080:false:rr",
				"1.1.1.1:6:8080:false:rr",
				"2.2.2.2:6:8080:false:rr",
			},
		},
		{
			name: "node has endpoints for service",
			service: &v1core.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "svc-1", Namespace: "default"},
				Spec: v1core.ServiceSpec{
					Type:                  "ClusterIP",
					ClusterIP:             "10.0.0.1",
					ExternalIPs:           []string{"1.1.1.1", "2.2.2.2"},
					InternalTrafficPolicy: &intTrafficPolicyCluster,
					ExternalTrafficPolicy: extTrafficPolicyCluster,
					Ports: []v1core.ServicePort{
						{Name: "port-1", Protocol: "TCP", Port: 8080},
					},
				},
			},
			endpointSlice: &discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc-1-slice",
					Namespace: "default",
					Labels: map[string]string{
						"kubernetes.io/service-name": "svc-1",
					},
				},
				AddressType: discoveryv1.AddressTypeIPv4,
				Endpoints: []discoveryv1.Endpoint{
					{
						Addresses:  []string{"172.20.1.1"},
						NodeName:   stringToPtr("node-1"),
						Conditions: discoveryv1.EndpointConditions{Ready: boolToPtr(true)},
					},
					{
						Addresses:  []string{"172.20.1.2"},
						NodeName:   stringToPtr("node-2"),
						Conditions: discoveryv1.EndpointConditions{Ready: boolToPtr(true)},
					},
				},
				Ports: []discoveryv1.EndpointPort{
					{Name: stringToPtr("port-1"), Port: int32ToPtr(80), Protocol: protoToPtr(v1core.ProtocolTCP)},
				},
			},
			expectedIPs: []string{"10.0.0.1", "1.1.1.1", "2.2.2.2"},
			expectedServices: []string{
				"10.0.0.1:6:8080:false:rr",
				"1.1.1.1:6:8080:false:rr",
				"2.2.2.2:6:8080:false:rr",
			},
			expectedEndpoints: []string{
				"10.0.0.1:8080->172.20.1.1:80",
				"1.1.1.1:8080->172.20.1.1:80",
				"2.2.2.2:8080->172.20.1.1:80",
				"10.0.0.1:8080->172.20.1.2:80",
				"1.1.1.1:8080->172.20.1.2:80",
				"2.2.2.2:8080->172.20.1.2:80",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ipvsState, mock, nsc := setupTestController(t, tc.service, tc.endpointSlice)

			// Inject pre-existing IPVS services if requested (to test deletion)
			var fooSvc1, fooSvc2 *ipvs.Service
			if tc.injectPreExistingIpvsSvc {
				fooSvc1 = ipvsState.addService(net.ParseIP("1.2.3.4"), 6, 1234)
				fooSvc2 = ipvsState.addService(net.ParseIP("5.6.7.8"), 6, 5678)
			}

			// Wait for endpoint slice if we have one with data
			if tc.endpointSlice != nil && tc.endpointSlice.Name != "" {
				waitForListerWithTimeout(t, nsc.epSliceLister, time.Second*10)
				nsc.endpointsMap = nsc.buildEndpointSliceInfo()
			}

			// Execute
			err := nsc.syncIpvsServices(nsc.getServiceMap(), nsc.endpointsMap)
			assert.NoError(t, err, "syncIpvsServices should succeed")

			// Verify DSR setup calls if requested
			if tc.verifyDSRSetup {
				assert.Len(t, mock.setupPolicyRoutingForDSRCalls(), 1,
					"setupPolicyRoutingForDSR should be called once")
				assert.NotEmpty(t, mock.getKubeDummyInterfaceCalls(),
					"getKubeDummyInterface should be called at least once")
				assert.NotEmpty(t, mock.setupRoutesForExternalIPForDSRCalls(),
					"setupRoutesForExternalIPForDSR should be called")
			}

			// Verify IP addresses added
			actualIPs := getIPsFromAddrAddCalls(mock)
			assert.ElementsMatch(t, tc.expectedIPs, actualIPs,
				"ipAddrAdd should be called for expected IPs")

			// Verify IPVS services created
			actualServices := getServicesFromAddServiceCalls(mock)
			assert.ElementsMatch(t, tc.expectedServices, actualServices,
				"ipvsAddService should be called for expected services")

			// Verify endpoints if expected
			if len(tc.expectedEndpoints) > 0 {
				actualEndpoints := getEndpointsFromAddServerCalls(mock)
				assert.ElementsMatch(t, tc.expectedEndpoints, actualEndpoints,
					"ipvsAddServer should be called for expected endpoints")
			}

			// Verify pre-existing services were deleted if requested
			if tc.verifyPreExistingDeleted {
				deleteCalls := mock.ipvsDelServiceCalls()
				assert.Len(t, deleteCalls, 2, "should delete 2 pre-existing services")
				// Verify the correct services were deleted (by pointer comparison)
				deletedPtrs := fmt.Sprintf("[{%p} {%p}]", fooSvc1, fooSvc2)
				actualPtrs := fmt.Sprintf("%v", deleteCalls)
				assert.Equal(t, deletedPtrs, actualPtrs,
					"should delete the correct pre-existing services")
			}
		})
	}
}

// TestNetworkServicesController_syncIpvsServices_DSRCallsWithServiceMap verifies that
// setupRoutesForExternalIPForDSR is called with the correct serviceInfoMap
func TestNetworkServicesController_syncIpvsServices_DSRCallsWithServiceMap(t *testing.T) {
	intTrafficPolicyCluster := v1core.ServiceInternalTrafficPolicyCluster
	extTrafficPolicyCluster := v1core.ServiceExternalTrafficPolicyCluster

	service := &v1core.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc-1"},
		Spec: v1core.ServiceSpec{
			Type:                  "ClusterIP",
			ClusterIP:             "10.0.0.1",
			ExternalIPs:           []string{"1.1.1.1"},
			InternalTrafficPolicy: &intTrafficPolicyCluster,
			ExternalTrafficPolicy: extTrafficPolicyCluster,
			Ports: []v1core.ServicePort{
				{Name: "port-1", Port: 8080, Protocol: "TCP"},
			},
		},
	}

	_, mock, nsc := setupTestController(t, service, &discoveryv1.EndpointSlice{})

	err := nsc.syncIpvsServices(nsc.getServiceMap(), nsc.endpointsMap)
	assert.NoError(t, err)

	// Verify setupRoutesForExternalIPForDSR was called with the service map
	dsrCalls := mock.setupRoutesForExternalIPForDSRCalls()
	assert.Len(t, dsrCalls, 1, "setupRoutesForExternalIPForDSR should be called once")

	// The call should contain a non-empty service map
	assert.NotEmpty(t, dsrCalls[0].ServiceInfo,
		"setupRoutesForExternalIPForDSR should be called with non-empty serviceInfoMap")
}
