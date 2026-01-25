package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/internal/testutils"
	"github.com/cloudnativelabs/kube-router/v2/pkg/k8s/indexers"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/moby/ipvs"
	v1core "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

//nolint:unparam // timeout parameter allows flexibility for future tests
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

// setupTestController creates and initializes a NetworkServicesController for testing.
// It returns the mock IPVS state (for injecting pre-existing services), the LinuxNetworkingMock
// (for verifying calls), and the controller.
func setupTestController(t *testing.T, service *v1core.Service, endpointSlice *discoveryv1.EndpointSlice) (
	*mockIPVSState, *LinuxNetworkingMock, *NetworkServicesController) {
	t.Helper()

	ipvsState := newMockIPVSState()
	netlinkState := newMockNetlinkState()

	// Create the mock using moq-generated LinuxNetworkingMock with state-based implementations
	mock := &LinuxNetworkingMock{
		// Netlink mocks use state-based implementations (no real system calls)
		getKubeDummyInterfaceFunc:          createMockGetKubeDummyInterface(netlinkState),
		ipAddrAddFunc:                      createMockIPAddrAdd(netlinkState),
		ipAddrDelFunc:                      createMockIPAddrDel(netlinkState),
		setupPolicyRoutingForDSRFunc:       createMockSetupPolicyRoutingForDSR(netlinkState),
		setupRoutesForExternalIPForDSRFunc: createMockSetupRoutesForExternalIPForDSR(netlinkState),
		configureContainerForDSRFunc:       createMockConfigureContainerForDSR(netlinkState),
		getContainerPidWithDockerFunc:      createMockGetContainerPidWithDocker(netlinkState),
		getContainerPidWithCRIFunc:         createMockGetContainerPidWithCRI(netlinkState),
		findIfaceLinkForPidFunc:            createMockFindIfaceLinkForPid(netlinkState),

		// IPVS mocks use state-based implementations
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
	}

	// Mock the standalone routeVIPTrafficToDirector function
	routeVIPTrafficToDirector = createMockRouteVIPTrafficToDirector(netlinkState)

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
		client:     clientset,
		fwMarkMap:  make(map[uint32]string),
	}

	startInformersForServiceProxy(t, nsc, clientset)
	waitForListerWithTimeout(t, nsc.svcLister, time.Second*10)

	nsc.setServiceMap(nsc.buildServicesInfo())
	nsc.endpointsMap = nsc.buildEndpointSliceInfo()

	return ipvsState, mock, nsc
}

// setupTestControllerWithEndpoints creates a NetworkServicesController for testing traffic policy behavior.
// It automatically generates an EndpointSlice from the provided local and remote endpoint IPs.
// - localEndpoints: IPs for endpoints on the local node ("localnode-1")
// - remoteEndpoints: IPs for endpoints on a remote node ("node-2")
// All endpoints are created with Ready=true, Port=80, Protocol=TCP.
//
// NOTE: This function uses "localnode-1" as the controller's node name to clearly distinguish
// between local and remote endpoints in traffic policy tests.
//
//nolint:unparam // mockIPVSState returned for API consistency with setupTestController
func setupTestControllerWithEndpoints(t *testing.T, service *v1core.Service,
	localEndpoints, remoteEndpoints []string) (*mockIPVSState, *LinuxNetworkingMock, *NetworkServicesController) {
	t.Helper()

	const localNodeName = "localnode-1"
	const remoteNodeName = "node-2"

	ipvsState := newMockIPVSState()
	netlinkState := newMockNetlinkState()

	mock := &LinuxNetworkingMock{
		// Netlink mocks use state-based implementations (no real system calls)
		getKubeDummyInterfaceFunc:          createMockGetKubeDummyInterface(netlinkState),
		ipAddrAddFunc:                      createMockIPAddrAdd(netlinkState),
		ipAddrDelFunc:                      createMockIPAddrDel(netlinkState),
		setupPolicyRoutingForDSRFunc:       createMockSetupPolicyRoutingForDSR(netlinkState),
		setupRoutesForExternalIPForDSRFunc: createMockSetupRoutesForExternalIPForDSR(netlinkState),
		configureContainerForDSRFunc:       createMockConfigureContainerForDSR(netlinkState),
		getContainerPidWithDockerFunc:      createMockGetContainerPidWithDocker(netlinkState),
		getContainerPidWithCRIFunc:         createMockGetContainerPidWithCRI(netlinkState),
		findIfaceLinkForPidFunc:            createMockFindIfaceLinkForPid(netlinkState),

		// IPVS mocks use state-based implementations
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
		ipvsAddFWMarkServiceFunc: func(svcs []*ipvs.Service, fwMark uint32, family uint16, protocol uint16,
			port uint16, persistent bool, persistentTimeout int32, scheduler string,
			flags schedFlags) (*ipvs.Service, error) {
			svc := &ipvs.Service{
				FWMark:   fwMark,
				Protocol: protocol,
				Port:     port,
			}
			ipvsState.services = append(ipvsState.services, svc)
			return svc, nil
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
			svcsCopy := make([]*ipvs.Service, len(ipvsState.services))
			copy(svcsCopy, ipvsState.services)
			return svcsCopy, nil
		},
	}

	// Mock the standalone routeVIPTrafficToDirector function
	routeVIPTrafficToDirector = createMockRouteVIPTrafficToDirector(netlinkState)

	clientset := fake.NewSimpleClientset()

	// Build EndpointSlice from provided endpoint IPs
	if len(localEndpoints) > 0 || len(remoteEndpoints) > 0 {
		var endpoints []discoveryv1.Endpoint

		for _, ip := range localEndpoints {
			endpoints = append(endpoints, discoveryv1.Endpoint{
				Addresses:  []string{ip},
				NodeName:   testutils.ValToPtr(localNodeName),
				Conditions: discoveryv1.EndpointConditions{Ready: testutils.ValToPtr(true)},
			})
		}

		for _, ip := range remoteEndpoints {
			endpoints = append(endpoints, discoveryv1.Endpoint{
				Addresses:  []string{ip},
				NodeName:   testutils.ValToPtr(remoteNodeName),
				Conditions: discoveryv1.EndpointConditions{Ready: testutils.ValToPtr(true)},
			})
		}

		endpointSlice := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      service.Name + "-slice",
				Namespace: service.Namespace,
				Labels: map[string]string{
					"kubernetes.io/service-name": service.Name,
				},
			},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints:   endpoints,
			Ports: []discoveryv1.EndpointPort{
				{Name: testutils.ValToPtr("http"), Port: testutils.ValToPtr(int32(80)), Protocol: testutils.ValToPtr(v1core.ProtocolTCP)},
			},
		}

		_, err := clientset.DiscoveryV1().EndpointSlices(service.Namespace).Create(
			context.Background(), endpointSlice, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("failed to create endpoint slice: %v", err)
		}
	}

	_, err := clientset.CoreV1().Services(service.Namespace).Create(
		context.Background(), service, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	krNode := &utils.LocalKRNode{
		KRNode: utils.KRNode{
			NodeName:  localNodeName,
			PrimaryIP: net.ParseIP("10.0.0.1"),
		},
	}
	// Create iptables mocks for DSR support
	ipv4Mock := &utils.IPTablesHandlerMock{
		AppendUniqueFunc: func(table string, chain string, rulespec ...string) error {
			return nil
		},
		ExistsFunc: func(table string, chain string, rulespec ...string) (bool, error) {
			return false, nil
		},
		DeleteFunc: func(table string, chain string, rulespec ...string) error {
			return nil
		},
	}
	ipv6Mock := &utils.IPTablesHandlerMock{
		AppendUniqueFunc: func(table string, chain string, rulespec ...string) error {
			return nil
		},
		ExistsFunc: func(table string, chain string, rulespec ...string) (bool, error) {
			return false, nil
		},
		DeleteFunc: func(table string, chain string, rulespec ...string) error {
			return nil
		},
	}

	nsc := &NetworkServicesController{
		krNode:     krNode,
		ln:         mock,
		nphc:       NewNodePortHealthCheck(),
		ipsetMutex: &sync.Mutex{},
		client:     clientset,
		fwMarkMap:  make(map[uint32]string),
		iptablesCmdHandlers: map[v1core.IPFamily]utils.IPTablesHandler{
			v1core.IPv4Protocol: ipv4Mock,
			v1core.IPv6Protocol: ipv6Mock,
		},
	}

	startInformersForServiceProxy(t, nsc, clientset)
	waitForListerWithTimeout(t, nsc.svcLister, time.Second*10)

	// Wait for endpoint slice if we created one
	if len(localEndpoints) > 0 || len(remoteEndpoints) > 0 {
		waitForListerWithTimeout(t, nsc.epSliceLister, time.Second*10)
	}

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
