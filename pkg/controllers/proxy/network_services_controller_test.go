package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/moby/ipvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	v1core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

type LinuxNetworkingMockImpl struct {
	ipvsSvcs []*ipvs.Service
}

func NewLinuxNetworkMock() *LinuxNetworkingMockImpl {
	lnm := &LinuxNetworkingMockImpl{
		ipvsSvcs: make([]*ipvs.Service, 0, 64),
	}
	return lnm
}

func (lnm *LinuxNetworkingMockImpl) getKubeDummyInterface() (netlink.Link, error) {
	var iface netlink.Link
	iface, err := netlink.LinkByName("lo")
	return iface, err
}
func (lnm *LinuxNetworkingMockImpl) setupPolicyRoutingForDSR() error {
	return nil
}
func (lnm *LinuxNetworkingMockImpl) setupRoutesForExternalIPForDSR(s serviceInfoMap) error {
	return nil
}
func (lnm *LinuxNetworkingMockImpl) ipvsGetServices() ([]*ipvs.Service, error) {
	// need to return a copy, else if the caller does `range svcs` and then calls
	// DelService (on the returned svcs reference), it'll skip the "next" element
	svcsCopy := make([]*ipvs.Service, len(lnm.ipvsSvcs))
	copy(svcsCopy, lnm.ipvsSvcs)
	return svcsCopy, nil
}
func (lnm *LinuxNetworkingMockImpl) ipAddrAdd(iface netlink.Link, addr string, addRouter bool) error {
	return nil
}
func (lnm *LinuxNetworkingMockImpl) ipvsAddServer(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error {
	return nil
}
func (lnm *LinuxNetworkingMockImpl) ipvsAddService(svcs []*ipvs.Service, vip net.IP, protocol, port uint16, persistent bool, persistentTimeout int32, scheduler string, flags schedFlags) (*ipvs.Service, error) {
	svc := &ipvs.Service{
		Address:  vip,
		Protocol: protocol,
		Port:     port,
	}
	lnm.ipvsSvcs = append(lnm.ipvsSvcs, svc)
	return svc, nil
}
func (lnm *LinuxNetworkingMockImpl) ipvsDelService(ipvsSvc *ipvs.Service) error {
	for idx, svc := range lnm.ipvsSvcs {
		if svc.Address.Equal(ipvsSvc.Address) && svc.Protocol == ipvsSvc.Protocol && svc.Port == ipvsSvc.Port {
			lnm.ipvsSvcs = append(lnm.ipvsSvcs[:idx], lnm.ipvsSvcs[idx+1:]...)
			break
		}
	}
	return nil
}
func (lnm *LinuxNetworkingMockImpl) ipvsGetDestinations(ipvsSvc *ipvs.Service) ([]*ipvs.Destination, error) {
	return []*ipvs.Destination{}, nil
}
func (lnm *LinuxNetworkingMockImpl) cleanupMangleTableRule(ip string, protocol string, port string, fwmark string, tcpMSS int) error {
	return nil
}

func fatalf(format string, a ...interface{}) {
	msg := fmt.Sprintf("FATAL: "+format+"\n", a...)
	Fail(msg)
}

// There's waitForListerWithTimeout in network_routes_controller_test.go
// that receives a 2nd *testing argument - mixing testing and ginkgo
// is discouraged (latter uses own GinkgoWriter), so need to create
// our own here.
func waitForListerWithTimeoutG(lister cache.Indexer, timeout time.Duration) {
	tick := time.Tick(100 * time.Millisecond)
	timeoutCh := time.After(timeout)
	for {
		select {
		case <-timeoutCh:
			fatalf("timeout exceeded waiting for service lister to fill cache")
		case <-tick:
			if len(lister.List()) != 0 {
				return
			}
		}
	}
}

type TestCaseSvcEPs struct {
	existingService  *v1core.Service
	existingEndpoint *v1core.Endpoints
	nodeHasEndpoints bool
}

var _ = Describe("NetworkServicesController", func() {
	var lnm *LinuxNetworkingMockImpl
	var testcase *TestCaseSvcEPs
	var mockedLinuxNetworking *LinuxNetworkingMock
	var nsc *NetworkServicesController
	BeforeEach(func() {
		lnm = NewLinuxNetworkMock()
		mockedLinuxNetworking = &LinuxNetworkingMock{
			cleanupMangleTableRuleFunc:         lnm.cleanupMangleTableRule,
			getKubeDummyInterfaceFunc:          lnm.getKubeDummyInterface,
			ipAddrAddFunc:                      lnm.ipAddrAdd,
			ipvsAddServerFunc:                  lnm.ipvsAddServer,
			ipvsAddServiceFunc:                 lnm.ipvsAddService,
			ipvsDelServiceFunc:                 lnm.ipvsDelService,
			ipvsGetDestinationsFunc:            lnm.ipvsGetDestinations,
			ipvsGetServicesFunc:                lnm.ipvsGetServices,
			setupPolicyRoutingForDSRFunc:       lnm.setupPolicyRoutingForDSR,
			setupRoutesForExternalIPForDSRFunc: lnm.setupRoutesForExternalIPForDSR,
		}

	})
	JustBeforeEach(func() {
		clientset := fake.NewSimpleClientset()

		_, err := clientset.CoreV1().Endpoints("default").Create(context.Background(), testcase.existingEndpoint, metav1.CreateOptions{})
		if err != nil {
			fatalf("failed to create existing endpoints: %v", err)
		}

		_, err = clientset.CoreV1().Services("default").Create(context.Background(), testcase.existingService, metav1.CreateOptions{})
		if err != nil {
			fatalf("failed to create existing services: %v", err)
		}

		nsc = &NetworkServicesController{
			nodeIP:       net.ParseIP("10.0.0.0"),
			nodeHostName: "node-1",
			ln:           mockedLinuxNetworking,
		}

		startInformersForServiceProxy(nsc, clientset)
		waitForListerWithTimeoutG(nsc.svcLister, time.Second*10)
		waitForListerWithTimeoutG(nsc.epLister, time.Second*10)

		nsc.serviceMap = nsc.buildServicesInfo()
		nsc.endpointsMap = nsc.buildEndpointsInfo()
	})
	Context("service no endpoints with externalIPs", func() {
		var fooSvc1, fooSvc2 *ipvs.Service
		var syncErr error
		BeforeEach(func() {
			testcase = &TestCaseSvcEPs{
				&v1core.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-1"},
					Spec: v1core.ServiceSpec{
						Type:        "ClusterIP",
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1", "2.2.2.2"},
						Ports: []v1core.ServicePort{
							{Name: "port-1", Port: 8080, Protocol: "TCP"},
						},
					},
				},
				&v1core.Endpoints{},
				false,
			}
		})
		JustBeforeEach(func() {
			// pre-inject some foo ipvs Service to verify its deletion
			fooSvc1, _ = lnm.ipvsAddService(lnm.ipvsSvcs, net.ParseIP("1.2.3.4"), 6, 1234, false, 0, "rr", schedFlags{})
			fooSvc2, _ = lnm.ipvsAddService(lnm.ipvsSvcs, net.ParseIP("5.6.7.8"), 6, 5678, false, 0, "rr", schedFlags{true, true, false})
			syncErr = nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
		})
		It("Should have called syncIpvsServices OK", func() {
			Expect(syncErr).To(Succeed())
		})
		It("Should have called cleanupMangleTableRule for ExternalIPs", func() {
			fwmark1, _ := generateFwmark("1.1.1.1", "tcp", "8080")
			fwmark2, _ := generateFwmark("2.2.2.2", "tcp", "8080")
			Expect(
				fmt.Sprintf("%v", mockedLinuxNetworking.cleanupMangleTableRuleCalls())).To(
				Equal(
					fmt.Sprintf("[{1.1.1.1 tcp 8080 %d} {2.2.2.2 tcp 8080 %d}]",
						fwmark1,
						fwmark2)))
		})
		It("Should have called setupPolicyRoutingForDSR", func() {
			Expect(
				mockedLinuxNetworking.setupPolicyRoutingForDSRCalls()).To(
				HaveLen(1))
		})
		It("Should have called getKubeDummyInterface", func() {
			Expect(
				mockedLinuxNetworking.getKubeDummyInterfaceCalls()).To(
				HaveLen(1))
		})
		It("Should have called setupRoutesForExternalIPForDSR with serviceInfoMap", func() {
			Expect(
				mockedLinuxNetworking.setupRoutesForExternalIPForDSRCalls()).To(
				ContainElement(
					struct{ In1 serviceInfoMap }{In1: nsc.serviceMap}))
		})
		It("Should have called ipAddrAdd for ClusterIP and ExternalIPs", func() {
			Expect((func() []string {
				ret := []string{}
				for _, addr := range mockedLinuxNetworking.ipAddrAddCalls() {
					ret = append(ret, addr.IP)
				}
				return ret
			})()).To(
				ConsistOf("10.0.0.1", "1.1.1.1", "2.2.2.2"))
		})
		It("Should have called ipvsDelService for pre-existing fooSvc1 fooSvc2", func() {
			Expect(fmt.Sprintf("%v", mockedLinuxNetworking.ipvsDelServiceCalls())).To(
				Equal(
					fmt.Sprintf("[{%p} {%p}]", fooSvc1, fooSvc2)))
		})
		It("Should have called ipvsAddService for ClusterIP and ExternalIPs", func() {
			Expect(func() []string {
				ret := []string{}
				for _, args := range mockedLinuxNetworking.ipvsAddServiceCalls() {
					ret = append(ret, fmt.Sprintf("%v:%v:%v:%v:%v",
						args.Vip, args.Protocol, args.Port,
						args.Persistent, args.Scheduler))
				}
				return ret
			}()).To(
				ConsistOf(
					"10.0.0.1:6:8080:false:rr",
					"1.1.1.1:6:8080:false:rr",
					"2.2.2.2:6:8080:false:rr"))
		})
	})
	Context("service no endpoints with loadbalancer IPs", func() {
		var syncErr error
		BeforeEach(func() {
			testcase = &TestCaseSvcEPs{
				&v1core.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:        "LoadBalancer",
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1", "2.2.2.2"},
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
				&v1core.Endpoints{},
				false,
			}
		})
		JustBeforeEach(func() {
			syncErr = nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
		})
		It("Should have called syncIpvsServices OK", func() {
			Expect(syncErr).To(Succeed())
		})
		It("Should have called ipAddrAdd for ClusterIP, ExternalIPs and LoadBalancerIPs", func() {
			Expect((func() []string {
				ret := []string{}
				for _, addr := range mockedLinuxNetworking.ipAddrAddCalls() {
					ret = append(ret, addr.IP)
				}
				return ret
			})()).To(
				ConsistOf(
					"10.0.0.1", "1.1.1.1", "2.2.2.2", "10.255.0.1", "10.255.0.2"))
		})
		It("Should have called ipvsAddService for ClusterIP, ExternalIPs and LoadBalancerIPs", func() {
			Expect(func() []string {
				ret := []string{}
				for _, args := range mockedLinuxNetworking.ipvsAddServiceCalls() {
					ret = append(ret, fmt.Sprintf("%v:%v:%v:%v:%v",
						args.Vip, args.Protocol, args.Port,
						args.Persistent, args.Scheduler))
				}
				return ret
			}()).To(
				ConsistOf(
					"10.0.0.1:6:8080:false:rr",
					"1.1.1.1:6:8080:false:rr",
					"2.2.2.2:6:8080:false:rr",
					"10.255.0.1:6:8080:false:rr",
					"10.255.0.2:6:8080:false:rr"))
		})
	})
	Context("service no endpoints with loadbalancer IPs with skiplbips annotation", func() {
		var syncErr error
		BeforeEach(func() {
			testcase = &TestCaseSvcEPs{
				&v1core.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
						Annotations: map[string]string{
							"kube-router.io/service.skiplbips": "true",
						},
					},
					Spec: v1core.ServiceSpec{
						Type:        "LoadBalancer",
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1", "2.2.2.2"},
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
				&v1core.Endpoints{},
				false,
			}
		})
		JustBeforeEach(func() {
			syncErr = nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
		})
		It("Should have called syncIpvsServices OK", func() {
			Expect(syncErr).To(Succeed())
		})
		It("Should have called ipAddrAdd only for ClusterIP and ExternalIPs", func() {
			Expect((func() []string {
				ret := []string{}
				for _, addr := range mockedLinuxNetworking.ipAddrAddCalls() {
					ret = append(ret, addr.IP)
				}
				return ret
			})()).To(
				ConsistOf(
					"10.0.0.1", "1.1.1.1", "2.2.2.2"))
		})
		It("Should have called ipvsAddService only for ClusterIP and ExternalIPs", func() {
			Expect(func() []string {
				ret := []string{}
				for _, args := range mockedLinuxNetworking.ipvsAddServiceCalls() {
					ret = append(ret, fmt.Sprintf("%v:%v:%v:%v:%v",
						args.Vip, args.Protocol, args.Port,
						args.Persistent, args.Scheduler))
				}
				return ret
			}()).To(
				ConsistOf(
					"10.0.0.1:6:8080:false:rr",
					"1.1.1.1:6:8080:false:rr",
					"2.2.2.2:6:8080:false:rr"))
		})
	})
	Context("service no endpoints with loadbalancer without IPs", func() {
		var syncErr error
		BeforeEach(func() {
			testcase = &TestCaseSvcEPs{
				&v1core.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:        "LoadBalancer",
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1", "2.2.2.2"},
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
				&v1core.Endpoints{},
				false,
			}
		})
		JustBeforeEach(func() {
			syncErr = nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
		})
		It("Should have called syncIpvsServices OK", func() {
			Expect(syncErr).To(Succeed())
		})
		It("Should have called ipAddrAdd only for ClusterIP and ExternalIPs", func() {
			Expect((func() []string {
				ret := []string{}
				for _, addr := range mockedLinuxNetworking.ipAddrAddCalls() {
					ret = append(ret, addr.IP)
				}
				return ret
			})()).To(
				ConsistOf(
					"10.0.0.1", "1.1.1.1", "2.2.2.2"))
		})
		It("Should have properly ipvsAddService only for ClusterIP and ExternalIPs", func() {
			Expect(func() []string {
				ret := []string{}
				for _, args := range mockedLinuxNetworking.ipvsAddServiceCalls() {
					ret = append(ret, fmt.Sprintf("%v:%v:%v:%v:%v",
						args.Vip, args.Protocol, args.Port,
						args.Persistent, args.Scheduler))
				}
				return ret
			}()).To(
				ConsistOf(
					"10.0.0.1:6:8080:false:rr",
					"1.1.1.1:6:8080:false:rr",
					"2.2.2.2:6:8080:false:rr"))
		})
	})
	Context("node has endpoints for service", func() {
		var syncErr error
		BeforeEach(func() {
			testcase = &TestCaseSvcEPs{
				&v1core.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-1", Namespace: "default"},
					Spec: v1core.ServiceSpec{
						Type:        "ClusterIP",
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1", "2.2.2.2"},
						Ports: []v1core.ServicePort{
							{Name: "port-1", Protocol: "TCP", Port: 8080},
						},
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
								{IP: "172.20.1.1", NodeName: ptrToString("node-1")},
								{IP: "172.20.1.2", NodeName: ptrToString("node-2")},
							},
							Ports: []v1core.EndpointPort{
								{Name: "port-1", Port: 80, Protocol: "TCP"},
							},
						},
					},
				},
				true,
			}
		})
		JustBeforeEach(func() {
			syncErr = nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
		})
		It("Should have called syncIpvsServices OK", func() {
			Expect(syncErr).To(Succeed())
		})
		It("Should have called AddServiceCalls for ClusterIP and ExternalIPs", func() {
			Expect((func() []string {
				ret := []string{}
				for _, args := range mockedLinuxNetworking.ipvsAddServiceCalls() {
					ret = append(ret, fmt.Sprintf("%v:%v:%v:%v:%v",
						args.Vip, args.Protocol, args.Port,
						args.Persistent, args.Scheduler))
				}
				return ret
			})()).To(ConsistOf(
				"10.0.0.1:6:8080:false:rr", "1.1.1.1:6:8080:false:rr", "2.2.2.2:6:8080:false:rr"))
		})
		It("Should have added proper Endpoints", func() {
			Expect((func() []string {
				ret := []string{}
				for _, args := range mockedLinuxNetworking.ipvsAddServerCalls() {
					svc := args.IpvsSvc
					dst := args.IpvsDst
					ret = append(ret, fmt.Sprintf("%v:%v->%v:%v",
						svc.Address, svc.Port,
						dst.Address, dst.Port))
				}
				return ret
			})()).To(ConsistOf(
				"10.0.0.1:8080->172.20.1.1:80", "1.1.1.1:8080->172.20.1.1:80", "2.2.2.2:8080->172.20.1.1:80",
				"10.0.0.1:8080->172.20.1.2:80", "1.1.1.1:8080->172.20.1.2:80", "2.2.2.2:8080->172.20.1.2:80",
			))
		})
	})
})

func startInformersForServiceProxy(nsc *NetworkServicesController, clientset kubernetes.Interface) {
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)
	svcInformer := informerFactory.Core().V1().Services().Informer()
	epInformer := informerFactory.Core().V1().Endpoints().Informer()
	podInformer := informerFactory.Core().V1().Pods().Informer()

	go informerFactory.Start(nil)
	informerFactory.WaitForCacheSync(nil)

	nsc.svcLister = svcInformer.GetIndexer()
	nsc.epLister = epInformer.GetIndexer()
	nsc.podLister = podInformer.GetIndexer()
}

func ptrToString(str string) *string {
	return &str
}
