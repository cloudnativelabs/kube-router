package controllers

import (
	"fmt"
	"github.com/cloudnativelabs/kube-router/app/watchers"
	"github.com/docker/libnetwork/ipvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	v1core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"net"
	"time"
)

type LinuxNetworkingMocker interface {
	getKubeDummyInterfaceMock() (netlink.Link, error)
	setupPolicyRoutingForDSRMock() error
	setupRoutesForExternalIPForDSRMock(s serviceInfoMap) error
	ipvsGetServicesMock() ([]*ipvs.Service, error)
	ipAddrAddMock(iface netlink.Link, addr string) error
	ipvsAddServerMock(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination, local bool, podCidr string) error
	ipvsAddServiceMock(svcs []*ipvs.Service, vip net.IP, protocol, port uint16, persistent bool, scheduler string) (*ipvs.Service, error)
	cleanupMangleTableRuleMock(ip string, protocol string, port string, fwmark string) error
}

type LinuxNetworkingMockImpl struct {
	ipvsSvcs []*ipvs.Service
}

func NewLinuxNetworkMock() *LinuxNetworkingMockImpl {
	lnm := &LinuxNetworkingMockImpl{
		ipvsSvcs: make([]*ipvs.Service, 0, 64),
	}
	return lnm
}

func (lnm *LinuxNetworkingMockImpl) getKubeDummyInterfaceMock() (netlink.Link, error) {
	var iface netlink.Link
	iface, err := netlink.LinkByName("lo")
	return iface, err
}
func (lnm *LinuxNetworkingMockImpl) setupPolicyRoutingForDSRMock() error {
	return nil
}
func (lnm *LinuxNetworkingMockImpl) setupRoutesForExternalIPForDSRMock(s serviceInfoMap) error {
	return nil
}
func (lnm *LinuxNetworkingMockImpl) ipvsGetServicesMock() ([]*ipvs.Service, error) {
	// need to return a copy, else if the caller does `range svcs` and then calls
	// DelService (on the returned svcs reference), it'll skip the "next" element
	svcsCopy := make([]*ipvs.Service, len(lnm.ipvsSvcs))
	copy(svcsCopy, lnm.ipvsSvcs)
	return svcsCopy, nil
}
func (lnm *LinuxNetworkingMockImpl) ipAddrAddMock(iface netlink.Link, addr string) error {
	return nil
}
func (lnm *LinuxNetworkingMockImpl) ipvsAddServerMock(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination, local bool, podCidr string) error {
	return nil
}
func (lnm *LinuxNetworkingMockImpl) ipvsAddServiceMock(svcs []*ipvs.Service, vip net.IP, protocol, port uint16, persistent bool, scheduler string) (*ipvs.Service, error) {
	svc := &ipvs.Service{
		Address:  vip,
		Protocol: protocol,
		Port:     port,
	}
	lnm.ipvsSvcs = append(lnm.ipvsSvcs, svc)
	return svc, nil
}
func (lnm *LinuxNetworkingMockImpl) ipvsDelServiceMock(ipvsSvc *ipvs.Service) error {
	for idx, svc := range lnm.ipvsSvcs {
		if svc.Address.Equal(ipvsSvc.Address) && svc.Protocol == ipvsSvc.Protocol && svc.Port == ipvsSvc.Port {
			lnm.ipvsSvcs = append(lnm.ipvsSvcs[:idx], lnm.ipvsSvcs[idx+1:]...)
			break
		}
	}
	return nil
}
func (lnm *LinuxNetworkingMockImpl) ipvsGetDestinationsMock(ipvsSvc *ipvs.Service) ([]*ipvs.Destination, error) {
	return []*ipvs.Destination{}, nil
}
func (lnm *LinuxNetworkingMockImpl) cleanupMangleTableRuleMock(ip string, protocol string, port string, fwmark string) error {
	return nil
}

func logf(format string, a ...interface{}) {
	fmt.Fprintf(GinkgoWriter, "INFO: "+format+"\n", a...)
}
func fatalf(format string, a ...interface{}) {
	msg := fmt.Sprintf("FATAL: "+format+"\n", a...)
	Fail(msg)
}
func waitForListerWithTimeout_(timeout time.Duration) {
	tick := time.Tick(100 * time.Millisecond)
	timeoutCh := time.After(timeout)
	for {
		select {
		case <-timeoutCh:
			fatalf("timeout exceeded waiting for service lister to fill cache")
		case <-tick:
			if len(watchers.ServiceWatcher.List()) != 0 {
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
			cleanupMangleTableRuleFunc:         lnm.cleanupMangleTableRuleMock,
			getKubeDummyInterfaceFunc:          lnm.getKubeDummyInterfaceMock,
			ipAddrAddFunc:                      lnm.ipAddrAddMock,
			ipvsAddServerFunc:                  lnm.ipvsAddServerMock,
			ipvsAddServiceFunc:                 lnm.ipvsAddServiceMock,
			ipvsDelServiceFunc:                 lnm.ipvsDelServiceMock,
			ipvsGetDestinationsFunc:            lnm.ipvsGetDestinationsMock,
			ipvsGetServicesFunc:                lnm.ipvsGetServicesMock,
			setupPolicyRoutingForDSRFunc:       lnm.setupPolicyRoutingForDSRMock,
			setupRoutesForExternalIPForDSRFunc: lnm.setupRoutesForExternalIPForDSRMock,
		}

	})
	JustBeforeEach(func() {
		clientset := fake.NewSimpleClientset()

		_, err := watchers.StartServiceWatcher(clientset, 0)
		if err != nil {
			fatalf("failed to initialize service watcher: %v", err)
		}

		_, err = watchers.StartEndpointsWatcher(clientset, 0)
		if err != nil {
			fatalf("failed to initialize endpoints watcher: %v", err)
		}

		_, err = clientset.CoreV1().Endpoints("default").Create(testcase.existingEndpoint)
		if err != nil {
			fatalf("failed to create existing endpoints: %v", err)
		}

		_, err = clientset.CoreV1().Services("default").Create(testcase.existingService)
		if err != nil {
			fatalf("failed to create existing services: %v", err)
		}

		waitForListerWithTimeout_(time.Second * 10)

		nsc = &NetworkServicesController{
			nodeIP:       net.ParseIP("10.0.0.0"),
			nodeHostName: "node-1",
			ln:           mockedLinuxNetworking,
			serviceMap:   buildServicesInfo(),
			endpointsMap: buildEndpointsInfo(),
		}
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
			fooSvc1, _ = lnm.ipvsAddServiceMock(lnm.ipvsSvcs, net.ParseIP("1.2.3.4"), 6, 1234, false, "rr")
			fooSvc2, _ = lnm.ipvsAddServiceMock(lnm.ipvsSvcs, net.ParseIP("5.6.7.8"), 6, 5678, false, "rr")
			syncErr = nsc.syncIpvsServices(nsc.serviceMap, nsc.endpointsMap)
		})
		It("Should have called syncIpvsServices OK", func() {
			Expect(syncErr).To(Succeed())
		})
		It("Should have properly called cleanupMangleTableRule", func() {
			Expect(
				fmt.Sprintf("%v", mockedLinuxNetworking.cleanupMangleTableRuleCalls())).To(
				Equal(
					fmt.Sprintf("[{1.1.1.1 tcp 8080 %d} {2.2.2.2 tcp 8080 %d}]",
						generateFwmark("1.1.1.1", "tcp", "8080"),
						generateFwmark("2.2.2.2", "tcp", "8080"))))
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
		It("Should have properly called setupRoutesForExternalIPForDSR", func() {
			Expect(
				mockedLinuxNetworking.setupRoutesForExternalIPForDSRCalls()).To(
				ContainElement(
					struct{ In1 serviceInfoMap }{In1: nsc.serviceMap}))
		})
		It("Should have properly called ipAddrAdd", func() {
			Expect((func() []string {
				ret := []string{}
				for _, addr := range mockedLinuxNetworking.ipAddrAddCalls() {
					ret = append(ret, addr.IP)
				}
				return ret
			})()).To(
				ConsistOf("10.0.0.1", "1.1.1.1", "2.2.2.2"))
		})
		It("Should have properly called ipvsDelService", func() {
			Expect(fmt.Sprintf("%v", mockedLinuxNetworking.ipvsDelServiceCalls())).To(
				Equal(
					fmt.Sprintf("[{%p} {%p}]", fooSvc1, fooSvc2)))
		})
		It("Should have properly called ipvsAddService", func() {
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
		It("Should have properly called ipAddrAdd", func() {
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
		It("Should have properly called ipvsAddService", func() {
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
		It("Should have properly called ipAddrAdd", func() {
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
		It("Should have properly called ipvsAddService", func() {
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
		It("Should have called properly AddServiceCalls", func() {
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
