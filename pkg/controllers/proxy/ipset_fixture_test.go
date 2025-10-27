package proxy

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ccoveille/go-safecast"
	"github.com/cloudnativelabs/kube-router/v2/pkg/controllers/testhelpers"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/moby/ipvs"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
)

type stubNode struct {
	name      string
	iface     string
	ipv4Addrs []net.IP
	ipv6Addrs []net.IP
}

func (n *stubNode) SloppyTCP() *utils.SysctlConfig {
	return &utils.SysctlConfig{}
}

func (n *stubNode) FindBestIPv4NodeAddress() net.IP {
	if len(n.ipv4Addrs) > 0 {
		return n.ipv4Addrs[0]
	}
	return nil
}

func (n *stubNode) FindBestIPv6NodeAddress() net.IP {
	if len(n.ipv6Addrs) > 0 {
		return n.ipv6Addrs[0]
	}
	return nil
}

func (n *stubNode) GetNodeIPv4Addrs() []net.IP {
	return append([]net.IP(nil), n.ipv4Addrs...)
}

func (n *stubNode) GetNodeIPv6Addrs() []net.IP {
	return append([]net.IP(nil), n.ipv6Addrs...)
}

func (n *stubNode) GetNodeIPAddrs() []net.IP {
	var res []net.IP
	res = append(res, n.ipv4Addrs...)
	res = append(res, n.ipv6Addrs...)
	return res
}

func (n *stubNode) GetPrimaryNodeIP() net.IP {
	if len(n.ipv4Addrs) > 0 {
		return n.ipv4Addrs[0]
	}
	if len(n.ipv6Addrs) > 0 {
		return n.ipv6Addrs[0]
	}
	return nil
}

func (n *stubNode) GetNodeInterfaceName() string {
	return n.iface
}

func (n *stubNode) GetNodeMTU() (int, error) {
	return 1500, nil
}

func (n *stubNode) IsIPv4Capable() bool {
	return len(n.ipv4Addrs) > 0
}

func (n *stubNode) IsIPv6Capable() bool {
	return len(n.ipv6Addrs) > 0
}

func (n *stubNode) GetNodeName() string {
	return n.name
}

type stubLinuxNetworking struct {
	services []*ipvs.Service
}

func (s *stubLinuxNetworking) ipvsNewService(_ *ipvs.Service) error { return nil }
func (s *stubLinuxNetworking) ipvsAddService(svcs []*ipvs.Service, _ net.IP, _ uint16, _ uint16, _ bool,
	_ int32, _ string, _ schedFlags) ([]*ipvs.Service, *ipvs.Service, error) {
	return svcs, nil, nil
}
func (s *stubLinuxNetworking) ipvsDelService(_ *ipvs.Service) error    { return nil }
func (s *stubLinuxNetworking) ipvsUpdateService(_ *ipvs.Service) error { return nil }
func (s *stubLinuxNetworking) ipvsGetServices() ([]*ipvs.Service, error) {
	return append([]*ipvs.Service(nil), s.services...), nil
}
func (s *stubLinuxNetworking) ipvsAddServer(_ *ipvs.Service, _ *ipvs.Destination) error { return nil }
func (s *stubLinuxNetworking) ipvsNewDestination(_ *ipvs.Service, _ *ipvs.Destination) error {
	return nil
}
func (s *stubLinuxNetworking) ipvsUpdateDestination(_ *ipvs.Service, _ *ipvs.Destination) error {
	return nil
}
func (s *stubLinuxNetworking) ipvsGetDestinations(_ *ipvs.Service) ([]*ipvs.Destination, error) {
	return nil, nil
}
func (s *stubLinuxNetworking) ipvsDelDestination(_ *ipvs.Service, _ *ipvs.Destination) error {
	return nil
}
func (s *stubLinuxNetworking) ipvsAddFWMarkService(_ []*ipvs.Service, _ uint32, _ uint16, _ uint16, _ uint16,
	_ bool, _ int32, _ string, _ schedFlags) (*ipvs.Service, error) {
	return nil, nil
}
func (s *stubLinuxNetworking) ipAddrAdd(_ netlink.Link, _ string, _ string, _ bool) error { return nil }
func (s *stubLinuxNetworking) ipAddrDel(_ netlink.Link, _ string, _ string) error         { return nil }
func (s *stubLinuxNetworking) getContainerPidWithDocker(_ string) (int, error)            { return 0, nil }
func (s *stubLinuxNetworking) getContainerPidWithCRI(_ string, _ string) (int, error)     { return 0, nil }
func (s *stubLinuxNetworking) getKubeDummyInterface() (netlink.Link, error)               { return nil, nil }
func (s *stubLinuxNetworking) setupRoutesForExternalIPForDSR(_ serviceInfoMap, _ bool, _ bool) error {
	return nil
}
func (s *stubLinuxNetworking) configureContainerForDSR(_ string, _ string, _ string, _ int,
	_ netns.NsHandle) error {
	return nil
}
func (s *stubLinuxNetworking) setupPolicyRoutingForDSR(_ bool, _ bool) error { return nil }
func (s *stubLinuxNetworking) findIfaceLinkForPid(_ int) (int, error)        { return 0, nil }

func buildIPVSServicesFromFixtures(t *testing.T, services *v1.ServiceList) []*ipvs.Service {
	t.Helper()
	var result []*ipvs.Service
	for i := range services.Items {
		svc := &services.Items[i]
		for _, port := range svc.Spec.Ports {
			proto := convertSvcProtoToSysCallProto(strings.ToLower(string(port.Protocol)))

			require.GreaterOrEqualf(t, port.Port, int32(0), "service %s/%s has negative port %d", svc.Namespace, svc.Name, port.Port)
			const maxServicePort = 1<<16 - 1
			require.LessOrEqualf(t, port.Port, int32(maxServicePort), "service %s/%s port %d exceeds %d", svc.Namespace, svc.Name, port.Port, maxServicePort)
			targetPort, err := safecast.ToUint16(port.Port)
			if err != nil {
				t.Fatalf("failed to convert port %d to uint16: %v", port.Port, err)
			}

			appendService := func(ipStr string) {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					return
				}
				result = append(result, &ipvs.Service{
					Address:  ip,
					Protocol: proto,
					Port:     targetPort,
				})
			}

			for _, clIP := range svc.Spec.ClusterIPs {
				appendService(clIP)
			}
			for _, exIP := range svc.Spec.ExternalIPs {
				appendService(exIP)
			}
		}
	}
	return result
}

func filterExpectations(src map[string]testhelpers.IPSetExpectation, include func(string) bool) map[string]testhelpers.IPSetExpectation {
	dst := make(map[string]testhelpers.IPSetExpectation)
	for k, v := range src {
		if include(k) {
			dst[k] = v
		}
	}
	return dst
}

func TestNetworkServicesFixtureIPSets(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "..", "testdata", "ipset_test_1")

	services := testhelpers.LoadServiceList(t, filepath.Join(fixtureDir, "services.yaml"))

	client := fake.NewSimpleClientset()
	for i := range services.Items {
		_, err := client.CoreV1().Services(services.Items[i].Namespace).Create(
			context.Background(), services.Items[i].DeepCopy(), metav1.CreateOptions{})
		require.NoError(t, err)
	}

	informerFactory := informers.NewSharedInformerFactory(client, 0)
	svcInformer := informerFactory.Core().V1().Services().Informer()
	svcIndexer := svcInformer.GetIndexer()
	for i := range services.Items {
		svc := services.Items[i].DeepCopy()
		svc.SetResourceVersion("1")
		require.NoError(t, svcIndexer.Add(svc))
	}

	ipv4Handler := testhelpers.NewFakeIPSetHandler(false)
	ipv6Handler := testhelpers.NewFakeIPSetHandler(true)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("ipv4 restore script:\n%s", ipv4Handler.Restored())
			t.Logf("ipv6 restore script:\n%s", ipv6Handler.Restored())
		}
	})

	node := &stubNode{
		name:      "kube-router-vm1",
		iface:     "eth0",
		ipv4Addrs: []net.IP{net.ParseIP("10.241.0.21")},
		ipv6Addrs: []net.IP{net.ParseIP("2001:db8:ca2:2::e7e5")},
	}

	ipvsServices := buildIPVSServicesFromFixtures(t, services)
	ln := &stubLinuxNetworking{services: ipvsServices}

	controller := &NetworkServicesController{
		krNode: node,
		ln:     ln,
		ipSetHandlers: map[v1.IPFamily]utils.IPSetHandler{
			v1.IPv4Protocol: ipv4Handler,
			v1.IPv6Protocol: ipv6Handler,
		},
		ipsetMutex: &sync.Mutex{},
		svcLister:  svcIndexer,
	}

	controller.setServiceMap(make(serviceInfoMap))
	controller.setServiceMap(controller.buildServicesInfo())

	err := controller.syncIpvsFirewall()
	require.NoError(t, err)

	actual := testhelpers.MergeExpectations(
		testhelpers.ParseRestoreScript(ipv4Handler.Restored()),
		testhelpers.ParseRestoreScript(ipv6Handler.Restored()),
	)

	include := func(name string) bool {
		// Exclude netpol ipsets
		if strings.Contains(name, "KUBE-DST") || strings.Contains(name, "KUBE-SRC") {
			return false
		}
		// Exclude routing ipsets
		if strings.Contains(name, "pod-subnets") || strings.Contains(name, "node-ips") {
			return false
		}
		return true
	}

	actual = filterExpectations(actual, include)

	expected := testhelpers.ParseSnapshotWithFilter(
		t,
		filepath.Join(fixtureDir, "ipset_save.txt"),
		include,
	)

	require.NotEmpty(t, expected, "expected snapshot should not be empty")
	require.Equal(t, testhelpers.ExpectedKeys(expected), testhelpers.ExpectedKeys(actual))

	for name, exp := range expected {
		act := actual[name]
		require.Equal(t, exp.SetType, act.SetType, "set type mismatch for %s", name)
		// For now we can't compare the entries because this makes a hard call to netlink libraries via getAllLocalIPs()
		// if we eventually abstract that out or refactor it in some way, then we can compare the entries
		// require.Equal(t, exp.Entries, act.Entries, "entries mismatch for %s", name)
	}
}
