package proxy

import (
	"errors"
	"net"
	"testing"

	"github.com/moby/ipvs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	v1core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cloudnativelabs/kube-router/v2/pkg/controllers/testhelpers"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
)

// These exist because syncIpvsServices used to log its failures and return nil, so the sync metrics
// reported clean no matter what the kernel actually accepted

var errInjected = errors.New("injected failure")

func newSyncReportingService(t *testing.T) *v1core.Service {
	t.Helper()
	intPolicyCluster := v1core.ServiceInternalTrafficPolicyCluster
	extPolicyCluster := v1core.ServiceExternalTrafficPolicyCluster

	return &v1core.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sync-reporting-svc",
			Namespace: "default",
		},
		Spec: v1core.ServiceSpec{
			Type:                  v1core.ServiceTypeClusterIP,
			ClusterIP:             "10.100.1.1",
			ExternalIPs:           []string{"1.1.1.1"},
			InternalTrafficPolicy: &intPolicyCluster,
			ExternalTrafficPolicy: extPolicyCluster,
			Ports: []v1core.ServicePort{
				{Name: "http", Port: 8080, Protocol: v1core.ProtocolTCP},
			},
		},
	}
}

func newClusterIPOnlySyncReportingService(t *testing.T) *v1core.Service {
	t.Helper()
	service := newSyncReportingService(t)
	service.Spec.ExternalIPs = nil
	return service
}

func TestClusterIPServicesReportKernelFailures(t *testing.T) {
	tests := []struct {
		name      string
		breakMock func(mock *LinuxNetworkingMock)
		wantErr   string
	}{
		{
			name: "assigning the ClusterIP fails",
			breakMock: func(mock *LinuxNetworkingMock) {
				mock.ipAddrAddFunc = func(iface netlink.Link, ip string, nodeIP string, addRoute bool) error {
					return errInjected
				}
			},
			wantErr: "assign cluster IP 10.100.1.1",
		},
		{
			name: "adding the IPVS service fails",
			breakMock: func(mock *LinuxNetworkingMock) {
				mock.ipvsAddServiceFunc = func(svcs []*ipvs.Service, vip net.IP, protocol uint16, port uint16,
					persistent bool, persistentTimeout int32, scheduler string,
					flags schedFlags) ([]*ipvs.Service, *ipvs.Service, error) {
					return svcs, nil, errInjected
				}
			},
			wantErr: "create ipvs service for 10.100.1.1:8080",
		},
		{
			name: "adding an IPVS endpoint fails",
			breakMock: func(mock *LinuxNetworkingMock) {
				mock.ipvsAddServerFunc = func(ipvsSvc *ipvs.Service, ipvsDst *ipvs.Destination) error {
					return errInjected
				}
			},
			wantErr: "add endpoint 172.20.1.1 to service VIP 10.100.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, mock, nsc := setupTestControllerWithEndpoints(t, newClusterIPOnlySyncReportingService(t),
				[]string{"172.20.1.1"}, nil)
			tt.breakMock(mock)

			err := nsc.syncIpvsServices(nsc.getServiceMap(), nsc.endpointsMap)

			require.Error(t, err)
			assert.ErrorContains(t, err, "cluster IP services")
			assert.ErrorContains(t, err, "service default/sync-reporting-svc")
			assert.ErrorContains(t, err, tt.wantErr)
			assert.ErrorIs(t, err, errInjected)
		})
	}
}

func TestSyncIpvsServicesReportsFailures(t *testing.T) {
	tests := []struct {
		name string
		// breakMock disables one dependency the way a real kernel or netlink failure would
		breakMock func(mock *LinuxNetworkingMock)
		wantErrs  []string
		// Not every step wraps with %w on the way up, so we only demand the chain where it does
		wantUnwrappable bool
	}{
		{
			name: "ipvs service enumeration fails",
			breakMock: func(mock *LinuxNetworkingMock) {
				mock.ipvsGetServicesFunc = func() ([]*ipvs.Service, error) {
					return nil, errInjected
				}
			},
			// Every setup step starts by listing services, so one broken call surfaces as several
			wantErrs: []string{"cluster IP services", "nodeport services", "external IP services",
				"stale IPVS config"},
			wantUnwrappable: true,
		},
		{
			name: "dummy interface is unavailable",
			breakMock: func(mock *LinuxNetworkingMock) {
				mock.getKubeDummyInterfaceFunc = func() (netlink.Link, error) {
					return nil, errInjected
				}
			},
			wantErrs:        []string{"stale dummy interface VIPs"},
			wantUnwrappable: true,
		},
		{
			name: "DSR policy routing setup fails",
			breakMock: func(mock *LinuxNetworkingMock) {
				mock.setupPolicyRoutingForDSRFunc = func(setupIPv4 bool, setupIPv6 bool) error {
					return errInjected
				}
			},
			wantErrs:        []string{"direct server return"},
			wantUnwrappable: true,
		},
		{
			name: "adding an IPVS service fails",
			breakMock: func(mock *LinuxNetworkingMock) {
				mock.ipvsAddServiceFunc = func(svcs []*ipvs.Service, vip net.IP, protocol uint16, port uint16,
					persistent bool, persistentTimeout int32, scheduler string,
					flags schedFlags) ([]*ipvs.Service, *ipvs.Service, error) {
					return nil, nil, errInjected
				}
			},
			wantErrs: []string{"external IP services", "failed to create ipvs service"},
		},
		{
			name: "everything fails at once",
			breakMock: func(mock *LinuxNetworkingMock) {
				mock.ipvsGetServicesFunc = func() ([]*ipvs.Service, error) {
					return nil, errInjected
				}
				mock.getKubeDummyInterfaceFunc = func() (netlink.Link, error) {
					return nil, errInjected
				}
				mock.setupPolicyRoutingForDSRFunc = func(setupIPv4 bool, setupIPv6 bool) error {
					return errInjected
				}
			},
			// Nothing short circuits, so a single broken sync still reports every broken step
			wantErrs: []string{"cluster IP services", "nodeport services", "external IP services",
				"stale dummy interface VIPs", "stale IPVS config", "direct server return"},
			wantUnwrappable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, mock, nsc := setupTestControllerWithEndpoints(t, newSyncReportingService(t),
				[]string{"172.20.1.1"}, []string{})
			tt.breakMock(mock)

			err := nsc.syncIpvsServices(nsc.getServiceMap(), nsc.endpointsMap)

			require.Error(t, err, "a broken dependency has to surface as a failed sync")
			for _, want := range tt.wantErrs {
				assert.ErrorContains(t, err, want)
			}
			if tt.wantUnwrappable {
				assert.ErrorIs(t, err, errInjected)
			}
		})
	}
}

func TestSyncIpvsServicesReportsSuccess(t *testing.T) {
	_, _, nsc := setupTestControllerWithEndpoints(t, newSyncReportingService(t),
		[]string{"172.20.1.1"}, []string{})

	assert.NoError(t, nsc.syncIpvsServices(nsc.getServiceMap(), nsc.endpointsMap))
}

// failingIPTablesHandler breaks both the masquerade and hairpin rule sync without a real iptables
func failingIPTablesHandler() *utils.IPTablesHandlerMock {
	return &utils.IPTablesHandlerMock{
		HasRandomFullyFunc: func() bool {
			return false
		},
		ExistsFunc: func(table string, chain string, rulespec ...string) (bool, error) {
			return false, errInjected
		},
		ListChainsFunc: func(table string) ([]string, error) {
			return nil, errInjected
		},
		AppendUniqueFunc: func(table string, chain string, rulespec ...string) error {
			return nil
		},
		DeleteFunc: func(table string, chain string, rulespec ...string) error {
			return nil
		},
	}
}

func TestDoSyncJoinsEveryStepsFailure(t *testing.T) {
	_, mock, nsc := setupTestControllerWithEndpoints(t, newSyncReportingService(t),
		[]string{"172.20.1.1"}, []string{})

	// The iptables steps no-op on a node with no addresses of that family, so give it one
	nsc.krNode = &utils.LocalKRNode{
		KRNode: utils.KRNode{
			NodeName:  "localnode-1",
			PrimaryIP: net.ParseIP("10.0.0.1"),
			NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{
				v1core.NodeInternalIP: {net.ParseIP("10.0.0.1")},
			},
		},
	}
	nsc.ipSetHandlers = map[v1core.IPFamily]utils.IPSetHandler{
		v1core.IPv4Protocol: testhelpers.NewFakeIPSetHandler(false),
	}
	// doSync used to overwrite its error each step, so only the last one could ever be reported
	nsc.iptablesCmdHandlers = map[v1core.IPFamily]utils.IPTablesHandler{
		v1core.IPv4Protocol: failingIPTablesHandler(),
	}
	mock.ipvsGetServicesFunc = func() ([]*ipvs.Service, error) {
		return nil, errInjected
	}

	err := nsc.doSync()

	require.Error(t, err)
	assert.ErrorContains(t, err, "masquerade rule")
	assert.ErrorContains(t, err, "hairpin iptables rules")
	assert.ErrorContains(t, err, "ipvs services")
}

func TestDoSyncReportsSuccess(t *testing.T) {
	_, _, nsc := setupTestControllerWithEndpoints(t, newSyncReportingService(t),
		[]string{"172.20.1.1"}, []string{})

	assert.NoError(t, nsc.doSync())
}
