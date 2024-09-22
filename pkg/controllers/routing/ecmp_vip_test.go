package routing

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	v1core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// Compare 2 string slices by value.
func Equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

var (
	testlocalExtTrafPol   = v1core.ServiceExternalTrafficPolicyLocal
	testClusterExtTrafPol = v1core.ServiceExternalTrafficPolicyCluster
	testLocalIntTrafPol   = v1core.ServiceInternalTrafficPolicyLocal
	testClusterIntTrafPol = v1core.ServiceInternalTrafficPolicyCluster
	testNodeIPv4          = "10.1.0.1"
	testNodeIPv6          = "2001:db8:42:2::1"
)

type ServiceAdvertisedIPs struct {
	service               *v1core.Service
	endpoints             *v1core.Endpoints
	internalTrafficPolicy *v1core.ServiceInternalTrafficPolicyType
	externalTrafficPolicy *v1core.ServiceExternalTrafficPolicyType
	advertisedIPs         []string
	withdrawnIPs          []string
	annotations           map[string]string
}

func Test_getVIPsForService(t *testing.T) {
	tests := []struct {
		name                 string
		nrc                  *NetworkRoutingController
		serviceAdvertisedIPs []*ServiceAdvertisedIPs
	}{
		{
			name: "advertise all IPs",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      true,
				advertiseExternalIP:     true,
				advertiseLoadBalancerIP: true,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv4),
					NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       getClusterSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1"},
					withdrawnIPs:  []string{},
					annotations:   nil,
				},
				{
					service:       getExternalSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:  []string{},
					annotations:   nil,
				},
				{
					service:       getNodePortSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:  []string{},
					annotations:   nil,
				},
				{
					service:       getLoadBalancerSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1", "10.0.255.1", "10.0.255.2"},
					withdrawnIPs:  []string{},
					annotations:   nil,
				},
			},
		},
		{
			name: "do not advertise any IPs",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      false,
				advertiseExternalIP:     false,
				advertiseLoadBalancerIP: false,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv4),
					NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       getClusterSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1"},
					annotations:   nil,
				},
				{
					service:       getExternalSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations:   nil,
				},
				{
					service:       getNodePortSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations:   nil,
				},
				{
					service:       getLoadBalancerSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1", "10.0.255.1", "10.0.255.2"},
					annotations:   nil,
				},
			},
		},
		{
			name: "advertise cluster IPs",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      true,
				advertiseExternalIP:     false,
				advertiseLoadBalancerIP: false,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv4),
					NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       getClusterSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1"},
					withdrawnIPs:  []string{},
					annotations:   nil,
				},
				{
					service:       getExternalSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1"},
					withdrawnIPs:  []string{"1.1.1.1"},
					annotations:   nil,
				},
				{
					service:       getNodePortSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1"},
					withdrawnIPs:  []string{"1.1.1.1"},
					annotations:   nil,
				},
				{
					service:       getLoadBalancerSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1"},
					withdrawnIPs:  []string{"1.1.1.1", "10.0.255.1", "10.0.255.2"},
					annotations:   nil,
				},
			},
		},
		{
			name: "advertise external IPs",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      false,
				advertiseExternalIP:     true,
				advertiseLoadBalancerIP: false,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv4),
					NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       getClusterSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1"},
					annotations:   nil,
				},
				{
					service:       getExternalSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"1.1.1.1"},
					withdrawnIPs:  []string{"10.0.0.1"},
					annotations:   nil,
				},
				{
					service:       getNodePortSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"1.1.1.1"},
					withdrawnIPs:  []string{"10.0.0.1"},
					annotations:   nil,
				},
				{
					service:       getLoadBalancerSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"1.1.1.1"},
					withdrawnIPs:  []string{"10.0.0.1", "10.0.255.1", "10.0.255.2"},
					annotations:   nil,
				},
			},
		},
		{
			name: "advertise loadbalancer IPs",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      false,
				advertiseExternalIP:     false,
				advertiseLoadBalancerIP: true,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv4),
					NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       getClusterSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1"},
					annotations:   nil,
				},
				{
					service:       getExternalSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations:   nil,
				},
				{
					service:       getNodePortSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations:   nil,
				},
				{
					service:       getLoadBalancerSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.255.1", "10.0.255.2"},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations:   nil,
				},
			},
		},
		{
			name: "opt in to advertise all IPs via annotations",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      false,
				advertiseExternalIP:     false,
				advertiseLoadBalancerIP: false,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv4),
					NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       getClusterSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1"},
					withdrawnIPs:  []string{},
					annotations: map[string]string{
						svcAdvertiseClusterAnnotation:      "true",
						svcAdvertiseExternalAnnotation:     "true",
						svcAdvertiseLoadBalancerAnnotation: "true",
					},
				},
				{
					service:       getExternalSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:  []string{},
					annotations: map[string]string{
						svcAdvertiseClusterAnnotation:      "true",
						svcAdvertiseExternalAnnotation:     "true",
						svcAdvertiseLoadBalancerAnnotation: "true",
					},
				},
				{
					service:       getNodePortSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:  []string{},
					annotations: map[string]string{
						svcAdvertiseClusterAnnotation:      "true",
						svcAdvertiseExternalAnnotation:     "true",
						svcAdvertiseLoadBalancerAnnotation: "true",
					},
				},
				{
					service:       getLoadBalancerSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1", "10.0.255.1", "10.0.255.2"},
					withdrawnIPs:  []string{},
					annotations: map[string]string{
						svcAdvertiseClusterAnnotation:      "true",
						svcAdvertiseExternalAnnotation:     "true",
						svcAdvertiseLoadBalancerAnnotation: "true",
					},
				},
				{
					// Special case to test svcAdvertiseLoadBalancerAnnotation vs legacy svcSkipLbIpsAnnotation
					service:       getLoadBalancerSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:  []string{"10.0.255.1", "10.0.255.2"},
					annotations: map[string]string{
						svcAdvertiseClusterAnnotation:      "true",
						svcAdvertiseExternalAnnotation:     "true",
						svcAdvertiseLoadBalancerAnnotation: "true",
						svcSkipLbIpsAnnotation:             "true",
					},
				},
			},
		},
		{
			name: "opt out to advertise any IPs via annotations",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      true,
				advertiseExternalIP:     true,
				advertiseLoadBalancerIP: true,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv4),
					NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       getClusterSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1"},
					annotations: map[string]string{
						svcAdvertiseClusterAnnotation:      "false",
						svcAdvertiseExternalAnnotation:     "false",
						svcAdvertiseLoadBalancerAnnotation: "false",
					},
				},
				{
					service:       getExternalSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations: map[string]string{
						svcAdvertiseClusterAnnotation:      "false",
						svcAdvertiseExternalAnnotation:     "false",
						svcAdvertiseLoadBalancerAnnotation: "false",
					},
				},
				{
					service:       getNodePortSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations: map[string]string{
						svcAdvertiseClusterAnnotation:      "false",
						svcAdvertiseExternalAnnotation:     "false",
						svcAdvertiseLoadBalancerAnnotation: "false",
					},
				},
				{
					service:       getLoadBalancerSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1", "10.0.255.1", "10.0.255.2"},
					annotations: map[string]string{
						svcAdvertiseClusterAnnotation:      "false",
						svcAdvertiseExternalAnnotation:     "false",
						svcAdvertiseLoadBalancerAnnotation: "false",
					},
				},
			},
		},
		{
			name: "check service local annotation with local IPv4 endpoints",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      true,
				advertiseExternalIP:     true,
				advertiseLoadBalancerIP: true,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv4),
					NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       getClusterSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1"},
					withdrawnIPs:  []string{},
					annotations: map[string]string{
						svcLocalAnnotation: "true",
					},
				},
				{
					service:       getExternalSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:  []string{},
					annotations: map[string]string{
						svcLocalAnnotation: "true",
					},
				},
				{
					service:       getNodePortSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:  []string{},
					annotations: map[string]string{
						svcLocalAnnotation: "true",
					},
				},
				{
					service:       getLoadBalancerSvc(),
					endpoints:     getContainsLocalIPv4EPs(),
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1", "10.0.255.1", "10.0.255.2"},
					withdrawnIPs:  []string{},
					annotations: map[string]string{
						svcLocalAnnotation: "true",
					},
				},
			},
		},
		{
			name: "check service local annotation with local IPv6 endpoints",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      true,
				advertiseExternalIP:     true,
				advertiseLoadBalancerIP: true,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv6),
					NodeIPv6Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv6)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       getClusterSvc(),
					endpoints:     getContainsLocalIPv6EPs(),
					advertisedIPs: []string{"10.0.0.1"},
					withdrawnIPs:  []string{},
					annotations: map[string]string{
						svcLocalAnnotation: "true",
					},
				},
				{
					service:       getExternalSvc(),
					endpoints:     getContainsLocalIPv6EPs(),
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:  []string{},
					annotations: map[string]string{
						svcLocalAnnotation: "true",
					},
				},
				{
					service:       getNodePortSvc(),
					endpoints:     getContainsLocalIPv6EPs(),
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:  []string{},
					annotations: map[string]string{
						svcLocalAnnotation: "true",
					},
				},
				{
					service:       getLoadBalancerSvc(),
					endpoints:     getContainsLocalIPv6EPs(),
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1", "10.0.255.1", "10.0.255.2"},
					withdrawnIPs:  []string{},
					annotations: map[string]string{
						svcLocalAnnotation: "true",
					},
				},
			},
		},
		{
			name: "check local external traffic policy with local IPv4 endpoints",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      true,
				advertiseExternalIP:     true,
				advertiseLoadBalancerIP: true,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv4),
					NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:               getClusterSvc(),
					endpoints:             getContainsLocalIPv4EPs(),
					advertisedIPs:         []string{"10.0.0.1"},
					withdrawnIPs:          []string{},
					annotations:           nil,
					externalTrafficPolicy: &testlocalExtTrafPol,
				},
				{
					service:               getExternalSvc(),
					endpoints:             getContainsLocalIPv4EPs(),
					advertisedIPs:         []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:          []string{},
					annotations:           nil,
					externalTrafficPolicy: &testlocalExtTrafPol,
				},
				{
					service:               getNodePortSvc(),
					endpoints:             getContainsLocalIPv4EPs(),
					advertisedIPs:         []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:          []string{},
					annotations:           nil,
					externalTrafficPolicy: &testlocalExtTrafPol,
				},
				{
					service:               getLoadBalancerSvc(),
					endpoints:             getContainsLocalIPv4EPs(),
					advertisedIPs:         []string{"10.0.0.1", "1.1.1.1", "10.0.255.1", "10.0.255.2"},
					withdrawnIPs:          []string{},
					annotations:           nil,
					externalTrafficPolicy: &testlocalExtTrafPol,
				},
			},
		},
		{
			name: "check local external traffic policy with local IPv6 endpoints",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      true,
				advertiseExternalIP:     true,
				advertiseLoadBalancerIP: true,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv6),
					NodeIPv6Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv6)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:               getClusterSvc(),
					endpoints:             getContainsLocalIPv6EPs(),
					advertisedIPs:         []string{"10.0.0.1"},
					withdrawnIPs:          []string{},
					annotations:           nil,
					externalTrafficPolicy: &testlocalExtTrafPol,
				},
				{
					service:               getExternalSvc(),
					endpoints:             getContainsLocalIPv6EPs(),
					advertisedIPs:         []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:          []string{},
					annotations:           nil,
					externalTrafficPolicy: &testlocalExtTrafPol,
				},
				{
					service:               getNodePortSvc(),
					endpoints:             getContainsLocalIPv6EPs(),
					advertisedIPs:         []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:          []string{},
					annotations:           nil,
					externalTrafficPolicy: &testlocalExtTrafPol,
				},
				{
					service:               getLoadBalancerSvc(),
					endpoints:             getContainsLocalIPv6EPs(),
					advertisedIPs:         []string{"10.0.0.1", "1.1.1.1", "10.0.255.1", "10.0.255.2"},
					withdrawnIPs:          []string{},
					annotations:           nil,
					externalTrafficPolicy: &testlocalExtTrafPol,
				},
			},
		},
		{
			name: "check service local annotation WITHOUT local IPv4 endpoints",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      true,
				advertiseExternalIP:     true,
				advertiseLoadBalancerIP: true,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv4),
					NodeIPv6Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv6)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       getClusterSvc(),
					endpoints:     getNoLocalAddressesEPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1"},
					annotations: map[string]string{
						svcLocalAnnotation: "true",
					},
				},
				{
					service:       getExternalSvc(),
					endpoints:     getNoLocalAddressesEPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations: map[string]string{
						svcLocalAnnotation: "true",
					},
				},
				{
					service:       getNodePortSvc(),
					endpoints:     getNoLocalAddressesEPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations: map[string]string{
						svcLocalAnnotation: "true",
					},
				},
				{
					service:       getLoadBalancerSvc(),
					endpoints:     getNoLocalAddressesEPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1", "10.0.255.1", "10.0.255.2"},
					annotations: map[string]string{
						svcLocalAnnotation: "true",
					},
				},
			},
		},
		{
			name: "check service local annotation WITHOUT local IPv6 endpoints",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      true,
				advertiseExternalIP:     true,
				advertiseLoadBalancerIP: true,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv6),
					NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       getClusterSvc(),
					endpoints:     getNoLocalAddressesEPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1"},
					annotations: map[string]string{
						svcLocalAnnotation: "true",
					},
				},
				{
					service:       getExternalSvc(),
					endpoints:     getNoLocalAddressesEPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations: map[string]string{
						svcLocalAnnotation: "true",
					},
				},
				{
					service:       getNodePortSvc(),
					endpoints:     getNoLocalAddressesEPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations: map[string]string{
						svcLocalAnnotation: "true",
					},
				},
				{
					service:       getLoadBalancerSvc(),
					endpoints:     getNoLocalAddressesEPs(),
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1", "10.0.255.1", "10.0.255.2"},
					annotations: map[string]string{
						svcLocalAnnotation: "true",
					},
				},
			},
		},
		{
			name: "check local external traffic policy WITHOUT local IPv4 endpoints",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      true,
				advertiseExternalIP:     true,
				advertiseLoadBalancerIP: true,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv4),
					NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:               getClusterSvc(),
					endpoints:             getNoLocalAddressesEPs(),
					advertisedIPs:         []string{"10.0.0.1"},
					withdrawnIPs:          []string{},
					annotations:           nil,
					externalTrafficPolicy: &testlocalExtTrafPol,
				},
				{
					service:               getExternalSvc(),
					endpoints:             getNoLocalAddressesEPs(),
					advertisedIPs:         []string{"10.0.0.1"},
					withdrawnIPs:          []string{"1.1.1.1"},
					annotations:           nil,
					externalTrafficPolicy: &testlocalExtTrafPol,
				},
				{
					service:               getNodePortSvc(),
					endpoints:             getNoLocalAddressesEPs(),
					advertisedIPs:         []string{"10.0.0.1"},
					withdrawnIPs:          []string{"1.1.1.1"},
					annotations:           nil,
					externalTrafficPolicy: &testlocalExtTrafPol,
				},
				{
					service:               getLoadBalancerSvc(),
					endpoints:             getNoLocalAddressesEPs(),
					advertisedIPs:         []string{"10.0.0.1"},
					withdrawnIPs:          []string{"1.1.1.1", "10.0.255.1", "10.0.255.2"},
					annotations:           nil,
					externalTrafficPolicy: &testlocalExtTrafPol,
				},
			},
		},
		{
			name: "check local external traffic policy WITHOUT local IPv6 endpoints",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      true,
				advertiseExternalIP:     true,
				advertiseLoadBalancerIP: true,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv6),
					NodeIPv6Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv6)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:               getClusterSvc(),
					endpoints:             getNoLocalAddressesEPs(),
					advertisedIPs:         []string{"10.0.0.1"},
					withdrawnIPs:          []string{},
					annotations:           nil,
					externalTrafficPolicy: &testlocalExtTrafPol,
				},
				{
					service:               getExternalSvc(),
					endpoints:             getNoLocalAddressesEPs(),
					advertisedIPs:         []string{"10.0.0.1"},
					withdrawnIPs:          []string{"1.1.1.1"},
					annotations:           nil,
					externalTrafficPolicy: &testlocalExtTrafPol,
				},
				{
					service:               getNodePortSvc(),
					endpoints:             getNoLocalAddressesEPs(),
					advertisedIPs:         []string{"10.0.0.1"},
					withdrawnIPs:          []string{"1.1.1.1"},
					annotations:           nil,
					externalTrafficPolicy: &testlocalExtTrafPol,
				},
				{
					service:               getLoadBalancerSvc(),
					endpoints:             getNoLocalAddressesEPs(),
					advertisedIPs:         []string{"10.0.0.1"},
					withdrawnIPs:          []string{"1.1.1.1", "10.0.255.1", "10.0.255.2"},
					annotations:           nil,
					externalTrafficPolicy: &testlocalExtTrafPol,
				},
			},
		},
		{
			name: "check local internal traffic policy WITHOUT local IPv4 endpoints",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      true,
				advertiseExternalIP:     true,
				advertiseLoadBalancerIP: true,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv4),
					NodeIPv4Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv4)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:               getClusterSvc(),
					endpoints:             getNoLocalAddressesEPs(),
					advertisedIPs:         []string{},
					withdrawnIPs:          []string{"10.0.0.1"},
					annotations:           nil,
					internalTrafficPolicy: &testLocalIntTrafPol,
				},
				{
					service:               getExternalSvc(),
					endpoints:             getNoLocalAddressesEPs(),
					advertisedIPs:         []string{"1.1.1.1"},
					withdrawnIPs:          []string{"10.0.0.1"},
					annotations:           nil,
					internalTrafficPolicy: &testLocalIntTrafPol,
				},
				{
					service:               getNodePortSvc(),
					endpoints:             getNoLocalAddressesEPs(),
					advertisedIPs:         []string{"1.1.1.1"},
					withdrawnIPs:          []string{"10.0.0.1"},
					annotations:           nil,
					internalTrafficPolicy: &testLocalIntTrafPol,
				},
				{
					service:               getLoadBalancerSvc(),
					endpoints:             getNoLocalAddressesEPs(),
					advertisedIPs:         []string{"1.1.1.1", "10.0.255.1", "10.0.255.2"},
					withdrawnIPs:          []string{"10.0.0.1"},
					annotations:           nil,
					internalTrafficPolicy: &testLocalIntTrafPol,
				},
			},
		},
		{
			name: "check local internal traffic policy WITHOUT local IPv6 endpoints",
			nrc: &NetworkRoutingController{
				advertiseClusterIP:      true,
				advertiseExternalIP:     true,
				advertiseLoadBalancerIP: true,
				krNode: &utils.KRNode{
					PrimaryIP:     net.ParseIP(testNodeIPv6),
					NodeIPv6Addrs: map[v1core.NodeAddressType][]net.IP{v1core.NodeInternalIP: {net.ParseIP(testNodeIPv6)}},
				},
			},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:               getClusterSvc(),
					endpoints:             getNoLocalAddressesEPs(),
					advertisedIPs:         []string{},
					withdrawnIPs:          []string{"10.0.0.1"},
					annotations:           nil,
					internalTrafficPolicy: &testLocalIntTrafPol,
				},
				{
					service:               getExternalSvc(),
					endpoints:             getNoLocalAddressesEPs(),
					advertisedIPs:         []string{"1.1.1.1"},
					withdrawnIPs:          []string{"10.0.0.1"},
					annotations:           nil,
					internalTrafficPolicy: &testLocalIntTrafPol,
				},
				{
					service:               getNodePortSvc(),
					endpoints:             getNoLocalAddressesEPs(),
					advertisedIPs:         []string{"1.1.1.1"},
					withdrawnIPs:          []string{"10.0.0.1"},
					annotations:           nil,
					internalTrafficPolicy: &testLocalIntTrafPol,
				},
				{
					service:               getLoadBalancerSvc(),
					endpoints:             getNoLocalAddressesEPs(),
					advertisedIPs:         []string{"1.1.1.1", "10.0.255.1", "10.0.255.2"},
					withdrawnIPs:          []string{"10.0.0.1"},
					annotations:           nil,
					internalTrafficPolicy: &testLocalIntTrafPol,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, serviceAdvertisedIP := range test.serviceAdvertisedIPs {
				endpoints := serviceAdvertisedIP.endpoints
				clientset := fake.NewSimpleClientset()
				startInformersForRoutes(test.nrc, clientset)

				// Take care of adding annotations
				if serviceAdvertisedIP.annotations != nil {
					serviceAdvertisedIP.service.ObjectMeta.Annotations = serviceAdvertisedIP.annotations
				}

				if serviceAdvertisedIP.internalTrafficPolicy != nil {
					serviceAdvertisedIP.service.Spec.InternalTrafficPolicy = serviceAdvertisedIP.internalTrafficPolicy
				}

				if serviceAdvertisedIP.externalTrafficPolicy != nil {
					serviceAdvertisedIP.service.Spec.ExternalTrafficPolicy = *serviceAdvertisedIP.externalTrafficPolicy
				}

				// Take care of adding endpoints if needed for test
				if endpoints != nil {
					endpoints.ObjectMeta.Name = serviceAdvertisedIP.service.Name
					endpoints.ObjectMeta.Namespace = serviceAdvertisedIP.service.Namespace
					if _, err := clientset.CoreV1().Endpoints(endpoints.GetObjectMeta().GetNamespace()).Create(
						context.Background(), endpoints, metav1.CreateOptions{}); err != nil {
						t.Fatalf("failed to create endpoints for test: %v", err)
					}
					waitForListerWithTimeout(test.nrc.epLister, time.Second*10, t)
				}

				svc, _ := clientset.CoreV1().Services("default").Create(context.Background(), serviceAdvertisedIP.service, metav1.CreateOptions{})
				advertisedIPs, withdrawnIPs, err := test.nrc.getAllVIPsForService(svc)
				if err != nil {
					t.Errorf("We shouldn't get an error for any of these tests, failing due to: %v", err)
				}
				t.Logf("AdvertisedIPs: %v\n", advertisedIPs)
				t.Logf("WithdrawnIPs: %v\n", withdrawnIPs)
				if !Equal(serviceAdvertisedIP.advertisedIPs, advertisedIPs) {
					t.Errorf("Advertised IPs are incorrect, got: %v, want: %v.", advertisedIPs, serviceAdvertisedIP.advertisedIPs)
				}
				if !Equal(serviceAdvertisedIP.withdrawnIPs, withdrawnIPs) {
					t.Errorf("Withdrawn IPs are incorrect, got: %v, want: %v.", withdrawnIPs, serviceAdvertisedIP.withdrawnIPs)
				}
			}
		})
	}
}

func getClusterSvc() *v1core.Service {
	return &v1core.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc-cluster",
			Namespace: "default",
		},
		Spec: v1core.ServiceSpec{
			Type:                  ClusterIPST,
			ClusterIP:             "10.0.0.1",
			InternalTrafficPolicy: &testClusterIntTrafPol,
			ExternalTrafficPolicy: testClusterExtTrafPol,
		},
	}
}

func getExternalSvc() *v1core.Service {
	return &v1core.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc-external",
			Namespace: "default",
		},
		Spec: v1core.ServiceSpec{
			Type:                  ClusterIPST,
			ClusterIP:             "10.0.0.1",
			ExternalIPs:           []string{"1.1.1.1"},
			InternalTrafficPolicy: &testClusterIntTrafPol,
			ExternalTrafficPolicy: testClusterExtTrafPol,
		},
	}
}

func getNodePortSvc() *v1core.Service {
	return &v1core.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc-nodeport",
			Namespace: "default",
		},
		Spec: v1core.ServiceSpec{
			Type:                  NodePortST,
			ClusterIP:             "10.0.0.1",
			ExternalIPs:           []string{"1.1.1.1"},
			InternalTrafficPolicy: &testClusterIntTrafPol,
			ExternalTrafficPolicy: testClusterExtTrafPol,
		},
	}
}

func getLoadBalancerSvc() *v1core.Service {
	return &v1core.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc-loadbalancer",
			Namespace: "default",
		},
		Spec: v1core.ServiceSpec{
			Type:                  LoadBalancerST,
			ClusterIP:             "10.0.0.1",
			ExternalIPs:           []string{"1.1.1.1"},
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
	}
}

func getContainsLocalIPv4EPs() *v1core.Endpoints {
	return &v1core.Endpoints{
		Subsets: []v1core.EndpointSubset{
			{
				Addresses: []v1core.EndpointAddress{
					{
						IP: testNodeIPv4,
					},
					{
						IP: "10.1.0.2",
					},
				},
			},
			{
				Addresses: []v1core.EndpointAddress{
					{
						IP: "10.1.1.1",
					},
				},
			},
		},
	}
}

func getContainsLocalIPv6EPs() *v1core.Endpoints {
	return &v1core.Endpoints{
		Subsets: []v1core.EndpointSubset{
			{
				Addresses: []v1core.EndpointAddress{
					{
						IP: testNodeIPv6,
					},
					{
						IP: "2001:db8:42:2::2",
					},
				},
			},
			{
				Addresses: []v1core.EndpointAddress{
					{
						IP: "2001:db8:42:2::3",
					},
				},
			},
		},
	}
}

func getNoLocalAddressesEPs() *v1core.Endpoints {
	return &v1core.Endpoints{
		Subsets: []v1core.EndpointSubset{
			{
				Addresses: []v1core.EndpointAddress{
					{
						IP: "2001:db8:42:2::3",
					},
					{
						IP: "2001:db8:42:2::2",
					},
				},
			},
			{
				Addresses: []v1core.EndpointAddress{
					{
						IP: "2001:db8:42:2::3",
					},
				},
			},
			{
				Addresses: []v1core.EndpointAddress{
					{
						IP: "10.1.0.2",
					},
				},
			},
		},
	}
}
