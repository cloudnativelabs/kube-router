package routing

import (
	"context"
	"testing"

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

type ServiceAdvertisedIPs struct {
	service       *v1core.Service
	advertisedIPs []string
	withdrawnIPs  []string
	annotations   map[string]string
}

func Test_getVIPsForService(t *testing.T) {
	services := map[string]*v1core.Service{
		"cluster": {
			ObjectMeta: metav1.ObjectMeta{
				Name: "svc-cluster",
			},
			Spec: v1core.ServiceSpec{
				Type:      ClusterIPST,
				ClusterIP: "10.0.0.1",
			},
		},
		"external": {
			ObjectMeta: metav1.ObjectMeta{
				Name: "svc-external",
			},
			Spec: v1core.ServiceSpec{
				Type:        ClusterIPST,
				ClusterIP:   "10.0.0.1",
				ExternalIPs: []string{"1.1.1.1"},
			},
		},
		"nodeport": {
			ObjectMeta: metav1.ObjectMeta{
				Name: "svc-nodeport",
			},
			Spec: v1core.ServiceSpec{
				Type:        NodePortST,
				ClusterIP:   "10.0.0.1",
				ExternalIPs: []string{"1.1.1.1"},
			},
		},
		"loadbalancer": {
			ObjectMeta: metav1.ObjectMeta{
				Name: "svc-loadbalancer",
			},
			Spec: v1core.ServiceSpec{
				Type:        LoadBalancerST,
				ClusterIP:   "10.0.0.1",
				ExternalIPs: []string{"1.1.1.1"},
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
	}

	tests := []struct {
		name string
		// cluster, external, loadbalancer
		advertiseSettings    [3]bool
		serviceAdvertisedIPs []*ServiceAdvertisedIPs
	}{
		{
			name:              "advertise all IPs",
			advertiseSettings: [3]bool{true, true, true},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       services["cluster"],
					advertisedIPs: []string{"10.0.0.1"},
					withdrawnIPs:  []string{},
					annotations:   nil,
				},
				{
					service:       services["external"],
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:  []string{},
					annotations:   nil,
				},
				{
					service:       services["nodeport"],
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:  []string{},
					annotations:   nil,
				},
				{
					service:       services["loadbalancer"],
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1", "10.0.255.1", "10.0.255.2"},
					withdrawnIPs:  []string{},
					annotations:   nil,
				},
			},
		},
		{
			name:              "do not advertise any IPs",
			advertiseSettings: [3]bool{false, false, false},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       services["cluster"],
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1"},
					annotations:   nil,
				},
				{
					service:       services["external"],
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations:   nil,
				},
				{
					service:       services["nodeport"],
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations:   nil,
				},
				{
					service:       services["loadbalancer"],
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1", "10.0.255.1", "10.0.255.2"},
					annotations:   nil,
				},
			},
		},
		{
			name:              "advertise cluster IPs",
			advertiseSettings: [3]bool{true, false, false},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       services["cluster"],
					advertisedIPs: []string{"10.0.0.1"},
					withdrawnIPs:  []string{},
					annotations:   nil,
				},
				{
					service:       services["external"],
					advertisedIPs: []string{"10.0.0.1"},
					withdrawnIPs:  []string{"1.1.1.1"},
					annotations:   nil,
				},
				{
					service:       services["nodeport"],
					advertisedIPs: []string{"10.0.0.1"},
					withdrawnIPs:  []string{"1.1.1.1"},
					annotations:   nil,
				},
				{
					service:       services["loadbalancer"],
					advertisedIPs: []string{"10.0.0.1"},
					withdrawnIPs:  []string{"1.1.1.1", "10.0.255.1", "10.0.255.2"},
					annotations:   nil,
				},
			},
		},
		{
			name:              "advertise external IPs",
			advertiseSettings: [3]bool{false, true, false},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       services["cluster"],
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1"},
					annotations:   nil,
				},
				{
					service:       services["external"],
					advertisedIPs: []string{"1.1.1.1"},
					withdrawnIPs:  []string{"10.0.0.1"},
					annotations:   nil,
				},
				{
					service:       services["nodeport"],
					advertisedIPs: []string{"1.1.1.1"},
					withdrawnIPs:  []string{"10.0.0.1"},
					annotations:   nil,
				},
				{
					service:       services["loadbalancer"],
					advertisedIPs: []string{"1.1.1.1"},
					withdrawnIPs:  []string{"10.0.0.1", "10.0.255.1", "10.0.255.2"},
					annotations:   nil,
				},
			},
		},
		{
			name:              "advertise loadbalancer IPs",
			advertiseSettings: [3]bool{false, false, true},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       services["cluster"],
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1"},
					annotations:   nil,
				},
				{
					service:       services["external"],
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations:   nil,
				},
				{
					service:       services["nodeport"],
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations:   nil,
				},
				{
					service:       services["loadbalancer"],
					advertisedIPs: []string{"10.0.255.1", "10.0.255.2"},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations:   nil,
				},
			},
		},
		{
			name:              "opt in to advertise all IPs via annotations",
			advertiseSettings: [3]bool{false, false, false},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       services["cluster"],
					advertisedIPs: []string{"10.0.0.1"},
					withdrawnIPs:  []string{},
					annotations: map[string]string{
						svcAdvertiseClusterAnnotation:      "true",
						svcAdvertiseExternalAnnotation:     "true",
						svcAdvertiseLoadBalancerAnnotation: "true",
					},
				},
				{
					service:       services["external"],
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:  []string{},
					annotations: map[string]string{
						svcAdvertiseClusterAnnotation:      "true",
						svcAdvertiseExternalAnnotation:     "true",
						svcAdvertiseLoadBalancerAnnotation: "true",
					},
				},
				{
					service:       services["nodeport"],
					advertisedIPs: []string{"10.0.0.1", "1.1.1.1"},
					withdrawnIPs:  []string{},
					annotations: map[string]string{
						svcAdvertiseClusterAnnotation:      "true",
						svcAdvertiseExternalAnnotation:     "true",
						svcAdvertiseLoadBalancerAnnotation: "true",
					},
				},
				{
					service:       services["loadbalancer"],
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
					service:       services["loadbalancer"],
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
			name:              "opt out to advertise any IPs via annotations",
			advertiseSettings: [3]bool{true, true, true},
			serviceAdvertisedIPs: []*ServiceAdvertisedIPs{
				{
					service:       services["cluster"],
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1"},
					annotations: map[string]string{
						svcAdvertiseClusterAnnotation:      "false",
						svcAdvertiseExternalAnnotation:     "false",
						svcAdvertiseLoadBalancerAnnotation: "false",
					},
				},
				{
					service:       services["external"],
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations: map[string]string{
						svcAdvertiseClusterAnnotation:      "false",
						svcAdvertiseExternalAnnotation:     "false",
						svcAdvertiseLoadBalancerAnnotation: "false",
					},
				},
				{
					service:       services["nodeport"],
					advertisedIPs: []string{},
					withdrawnIPs:  []string{"10.0.0.1", "1.1.1.1"},
					annotations: map[string]string{
						svcAdvertiseClusterAnnotation:      "false",
						svcAdvertiseExternalAnnotation:     "false",
						svcAdvertiseLoadBalancerAnnotation: "false",
					},
				},
				{
					service:       services["loadbalancer"],
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
	}

	for _, test := range tests {
		nrc := NetworkRoutingController{}
		t.Run(test.name, func(t *testing.T) {
			nrc.advertiseClusterIP = test.advertiseSettings[0]
			nrc.advertiseExternalIP = test.advertiseSettings[1]
			nrc.advertiseLoadBalancerIP = test.advertiseSettings[2]

			for _, serviceAdvertisedIP := range test.serviceAdvertisedIPs {
				clientset := fake.NewSimpleClientset()

				if serviceAdvertisedIP.annotations != nil {
					serviceAdvertisedIP.service.ObjectMeta.Annotations = serviceAdvertisedIP.annotations
				}
				svc, _ := clientset.CoreV1().Services("default").Create(context.Background(), serviceAdvertisedIP.service, metav1.CreateOptions{})
				advertisedIPs, withdrawnIPs, _ := nrc.getVIPsForService(svc, false)
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
