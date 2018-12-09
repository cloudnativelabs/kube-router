package routing

import (
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
	annotations   map[string]string
}

func Test_getVIPsForService(t *testing.T) {
	services := map[string]*v1core.Service{
		"cluster": {
			ObjectMeta: metav1.ObjectMeta{
				Name: "svc-cluster",
			},
			Spec: v1core.ServiceSpec{
				Type:      "ClusterIP",
				ClusterIP: "10.0.0.1",
			},
		},
		"external": {
			ObjectMeta: metav1.ObjectMeta{
				Name: "svc-external",
			},
			Spec: v1core.ServiceSpec{
				Type:        "ClusterIP",
				ClusterIP:   "10.0.0.1",
				ExternalIPs: []string{"1.1.1.1"},
			},
		},
		"nodeport": {
			ObjectMeta: metav1.ObjectMeta{
				Name: "svc-nodeport",
			},
			Spec: v1core.ServiceSpec{
				Type:        "NodePort",
				ClusterIP:   "10.0.0.1",
				ExternalIPs: []string{"1.1.1.1"},
			},
		},
		"loadbalancer": {
			ObjectMeta: metav1.ObjectMeta{
				Name: "svc-loadbalancer",
			},
			Spec: v1core.ServiceSpec{
				Type:      "LoadBalancer",
				ClusterIP: "10.0.0.1",
				// External IPs are ignored since LoadBalancer services don't
				// advertise external IPs.
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
			"advertise all IPs",
			[3]bool{true, true, true},
			[]*ServiceAdvertisedIPs{
				{
					services["cluster"],
					[]string{"10.0.0.1"},
					nil,
				},
				{
					services["external"],
					[]string{"10.0.0.1", "1.1.1.1"},
					nil,
				},
				{
					services["nodeport"],
					[]string{"10.0.0.1", "1.1.1.1"},
					nil,
				},
				{
					services["loadbalancer"],
					[]string{"10.0.0.1", "10.0.255.1", "10.0.255.2"},
					nil,
				},
			},
		},
		{
			"do not advertise any IPs",
			[3]bool{false, false, false},
			[]*ServiceAdvertisedIPs{
				{
					services["cluster"],
					[]string{},
					nil,
				},
				{
					services["external"],
					[]string{},
					nil,
				},
				{
					services["nodeport"],
					[]string{},
					nil,
				},
				{
					services["loadbalancer"],
					[]string{},
					nil,
				},
			},
		},
		{
			"advertise cluster IPs",
			[3]bool{true, false, false},
			[]*ServiceAdvertisedIPs{
				{
					services["cluster"],
					[]string{"10.0.0.1"},
					nil,
				},
				{
					services["external"],
					[]string{"10.0.0.1"},
					nil,
				},
				{
					services["nodeport"],
					[]string{"10.0.0.1"},
					nil,
				},
				{
					services["loadbalancer"],
					[]string{"10.0.0.1"},
					nil,
				},
			},
		},
		{
			"advertise external IPs",
			[3]bool{false, true, false},
			[]*ServiceAdvertisedIPs{
				{
					services["cluster"],
					[]string{},
					nil,
				},
				{
					services["external"],
					[]string{"1.1.1.1"},
					nil,
				},
				{
					services["nodeport"],
					[]string{"1.1.1.1"},
					nil,
				},
				{
					services["loadbalancer"],
					[]string{},
					nil,
				},
			},
		},
		{
			"advertise loadbalancer IPs",
			[3]bool{false, false, true},
			[]*ServiceAdvertisedIPs{
				{
					services["cluster"],
					[]string{},
					nil,
				},
				{
					services["external"],
					[]string{},
					nil,
				},
				{
					services["nodeport"],
					[]string{},
					nil,
				},
				{
					services["loadbalancer"],
					[]string{"10.0.255.1", "10.0.255.2"},
					nil,
				},
			},
		},
		{
			"opt in to advertise all IPs via annotations",
			[3]bool{false, false, false},
			[]*ServiceAdvertisedIPs{
				{
					services["cluster"],
					[]string{"10.0.0.1"},
					map[string]string{
						svcAdvertiseClusterAnnotation:      "true",
						svcAdvertiseExternalAnnotation:     "true",
						svcAdvertiseLoadBalancerAnnotation: "true",
					},
				},
				{
					services["external"],
					[]string{"10.0.0.1", "1.1.1.1"},
					map[string]string{
						svcAdvertiseClusterAnnotation:      "true",
						svcAdvertiseExternalAnnotation:     "true",
						svcAdvertiseLoadBalancerAnnotation: "true",
					},
				},
				{
					services["nodeport"],
					[]string{"10.0.0.1", "1.1.1.1"},
					map[string]string{
						svcAdvertiseClusterAnnotation:      "true",
						svcAdvertiseExternalAnnotation:     "true",
						svcAdvertiseLoadBalancerAnnotation: "true",
					},
				},
				{
					services["loadbalancer"],
					[]string{"10.0.0.1", "10.0.255.1", "10.0.255.2"},
					map[string]string{
						svcAdvertiseClusterAnnotation:      "true",
						svcAdvertiseExternalAnnotation:     "true",
						svcAdvertiseLoadBalancerAnnotation: "true",
					},
				},
				{
					// Special case to test svcAdvertiseLoadBalancerAnnotation vs legacy svcSkipLbIpsAnnotation
					services["loadbalancer"],
					[]string{"10.0.0.1"},
					map[string]string{
						svcAdvertiseClusterAnnotation:      "true",
						svcAdvertiseExternalAnnotation:     "true",
						svcAdvertiseLoadBalancerAnnotation: "true",
						svcSkipLbIpsAnnotation:             "true",
					},
				},
			},
		},
		{
			"opt out to advertise any IPs via annotations",
			[3]bool{true, true, true},
			[]*ServiceAdvertisedIPs{
				{
					services["cluster"],
					[]string{},
					map[string]string{
						svcAdvertiseClusterAnnotation:      "false",
						svcAdvertiseExternalAnnotation:     "false",
						svcAdvertiseLoadBalancerAnnotation: "false",
					},
				},
				{
					services["external"],
					[]string{},
					map[string]string{
						svcAdvertiseClusterAnnotation:      "false",
						svcAdvertiseExternalAnnotation:     "false",
						svcAdvertiseLoadBalancerAnnotation: "false",
					},
				},
				{
					services["nodeport"],
					[]string{},
					map[string]string{
						svcAdvertiseClusterAnnotation:      "false",
						svcAdvertiseExternalAnnotation:     "false",
						svcAdvertiseLoadBalancerAnnotation: "false",
					},
				},
				{
					services["loadbalancer"],
					[]string{},
					map[string]string{
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
				svc, _ := clientset.CoreV1().Services("default").Create(serviceAdvertisedIP.service)
				advertisedIPs, _, _ := nrc.getVIPsForService(svc, false)
				t.Logf("AdvertisedIPs: %v\n", advertisedIPs)
				if !Equal(serviceAdvertisedIP.advertisedIPs, advertisedIPs) {
					t.Errorf("Advertised IPs are incorrect, got: %v, want: %v.", serviceAdvertisedIP.advertisedIPs, advertisedIPs)
				}
			}
		})
	}
}
