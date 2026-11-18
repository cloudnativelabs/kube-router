package netpol

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func Test_grabNamedPortFromPod(t *testing.T) {
	newPod := func(name, ip string, ports ...v1.ContainerPort) *v1.Pod {
		return &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       v1.PodSpec{Containers: []v1.Container{{Name: "c", Ports: ports}}},
			Status:     v1.PodStatus{PodIPs: []v1.PodIP{{IP: ip}}},
		}
	}
	metrics := v1.ContainerPort{Name: "metrics", ContainerPort: 9100, Protocol: v1.ProtocolTCP}
	web := v1.ContainerPort{Name: "web", ContainerPort: 8080, Protocol: v1.ProtocolTCP}

	t.Run("pods are only added to the named ports they expose", func(t *testing.T) {
		npc := &NetworkPolicyControllerBase{}
		eps := make(namedPort2eps)
		npc.grabNamedPortFromPod(newPod("a", "10.0.0.1", metrics, web), &eps)
		npc.grabNamedPortFromPod(newPod("b", "10.0.0.2", web), &eps)

		assert.ElementsMatch(t, []string{"10.0.0.1"}, eps["metrics"]["TCP"]["9100"].ips[v1.IPv4Protocol])
		assert.ElementsMatch(t, []string{"10.0.0.1", "10.0.0.2"}, eps["web"]["TCP"]["8080"].ips[v1.IPv4Protocol])
	})
}

func Test_processNetworkPolicyPorts(t *testing.T) {
	t.Run("a named port with several numbers resolves in the same order every time", func(t *testing.T) {
		npc := &NetworkPolicyControllerBase{}
		eps := make(namedPort2eps)
		for i, number := range []int32{8080, 3000, 9090, 8443} {
			npc.grabNamedPortFromPod(&v1.Pod{
				Spec: v1.PodSpec{Containers: []v1.Container{{Ports: []v1.ContainerPort{
					{Name: "http", ContainerPort: number, Protocol: v1.ProtocolTCP},
				}}}},
				Status: v1.PodStatus{PodIPs: []v1.PodIP{{IP: fmt.Sprintf("10.0.0.%d", i+1)}}},
			}, &eps)
		}
		tcp := v1.ProtocolTCP
		http := intstr.FromString("http")
		npPorts := []networking.NetworkPolicyPort{{Protocol: &tcp, Port: &http}}

		// the named port ipsets are named by the position of their entry, so the order has to hold across syncs
		for range 20 {
			_, namedPorts := npc.processNetworkPolicyPorts(npPorts, eps)
			var numbers []string
			for _, ep := range namedPorts {
				numbers = append(numbers, ep.port)
			}
			assert.Equal(t, []string{"3000", "8080", "8443", "9090"}, numbers)
		}
	})
}
