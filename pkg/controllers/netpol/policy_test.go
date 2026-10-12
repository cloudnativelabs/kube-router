package netpol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
