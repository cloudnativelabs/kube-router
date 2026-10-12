package netpol

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testNamePrefix(t *testing.T, testString string, isIPv6 bool) {
	if isIPv6 {
		assert.Truef(t, strings.HasPrefix(testString, "inet6:"), "%s is IPv6 and should begin with inet6:", testString)
	}
}

func Test_policySourcePodIPSetName(t *testing.T) {
	t.Run("Check IPv4 and IPv6 names are correct", func(t *testing.T) {
		setName := policySourcePodIPSetName("foo", "bar", v1.IPv4Protocol)
		testNamePrefix(t, setName, false)
		setName = policySourcePodIPSetName("foo", "bar", v1.IPv6Protocol)
		testNamePrefix(t, setName, true)
	})
}

func Test_policyDestinationPodIPSetName(t *testing.T) {
	t.Run("Check IPv4 and IPv6 names are correct", func(t *testing.T) {
		setName := policyDestinationPodIPSetName("foo", "bar", v1.IPv4Protocol)
		testNamePrefix(t, setName, false)
		setName = policyDestinationPodIPSetName("foo", "bar", v1.IPv6Protocol)
		testNamePrefix(t, setName, true)
	})
}

func Test_policyIndexedSourcePodIPSetName(t *testing.T) {
	t.Run("Check IPv4 and IPv6 names are correct", func(t *testing.T) {
		setName := policyIndexedSourcePodIPSetName("foo", "bar", 1, v1.IPv4Protocol)
		testNamePrefix(t, setName, false)
		setName = policyIndexedSourcePodIPSetName("foo", "bar", 1, v1.IPv6Protocol)
		testNamePrefix(t, setName, true)
	})
}

func Test_policyIndexedDestinationPodIPSetName(t *testing.T) {
	t.Run("Check IPv4 and IPv6 names are correct", func(t *testing.T) {
		setName := policyIndexedDestinationPodIPSetName("foo", "bar", 1, v1.IPv4Protocol)
		testNamePrefix(t, setName, false)
		setName = policyIndexedDestinationPodIPSetName("foo", "bar", 1, v1.IPv6Protocol)
		testNamePrefix(t, setName, true)
	})
}

func Test_policyIndexedSourceIPBlockIPSetName(t *testing.T) {
	t.Run("Check IPv4 and IPv6 names are correct", func(t *testing.T) {
		setName := policyIndexedSourceIPBlockIPSetName("foo", "bar", 1, v1.IPv4Protocol)
		testNamePrefix(t, setName, false)
		setName = policyIndexedSourceIPBlockIPSetName("foo", "bar", 1, v1.IPv6Protocol)
		testNamePrefix(t, setName, true)
	})
}

func Test_policyIndexedDestinationIPBlockIPSetName(t *testing.T) {
	t.Run("Check IPv4 and IPv6 names are correct", func(t *testing.T) {
		setName := policyIndexedDestinationIPBlockIPSetName("foo", "bar", 1, v1.IPv4Protocol)
		testNamePrefix(t, setName, false)
		setName = policyIndexedDestinationIPBlockIPSetName("foo", "bar", 1, v1.IPv6Protocol)
		testNamePrefix(t, setName, true)
	})
}

func Test_policyIndexedIngressNamedPortIPSetName(t *testing.T) {
	t.Run("Check IPv4 and IPv6 names are correct", func(t *testing.T) {
		setName := policyIndexedIngressNamedPortIPSetName("foo", "bar", 1, 1, v1.IPv4Protocol)
		testNamePrefix(t, setName, false)
		setName = policyIndexedIngressNamedPortIPSetName("foo", "bar", 1, 1, v1.IPv6Protocol)
		testNamePrefix(t, setName, true)
	})
}

func Test_policyIndexedEgressNamedPortIPSetName(t *testing.T) {
	t.Run("Check IPv4 and IPv6 names are correct", func(t *testing.T) {
		setName := policyIndexedEgressNamedPortIPSetName("foo", "bar", 1, 1, v1.IPv4Protocol)
		testNamePrefix(t, setName, false)
		setName = policyIndexedEgressNamedPortIPSetName("foo", "bar", 1, 1, v1.IPv6Protocol)
		testNamePrefix(t, setName, true)
	})
}

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
