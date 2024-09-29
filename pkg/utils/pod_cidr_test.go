package utils

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func Test_GetPodCidrFromNodeSpec(t *testing.T) {
	testcases := []struct {
		name             string
		hostnameOverride string
		existingNode     *apiv1.Node
		podCIDR          string
		err              error
	}{
		{
			"node with node.Spec.PodCIDR",
			"test-node",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Spec: apiv1.NodeSpec{
					PodCIDR: "172.17.0.0/24",
				},
			},
			"172.17.0.0/24",
			nil,
		},
		{
			"node with node.Annotations['kube-router.io/pod-cidr']",
			"test-node",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						podCIDRAnnotation: "172.17.0.0/24",
					},
				},
			},
			"172.17.0.0/24",
			nil,
		},
		{
			"node with invalid pod cidr in node.Annotations['kube-router.io/pod-cidr']",
			"test-node",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						podCIDRAnnotation: "172.17.0.0",
					},
				},
			},
			"",
			errors.New("error parsing pod CIDR in node annotation: invalid CIDR address: 172.17.0.0"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset()
			_, err := clientset.CoreV1().Nodes().Create(context.Background(), testcase.existingNode, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("failed to create existing nodes for test: %v", err)
			}
			node, err := GetNodeObject(clientset, testcase.hostnameOverride)
			if err != nil {
				t.Error("unable to get node object from API: " + err.Error())
			}
			podCIDR, err := GetPodCidrFromNodeSpec(node)
			if testcase.err != nil {
				assert.EqualError(t, err, testcase.err.Error())
			}

			if podCIDR != testcase.podCIDR {
				t.Logf("actual podCIDR: %q", podCIDR)
				t.Logf("expected podCIDR: %q", testcase.podCIDR)
				t.Error("did not get expected podCIDR")
			}
		})
	}
}

func Test_GetPodCIDRsFromNodeSpec(t *testing.T) {
	var blankCIDR []string
	testcases := []struct {
		name             string
		hostnameOverride string
		existingNode     *apiv1.Node
		ipv4CIDRs        []string
		ipv6CIDRs        []string
		err              error
	}{
		{
			"node with node.Spec.PodCIDRs",
			"test-node",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Spec: apiv1.NodeSpec{
					PodCIDRs: []string{
						"172.17.0.0/24",
						"2001:db8:42:0::/64",
					},
				},
			},
			[]string{"172.17.0.0/24"},
			[]string{"2001:db8:42:0::/64"},
			nil,
		},
		{
			"node with multiple IPv4 addresses and no IPv6 in node.Spec.PodCIDRs",
			"test-node",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Spec: apiv1.NodeSpec{
					PodCIDRs: []string{
						"172.17.0.0/24",
						"172.18.0.0/24",
					},
				},
			},
			[]string{"172.17.0.0/24", "172.18.0.0/24"},
			blankCIDR,
			nil,
		},
		{
			"node with multiple IPv6 addresses in node.Spec.PodCIDRs",
			"test-node",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Spec: apiv1.NodeSpec{
					PodCIDRs: []string{
						"172.17.0.0/24",
						"2001:db8:42:0::/64",
						"2001:db8:42:1::/64",
					},
				},
			},
			[]string{"172.17.0.0/24"},
			[]string{"2001:db8:42:0::/64", "2001:db8:42:1::/64"},
			nil,
		},
		{
			"node with node.Annotations['kube-router.io/pod-cidrs']",
			"test-node",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						podCIDRsAnnotation: "172.17.0.0/24,2001:db8:42:2::/64",
					},
				},
			},
			[]string{"172.17.0.0/24"},
			[]string{"2001:db8:42:2::/64"},
			nil,
		},
		{
			"node with invalid pod IPv4 cidrs in node.Annotations['kube-router.io/pod-cidrs']",
			"test-node",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						podCIDRsAnnotation: "172.17.0.0,2001:db8:42:2::/64",
					},
				},
			},
			blankCIDR,
			blankCIDR,
			errors.New("error parsing pod CIDR in node annotation: invalid CIDR address: 172.17.0.0"),
		},
		{
			"node with invalid pod IPv6 cidrs in node.Annotations['kube-router.io/pod-cidrs']",
			"test-node",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
					Annotations: map[string]string{
						podCIDRsAnnotation: "172.17.0.0/24,2001:db8:42:2::",
					},
				},
			},
			[]string{"172.17.0.0/24"},
			blankCIDR,
			fmt.Errorf("error parsing pod CIDR in node annotation: invalid CIDR address: %s",
				"2001:db8:42:2::"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset()
			_, err := clientset.CoreV1().Nodes().Create(context.Background(), testcase.existingNode, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("failed to create existing nodes for test: %v", err)
			}
			node, err := GetNodeObject(clientset, testcase.hostnameOverride)
			if err != nil {
				t.Error("unable to get node object from API: " + err.Error())
			}
			ipv4CIDRs, ipv6CIDRs, err := GetPodCIDRsFromNodeSpecDualStack(node)

			if testcase.err != nil {
				assert.EqualError(t, err, testcase.err.Error())
			}

			if !reflect.DeepEqual(ipv4CIDRs, testcase.ipv4CIDRs) {
				t.Logf("actual IPv4 podCIDR: %q", ipv4CIDRs)
				t.Logf("expected IPv4 podCIDR: %q", testcase.ipv4CIDRs)
				t.Error("did not get expected IPv4 podCIDR")
			}

			if !reflect.DeepEqual(ipv6CIDRs, testcase.ipv6CIDRs) {
				t.Logf("actual IPv6 podCIDR: %q", ipv6CIDRs)
				t.Logf("expected IPv6 podCIDR: %q", testcase.ipv6CIDRs)
				t.Error("did not get expected IPv6 podCIDR")
			}
		})
	}
}
