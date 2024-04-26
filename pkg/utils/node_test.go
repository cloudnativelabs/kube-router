package utils

import (
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"testing"

	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func Test_GetNodeObject(t *testing.T) {
	curHostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("failed to get local hostname: %v", err)
	}

	testcases := []struct {
		name             string
		envNodeName      string
		hostnameOverride string
		existingNode     *apiv1.Node
		err              error
	}{
		{
			"node with NODE_NAME exists",
			"test-node",
			"",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
			},
			nil,
		},
		{
			"node with hostname override exists",
			"something-else",
			"test-node",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
			},
			nil,
		},
		{
			"node with current hostname exists",
			"",
			"",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: curHostname,
				},
			},
			nil,
		},
		{
			"node with NODE_NAME, hostname override or current hostname does not exists",
			"test-node",
			"",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "another-node",
				},
			},
			errors.New("unable to get node test-node, due to: nodes \"test-node\" not found"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset()
			_, err := clientset.CoreV1().Nodes().Create(context.Background(), testcase.existingNode, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("failed to create existing nodes for test: %v", err)
			}

			os.Setenv("NODE_NAME", testcase.envNodeName)
			defer os.Unsetenv("NODE_NAME")

			_, err = GetNodeObject(clientset, testcase.hostnameOverride)
			if !reflect.DeepEqual(err, testcase.err) {
				t.Logf("actual error: %v", err)
				t.Logf("expected error: %v", testcase.err)
				t.Error("did not get expected error")
			}
		})
	}
}

func Test_GetNodeIP(t *testing.T) {
	testcases := []struct {
		name string
		node *apiv1.Node
		ip   net.IP
		err  error
	}{
		{
			"has external and internal IPs",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeInternalIP,
							Address: "10.0.0.1",
						},
						{
							Type:    apiv1.NodeExternalIP,
							Address: "1.1.1.1",
						},
					},
				},
			},
			net.ParseIP("10.0.0.1"),
			nil,
		},
		{
			"has only internal IP",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeInternalIP,
							Address: "10.0.0.1",
						},
					},
				},
			},
			net.ParseIP("10.0.0.1"),
			nil,
		},
		{
			"has only external IP",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeExternalIP,
							Address: "1.1.1.1",
						},
					},
				},
			},
			net.ParseIP("1.1.1.1"),
			nil,
		},
		{
			"has no addresses",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{},
				},
			},
			nil,
			errors.New("host IP unknown"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			ip, err := GetPrimaryNodeIP(testcase.node)
			if !reflect.DeepEqual(err, testcase.err) {
				t.Logf("actual error: %v", err)
				t.Logf("expected error: %v", testcase.err)
				t.Error("did not get expected error")
			}

			if !reflect.DeepEqual(ip, testcase.ip) {
				t.Logf("actual ip: %v", ip)
				t.Logf("expected ip: %v", testcase.ip)
				t.Error("did not get expected node ip")
			}
		})
	}
}
