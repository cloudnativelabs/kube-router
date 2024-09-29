package utils

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/vishvananda/netlink"
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
			if testcase.err != nil {
				assert.EqualError(t, err, testcase.err.Error())
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
			errors.New("error getting primary NodeIP: host IP unknown"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			krNode, err := NewRemoteKRNode(testcase.node)
			if err != nil {
				assert.EqualError(t, err, testcase.err.Error())
				return
			}
			ip := krNode.GetPrimaryNodeIP()

			if testcase.err == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, testcase.err.Error())
			}

			assert.Equal(t, testcase.ip, ip)
		})
	}
}

func Test_GetNodeIPv4Addrs(t *testing.T) {
	testcases := []struct {
		name     string
		node     *apiv1.Node
		expected []net.IP
		err      error
	}{
		{
			"node with internal and external IPv4 addresses",
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
							Address: "192.168.1.1",
						},
						{
							Type:    apiv1.NodeExternalIP,
							Address: "2001:db8::1",
						},
					},
				},
			},
			[]net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1")},
			nil,
		},
		{
			"node with only internal IPv4 address",
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
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8::1",
						},
						{
							Type:    apiv1.NodeExternalIP,
							Address: "2001:db8::2",
						},
					},
				},
			},
			[]net.IP{net.ParseIP("10.0.0.1")},
			nil,
		},
		{
			"node with only external IPv4 address",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeExternalIP,
							Address: "192.168.1.1",
						},
						{
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8::1",
						},
					},
				},
			},
			[]net.IP{net.ParseIP("192.168.1.1")},
			nil,
		},
		{
			"node with no IPv4 addresses",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{},
				},
			},
			[]net.IP{},
			errors.New("error getting primary NodeIP: host IP unknown"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			krNode, err := NewRemoteKRNode(testcase.node)
			if err != nil {
				if testcase.err == nil {
					t.Fatalf("failed to create KRNode: %v", err)
				}
				assert.EqualError(t, err, testcase.err.Error())
				return
			}
			ipv4Addrs := krNode.GetNodeIPv4Addrs()
			assert.Equal(t, testcase.expected, ipv4Addrs,
				"testcase: %s, expected: %s, actual %s", testcase.name, testcase.expected, ipv4Addrs)
		})
	}
}

func Test_GetNodeIPv6Addrs(t *testing.T) {
	testcases := []struct {
		name     string
		node     *apiv1.Node
		expected []net.IP
		err      error
	}{
		{
			"node with internal and external IPv4 and external IPv6 addresses",
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
							Address: "192.168.1.1",
						},
						{
							Type:    apiv1.NodeExternalIP,
							Address: "2001:db8::1",
						},
					},
				},
			},
			[]net.IP{net.ParseIP("2001:db8::1")},
			nil,
		},
		{
			"node with only internal IPv4 and IPv6 addresses",
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
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8::1",
						},
						{
							Type:    apiv1.NodeExternalIP,
							Address: "2001:db8::2",
						},
					},
				},
			},
			[]net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")},
			nil,
		},
		{
			"node with only external IPv4 & internal IPv6 address",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeExternalIP,
							Address: "192.168.1.1",
						},
						{
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8::1",
						},
					},
				},
			},
			[]net.IP{net.ParseIP("2001:db8::1")},
			nil,
		},
		{
			"node with no IPv6 addresses",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{},
				},
			},
			[]net.IP{},
			errors.New("error getting primary NodeIP: host IP unknown"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			krNode, err := NewRemoteKRNode(testcase.node)
			if err != nil {
				if testcase.err == nil {
					t.Fatalf("failed to create KRNode: %v", err)
				}
				assert.EqualError(t, err, testcase.err.Error())
				return
			}
			ipv4Addrs := krNode.GetNodeIPv6Addrs()
			assert.Equal(t, testcase.expected, ipv4Addrs)
		})
	}
}

func Test_FindBestIPv6NodeAddress(t *testing.T) {
	testcases := []struct {
		name     string
		node     *apiv1.Node
		expected net.IP
	}{
		{
			"primary IP is already IPv6",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8::1",
						},
					},
				},
			},
			net.ParseIP("2001:db8::1"),
		},
		{
			"internal IPv6 address available",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8::1",
						},
						{
							Type:    apiv1.NodeExternalIP,
							Address: "2001:db8::2",
						},
					},
				},
			},
			net.ParseIP("2001:db8::1"),
		},
		{
			"external IPv6 address available",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeExternalIP,
							Address: "2001:db8::2",
						},
					},
				},
			},
			net.ParseIP("2001:db8::2"),
		},
		{
			"no IPv6 address available",
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
			nil,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			krNode, err := NewRemoteKRNode(testcase.node)
			if err != nil {
				t.Fatalf("failed to create KRNode: %v", err)
			}
			ip := krNode.FindBestIPv6NodeAddress()
			assert.Equal(t, testcase.expected, ip)
		})
	}
}

func Test_FindBestIPv4NodeAddress(t *testing.T) {
	testcases := []struct {
		name     string
		node     *apiv1.Node
		expected net.IP
	}{
		{
			"primary IP is already IPv4",
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
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8::1",
						},
					},
				},
			},
			net.ParseIP("10.0.0.1"),
		},
		{
			"internal IPv4 address available",
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
							Address: "192.168.1.1",
						},
						{
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8::1",
						},
					},
				},
			},
			net.ParseIP("10.0.0.1"),
		},
		{
			"external IPv4 address available",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeExternalIP,
							Address: "192.168.1.1",
						},
						{
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8::1",
						},
					},
				},
			},
			net.ParseIP("192.168.1.1"),
		},
		{
			"no IPv4 address available",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8::1",
						},
					},
				},
			},
			nil,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			krNode, err := NewRemoteKRNode(testcase.node)
			if err != nil {
				t.Fatalf("failed to create KRNode: %v", err)
			}
			ip := krNode.FindBestIPv4NodeAddress()
			assert.Equal(t, testcase.expected, ip)
		})
	}
}

func Test_NewKRNode(t *testing.T) {
	testcases := []struct {
		name        string
		node        *apiv1.Node
		linkQ       LocalLinkQuerier
		enableIPv4  bool
		enableIPv6  bool
		expectedErr error
	}{
		{
			"valid node with IPv4 and IPv6",
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
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8::1",
						},
					},
				},
			},
			NewFakeLocalLinkQuerier([]string{"10.0.0.1", "2001:db8::1"}, nil),
			true,
			true,
			nil,
		},
		{
			"node with no IPv4 address",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{
						{
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8::1",
						},
					},
				},
			},
			NewFakeLocalLinkQuerier([]string{"2001:db8::1"}, nil),
			true,
			true,
			errors.New("IPv4 was enabled, but no IPv4 address was found on the node"),
		},
		{
			"node with no IPv6 address",
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
			NewFakeLocalLinkQuerier([]string{"10.0.0.1"}, nil),
			true,
			true,
			errors.New("IPv6 was enabled, but no IPv6 address was found on the node"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			_, err := NewKRNode(testcase.node, testcase.linkQ, testcase.enableIPv4, testcase.enableIPv6)
			if testcase.expectedErr != nil {
				assert.EqualError(t, err, testcase.expectedErr.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_NewRemoteKRNode(t *testing.T) {
	testcases := []struct {
		name        string
		node        *apiv1.Node
		expectedErr error
	}{
		{
			"valid node with IPv4 and IPv6",
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
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8::1",
						},
					},
				},
			},
			nil,
		},
		{
			"node with no addresses",
			&apiv1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node",
				},
				Status: apiv1.NodeStatus{
					Addresses: []apiv1.NodeAddress{},
				},
			},
			errors.New("error getting primary NodeIP: host IP unknown"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			_, err := NewRemoteKRNode(testcase.node)
			if testcase.expectedErr != nil {
				assert.EqualError(t, err, testcase.expectedErr.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_GetNodeMTU(t *testing.T) {
	testcases := []struct {
		name        string
		node        *apiv1.Node
		linkQ       LocalLinkQuerier
		expectedMTU int
		expectedErr error
	}{
		{
			"valid node with MTU",
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
							Type:    apiv1.NodeInternalIP,
							Address: "2001:db8::1",
						},
					},
				},
			},
			NewFakeLocalLinkQuerier([]string{"10.0.0.1", "2001:db8::1"}, []int{1480, 1500}),
			1480,
			nil,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			krNode, err := NewKRNode(testcase.node, testcase.linkQ, true, true)
			if err != nil {
				t.Fatalf("failed to create KRNode: %v", err)
			}
			mtu, err := krNode.GetNodeMTU()
			if testcase.expectedErr != nil {
				assert.EqualError(t, err, testcase.expectedErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, testcase.expectedMTU, mtu)
			}
		})
	}
}
func Test_GetNodeSubnet(t *testing.T) {
	testcases := []struct {
		name        string
		nodeIP      net.IP
		setupMock   func(*MockLocalLinkQuerier)
		expectedNet net.IPNet
		expectedInt string
		expectedErr error
	}{
		{
			"valid node with subnet",
			net.ParseIP("10.0.0.1"),
			func(myMock *MockLocalLinkQuerier) {
				myMock.On("LinkList").Return(
					[]netlink.Link{&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}}}, nil)
				myMock.On("AddrList", mock.Anything, mock.Anything).Return(
					[]netlink.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}}}, nil)
			},
			net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
			"eth0",
			nil,
		},
		{
			"node with no matching IP",
			net.ParseIP("10.0.0.2"),
			func(myMock *MockLocalLinkQuerier) {
				myMock.On("LinkList").Return(
					[]netlink.Link{&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}}}, nil)
				myMock.On("AddrList", mock.Anything, mock.Anything).Return(
					[]netlink.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}}}, nil)
			},
			net.IPNet{},
			"",
			errors.New("failed to find interface with specified node ip"),
		},
		{
			"error getting list of links",
			net.ParseIP("10.0.0.1"),
			func(myMock *MockLocalLinkQuerier) {
				myMock.On("LinkList").Return([]netlink.Link{}, errors.New("failed to get list of links"))
			},
			net.IPNet{},
			"",
			errors.New("failed to get list of links"),
		},
		{
			"error getting addrs",
			net.ParseIP("10.0.0.1"),
			func(myMock *MockLocalLinkQuerier) {
				myMock.On("LinkList").Return(
					[]netlink.Link{&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}}}, nil)
				myMock.On("AddrList", mock.Anything, mock.Anything).Return(
					[]netlink.Addr{}, errors.New("failed to get list of addrs"))
			},
			net.IPNet{},
			"",
			errors.New("failed to get list of addrs"),
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			mockLinkQ := &MockLocalLinkQuerier{}
			testcase.setupMock(mockLinkQ)
			subnet, iface, err := GetNodeSubnet(testcase.nodeIP, mockLinkQ)
			if testcase.expectedErr != nil {
				assert.EqualError(t, err, testcase.expectedErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, testcase.expectedNet, subnet)
				assert.Equal(t, testcase.expectedInt, iface)
			}
		})
	}
}
