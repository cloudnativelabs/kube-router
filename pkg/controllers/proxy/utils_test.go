package proxy

import (
	"fmt"
	"net"
	"strconv"
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func getMoqNSC() *NetworkServicesController {
	lnm := NewLinuxNetworkMock()
	mockedLinuxNetworking := &LinuxNetworkingMock{
		getKubeDummyInterfaceFunc:          lnm.getKubeDummyInterface,
		ipAddrAddFunc:                      lnm.ipAddrAdd,
		ipvsAddServerFunc:                  lnm.ipvsAddServer,
		ipvsAddServiceFunc:                 lnm.ipvsAddService,
		ipvsDelServiceFunc:                 lnm.ipvsDelService,
		ipvsGetDestinationsFunc:            lnm.ipvsGetDestinations,
		ipvsGetServicesFunc:                lnm.ipvsGetServices,
		setupPolicyRoutingForDSRFunc:       lnm.setupPolicyRoutingForDSR,
		setupRoutesForExternalIPForDSRFunc: lnm.setupRoutesForExternalIPForDSR,
	}

	krNode := &utils.KRNode{
		NodeName:  "node-1",
		PrimaryIP: net.ParseIP("10.0.0.0"),
	}
	return &NetworkServicesController{
		krNode:    krNode,
		ln:        mockedLinuxNetworking,
		fwMarkMap: map[uint32]string{},
	}
}

func TestNetworkServicesController_generateUniqueFWMark(t *testing.T) {
	t.Run("ensure same service protocol and port get same FW mark", func(t *testing.T) {
		nsc := getMoqNSC()
		fwMark1, err1 := nsc.generateUniqueFWMark("10.255.0.1", "TCP", "80")
		fwMark2, err2 := nsc.generateUniqueFWMark("10.255.0.1", "TCP", "80")

		assert.NoError(t, err1, "there shouldn't have been an error calling generateUniqueFWMark the first time")
		assert.NoError(t, err2, "there shouldn't have been an error calling generateUniqueFWMark the second time")

		assert.Equal(t, fwMark1, fwMark2,
			"expected the FW marks for generateUniqueFWMark to be the same when called with the same parameters")
	})

	t.Run("ensure FW marks cannot be duplicated", func(t *testing.T) {
		nsc := getMoqNSC()
		fwMark1, err1 := nsc.generateUniqueFWMark("10.255.0.1", "TCP", "80")
		// Now we change the port number of the backing map so that when generateUniqueFWMark evaluates the same service
		// it will find that it doesn't match and give attempt to give us a new FW mark
		nsc.fwMarkMap[fwMark1] = fmt.Sprintf("%s-%s-%s", "10.255.0.1", "TCP", "81")

		fwMark2, err2 := nsc.generateUniqueFWMark("10.255.0.1", "TCP", "80")

		assert.NoError(t, err1, "there shouldn't have been an error calling generateUniqueFWMark the first time")
		assert.NoError(t, err2, "there shouldn't have been an error calling generateUniqueFWMark the second time")

		assert.NotEqual(t, fwMark1, fwMark2,
			"expected the FW marks for generateUniqueFWMark to be different when we changed the "+
				"stored service key of the fwMarkMap")
	})

	t.Run("ensure error is passed when generateUniqueFWMark is filled", func(t *testing.T) {
		nsc := getMoqNSC()
		fwMark1, err1 := nsc.generateUniqueFWMark("10.255.0.1", "TCP", "80")
		assert.NoError(t, err1, "there shouldn't have been an error calling generateUniqueFWMark the first time")
		// Artificially fill up the fwMarkMap using the same way that the function internally would increment the
		// service if it conflicted which is <ip>-<protocol>-<port>-<increment> up to maxUniqueFWMarkInc size
		for i := 1; i < 16380+1; i++ {
			_, err1 = nsc.generateUniqueFWMark("10.255.0.1", "TCP", fmt.Sprintf("80-%d", i))
			assert.NoError(t, err1, "there shouldn't have been an error calling generateUniqueFWMark the %d time", i)
		}
		// Then we need to change the original FW mark so that it doesn't just return that one as a match
		nsc.fwMarkMap[fwMark1] = fmt.Sprintf("%s-%s-%s", "10.255.0.1", "TCP", "81")

		fwMark2, err2 := nsc.generateUniqueFWMark("10.255.0.1", "TCP", "80")

		assert.EqualError(t, err2,
			fmt.Sprintf("could not obtain a unique FWMark for %s:%s:%s after %d tries", "TCP", "10.255.0.1", "80", 16380),
			"expected an error after filling up the internal fwMarkMap with possibilities")
		assert.Equal(t, uint32(0), fwMark2, "excepted FW mark to be 0 after an error")
	})
}

func TestNetworkServicesController_lookupFWMarkByService(t *testing.T) {
	t.Run("ensure existing FW mark is found in lookup", func(t *testing.T) {
		nsc := getMoqNSC()
		fwMark1, err1 := nsc.generateUniqueFWMark("10.255.0.1", "TCP", "80")
		fwMark2 := nsc.lookupFWMarkByService("10.255.0.1", "TCP", "80")

		assert.NoError(t, err1, "there shouldn't have been an error calling generateUniqueFWMark")

		assert.Equal(t, fwMark1, fwMark2,
			"given the same inputs, lookupFWMarkByService should be able to find the previously generated FW mark")
	})
	t.Run("ensure error is returned when a service doesn't exist in FW mark map", func(t *testing.T) {
		nsc := getMoqNSC()
		fwMark := nsc.lookupFWMarkByService("10.255.0.1", "TCP", "80")

		assert.Equal(t, uint32(0), fwMark, "expected FW mark to be 0 on error condition")
	})
}

func TestNetworkServicesController_lookupServiceByFWMark(t *testing.T) {
	t.Run("ensure that the found service matches the same inputs that were passed in to create the FW mark", func(t *testing.T) {
		ip := "10.255.0.1"
		protocol := "TCP"
		port := 80
		nsc := getMoqNSC()

		fwMark, err := nsc.generateUniqueFWMark(ip, protocol, strconv.Itoa(port))

		assert.NoError(t, err, "there shouldn't have been an error calling generateUniqueFWMark")

		foundIP, foundProtocol, foundPort, err1 := nsc.lookupServiceByFWMark(fwMark)

		assert.NoError(t, err1, "there shouldn't have been an error calling lookupServiceByFWMark")
		assert.Equal(t, ip, foundIP, "IP addresses should match given matching inputs")
		assert.Equal(t, protocol, foundProtocol, "protocol should match given matching inputs")
		assert.Equal(t, port, foundPort, "port should match given matching inputs")
	})

	t.Run("ensure error is returned if no service is found for FW mark", func(t *testing.T) {
		nsc := getMoqNSC()
		foundIP, foundProtocol, foundPort, err1 := nsc.lookupServiceByFWMark(uint32(1002))

		assert.Errorf(t, err1, "could not find service matching the given FW mark",
			"an error should be returned for a made-up FW mark")
		assert.Empty(t, foundIP, "IP should be empty on error")
		assert.Empty(t, foundProtocol, "protocol should be empty on error")
		assert.Zero(t, foundPort, "port should be zero on error")
	})
}

func TestNetworkServicesController_getLabelFromMap(t *testing.T) {
	labels := map[string]string{
		"service.kubernetes.io": "foo",
		"kube-router.io":        "bar",
	}
	copyLabels := func(srcLbls map[string]string) map[string]string {
		dstLbls := map[string]string{}
		for k, v := range srcLbls {
			dstLbls[k] = v
		}
		return dstLbls
	}
	t.Run("return blank when passed labels don't contain service-proxy-name label", func(t *testing.T) {
		lbl, err := getLabelFromMap(svcProxyNameLabel, labels)
		assert.Empty(t, lbl, "should return blank for a list of labels that don't contain a service-proxy-name label")
		assert.Error(t, err, "should return an error when the label doesn't exist")
	})

	t.Run("return blank when empty label map is passed", func(t *testing.T) {
		lbls := map[string]string{}
		lbl, err := getLabelFromMap(svcProxyNameLabel, lbls)
		assert.Empty(t, lbl, "should return blank for a map with no elements")
		assert.Error(t, err, "should return an error when the map doesn't contain any elements")
	})

	t.Run("return value when an labels contains service-proxy-name label", func(t *testing.T) {
		lbls := copyLabels(labels)
		lbls[svcProxyNameLabel] = "foo"
		lbl, err := getLabelFromMap(svcProxyNameLabel, lbls)
		assert.Equal(t, "foo", lbl, "should return value when service-proxy-name passed")
		assert.Nil(t, err, "error should be nil when the label exists")
	})
}

func TestIsValidKubeRouterServiceArtifact(t *testing.T) {
	// Mock data
	service1 := &serviceInfo{
		clusterIPs:      []string{"10.0.0.1"},
		externalIPs:     []string{"192.168.1.1"},
		loadBalancerIPs: []string{"172.16.0.1"},
		nodePort:        30000,
	}
	service2 := &serviceInfo{
		clusterIPs:      []string{"10.0.0.2"},
		externalIPs:     []string{"192.168.1.2"},
		loadBalancerIPs: []string{"172.16.0.2"},
		nodePort:        30001,
	}
	service3 := &serviceInfo{
		clusterIPs:      []string{"10.0.0.3"},
		externalIPs:     []string{"192.168.1.3"},
		loadBalancerIPs: []string{"172.16.0.3"},
	}

	krNode := &utils.KRNode{
		NodeName:  "node-1",
		PrimaryIP: net.ParseIP("192.168.1.10"),
	}

	nsc := &NetworkServicesController{
		krNode: krNode,
		serviceMap: map[string]*serviceInfo{
			"service1": service1,
			"service2": service2,
			"service3": service3,
		},
		nodeportBindOnAllIP: false,
	}

	tests := []struct {
		address  net.IP
		port     int
		expected bool
		err      error
	}{
		{net.ParseIP("10.0.0.1"), 0, true, nil},
		{net.ParseIP("192.168.1.1"), 0, true, nil},
		{net.ParseIP("172.16.0.1"), 0, true, nil},
		{net.ParseIP("10.0.0.2"), 0, true, nil},
		{net.ParseIP("192.168.1.2"), 0, true, nil},
		{net.ParseIP("172.16.0.2"), 0, true, nil},
		{net.ParseIP("192.168.1.10"), 30000, true, nil},
		{net.ParseIP("192.168.1.10"), 30001, true, nil},
		{net.ParseIP("192.168.1.4"), 0, false, fmt.Errorf("service not found for address 192.168.1.4")},
		{net.ParseIP("192.168.1.10"), 0, false, fmt.Errorf("service not found for address 192.168.1.10")},
	}

	for _, test := range tests {
		result, err := nsc.isValidKubeRouterServiceArtifact(test.address, test.port)
		if result != test.expected || (err != nil && err.Error() != test.err.Error()) {
			t.Errorf("lookupServiceByAddress(%v) = %v, %v; want %v, %v", test.address, result, err, test.expected, test.err)
		}
	}
}
