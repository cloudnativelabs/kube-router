package proxy

import (
	"fmt"
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func getMoqNSC() *NetworkServicesController {
	lnm := NewLinuxNetworkMock()
	mockedLinuxNetworking := &LinuxNetworkingMock{
		cleanupMangleTableRuleFunc:         lnm.cleanupMangleTableRule,
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
	return &NetworkServicesController{
		nodeIP:       net.ParseIP("10.0.0.0"),
		nodeHostName: "node-1",
		ln:           mockedLinuxNetworking,
		fwMarkMap:    map[uint32]string{},
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
