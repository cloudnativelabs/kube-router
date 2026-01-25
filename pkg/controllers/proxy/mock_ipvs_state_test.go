package proxy

import (
	"net"

	"github.com/moby/ipvs"
)

// mockIPVSState holds stateful IPVS data for tests that need to track services
type mockIPVSState struct {
	services []*ipvs.Service
}

func newMockIPVSState() *mockIPVSState {
	return &mockIPVSState{
		services: make([]*ipvs.Service, 0, 64),
	}
}

// addService adds an IPVS service to the mock state and returns the created service
func (m *mockIPVSState) addService(vip net.IP, protocol, port uint16) *ipvs.Service {
	svc := &ipvs.Service{
		Address:  vip,
		Protocol: protocol,
		Port:     port,
	}
	m.services = append(m.services, svc)
	return svc
}
