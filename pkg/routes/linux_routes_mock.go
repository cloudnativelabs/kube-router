package routes

import (
	"net"

	"github.com/stretchr/testify/mock"
)

// Define the mock struct
type MockLinuxRouter struct {
	mock.Mock
}

// Implement the InjectRoute method
func (m *MockLinuxRouter) InjectRoute(subnet *net.IPNet, gw net.IP) error {
	args := m.Called(subnet, gw)
	return args.Error(0)
}
