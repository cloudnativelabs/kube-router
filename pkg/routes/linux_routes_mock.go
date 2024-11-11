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
func (m *MockLinuxRouter) InjectRoute(subnet *net.IPNet, gw net.IP) (bool, error) {
	args := m.Called(subnet, gw)
	err := args.Error(0)
	if err != nil {
		return false, err
	}
	return true, args.Error(0)
}
