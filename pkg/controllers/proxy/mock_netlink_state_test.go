package proxy

import (
	"fmt"
	"net"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	v1core "k8s.io/api/core/v1"
)

// mockNetlinkState holds stateful netlink data for tests - simulates network interfaces,
// addresses, routes, and policy routing rules without making real system calls.
//
// This allows tests to run without privileges and prevents accidental modifications
// to the host network configuration.
//
// Usage:
//
//	Tests that use setupTestController() or setupTestControllerWithEndpoints() automatically
//	get a fully configured mockNetlinkState. Tests can:
//	- Query mock state to verify netlink operations occurred correctly
//	- Enable error simulation by modifying the errorMode field
//	- Override specific mock functions if needed for custom behavior
//
// Example:
//
//	netlinkState := newMockNetlinkState()
//	netlinkState.errorMode.permissionDenied = true // Simulate permission errors
//	mock := &LinuxNetworkingMock{
//	    getKubeDummyInterfaceFunc: createMockGetKubeDummyInterface(netlinkState),
//	    // ... other mock functions
//	}
//
// The mock is designed to be extensible - it can be moved to internal/testutils/netlinkmock
// if other packages need to use it in the future.
type mockNetlinkState struct {
	// interfaces maps interface name to mock netlink.Link
	interfaces map[string]netlink.Link
	// interfaceIndex tracks the next available interface index
	interfaceIndex int
	// addresses maps interface name to list of addresses on that interface
	addresses map[string][]*mockAddress
	// routes maps routing table ID to list of routes in that table
	routes map[int][]*mockRoute
	// rules contains policy routing rules
	rules []*mockRule
	// errorMode controls error simulation for testing error handling
	errorMode mockNetlinkErrorMode
}

// mockAddress represents an IP address assigned to an interface
type mockAddress struct {
	ip     net.IP
	ipNet  *net.IPNet
	family int // netlink.FAMILY_V4 or netlink.FAMILY_V6
	scope  int // syscall.RT_SCOPE_*
}

// mockRoute represents a routing table entry
type mockRoute struct {
	dst       *net.IPNet
	src       net.IP
	linkIndex int
	table     int
	routeType int // unix.RTN_*
	protocol  int
	scope     int
	family    int
}

// mockRule represents a policy routing rule
type mockRule struct {
	family   int
	priority int
	src      *net.IPNet
	table    int
}

// mockNetlinkErrorMode controls what errors the mock netlink should simulate
type mockNetlinkErrorMode struct {
	permissionDenied  bool
	interfaceNotFound bool
	addressExists     bool
}

func newMockNetlinkState() *mockNetlinkState {
	state := &mockNetlinkState{
		interfaces:     make(map[string]netlink.Link),
		interfaceIndex: 1,
		addresses:      make(map[string][]*mockAddress),
		routes:         make(map[int][]*mockRoute),
		rules:          make([]*mockRule, 0),
		errorMode:      mockNetlinkErrorMode{},
	}

	// Pre-create standard interfaces that tests expect
	state.addInterface("lo", netlink.LinkAttrs{
		Name:  "lo",
		Flags: net.FlagUp | net.FlagLoopback,
		MTU:   65536,
	})

	state.addInterface(KubeDummyIf, netlink.LinkAttrs{
		Name:  KubeDummyIf,
		Flags: net.FlagUp,
		MTU:   1500,
	})

	return state
}

// addInterface adds a mock interface to the state
func (m *mockNetlinkState) addInterface(name string, attrs netlink.LinkAttrs) {
	attrs.Index = m.interfaceIndex
	m.interfaceIndex++

	// Create a Dummy link with the specified attributes
	link := &netlink.Dummy{LinkAttrs: attrs}
	m.interfaces[name] = link
	m.addresses[name] = make([]*mockAddress, 0)
}

// getInterface retrieves a mock interface by name
func (m *mockNetlinkState) getInterface(name string) (netlink.Link, error) {
	if m.errorMode.interfaceNotFound {
		return nil, fmt.Errorf("Link not found")
	}

	link, exists := m.interfaces[name]
	if !exists {
		return nil, fmt.Errorf("Link not found")
	}
	return link, nil
}

// addAddress adds an IP address to a mock interface
func (m *mockNetlinkState) addAddress(ifaceName string, ip net.IP, ipNet *net.IPNet, family, scope int) error {
	if m.errorMode.permissionDenied {
		return fmt.Errorf("operation not permitted")
	}

	if _, exists := m.interfaces[ifaceName]; !exists {
		return fmt.Errorf("interface %s not found", ifaceName)
	}

	// Check if address already exists
	for _, addr := range m.addresses[ifaceName] {
		if addr.ip.Equal(ip) {
			if m.errorMode.addressExists {
				return fmt.Errorf("file exists")
			}
			// Address already exists, this is idempotent
			return nil
		}
	}

	m.addresses[ifaceName] = append(m.addresses[ifaceName], &mockAddress{
		ip:     ip,
		ipNet:  ipNet,
		family: family,
		scope:  scope,
	})
	return nil
}

// deleteAddress removes an IP address from a mock interface
func (m *mockNetlinkState) deleteAddress(ifaceName string, ip net.IP) error {
	if m.errorMode.permissionDenied {
		return fmt.Errorf("operation not permitted")
	}

	if _, exists := m.interfaces[ifaceName]; !exists {
		return fmt.Errorf("interface %s not found", ifaceName)
	}

	addrs := m.addresses[ifaceName]
	for i, addr := range addrs {
		if addr.ip.Equal(ip) {
			m.addresses[ifaceName] = append(addrs[:i], addrs[i+1:]...)
			return nil
		}
	}

	// Address not found - return "cannot assign requested address"
	return fmt.Errorf("cannot assign requested address")
}

// listAddresses returns all addresses for an interface with the specified family
// This method is part of the comprehensive mock API for future extensibility
//
//nolint:unused // Reserved for future test extensions and external package usage
func (m *mockNetlinkState) listAddresses(ifaceName string, family int) ([]*mockAddress, error) {
	if m.errorMode.permissionDenied {
		return nil, fmt.Errorf("operation not permitted")
	}

	if _, exists := m.interfaces[ifaceName]; !exists {
		return nil, fmt.Errorf("interface %s not found", ifaceName)
	}

	var result []*mockAddress
	for _, addr := range m.addresses[ifaceName] {
		if family == 0 || addr.family == family {
			result = append(result, addr)
		}
	}
	return result, nil
}

// addRoute adds a route to the specified routing table
func (m *mockNetlinkState) addRoute(route *mockRoute) error {
	if m.errorMode.permissionDenied {
		return fmt.Errorf("operation not permitted")
	}

	if m.routes[route.table] == nil {
		m.routes[route.table] = make([]*mockRoute, 0)
	}

	m.routes[route.table] = append(m.routes[route.table], route)
	return nil
}

// deleteRoute removes a route from the routing table
func (m *mockNetlinkState) deleteRoute(route *mockRoute) error {
	if m.errorMode.permissionDenied {
		return fmt.Errorf("operation not permitted")
	}

	routes, exists := m.routes[route.table]
	if !exists {
		return fmt.Errorf("no such process")
	}

	for i, r := range routes {
		if routesMatch(r, route) {
			m.routes[route.table] = append(routes[:i], routes[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("no such process")
}

// listRoutes returns routes matching the filter
// This method is part of the comprehensive mock API for future extensibility
//
//nolint:unused // Reserved for future test extensions and external package usage
func (m *mockNetlinkState) listRoutes(family, table int, dst *net.IPNet) ([]*mockRoute, error) {
	if m.errorMode.permissionDenied {
		return nil, fmt.Errorf("operation not permitted")
	}

	var result []*mockRoute

	// If table is specified, only search that table
	tablesToSearch := []int{}
	if table > 0 {
		tablesToSearch = append(tablesToSearch, table)
	} else {
		// Search all tables
		for t := range m.routes {
			tablesToSearch = append(tablesToSearch, t)
		}
	}

	for _, t := range tablesToSearch {
		for _, route := range m.routes[t] {
			// Filter by family
			if family != 0 && route.family != family {
				continue
			}
			// Filter by destination
			if dst != nil && (route.dst == nil || !route.dst.IP.Equal(dst.IP)) {
				continue
			}
			result = append(result, route)
		}
	}

	return result, nil
}

// addRule adds a policy routing rule
func (m *mockNetlinkState) addRule(rule *mockRule) error {
	if m.errorMode.permissionDenied {
		return fmt.Errorf("operation not permitted")
	}

	m.rules = append(m.rules, rule)
	return nil
}

// listRules returns policy routing rules matching the filter
func (m *mockNetlinkState) listRules(family, table, priority int) ([]*mockRule, error) {
	if m.errorMode.permissionDenied {
		return nil, fmt.Errorf("operation not permitted")
	}

	var result []*mockRule
	for _, rule := range m.rules {
		// Filter by family
		if family != 0 && rule.family != family {
			continue
		}
		// Filter by table
		if table > 0 && rule.table != table {
			continue
		}
		// Filter by priority
		if priority > 0 && rule.priority != priority {
			continue
		}
		result = append(result, rule)
	}
	return result, nil
}

// routesMatch checks if two routes are equivalent for comparison
func routesMatch(r1, r2 *mockRoute) bool {
	if r1.table != r2.table {
		return false
	}
	if r1.routeType != r2.routeType {
		return false
	}
	if r1.dst != nil && r2.dst != nil {
		if !r1.dst.IP.Equal(r2.dst.IP) {
			return false
		}
	} else if r1.dst != r2.dst {
		return false
	}
	if r1.linkIndex != r2.linkIndex {
		return false
	}
	return true
}

// Mock implementation functions for netlinkCalls interface
// These functions use mockNetlinkState to simulate netlink operations without making real system calls

// createMockGetKubeDummyInterface creates a mock implementation of getKubeDummyInterface
func createMockGetKubeDummyInterface(state *mockNetlinkState) func() (netlink.Link, error) {
	return func() (netlink.Link, error) {
		return state.getInterface(KubeDummyIf)
	}
}

// createMockIPAddrAdd creates a mock implementation of ipAddrAdd
func createMockIPAddrAdd(state *mockNetlinkState) func(netlink.Link, string, string, bool) error {
	return func(iface netlink.Link, ip string, nodeIP string, addRoute bool) error {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return fmt.Errorf("invalid IP address: %s", ip)
		}

		var family int
		if parsedIP.To4() != nil {
			family = netlink.FAMILY_V4
		} else {
			family = netlink.FAMILY_V6
		}

		ipNet := utils.GetSingleIPNet(parsedIP)
		ifaceName := iface.Attrs().Name

		// Add address to the interface
		err := state.addAddress(ifaceName, parsedIP, ipNet, family, 0)
		if err != nil && err.Error() != "file exists" {
			return err
		}

		// If addRoute is requested, add route to local routing table
		if addRoute {
			parsedNodeIP := net.ParseIP(nodeIP)
			if parsedNodeIP == nil {
				return fmt.Errorf("invalid node IP address: %s", nodeIP)
			}

			route := &mockRoute{
				dst:       ipNet,
				src:       parsedNodeIP,
				linkIndex: iface.Attrs().Index,
				table:     255, // RT_TABLE_LOCAL
				routeType: 2,   // RTN_LOCAL
				protocol:  2,   // RTPROT_KERNEL
				scope:     254, // RT_SCOPE_HOST
				family:    family,
			}
			return state.addRoute(route)
		}

		return nil
	}
}

// createMockIPAddrDel creates a mock implementation of ipAddrDel
func createMockIPAddrDel(state *mockNetlinkState) func(netlink.Link, string, string) error {
	return func(iface netlink.Link, ip string, nodeIP string) error {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return fmt.Errorf("invalid IP address: %s", ip)
		}

		ifaceName := iface.Attrs().Name

		// Delete address from the interface
		err := state.deleteAddress(ifaceName, parsedIP)
		if err != nil && err.Error() != "cannot assign requested address" {
			return err
		}

		// Also delete route from local routing table if it exists
		var family int
		if parsedIP.To4() != nil {
			family = netlink.FAMILY_V4
		} else {
			family = netlink.FAMILY_V6
		}

		ipNet := utils.GetSingleIPNet(parsedIP)
		route := &mockRoute{
			dst:       ipNet,
			linkIndex: iface.Attrs().Index,
			table:     255, // RT_TABLE_LOCAL
			routeType: 2,   // RTN_LOCAL
			family:    family,
		}
		// Ignore error on route deletion - it may not exist
		_ = state.deleteRoute(route)

		return nil
	}
}

// createMockSetupPolicyRoutingForDSR creates a mock implementation of setupPolicyRoutingForDSR
func createMockSetupPolicyRoutingForDSR(state *mockNetlinkState) func(bool, bool) error {
	return func(setupIPv4 bool, setupIPv6 bool) error {
		// Get loopback interface
		loIface, err := state.getInterface("lo")
		if err != nil {
			return fmt.Errorf("failed to get loopback interface: %v", err)
		}

		if setupIPv4 {
			// Add IPv4 default route to custom DSR table
			defaultRouteCIDR := utils.GetDefaultIPv4Route()
			route := &mockRoute{
				dst:       defaultRouteCIDR,
				linkIndex: loIface.Attrs().Index,
				table:     78, // customDSRRouteTableID
				routeType: 2,  // RTN_LOCAL
				family:    netlink.FAMILY_V4,
				scope:     254, // RT_SCOPE_HOST
			}
			if err := state.addRoute(route); err != nil {
				return err
			}
		}

		if setupIPv6 {
			// Add IPv6 default route to custom DSR table
			defaultRouteCIDR := utils.GetDefaultIPv6Route()
			route := &mockRoute{
				dst:       defaultRouteCIDR,
				linkIndex: loIface.Attrs().Index,
				table:     78, // customDSRRouteTableID
				routeType: 2,  // RTN_LOCAL
				family:    netlink.FAMILY_V6,
				scope:     254, // RT_SCOPE_HOST
			}
			if err := state.addRoute(route); err != nil {
				return err
			}
		}

		return nil
	}
}

// createMockSetupRoutesForExternalIPForDSR creates a mock implementation of setupRoutesForExternalIPForDSR
func createMockSetupRoutesForExternalIPForDSR(state *mockNetlinkState) func(serviceInfoMap, bool, bool) error {
	return func(serviceInfo serviceInfoMap, setupIPv4 bool, setupIPv6 bool) error {
		setupRulesForFamily := func(isIPv6 bool) error {
			var family int
			var defaultPrefixCIDR *net.IPNet

			if isIPv6 {
				family = netlink.FAMILY_V6
				defaultPrefixCIDR = utils.GetDefaultIPv6Route()
			} else {
				family = netlink.FAMILY_V4
				defaultPrefixCIDR = utils.GetDefaultIPv4Route()
			}

			// Check if default rule already exists
			rules, err := state.listRules(family, 79 /* externalIPRouteTableID */, 32765 /* defaultDSRPolicyRulePriority */)
			if err != nil {
				return err
			}

			defaultRuleFound := false
			for _, rule := range rules {
				// A rule with nil src represents the default route rule (0.0.0.0/0 or ::/0)
				if rule.src == nil {
					defaultRuleFound = true
					break
				}
			}

			if !defaultRuleFound {
				// Add default rule
				rule := &mockRule{
					family:   family,
					priority: 32765, // defaultDSRPolicyRulePriority
					src:      defaultPrefixCIDR,
					table:    79, // externalIPRouteTableID
				}
				if err := state.addRule(rule); err != nil {
					return err
				}
			}

			return nil
		}

		if setupIPv4 {
			if err := setupRulesForFamily(false); err != nil {
				return err
			}
		}

		if setupIPv6 {
			if err := setupRulesForFamily(true); err != nil {
				return err
			}
		}

		return nil
	}
}

// createMockConfigureContainerForDSR creates a mock implementation of configureContainerForDSR
func createMockConfigureContainerForDSR(state *mockNetlinkState) func(string, string, string, int, netns.NsHandle) error {
	return func(vip, endpointIP, containerID string, pid int, hostNetworkNamespaceHandle netns.NsHandle) error {
		// In tests, we just simulate successful configuration
		// The actual namespace switching and interface creation would happen here in real code
		return nil
	}
}

// createMockGetContainerPidWithDocker creates a mock implementation of getContainerPidWithDocker
func createMockGetContainerPidWithDocker(state *mockNetlinkState) func(string) (int, error) {
	return func(containerID string) (int, error) {
		// Return a mock PID for testing
		return 12345, nil
	}
}

// createMockGetContainerPidWithCRI creates a mock implementation of getContainerPidWithCRI
func createMockGetContainerPidWithCRI(state *mockNetlinkState) func(string, string) (int, error) {
	return func(runtimeEndpoint string, containerID string) (int, error) {
		// Return a mock PID for testing
		return 12345, nil
	}
}

// createMockFindIfaceLinkForPid creates a mock implementation of findIfaceLinkForPid
func createMockFindIfaceLinkForPid(state *mockNetlinkState) func(int) (int, error) {
	return func(pid int) (int, error) {
		// Return a mock interface link number for testing
		return 10, nil
	}
}

// createMockRouteVIPTrafficToDirector creates a mock implementation of routeVIPTrafficToDirector
func createMockRouteVIPTrafficToDirector(state *mockNetlinkState) func(uint32, v1core.IPFamily) error {
	return func(fwmark uint32, family v1core.IPFamily) error {
		// Mock implementation: add a rule for the fwmark
		var nFamily int
		if family == v1core.IPv6Protocol {
			nFamily = netlink.FAMILY_V6
		} else {
			nFamily = netlink.FAMILY_V4
		}

		// Check if rule already exists
		rules, err := state.listRules(nFamily, 78 /* customDSRRouteTableID */, 30000 /* defaultTrafficDirectorRulePriority */)
		if err != nil {
			return err
		}

		// Check if a rule for this fwmark already exists
		for _, rule := range rules {
			// For simplicity, we just check if any rule exists - in real implementation
			// we'd check the mark, but mockRule doesn't have a mark field yet
			if rule.table == 78 && rule.priority == 30000 {
				// Rule already exists
				return nil
			}
		}

		// Add the rule
		rule := &mockRule{
			family:   nFamily,
			priority: 30000, // defaultTrafficDirectorRulePriority
			src:      nil,
			table:    78, // customDSRRouteTableID
		}
		return state.addRule(rule)
	}
}
