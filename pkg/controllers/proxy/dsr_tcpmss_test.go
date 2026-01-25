package proxy

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
	v1core "k8s.io/api/core/v1"
)

const (
	testMTU = 1500
	// Expected MSS values based on address family:
	// IPv4: MTU - 2*20 (IP headers) - 20 (TCP header) = MTU - 60
	// IPv6: MTU - 2*40 (IP headers) - 20 (TCP header) = MTU - 100
	expectedIPv4MSS = "1440" // 1500 - 60
	expectedIPv6MSS = "1400" // 1500 - 100
	// Old incorrect IPv6 MSS (used MTU - 60 like IPv4)
	oldIncorrectIPv6MSS = "1440" // 1500 - 60 (bug)
)

// Helper function to find all MSS values in iptables calls
func findMSSInCalls(calls []struct {
	Table    string
	Chain    string
	Rulespec []string
}) []string {
	var mssValues []string
	for _, call := range calls {
		for i, arg := range call.Rulespec {
			if arg == "--set-mss" && i+1 < len(call.Rulespec) {
				mssValues = append(mssValues, call.Rulespec[i+1])
			}
		}
	}
	return mssValues
}

// Helper function to find all chains in calls
func findChainsInCalls(calls []struct {
	Table    string
	Chain    string
	Rulespec []string
}, table string) []string {
	var chains []string
	for _, call := range calls {
		if call.Table == table {
			chains = append(chains, call.Chain)
		}
	}
	return chains
}

// createTestNSC creates a NetworkServicesController with mock iptables handlers for testing
func createTestNSC(existsRules map[string]bool) (*NetworkServicesController, *utils.IPTablesHandlerMock, *utils.IPTablesHandlerMock) {
	ipv4Mock := &utils.IPTablesHandlerMock{
		AppendUniqueFunc: func(table string, chain string, rulespec ...string) error {
			return nil
		},
		ExistsFunc: func(table string, chain string, rulespec ...string) (bool, error) {
			key := fmt.Sprintf("%s:%s:%v", table, chain, rulespec)
			return existsRules[key], nil
		},
		DeleteFunc: func(table string, chain string, rulespec ...string) error {
			return nil
		},
	}

	ipv6Mock := &utils.IPTablesHandlerMock{
		AppendUniqueFunc: func(table string, chain string, rulespec ...string) error {
			return nil
		},
		ExistsFunc: func(table string, chain string, rulespec ...string) (bool, error) {
			key := fmt.Sprintf("%s:%s:%v", table, chain, rulespec)
			return existsRules[key], nil
		},
		DeleteFunc: func(table string, chain string, rulespec ...string) error {
			return nil
		},
	}

	nsc := &NetworkServicesController{
		mtu: testMTU,
		iptablesCmdHandlers: map[v1core.IPFamily]utils.IPTablesHandler{
			v1core.IPv4Protocol: ipv4Mock,
			v1core.IPv6Protocol: ipv6Mock,
		},
	}

	return nsc, ipv4Mock, ipv6Mock
}

// errorInjectionConfig configures which iptables operation should fail and when.
// A value of 0 means never fail, a positive value means fail on that call number.
type errorInjectionConfig struct {
	appendUniqueFailOnCall int
	existsFailOnCall       int
	deleteFailOnCall       int
	existsRules            map[string]bool
}

// createTestNSCWithErrorInjection creates a NetworkServicesController with configurable
// error injection for testing error handling paths.
func createTestNSCWithErrorInjection(config errorInjectionConfig) *NetworkServicesController {
	var mu sync.Mutex
	callCount := struct {
		appendUnique int
		exists       int
		delete       int
	}{}

	mock := &utils.IPTablesHandlerMock{
		AppendUniqueFunc: func(table string, chain string, rulespec ...string) error {
			mu.Lock()
			callCount.appendUnique++
			currentCall := callCount.appendUnique
			mu.Unlock()
			if config.appendUniqueFailOnCall > 0 && currentCall == config.appendUniqueFailOnCall {
				return errors.New("mock iptables AppendUnique error")
			}
			return nil
		},
		ExistsFunc: func(table string, chain string, rulespec ...string) (bool, error) {
			mu.Lock()
			callCount.exists++
			currentCall := callCount.exists
			mu.Unlock()
			if config.existsFailOnCall > 0 && currentCall == config.existsFailOnCall {
				return false, errors.New("mock iptables Exists error")
			}
			if config.existsRules != nil {
				key := fmt.Sprintf("%s:%s:%v", table, chain, rulespec)
				return config.existsRules[key], nil
			}
			return false, nil
		},
		DeleteFunc: func(table string, chain string, rulespec ...string) error {
			mu.Lock()
			callCount.delete++
			currentCall := callCount.delete
			mu.Unlock()
			if config.deleteFailOnCall > 0 && currentCall == config.deleteFailOnCall {
				return errors.New("mock iptables Delete error")
			}
			return nil
		},
	}

	nsc := &NetworkServicesController{
		mtu: testMTU,
		iptablesCmdHandlers: map[v1core.IPFamily]utils.IPTablesHandler{
			v1core.IPv4Protocol: mock,
			v1core.IPv6Protocol: mock,
		},
	}

	return nsc
}

// =============================================================================
// setupMangleTableRule Error Handling Tests
// =============================================================================

func TestSetupMangleTableRule_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func() errorInjectionConfig
		expectedErr string
	}{
		{
			name: "FWMARK PREROUTING fails",
			setupConfig: func() errorInjectionConfig {
				return errorInjectionConfig{
					appendUniqueFailOnCall: 1, // Fail on first AppendUnique call (FWMARK PREROUTING)
				}
			},
			expectedErr: "failed to run iptables command to set up FWMARK",
		},
		{
			name: "FWMARK OUTPUT fails",
			setupConfig: func() errorInjectionConfig {
				return errorInjectionConfig{
					appendUniqueFailOnCall: 2, // Fail on second AppendUnique call (FWMARK OUTPUT)
				}
			},
			expectedErr: "failed to run iptables command to set up FWMARK",
		},
		{
			name: "TCPMSS fails",
			setupConfig: func() errorInjectionConfig {
				return errorInjectionConfig{
					appendUniqueFailOnCall: 3, // Fail on third AppendUnique call (TCPMSS)
				}
			},
			expectedErr: "failed to run iptables command to set up TCPMSS",
		},
		{
			name: "Legacy cleanup Exists fails",
			setupConfig: func() errorInjectionConfig {
				return errorInjectionConfig{
					existsFailOnCall: 1, // Fail on first Exists call (legacy cleanup check)
				}
			},
			expectedErr: "failed to cleanup iptables command to set up TCPMSS",
		},
		{
			name: "Legacy cleanup Delete fails",
			setupConfig: func() errorInjectionConfig {
				// Configure mock to report that legacy POSTROUTING rule exists
				existsRules := make(map[string]bool)
				oldRuleKey := fmt.Sprintf("mangle:POSTROUTING:%v", []string{
					"-s", "10.0.0.1", "-m", "tcp", "-p", "tcp",
					"--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", expectedIPv4MSS,
				})
				existsRules[oldRuleKey] = true

				return errorInjectionConfig{
					existsRules:      existsRules,
					deleteFailOnCall: 1, // Fail on first Delete call (legacy cleanup)
				}
			},
			expectedErr: "failed to cleanup iptables command to set up TCPMSS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			config := tt.setupConfig()
			nsc := createTestNSCWithErrorInjection(config)

			err := nsc.setupMangleTableRule("10.0.0.1", "tcp", "8080", "1234")

			assert.ErrorContains(t, err, tt.expectedErr)
		})
	}
}

// =============================================================================
// cleanupMangleTableRule Error Handling Tests
// =============================================================================

func TestCleanupMangleTableRule_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func() errorInjectionConfig
		expectedErr string
	}{
		{
			name: "FWMARK PREROUTING Exists fails",
			setupConfig: func() errorInjectionConfig {
				return errorInjectionConfig{
					existsFailOnCall: 1, // Fail on first Exists call (FWMARK PREROUTING)
				}
			},
			expectedErr: "failed to cleanup iptables command to set up FWMARK",
		},
		{
			name: "FWMARK PREROUTING Delete fails",
			setupConfig: func() errorInjectionConfig {
				// Configure mock to report that FWMARK PREROUTING rule exists
				existsRules := make(map[string]bool)
				markRuleKey := fmt.Sprintf("mangle:PREROUTING:%v", []string{
					"-d", "10.0.0.1", "-m", "tcp", "-p", "tcp", "--dport", "8080",
					"-j", "MARK", "--set-mark", "1234",
				})
				existsRules[markRuleKey] = true

				return errorInjectionConfig{
					existsRules:      existsRules,
					deleteFailOnCall: 1, // Fail on first Delete call
				}
			},
			expectedErr: "failed to cleanup iptables command to set up FWMARK",
		},
		{
			name: "TCPMSS Exists fails",
			setupConfig: func() errorInjectionConfig {
				return errorInjectionConfig{
					existsFailOnCall: 3, // Fail on third Exists call (TCPMSS check, after FWMARK PREROUTING and OUTPUT)
				}
			},
			expectedErr: "failed to cleanup iptables command to set up TCPMSS",
		},
		{
			name: "TCPMSS Delete fails",
			setupConfig: func() errorInjectionConfig {
				// Configure mock to report that TCPMSS rule exists
				existsRules := make(map[string]bool)
				mssRuleKey := fmt.Sprintf("mangle:PREROUTING:%v", []string{
					"-s", "10.0.0.1", "-m", "tcp", "-p", "tcp", "--sport", "8080",
					"-i", "kube-bridge", "--tcp-flags", "SYN,RST", "SYN",
					"-j", "TCPMSS", "--set-mss", expectedIPv4MSS,
				})
				existsRules[mssRuleKey] = true

				return errorInjectionConfig{
					existsRules:      existsRules,
					deleteFailOnCall: 1, // Fail on first Delete call (TCPMSS)
				}
			},
			expectedErr: "failed to cleanup iptables command to set up TCPMSS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			config := tt.setupConfig()
			nsc := createTestNSCWithErrorInjection(config)

			err := nsc.cleanupMangleTableRule("10.0.0.1", "tcp", "8080", "1234")

			assert.ErrorContains(t, err, tt.expectedErr)
		})
	}
}

// =============================================================================
// Original Tests (unchanged)
// =============================================================================

func TestSetupMangleTableRule_IPv4_MSS(t *testing.T) {
	t.Parallel()
	existsRules := make(map[string]bool)
	nsc, ipv4Mock, _ := createTestNSC(existsRules)

	err := nsc.setupMangleTableRule("10.0.0.1", "tcp", "8080", "1234")
	assert.NoError(t, err)

	// Verify TCPMSS rule was created with correct MSS for IPv4 (MTU - 60)
	calls := ipv4Mock.AppendUniqueCalls()
	mssValues := findMSSInCalls(calls)
	assert.Contains(t, mssValues, expectedIPv4MSS,
		"Expected IPv4 TCPMSS rule with MSS %s, got %v", expectedIPv4MSS, mssValues)
}

func TestSetupMangleTableRule_IPv4_Chains(t *testing.T) {
	t.Parallel()
	existsRules := make(map[string]bool)
	nsc, ipv4Mock, _ := createTestNSC(existsRules)

	err := nsc.setupMangleTableRule("10.0.0.1", "tcp", "8080", "1234")
	assert.NoError(t, err)

	// Verify FWMARK rules were created in PREROUTING and OUTPUT chains
	calls := ipv4Mock.AppendUniqueCalls()
	chains := findChainsInCalls(calls, "mangle")
	assert.Contains(t, chains, "PREROUTING", "Expected PREROUTING chain to be used")
	assert.Contains(t, chains, "OUTPUT", "Expected OUTPUT chain to be used")
}

func TestSetupMangleTableRule_IPv6_MSS(t *testing.T) {
	t.Parallel()
	existsRules := make(map[string]bool)
	nsc, _, ipv6Mock := createTestNSC(existsRules)

	err := nsc.setupMangleTableRule("2001:db8::1", "tcp", "8080", "1234")
	assert.NoError(t, err)

	// Verify TCPMSS rule was created with correct MSS for IPv6 (MTU - 100)
	calls := ipv6Mock.AppendUniqueCalls()
	mssValues := findMSSInCalls(calls)
	assert.Contains(t, mssValues, expectedIPv6MSS,
		"Expected IPv6 TCPMSS rule with MSS %s, got %v", expectedIPv6MSS, mssValues)
}

func TestSetupMangleTableRule_IPv6_UsesCorrectHandler(t *testing.T) {
	t.Parallel()
	existsRules := make(map[string]bool)
	nsc, ipv4Mock, ipv6Mock := createTestNSC(existsRules)

	err := nsc.setupMangleTableRule("fd00::1", "tcp", "8080", "1234")
	assert.NoError(t, err)

	// IPv6 mock should have been called
	assert.NotEmpty(t, ipv6Mock.AppendUniqueCalls(), "Expected IPv6 handler to be called")
	// IPv4 mock should NOT have been called
	assert.Empty(t, ipv4Mock.AppendUniqueCalls(), "Expected IPv4 handler NOT to be called for IPv6 address")
}

func TestSetupMangleTableRule_UDP_NoTCPMSS(t *testing.T) {
	t.Parallel()
	existsRules := make(map[string]bool)
	nsc, ipv4Mock, _ := createTestNSC(existsRules)

	err := nsc.setupMangleTableRule("10.0.0.1", "udp", "8080", "1234")
	assert.NoError(t, err)

	// Check that no TCPMSS rule was created (TCPMSS is TCP-only)
	calls := ipv4Mock.AppendUniqueCalls()
	mssValues := findMSSInCalls(calls)
	assert.Empty(t, mssValues, "Expected no TCPMSS rule for UDP, got MSS values %v", mssValues)
}

func TestSetupMangleTableRule_LegacyCleanup_POSTROUTING(t *testing.T) {
	t.Parallel()
	existsRules := make(map[string]bool)

	// Configure mock to report that old-style POSTROUTING rule exists
	oldRuleKey := fmt.Sprintf("mangle:POSTROUTING:%v", []string{
		"-s", "10.0.0.1", "-m", "tcp", "-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", expectedIPv4MSS,
	})
	existsRules[oldRuleKey] = true

	nsc, ipv4Mock, _ := createTestNSC(existsRules)

	err := nsc.setupMangleTableRule("10.0.0.1", "tcp", "8080", "1234")
	assert.NoError(t, err)

	// Verify Delete was called for the old-style rule
	deleteCalls := ipv4Mock.DeleteCalls()
	deletedChains := findChainsInCalls(deleteCalls, "mangle")
	assert.Contains(t, deletedChains, "POSTROUTING",
		"Expected old POSTROUTING rule to be deleted")
}

func TestSetupMangleTableRule_LegacyCleanup_PREROUTING(t *testing.T) {
	t.Parallel()
	existsRules := make(map[string]bool)

	// Configure mock to report that old-style PREROUTING rule with -d exists
	oldRuleKey := fmt.Sprintf("mangle:PREROUTING:%v", []string{
		"-d", "10.0.0.1", "-m", "tcp", "-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", expectedIPv4MSS,
	})
	existsRules[oldRuleKey] = true

	nsc, ipv4Mock, _ := createTestNSC(existsRules)

	err := nsc.setupMangleTableRule("10.0.0.1", "tcp", "8080", "1234")
	assert.NoError(t, err)

	// Verify Exists was called to check for old-style PREROUTING rule
	existsCalls := ipv4Mock.ExistsCalls()
	checkedChains := findChainsInCalls(existsCalls, "mangle")
	assert.Contains(t, checkedChains, "PREROUTING",
		"Expected old PREROUTING rule to be checked for cleanup")
}

// TestSetupMangleTableRule_UpgradeCleanup_IncorrectIPv6MSS tests that when upgrading
// from a version that had the bug (using MTU-60 for IPv6 instead of MTU-100),
// the old incorrect rules are cleaned up.
//
// EXPECTED TO FAIL: The current implementation does not clean up old IPv6 rules
// that were created with the incorrect MSS value.
func TestSetupMangleTableRule_UpgradeCleanup_IncorrectIPv6MSS(t *testing.T) {
	t.Parallel()
	existsRules := make(map[string]bool)

	// Configure mock to report that old incorrect IPv6 rule exists
	// The old buggy code used MTU-60 for IPv6 (same as IPv4)
	oldIncorrectRuleKey := fmt.Sprintf("mangle:PREROUTING:%v", []string{
		"-s", "2001:db8::1", "-m", "tcp", "-p", "tcp", "--sport", "8080",
		"-i", "kube-bridge", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--set-mss", oldIncorrectIPv6MSS,
	})
	existsRules[oldIncorrectRuleKey] = true

	nsc, _, ipv6Mock := createTestNSC(existsRules)

	err := nsc.setupMangleTableRule("2001:db8::1", "tcp", "8080", "1234")
	assert.NoError(t, err)

	// Verify that the old incorrect rule was deleted
	deleteCalls := ipv6Mock.DeleteCalls()
	var deletedMSSValues []string
	for _, call := range deleteCalls {
		for i, arg := range call.Rulespec {
			if arg == "--set-mss" && i+1 < len(call.Rulespec) {
				deletedMSSValues = append(deletedMSSValues, call.Rulespec[i+1])
			}
		}
	}
	assert.Contains(t, deletedMSSValues, oldIncorrectIPv6MSS,
		"Expected old incorrect IPv6 TCPMSS rule with MSS %s to be deleted, "+
			"but deleted MSS values were: %v. "+
			"This test is expected to fail until the cleanup gap is fixed.",
		oldIncorrectIPv6MSS, deletedMSSValues)
}

func TestCleanupMangleTableRule_IPv4_CorrectMSS(t *testing.T) {
	t.Parallel()
	existsRules := make(map[string]bool)

	// Configure mock to report that rules exist
	markRuleKey := fmt.Sprintf("mangle:PREROUTING:%v", []string{
		"-d", "10.0.0.1", "-m", "tcp", "-p", "tcp", "--dport", "8080",
		"-j", "MARK", "--set-mark", "1234",
	})
	existsRules[markRuleKey] = true

	mssRuleKey := fmt.Sprintf("mangle:PREROUTING:%v", []string{
		"-s", "10.0.0.1", "-m", "tcp", "-p", "tcp", "--sport", "8080",
		"-i", "kube-bridge", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--set-mss", expectedIPv4MSS,
	})
	existsRules[mssRuleKey] = true

	nsc, ipv4Mock, _ := createTestNSC(existsRules)

	err := nsc.cleanupMangleTableRule("10.0.0.1", "tcp", "8080", "1234")
	assert.NoError(t, err)

	// Verify Exists was called with correct MSS value for IPv4
	existsCalls := ipv4Mock.ExistsCalls()
	checkedMSSValues := findMSSInCalls(existsCalls)
	assert.Contains(t, checkedMSSValues, expectedIPv4MSS,
		"Expected cleanup to check for IPv4 TCPMSS rule with MSS %s", expectedIPv4MSS)
}

func TestCleanupMangleTableRule_IPv6_CorrectMSS(t *testing.T) {
	t.Parallel()
	existsRules := make(map[string]bool)

	// Configure mock to report that rules exist
	markRuleKey := fmt.Sprintf("mangle:PREROUTING:%v", []string{
		"-d", "2001:db8::1", "-m", "tcp", "-p", "tcp", "--dport", "8080",
		"-j", "MARK", "--set-mark", "1234",
	})
	existsRules[markRuleKey] = true

	mssRuleKey := fmt.Sprintf("mangle:PREROUTING:%v", []string{
		"-s", "2001:db8::1", "-m", "tcp", "-p", "tcp", "--sport", "8080",
		"-i", "kube-bridge", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--set-mss", expectedIPv6MSS,
	})
	existsRules[mssRuleKey] = true

	nsc, _, ipv6Mock := createTestNSC(existsRules)

	err := nsc.cleanupMangleTableRule("2001:db8::1", "tcp", "8080", "1234")
	assert.NoError(t, err)

	// Verify Exists was called with correct MSS value for IPv6
	existsCalls := ipv6Mock.ExistsCalls()
	checkedMSSValues := findMSSInCalls(existsCalls)
	assert.Contains(t, checkedMSSValues, expectedIPv6MSS,
		"Expected cleanup to check for IPv6 TCPMSS rule with MSS %s", expectedIPv6MSS)
}

func TestCleanupMangleTableRule_IPv6_UsesCorrectHandler(t *testing.T) {
	t.Parallel()
	existsRules := make(map[string]bool)
	nsc, ipv4Mock, ipv6Mock := createTestNSC(existsRules)

	err := nsc.cleanupMangleTableRule("fd00::1", "tcp", "8080", "1234")
	assert.NoError(t, err)

	// IPv6 mock should have been called
	assert.NotEmpty(t, ipv6Mock.ExistsCalls(), "Expected IPv6 handler to be called")
	// IPv4 mock should NOT have been called
	assert.Empty(t, ipv4Mock.ExistsCalls(), "Expected IPv4 handler NOT to be called for IPv6 address")
}

// TestDSRTCPMSSCalculation_TableDriven provides a comprehensive table-driven test
// for verifying MSS calculations across different scenarios
func TestDSRTCPMSSCalculation_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		ip          string
		protocol    string
		expectedMSS string
		expectMSS   bool // whether we expect a TCPMSS rule at all
		isIPv6      bool
	}{
		{
			name:        "IPv4 TCP should use MTU-60",
			ip:          "10.0.0.1",
			protocol:    "tcp",
			expectedMSS: expectedIPv4MSS,
			expectMSS:   true,
			isIPv6:      false,
		},
		{
			name:        "IPv4 alternate address TCP",
			ip:          "192.168.1.100",
			protocol:    "tcp",
			expectedMSS: expectedIPv4MSS,
			expectMSS:   true,
			isIPv6:      false,
		},
		{
			name:        "IPv6 TCP should use MTU-100",
			ip:          "2001:db8::1",
			protocol:    "tcp",
			expectedMSS: expectedIPv6MSS,
			expectMSS:   true,
			isIPv6:      true,
		},
		{
			name:        "IPv6 link-local TCP",
			ip:          "fe80::1",
			protocol:    "tcp",
			expectedMSS: expectedIPv6MSS,
			expectMSS:   true,
			isIPv6:      true,
		},
		{
			name:        "IPv6 ULA TCP",
			ip:          "fd00::1",
			protocol:    "tcp",
			expectedMSS: expectedIPv6MSS,
			expectMSS:   true,
			isIPv6:      true,
		},
		{
			name:        "IPv4 UDP should not create TCPMSS",
			ip:          "10.0.0.1",
			protocol:    "udp",
			expectedMSS: "",
			expectMSS:   false,
			isIPv6:      false,
		},
		{
			name:        "IPv6 UDP should not create TCPMSS",
			ip:          "2001:db8::1",
			protocol:    "udp",
			expectedMSS: "",
			expectMSS:   false,
			isIPv6:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			existsRules := make(map[string]bool)
			nsc, ipv4Mock, ipv6Mock := createTestNSC(existsRules)

			err := nsc.setupMangleTableRule(tc.ip, tc.protocol, "8080", "1234")
			assert.NoError(t, err)

			var mock *utils.IPTablesHandlerMock
			if tc.isIPv6 {
				mock = ipv6Mock
			} else {
				mock = ipv4Mock
			}

			calls := mock.AppendUniqueCalls()
			mssValues := findMSSInCalls(calls)

			if tc.expectMSS {
				assert.True(t, slices.Contains(mssValues, tc.expectedMSS),
					"Expected MSS %s in %v", tc.expectedMSS, mssValues)
			} else {
				assert.Empty(t, mssValues,
					"Expected no TCPMSS rule, got MSS values %v", mssValues)
			}
		})
	}
}
