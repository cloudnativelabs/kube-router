//go:build linux && privileged

package routes

import (
	"net"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// setUpNetlinkTest creates an isolated network namespace for testing netlink operations. The returned cleanup function
// restores the original namespace. Tests using this helper require root privileges and will be skipped otherwise.
func setUpNetlinkTest(t *testing.T) {
	t.Helper()

	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}

	runtime.LockOSThread()

	origNS, err := netns.Get()
	require.NoError(t, err, "failed to get current namespace")

	ns, err := netns.New()
	if err != nil {
		_ = netns.Set(origNS)
		runtime.UnlockOSThread()
		require.NoError(t, err, "failed to create new namespace")
	}

	t.Cleanup(func() {
		ns.Close()
		err := netns.Set(origNS)
		if err != nil {
			t.Fatalf("Failed to restore original namespace: %v", err)
		}
		_ = origNS.Close()
		runtime.UnlockOSThread()
	})
}

// TestRuleListFilteredDefaultRoute verifies that netlink.RuleListFiltered correctly matches rules whose Src or Dst is
// a default route (0.0.0.0/0 or ::/0). This is a regression test for https://github.com/vishvananda/netlink/issues/1080
// which was fixed upstream in https://github.com/vishvananda/netlink/pull/1178.
//
// When the kernel returns a rule with Src/Dst set to a default route, it omits the FRA_SRC/FRA_DST attribute (prefix
// length is 0), so the parsed rule.Src/rule.Dst is nil. The fix ensures that the filter logic treats nil as equivalent
// to /0, so that filtering by Src = 0.0.0.0/0 correctly matches these rules.
func TestPrivilegedRuleListFilteredDefaultRoute(t *testing.T) {
	tests := []struct {
		name       string
		family     int
		src        *net.IPNet
		table      int
		filterMask uint64
	}{
		{
			name:       "IPv4 default route Src filtered by RT_FILTER_SRC",
			family:     netlink.FAMILY_V4,
			src:        &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			table:      100,
			filterMask: netlink.RT_FILTER_SRC,
		},
		{
			name:       "IPv4 default route Src filtered by RT_FILTER_SRC and RT_FILTER_TABLE",
			family:     netlink.FAMILY_V4,
			src:        &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			table:      101,
			filterMask: netlink.RT_FILTER_SRC | netlink.RT_FILTER_TABLE,
		},
		{
			name:       "IPv6 default route Src filtered by RT_FILTER_SRC",
			family:     netlink.FAMILY_V6,
			src:        &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			table:      102,
			filterMask: netlink.RT_FILTER_SRC,
		},
		{
			name:       "IPv6 default route Src filtered by RT_FILTER_SRC and RT_FILTER_TABLE",
			family:     netlink.FAMILY_V6,
			src:        &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			table:      103,
			filterMask: netlink.RT_FILTER_SRC | netlink.RT_FILTER_TABLE,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setUpNetlinkTest(t)

			// Add a rule with a default route Src
			rule := netlink.NewRule()
			rule.Family = tt.family
			rule.Src = tt.src
			rule.Table = tt.table
			rule.Priority = 1000
			require.NoError(t, netlink.RuleAdd(rule), "failed to add rule")
			t.Cleanup(func() {
				_ = netlink.RuleDel(rule)
			})

			// Build the filter — this is how ipRuleAbstraction does it
			filter := netlink.NewRule()
			filter.Family = tt.family
			filter.Src = tt.src
			filter.Table = tt.table

			// This is the call that was broken before the upstream fix: filtering by RT_FILTER_SRC with a
			// default route Src would return 0 results because the kernel returns nil for default route Src
			// and the old code treated nil as "not matching".
			rules, err := netlink.RuleListFiltered(tt.family, filter, tt.filterMask)
			require.NoError(t, err, "RuleListFiltered failed")

			assert.NotEmpty(t, rules,
				"RuleListFiltered with default route Src returned no results — "+
					"this indicates https://github.com/vishvananda/netlink/issues/1080 has regressed")

			// Verify our rule is among the results. We can't assume it's at index 0 because a fresh
			// network namespace has pre-existing rules (e.g. "from all lookup local", table 255)
			// that also match a default route Src filter when RT_FILTER_TABLE is not set.
			found := false
			for _, r := range rules {
				if r.Table == tt.table {
					found = true
					break
				}
			}
			assert.True(t, found,
				"expected to find rule with table %d in filtered results, got tables: %v",
				tt.table, ruleTables(rules))
		})
	}
}

// TestRuleListFilteredNonDefaultRoute verifies that RuleListFiltered still works correctly for non-default (normal)
// routes alongside the default route fix. This ensures the upstream fix didn't break normal filtering behavior.
func TestPrivilegedRuleListFilteredNonDefaultRoute(t *testing.T) {
	tests := []struct {
		name   string
		family int
		src    *net.IPNet
		table  int
	}{
		{
			name:   "IPv4 specific CIDR",
			family: netlink.FAMILY_V4,
			src:    &net.IPNet{IP: net.IPv4(172, 20, 0, 0), Mask: net.CIDRMask(24, 32)},
			table:  110,
		},
		{
			name:   "IPv6 specific CIDR",
			family: netlink.FAMILY_V6,
			src:    &net.IPNet{IP: net.ParseIP("fd00:db8::"), Mask: net.CIDRMask(64, 128)},
			table:  111,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setUpNetlinkTest(t)

			rule := netlink.NewRule()
			rule.Family = tt.family
			rule.Src = tt.src
			rule.Table = tt.table
			rule.Priority = 1000
			require.NoError(t, netlink.RuleAdd(rule), "failed to add rule")
			t.Cleanup(func() {
				_ = netlink.RuleDel(rule)
			})

			filter := netlink.NewRule()
			filter.Family = tt.family
			filter.Src = tt.src
			filter.Table = tt.table

			rules, err := netlink.RuleListFiltered(tt.family, filter,
				netlink.RT_FILTER_SRC|netlink.RT_FILTER_TABLE)
			require.NoError(t, err, "RuleListFiltered failed")

			assert.Len(t, rules, 1, "expected exactly one matching rule")
			if len(rules) > 0 {
				assert.Equal(t, tt.table, rules[0].Table, "matched rule has unexpected table")
			}
		})
	}
}

// TestRuleListFilteredDefaultRouteDoesNotMatchSpecific verifies that a default route filter does NOT match rules with
// a specific (non-default) Src. This ensures the nil ≡ /0 equivalence in the upstream fix is correctly scoped.
func TestPrivilegedRuleListFilteredDefaultRouteDoesNotMatchSpecific(t *testing.T) {
	setUpNetlinkTest(t)

	// Add a rule with a specific (non-default) Src
	specificSrc := &net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)}
	rule := netlink.NewRule()
	rule.Family = netlink.FAMILY_V4
	rule.Src = specificSrc
	rule.Table = 120
	rule.Priority = 1000
	require.NoError(t, netlink.RuleAdd(rule), "failed to add rule")
	t.Cleanup(func() {
		_ = netlink.RuleDel(rule)
	})

	// Filter with a default route Src — this should NOT match the specific rule above
	defaultSrc := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	filter := netlink.NewRule()
	filter.Family = netlink.FAMILY_V4
	filter.Src = defaultSrc
	filter.Table = 120

	rules, err := netlink.RuleListFiltered(netlink.FAMILY_V4, filter,
		netlink.RT_FILTER_SRC|netlink.RT_FILTER_TABLE)
	require.NoError(t, err, "RuleListFiltered failed")

	assert.Empty(t, rules,
		"default route filter should NOT match a rule with a specific Src (10.0.0.0/8)")
}

// TestIpRuleAbstractionDefaultRoute exercises the full ipRuleAbstraction function with a default route CIDR, verifying
// the add and delete lifecycle works end-to-end.
func TestPrivilegedIpRuleAbstractionDefaultRoute(t *testing.T) {
	tests := []struct {
		name   string
		family int
		cidr   string
	}{
		{
			name:   "IPv4 default route",
			family: netlink.FAMILY_V4,
			cidr:   "0.0.0.0/0",
		},
		{
			name:   "IPv6 default route",
			family: netlink.FAMILY_V6,
			cidr:   "::/0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setUpNetlinkTest(t)

			// Add the rule via ipRuleAbstraction
			err := ipRuleAbstraction(tt.family, PBRRuleAdd, tt.cidr)
			require.NoError(t, err, "ipRuleAbstraction add failed")

			// Verify the rule was created by listing with RT_FILTER_TABLE
			_, nSrc, _ := net.ParseCIDR(tt.cidr)
			filter := netlink.NewRule()
			filter.Family = tt.family
			filter.Src = nSrc
			filter.Table = CustomTableID

			rules, err := netlink.RuleListFiltered(tt.family, filter,
				netlink.RT_FILTER_SRC|netlink.RT_FILTER_TABLE)
			require.NoError(t, err, "RuleListFiltered failed")
			assert.NotEmpty(t, rules, "rule should exist after add")

			// Adding again should be idempotent (no error, no duplicate)
			err = ipRuleAbstraction(tt.family, PBRRuleAdd, tt.cidr)
			require.NoError(t, err, "idempotent add failed")

			// Delete the rule via ipRuleAbstraction
			err = ipRuleAbstraction(tt.family, PBRRuleDel, tt.cidr)
			require.NoError(t, err, "ipRuleAbstraction del failed")

			// Verify the rule was removed
			rules, err = netlink.RuleListFiltered(tt.family, filter,
				netlink.RT_FILTER_SRC|netlink.RT_FILTER_TABLE)
			require.NoError(t, err, "RuleListFiltered failed")
			assert.Empty(t, rules, "rule should not exist after delete")

			// Deleting again should be idempotent (no error)
			err = ipRuleAbstraction(tt.family, PBRRuleDel, tt.cidr)
			require.NoError(t, err, "idempotent del failed")
		})
	}
}

// TestIpRuleAbstractionNonDefaultRoute exercises ipRuleAbstraction with typical pod CIDRs (the common case) to ensure
// the default route changes didn't break normal behavior.
func TestPrivilegedIpRuleAbstractionNonDefaultRoute(t *testing.T) {
	tests := []struct {
		name   string
		family int
		cidr   string
	}{
		{
			name:   "IPv4 pod CIDR",
			family: netlink.FAMILY_V4,
			cidr:   "172.20.0.0/24",
		},
		{
			name:   "IPv6 pod CIDR",
			family: netlink.FAMILY_V6,
			cidr:   "fd00:db8:42:2::/64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setUpNetlinkTest(t)

			// Add
			err := ipRuleAbstraction(tt.family, PBRRuleAdd, tt.cidr)
			require.NoError(t, err, "ipRuleAbstraction add failed")

			// Verify
			_, nSrc, _ := net.ParseCIDR(tt.cidr)
			filter := netlink.NewRule()
			filter.Family = tt.family
			filter.Src = nSrc
			filter.Table = CustomTableID

			rules, err := netlink.RuleListFiltered(tt.family, filter,
				netlink.RT_FILTER_SRC|netlink.RT_FILTER_TABLE)
			require.NoError(t, err, "RuleListFiltered failed")
			assert.Len(t, rules, 1, "expected exactly one matching rule")

			// Delete
			err = ipRuleAbstraction(tt.family, PBRRuleDel, tt.cidr)
			require.NoError(t, err, "ipRuleAbstraction del failed")

			// Verify deletion
			rules, err = netlink.RuleListFiltered(tt.family, filter,
				netlink.RT_FILTER_SRC|netlink.RT_FILTER_TABLE)
			require.NoError(t, err, "RuleListFiltered failed")
			assert.Empty(t, rules, "rule should not exist after delete")
		})
	}
}

// ruleTables extracts the Table field from a slice of rules for diagnostic output.
func ruleTables(rules []netlink.Rule) []int {
	tables := make([]int, len(rules))
	for i, r := range rules {
		tables[i] = r.Table
	}
	return tables
}
