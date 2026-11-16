//go:build linux && privileged

package netpol

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"

	v1 "k8s.io/api/core/v1"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
)

// tForeignChains are the chains that other programs own after the change that tChangeForeignChains makes
var tForeignChains = []string{"INPUT", "FORWARD", "OUTPUT", "CUSTOM-FORWARD", "FLANNEL-FWD", "KUBE-EXTERNAL-SERVICES",
	"KUBE-FIREWALL", "KUBE-FORWARD", "KUBE-KUBELET-CANARY", "KUBE-NODEPORTS", "KUBE-PROXY-CANARY",
	"KUBE-PROXY-FIREWALL", "KUBE-ROUTER-SERVICES", "KUBE-SERVICES"}

var tBackends = []string{"nft", "legacy"}

var tFamilies = []v1.IPFamily{v1.IPv4Protocol, v1.IPv6Protocol}

// tFamilyFixture returns fixture for ipFamily
func tFamilyFixture(ipFamily v1.IPFamily, fixture string) string {
	if ipFamily == v1.IPv6Protocol {
		return tIPv6.Replace(fixture)
	}
	return fixture
}

// setUpIptablesTest runs the test in a new network namespace, which comes with empty iptables tables of its own.
// Tests using this helper require root privileges and the iptables commands, and will be skipped otherwise.
func setUpIptablesTest(t *testing.T) {
	t.Helper()

	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}
	for _, cmd := range []string{"iptables", "iptables-save", "iptables-restore"} {
		if _, err := exec.LookPath(cmd); err != nil {
			t.Skipf("Test requires %s in PATH.", cmd)
		}
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

// tUseBackend points the iptables commands in PATH at the legacy or the nft backend for the rest of the test, and
// skips the test if that backend can't be used for ipFamily here (legacy needs the ip(6)_tables kernel modules)
func tUseBackend(t *testing.T, backend string, ipFamily v1.IPFamily) {
	t.Helper()
	multi, err := exec.LookPath("xtables-" + backend + "-multi")
	if err != nil {
		t.Skipf("Test requires xtables-%s-multi in PATH.", backend)
	}
	dir := t.TempDir()
	for _, prefix := range []string{"iptables", "ip6tables"} {
		for _, suffix := range []string{"", "-save", "-restore"} {
			require.NoError(t, os.Symlink(multi, filepath.Join(dir, prefix+suffix)))
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := tBackendUsable(t, ipFamily); err != nil {
		t.Skipf("The %s backend can't be used for %s here: %v", backend, ipFamily, err)
	}
}

// tBackendUsable returns an error if the iptables command in PATH can't be used for ipFamily
func tBackendUsable(t *testing.T, ipFamily v1.IPFamily) error {
	t.Helper()
	cmd := "iptables"
	if ipFamily == v1.IPv6Protocol {
		cmd = "ip6tables"
	}
	if out, err := exec.CommandContext(t.Context(), cmd, "-w", "-S").CombinedOutput(); err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func tNewIPTables(t *testing.T, ipFamily v1.IPFamily) *iptables.IPTables {
	t.Helper()
	proto := iptables.ProtocolIPv4
	if ipFamily == v1.IPv6Protocol {
		proto = iptables.ProtocolIPv6
	}
	ipt, err := iptables.NewWithProtocol(proto)
	require.NoError(t, err)
	return ipt
}

// tChangeForeignChains makes the kind of change that kube-proxy and other programs make to their own chains at any
// time: an endpoint became ready, a load balancer got a source range and a new chain was hooked into FORWARD
func tChangeForeignChains(t *testing.T, ipt *iptables.IPTables, ipFamily v1.IPFamily) {
	t.Helper()
	args := func(args ...string) []string {
		for i := range args {
			args[i] = tFamilyFixture(ipFamily, args[i])
		}
		return args
	}
	require.NoError(t, ipt.Delete("filter", "KUBE-SERVICES", args("-d", "10.43.0.10/32", "-p", "tcp", "-m", "comment",
		"--comment", "kube-system/kube-dns:dns-tcp has no endpoints", "-m", "tcp", "--dport", "53",
		"-j", "REJECT", "--reject-with", "icmp-port-unreachable")...))
	require.NoError(t, ipt.Insert("filter", "KUBE-PROXY-FIREWALL", 1, args("-d", "192.168.1.240/32", "-p", "tcp",
		"-m", "comment", "--comment", "default/web:http traffic not accepted by KUBE-FW-LBAOEDQXSHJR5YRS",
		"-m", "tcp", "--dport", "80", "-s", "192.168.1.0/24", "-j", "RETURN")...))
	require.NoError(t, ipt.NewChain("filter", "CUSTOM-FORWARD"))
	require.NoError(t, ipt.Append("filter", "CUSTOM-FORWARD", args("-d", "10.42.0.0/16", "-j", "ACCEPT")...))
	require.NoError(t, ipt.Append("filter", "FORWARD", "-j", "CUSTOM-FORWARD"))
}

// tListChains returns the rules of those chains that exist in iptables -S form, leaving out the rules that jump to
// one of withoutJumpsTo
func tListChains(t *testing.T, ipt *iptables.IPTables, chains []string, withoutJumpsTo []string) map[string][]string {
	t.Helper()
	rules := make(map[string][]string, len(chains))
	for _, chain := range chains {
		exists, err := ipt.ChainExists("filter", chain)
		require.NoError(t, err)
		if !exists {
			continue
		}
		chainRules, err := ipt.List("filter", chain)
		require.NoError(t, err, "failed to list chain %s", chain)
		rules[chain] = slices.DeleteFunc(chainRules, func(rule string) bool {
			fields := strings.Fields(rule)
			return len(fields) > 1 && slices.Contains(withoutJumpsTo, fields[len(fields)-1])
		})
	}
	return rules
}

// tLoadPreviousSync loads tFilterTableSave for ipFamily, the filter table that the previous sync left behind
func tLoadPreviousSync(t *testing.T, ipFamily v1.IPFamily) {
	t.Helper()
	require.NoError(t, utils.NewIPTablesSaveRestore(ipFamily).Restore("filter",
		[]byte(tFamilyFixture(ipFamily, tFilterTableSave))), "failed to load the filter table of the previous sync")
}

// tNewController returns a controller that only has what cleanupStaleRules and Cleanup need for ipFamilies
func tNewController(t *testing.T, ipFamilies ...v1.IPFamily) *NetworkPolicyControllerIptables {
	t.Helper()
	npc := &NetworkPolicyControllerIptables{NetworkPolicyControllerBase: &NetworkPolicyControllerBase{}}
	npc.iptablesCmdHandlers = map[v1.IPFamily]utils.IPTablesHandler{}
	npc.iptablesSaveRestore = map[v1.IPFamily]utils.IPTablesSaveRestorer{}
	npc.filterTableRules = map[v1.IPFamily]*bytes.Buffer{}
	for _, ipFamily := range ipFamilies {
		npc.iptablesCmdHandlers[ipFamily] = tNewIPTables(t, ipFamily)
		npc.iptablesSaveRestore[ipFamily] = utils.NewIPTablesSaveRestore(ipFamily)
		npc.filterTableRules[ipFamily] = &bytes.Buffer{}
	}
	return npc
}

// tSaveCleanupRestore runs the iptables-save, cleanupStaleRules and iptables-restore steps of a full sync (or of a
// cleanup with deleteDefaultChains) for ipFamily, calling betweenSaveAndRestore after the save
func tSaveCleanupRestore(t *testing.T, ipFamily v1.IPFamily, syncRules string, activePolicyChains,
	activePodFwChains map[string]bool, deleteDefaultChains bool, betweenSaveAndRestore func()) {
	t.Helper()
	npc := tNewController(t, ipFamily)
	require.NoError(t, npc.iptablesSaveRestore[ipFamily].SaveInto("filter", npc.filterTableRules[ipFamily]))
	npc.filterTableRules[ipFamily].WriteString(syncRules)

	betweenSaveAndRestore()

	require.NoError(t, npc.cleanupStaleRules(activePolicyChains, activePodFwChains, deleteDefaultChains))
	payload := npc.filterTableRules[ipFamily].String()
	require.NoError(t, npc.iptablesSaveRestore[ipFamily].Restore("filter", []byte(payload)),
		"iptables-restore failed for:\n%s", payload)
}

// TestPrivilegedCleanupStaleRulesRestore runs the iptables-save, cleanupStaleRules and iptables-restore steps of a
// full sync and of a cleanup against the kernel, for both backends and IP families, while other programs change
// their own chains between the save and the restore
func TestPrivilegedCleanupStaleRulesRestore(t *testing.T) {
	tests := []struct {
		name                string
		syncRules           string
		activePolicyChains  map[string]bool
		activePodFwChains   map[string]bool
		deleteDefaultChains bool
		deletedChains       []string
		wantRules           map[string][]string
	}{
		{
			name:      "sync",
			syncRules: tFilterTableSyncRules,
			activePolicyChains: map[string]bool{"KUBE-NWPLCY-C2X6HSYNWOLCJ5QF": true,
				"KUBE-NWPLCY-RZ4PMGQ2LDWNKH7E": true},
			activePodFwChains: map[string]bool{"KUBE-POD-FW-J3VXQYNMB6TLZK2A": true},
			deletedChains:     []string{"KUBE-NWPLCY-LQXVSL3JNEZ2DTOP", "KUBE-POD-FW-4MKDWQBHZ6VQ3TOX"},
			wantRules: map[string][]string{
				"KUBE-ROUTER-FORWARD": {
					"-N KUBE-ROUTER-FORWARD",
					`-A KUBE-ROUTER-FORWARD -m comment --comment "rule to explicitly handle traffic for network policies ACCEPT/REJECT decision" -j KUBE-NWPLCY-TAIL`,
					`-A KUBE-ROUTER-FORWARD -m comment --comment "rule to explicitly ACCEPT traffic that comply to network policies" -m mark --mark 0x20000/0x20000 -j ACCEPT`,
					`-A KUBE-ROUTER-FORWARD -d 10.42.0.5/32 -m comment --comment "default/web-0 in" -j KUBE-POD-FW-J3VXQYNMB6TLZK2A`,
					`-A KUBE-ROUTER-FORWARD -s 10.42.0.5/32 -m comment --comment "default/web-0 out" -j KUBE-POD-FW-J3VXQYNMB6TLZK2A`,
				},
				"KUBE-NWPLCY-C2X6HSYNWOLCJ5QF": {
					"-N KUBE-NWPLCY-C2X6HSYNWOLCJ5QF",
					`-A KUBE-NWPLCY-C2X6HSYNWOLCJ5QF -s 10.42.0.0/24 -p tcp -m comment --comment "default/allow-web ingress pods" -m tcp --dport 8080 -j MARK --set-xmark 0x10000/0x10000`,
					`-A KUBE-NWPLCY-C2X6HSYNWOLCJ5QF -s 10.42.0.0/24 -p tcp -m comment --comment "default/allow-web ingress pods" -m tcp --dport 8080 -m mark --mark 0x10000/0x10000 -j RETURN`,
				},
				"KUBE-POD-FW-J3VXQYNMB6TLZK2A": {
					"-N KUBE-POD-FW-J3VXQYNMB6TLZK2A",
					`-A KUBE-POD-FW-J3VXQYNMB6TLZK2A -m comment --comment "common netpol rules" -j KUBE-NWPLCY-COMMON`,
					`-A KUBE-POD-FW-J3VXQYNMB6TLZK2A -d 10.42.0.5/32 -m comment --comment "from local node" -m addrtype --src-type LOCAL -j ACCEPT`,
					`-A KUBE-POD-FW-J3VXQYNMB6TLZK2A -s 10.42.0.5/32 -m comment --comment "default egress" -j KUBE-NWPLCY-DEFAULT`,
					`-A KUBE-POD-FW-J3VXQYNMB6TLZK2A -d 10.42.0.5/32 -m comment --comment "default/allow-web policy" -j KUBE-NWPLCY-C2X6HSYNWOLCJ5QF`,
					`-A KUBE-POD-FW-J3VXQYNMB6TLZK2A -m comment --comment "default/web-0 log-drop" -m mark ! --mark 0x10000/0x10000 -m limit --limit 10/min --limit-burst 10 -j NFLOG --nflog-group 100`,
					`-A KUBE-POD-FW-J3VXQYNMB6TLZK2A -m comment --comment "default/web-0 reject" -m mark ! --mark 0x10000/0x10000 -j REJECT --reject-with icmp-port-unreachable`,
					`-A KUBE-POD-FW-J3VXQYNMB6TLZK2A -j MARK --set-xmark 0x0/0x10000`,
					`-A KUBE-POD-FW-J3VXQYNMB6TLZK2A -m comment --comment "set netpol-ok mark" -j MARK --set-xmark 0x20000/0x20000`,
				},
			},
		},
		{
			name:                "cleanup",
			deleteDefaultChains: true,
			deletedChains: []string{"KUBE-ROUTER-INPUT", "KUBE-ROUTER-FORWARD", "KUBE-ROUTER-OUTPUT",
				"KUBE-NWPLCY-DEFAULT", "KUBE-NWPLCY-COMMON", "KUBE-NWPLCY-LQXVSL3JNEZ2DTOP",
				"KUBE-POD-FW-4MKDWQBHZ6VQ3TOX"},
		},
	}

	for _, backend := range tBackends {
		for _, ipFamily := range tFamilies {
			for _, tt := range tests {
				t.Run(backend+"/"+string(ipFamily)+"/"+tt.name, func(t *testing.T) {
					setUpIptablesTest(t)
					tUseBackend(t, backend, ipFamily)
					ipt := tNewIPTables(t, ipFamily)
					tLoadPreviousSync(t, ipFamily)

					deletedChains := make([]string, len(tt.deletedChains))
					for i, chain := range tt.deletedChains {
						deletedChains[i] = tFamilyFixture(ipFamily, chain)
					}
					var wantForeign map[string][]string
					tSaveCleanupRestore(t, ipFamily, tFamilyFixture(ipFamily, tt.syncRules), tt.activePolicyChains,
						tt.activePodFwChains, tt.deleteDefaultChains, func() {
							tChangeForeignChains(t, ipt, ipFamily)
							wantForeign = tListChains(t, ipt, tForeignChains, deletedChains)
						})

					assert.Equal(t, wantForeign, tListChains(t, ipt, tForeignChains, nil),
						"chains of other programs changed")
					for _, chain := range deletedChains {
						exists, err := ipt.ChainExists("filter", chain)
						require.NoError(t, err)
						assert.False(t, exists, "chain %s should have been deleted", chain)
					}
					for chain, rules := range tt.wantRules {
						chain = tFamilyFixture(ipFamily, chain)
						got, err := ipt.List("filter", chain)
						require.NoError(t, err, "failed to list chain %s", chain)
						want := make([]string, len(rules))
						for i, rule := range rules {
							want[i] = tFamilyFixture(ipFamily, rule)
						}
						assert.Equal(t, want, got, "unexpected rules in chain %s", chain)
					}
				})
			}
		}
	}
}

// TestPrivilegedCleanupRemovesItsChains runs Cleanup() on a dual-stack node (or on the families that the backend can be
// used for here) and checks that it removes the chains of the network policy controller and the jumps into them, and
// leaves the chains of other programs alone
func TestPrivilegedCleanupRemovesItsChains(t *testing.T) {
	topLevelChains := []string{kubeInputChainName, kubeForwardChainName, kubeOutputChainName}
	for _, backend := range tBackends {
		t.Run(backend, func(t *testing.T) {
			setUpIptablesTest(t)
			tUseBackend(t, backend, v1.IPv4Protocol)
			families := slices.DeleteFunc(slices.Clone(tFamilies), func(ipFamily v1.IPFamily) bool {
				if err := tBackendUsable(t, ipFamily); err != nil {
					t.Logf("Leaving out %s, the %s backend can't be used for it here: %v", ipFamily, backend, err)
					return true
				}
				return false
			})
			wantForeign := map[v1.IPFamily]map[string][]string{}
			for _, ipFamily := range families {
				tLoadPreviousSync(t, ipFamily)
				ipt := tNewIPTables(t, ipFamily)
				tChangeForeignChains(t, ipt, ipFamily)
				wantForeign[ipFamily] = tListChains(t, ipt, tForeignChains, topLevelChains)
			}

			tNewController(t, families...).Cleanup()

			for _, ipFamily := range families {
				ipt := tNewIPTables(t, ipFamily)
				assert.Equal(t, wantForeign[ipFamily], tListChains(t, ipt, tForeignChains, nil),
					"%s: chains of other programs changed", ipFamily)
				chains, err := ipt.ListChains("filter")
				require.NoError(t, err)
				left := slices.DeleteFunc(chains, func(chain string) bool { return !tNetpolChainRe.MatchString(chain) })
				// KUBE-NWPLCY-TAIL isn't removed by Cleanup() yet
				assert.Equal(t, []string{kubeTailNetpolChain}, left, "%s: chains left behind", ipFamily)
			}
		})
	}
}

// TestPrivilegedNativeNftRuleSurvivesSync checks that a sync leaves alone a rule that another program added with nft
// to the filter table of the nft backend, which iptables-save can't show exactly. Restoring what iptables-save
// shows for it would turn "tcp dport { 1111, 2222 } accept" into an accept for all TCP.
func TestPrivilegedNativeNftRuleSurvivesSync(t *testing.T) {
	setUpIptablesTest(t)
	tUseBackend(t, "nft", v1.IPv4Protocol)
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("Test requires nft in PATH.")
	}
	tLoadPreviousSync(t, v1.IPv4Protocol)

	nft := func(args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(t.Context(), "nft", args...).CombinedOutput()
		require.NoError(t, err, "nft %v: %s", args, out)
		return string(out)
	}
	nft("add", "chain", "ip", "filter", "NATIVE-TEST")
	nft("add", "rule", "ip", "filter", "NATIVE-TEST", "tcp", "dport", "{ 1111, 2222 }", "counter", "accept")
	nft("add", "rule", "ip", "filter", "FORWARD", "ip", "saddr", "192.0.2.77", "jump", "NATIVE-TEST")
	wantChain := nft("list", "chain", "ip", "filter", "NATIVE-TEST")
	require.Contains(t, wantChain, "tcp dport { 1111, 2222 }")

	tSaveCleanupRestore(t, v1.IPv4Protocol, tFilterTableSyncRules,
		map[string]bool{"KUBE-NWPLCY-C2X6HSYNWOLCJ5QF": true}, map[string]bool{"KUBE-POD-FW-J3VXQYNMB6TLZK2A": true},
		false, func() {})

	assert.Equal(t, wantChain, nft("list", "chain", "ip", "filter", "NATIVE-TEST"), "the native nft rule changed")
	assert.Contains(t, nft("list", "chain", "ip", "filter", "FORWARD"), "ip saddr 192.0.2.77 jump NATIVE-TEST")
}
