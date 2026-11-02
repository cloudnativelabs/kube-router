//go:build linux && privileged

package netpol

import (
	"bytes"
	"os"
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

// setUpIptablesTest runs the test in a new network namespace, which comes with empty iptables tables of its own.
// Tests using this helper require root privileges and will be skipped otherwise.
func setUpIptablesTest(t *testing.T) {
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

// tChangeForeignChains makes the kind of change that kube-proxy and other programs make to their own chains at any
// time: an endpoint became ready, a load balancer got a source range and a new chain was hooked into FORWARD
func tChangeForeignChains(t *testing.T, ipt *iptables.IPTables) {
	t.Helper()
	require.NoError(t, ipt.Delete("filter", "KUBE-SERVICES", "-d", "10.43.0.10/32", "-p", "tcp", "-m", "comment",
		"--comment", "kube-system/kube-dns:dns-tcp has no endpoints", "-m", "tcp", "--dport", "53",
		"-j", "REJECT", "--reject-with", "icmp-port-unreachable"))
	require.NoError(t, ipt.Insert("filter", "KUBE-PROXY-FIREWALL", 1, "-d", "192.168.1.240/32", "-p", "tcp",
		"-m", "comment", "--comment", "default/web:http traffic not accepted by KUBE-FW-LBAOEDQXSHJR5YRS",
		"-m", "tcp", "--dport", "80", "-s", "192.168.1.0/24", "-j", "RETURN"))
	require.NoError(t, ipt.NewChain("filter", "CUSTOM-FORWARD"))
	require.NoError(t, ipt.Append("filter", "CUSTOM-FORWARD", "-d", "10.42.0.0/16", "-j", "ACCEPT"))
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

// TestPrivilegedCleanupStaleRulesRestore runs the iptables-save, cleanupStaleRules and iptables-restore steps of a
// full sync and of a cleanup against the kernel, while other programs change their own chains between the save and
// the restore. It uses the iptables-save and iptables-restore found first in PATH, so it covers the legacy or the nft
// backend depending on which one those are.
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
			name:               "sync",
			syncRules:          tFilterTableSyncRules,
			activePolicyChains: map[string]bool{"KUBE-NWPLCY-C2X6HSYNWOLCJ5QF": true},
			activePodFwChains:  map[string]bool{"KUBE-POD-FW-J3VXQYNMB6TLZK2A": true},
			deletedChains:      []string{"KUBE-NWPLCY-LQXVSL3JNEZ2DTOP", "KUBE-POD-FW-4MKDWQBHZ6VQ3TOX"},
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setUpIptablesTest(t)

			ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
			require.NoError(t, err)
			saveRestore := utils.NewIPTablesSaveRestore(v1.IPv4Protocol)
			require.NoError(t, saveRestore.Restore("filter", []byte(tFilterTableSave)),
				"failed to load the filter table of the previous sync")

			npc := NetworkPolicyControllerIptables{NetworkPolicyControllerBase: &NetworkPolicyControllerBase{}}
			npc.iptablesCmdHandlers = map[v1.IPFamily]utils.IPTablesHandler{v1.IPv4Protocol: ipt}
			npc.filterTableRules = map[v1.IPFamily]*bytes.Buffer{v1.IPv4Protocol: {}}
			require.NoError(t, saveRestore.SaveInto("filter", npc.filterTableRules[v1.IPv4Protocol]))
			npc.filterTableRules[v1.IPv4Protocol].WriteString(tt.syncRules)

			tChangeForeignChains(t, ipt)
			wantForeign := tListChains(t, ipt, tForeignChains, tt.deletedChains)

			err = npc.cleanupStaleRules(tt.activePolicyChains, tt.activePodFwChains, tt.deleteDefaultChains)
			require.NoError(t, err)
			err = saveRestore.Restore("filter", npc.filterTableRules[v1.IPv4Protocol].Bytes())
			require.NoError(t, err, "iptables-restore failed for:\n%s", npc.filterTableRules[v1.IPv4Protocol].String())

			assert.Equal(t, wantForeign, tListChains(t, ipt, tForeignChains, nil),
				"chains of other programs changed")
			for _, chain := range tt.deletedChains {
				exists, err := ipt.ChainExists("filter", chain)
				require.NoError(t, err)
				assert.False(t, exists, "chain %s should have been deleted", chain)
			}
			for chain, rules := range tt.wantRules {
				got, err := ipt.List("filter", chain)
				require.NoError(t, err, "failed to list chain %s", chain)
				assert.Equal(t, rules, got, "unexpected rules in chain %s", chain)
			}
		})
	}
}
