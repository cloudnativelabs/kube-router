package netpol_e2e

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSetsHolding runs without a cluster, so the parser behind the stale-IP spec gets checked by plain `go test`
func TestSetsHolding(t *testing.T) {
	const ipsetSave = `create KUBE-SRC-ABC hash:ip family inet hashsize 1024 maxelem 65536 timeout 0
add KUBE-SRC-ABC 10.244.1.5 timeout 0
create KUBE-SRC-DEF hash:ip family inet hashsize 1024 maxelem 65536 timeout 0
add KUBE-SRC-DEF 10.244.1.50 timeout 0
create KUBE-DST-PORT hash:ip,port family inet hashsize 1024 maxelem 65536
add KUBE-DST-PORT 10.244.2.7,tcp:8080
create kube-router-pod-subnets hash:net family inet hashsize 1024 maxelem 65536
add kube-router-pod-subnets 10.244.1.0/24
create inet6:KUBE-SRC-ABC hash:ip family inet6 hashsize 1024 maxelem 65536 timeout 0
add inet6:KUBE-SRC-ABC fd00:10:244:1::5 timeout 0
`
	const nftRuleset = `table ip kube-router-filter-ipv4 {
	set kube-router-local-pods {
		type ipv4_addr
		elements = { 10.244.1.4, 10.244.1.6 }
	}
	set KUBE-SRC-XYZ {
		type ipv4_addr
		flags interval
		elements = { 10.244.1.2, 10.244.1.60,
			     10.244.1.7/32 }
	}
	map pod-fw {
		type ipv4_addr : verdict
		elements = { 10.244.1.8 : jump KUBE-POD-FW-1 }
	}
	chain KUBE-ROUTER-FORWARD {
		ip daddr 10.244.1.9 jump KUBE-POD-FW-2
	}
}
table ip6 kube-router-filter-ipv6 {
	set kube-router-local-pods {
		type ipv6_addr
		elements = { fd00:10:244:1::6 }
	}
}
`
	tests := []struct {
		name   string
		output string
		ip     string
		want   []string
	}{
		{name: "ipset entry, ignoring longer addresses", output: ipsetSave, ip: "10.244.1.5",
			want: []string{"KUBE-SRC-ABC"}},
		{name: "ipset ip,port entry", output: ipsetSave, ip: "10.244.2.7", want: []string{"KUBE-DST-PORT"}},
		{name: "ipset IPv6 entry", output: ipsetSave, ip: "fd00:10:244:1::5", want: []string{"inet6:KUBE-SRC-ABC"}},
		{name: "ipset ignores an enclosing CIDR", output: ipsetSave, ip: "10.244.1.99", want: nil},
		{name: "nft elements, ignoring longer addresses", output: nftRuleset, ip: "10.244.1.6",
			want: []string{"kube-router-local-pods"}},
		{name: "nft multi-line elements with a /32", output: nftRuleset, ip: "10.244.1.7",
			want: []string{"KUBE-SRC-XYZ"}},
		{name: "nft map key", output: nftRuleset, ip: "10.244.1.8", want: []string{"pod-fw"}},
		{name: "nft ignores rules", output: nftRuleset, ip: "10.244.1.9", want: nil},
		{name: "nft IPv6 elements", output: nftRuleset, ip: "fd00:10:244:1::6",
			want: []string{"kube-router-local-pods"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, setsHolding(tt.output, netip.MustParseAddr(tt.ip)))
		})
	}
}
