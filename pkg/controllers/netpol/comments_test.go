package netpol

import (
	"strings"
	"testing"
)

// nftMaxCommentLen is nftables' hard limit; maxCommentLen must stay at or below it so a single
// clamp is safe for both backends (iptables' cap is 256, so the smaller limit governs).
const nftMaxCommentLen = 128

func TestMaxCommentLenWithinNftablesLimit(t *testing.T) {
	if maxCommentLen > nftMaxCommentLen {
		t.Fatalf("maxCommentLen = %d exceeds the nftables limit of %d; comments could be rejected",
			maxCommentLen, nftMaxCommentLen)
	}
}

func TestClampComment(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "short string is unchanged",
			in:   "netpol-x/allow-a ingress pods",
			want: "netpol-x/allow-a ingress pods",
		},
		{
			name: "control characters are stripped",
			in:   "netpol-x/allow\n\t-a ingress pods",
			want: "netpol-x/allow-a ingress pods",
		},
		{
			name: "over-limit string is truncated to maxCommentLen",
			in:   strings.Repeat("x", maxCommentLen+50),
			want: strings.Repeat("x", maxCommentLen),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clampComment(tt.in)
			if got != tt.want {
				t.Errorf("clampComment() = %q, want %q", got, tt.want)
			}
			if len(got) > maxCommentLen {
				t.Errorf("clampComment() length = %d, want <= %d", len(got), maxCommentLen)
			}
		})
	}
}

// TestPolicyCommentsWithinLimit drives every policy-rule comment builder with Kubernetes' maximum
// identity (63-char namespace, 253-char name) and asserts each stays within nftables' limit and still
// leads with the namespace. These builders embed the only unbounded data, which caused the original
// sync-abort regression.
func TestPolicyCommentsWithinLimit(t *testing.T) {
	longNS := strings.Repeat("n", 63)
	longName := strings.Repeat("p", 253)
	policy := networkPolicyInfo{namespace: longNS, name: longName}

	// This list is maintained by hand: when a new cmt* constant (or combination with cmtNamedPort)
	// is introduced in comments.go, add it here so the length guard keeps covering it.
	kinds := []string{
		cmtIngressPods, cmtIngressPods + cmtNamedPort,
		cmtIngressAny, cmtIngressAny + cmtNamedPort,
		cmtIngressCIDR, cmtIngressCIDR + cmtNamedPort,
		cmtEgressPods, cmtEgressPods + cmtNamedPort,
		cmtEgressAny, cmtEgressAny + cmtNamedPort,
		cmtEgressCIDR,
		cmtExceptSrc, cmtExceptDst, cmtIPBlock, cmtJumpPolicy,
		cmtLogDrop, cmtReject, cmtJumpIn, cmtJumpOut,
	}

	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			got := polRuleComment(policy, kind)
			if len(got) > nftMaxCommentLen {
				t.Errorf("polRuleComment(%q) length = %d, want <= %d", kind, len(got), nftMaxCommentLen)
			}
			// Identity leads, so a clamp trims the low-value tag, never the namespace.
			if !strings.HasPrefix(got, longNS+"/") {
				t.Errorf("polRuleComment(%q) = %q, want it to lead with the namespace", kind, got)
			}
		})
	}
}
