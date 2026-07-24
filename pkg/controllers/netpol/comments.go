package netpol

// nftables rejects a transaction whose comment exceeds 128 bytes (iptables caps at 256), so we
// clamp to the smaller limit and lead every comment with ns/name identity so a clamp only trims
// the descriptive tail. Some iptables comments are instead frozen at their historical text because
// they act as rule identity for AppendUnique/Exists; see the note on ensureExplicitAccept.
const maxCommentLen = 120

// clampComment strips control characters (defense-in-depth for iptables-restore) and caps
// the result at maxCommentLen. Callers lead with ns/name so truncation only trims the tail.
func clampComment(s string) string {
	s = sanitizeForComment(s)
	if len(s) > maxCommentLen {
		s = s[:maxCommentLen]
	}
	return s
}

// Short, stable kind tags appended after the policy/pod identity. The rule's own match and
// verdict already carry the detail, so the tag stays terse.
const (
	cmtIngressPods = "ingress pods" // ingress from selected source pods
	cmtIngressAny  = "ingress any"  // ingress from all sources
	cmtIngressCIDR = "ingress cidr" // ingress from ipBlock CIDRs
	cmtEgressPods  = "egress pods"  // egress to selected destination pods
	cmtEgressAny   = "egress any"   // egress to all destinations
	cmtEgressCIDR  = "egress cidr"  // egress to ipBlock CIDRs
	cmtNamedPort   = " np"          // suffix on any of the above: matches a named port
	cmtExceptSrc   = "except-src"   // ingress ipBlock except sub-chain (return excepted CIDRs)
	cmtExceptDst   = "except-dst"   // egress ipBlock except sub-chain (return excepted CIDRs)
	cmtIPBlock     = "ipblock"      // jump into an ipBlock except sub-chain
	cmtJumpPolicy  = "policy"       // pod-fw jump into a policy chain
	cmtLogDrop     = "log-drop"     // NFLOG rule for policy-denied traffic
	cmtReject      = "reject"       // REJECT rule for policy-denied traffic
	cmtJumpIn      = "in"           // top-level jump for traffic destined to a pod
	cmtJumpOut     = "out"          // top-level jump for traffic sourced from a pod
)

// idComment builds "<namespace>/<name> <kind>", clamped. Single entry point for every comment
// that embeds variable identity, so the length invariant is enforced in one place.
func idComment(namespace, name, kind string) string {
	return clampComment(namespace + "/" + name + " " + kind)
}

// polRuleComment is idComment for a rule inside a network-policy chain.
func polRuleComment(p networkPolicyInfo, kind string) string {
	return idComment(p.namespace, p.name, kind)
}
