package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"

	v1core "k8s.io/api/core/v1"
)

func TestCommonICMPRules(t *testing.T) {
	tests := []struct {
		name     string
		family   v1core.IPFamily
		expected []ICMPRule
	}{
		{
			name:   "IPv4",
			family: v1core.IPv4Protocol,
			expected: []ICMPRule{
				{"icmp", "--icmp-type", "icmp", "echo-request", "echo-request", "allow icmp echo requests"},
				{"icmp", "--icmp-type", "icmp", "destination-unreachable", "destination-unreachable", "allow icmp destination unreachable messages"},
				{"icmp", "--icmp-type", "icmp", "time-exceeded", "time-exceeded", "allow icmp time exceeded messages"},
			},
		},
		{
			name:   "IPv6",
			family: v1core.IPv6Protocol,
			expected: []ICMPRule{
				{"ipv6-icmp", "--icmpv6-type", "icmpv6", "echo-request", "echo-request", "allow icmp echo requests"},
				{"ipv6-icmp", "--icmpv6-type", "icmpv6", "destination-unreachable", "destination-unreachable", "allow icmp destination unreachable messages"},
				{"ipv6-icmp", "--icmpv6-type", "icmpv6", "time-exceeded", "time-exceeded", "allow icmp time exceeded messages"},
				{"ipv6-icmp", "--icmpv6-type", "icmpv6", "neighbor-solicitation", "nd-neighbor-solicit", "allow icmp neighbor solicitation messages"},
				{"ipv6-icmp", "--icmpv6-type", "icmpv6", "neighbor-advertisement", "nd-neighbor-advert", "allow icmp neighbor advertisement messages"},
				{"ipv6-icmp", "--icmpv6-type", "icmpv6", "echo-reply", "echo-reply", "allow icmp echo reply messages"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CommonICMPRules(tt.family)
			assert.Equal(t, tt.expected, result, "CommonICMPRules(%v) = %v, want %v", tt.family, result, tt.expected)
		})
	}
}
