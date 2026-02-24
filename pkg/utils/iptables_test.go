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
				{"icmp", "--icmp-type", "icmp", "echo-request", icmpEchoRequestComment},
				{"icmp", "--icmp-type", "icmp", icmpTypeDestinationUnreachable, icmpDestinationUnreachableComment},
				{"icmp", "--icmp-type", "icmp", "time-exceeded", icmpTimeExceededComment},
			},
		},
		{
			name:   "IPv6",
			family: v1core.IPv6Protocol,
			expected: []ICMPRule{
				{"ipv6-icmp", "--icmpv6-type", "icmpv6", "echo-request", icmpEchoRequestComment},
				{"ipv6-icmp", "--icmpv6-type", "icmpv6", icmpTypeDestinationUnreachable, icmpDestinationUnreachableComment},
				{"ipv6-icmp", "--icmpv6-type", "icmpv6", "time-exceeded", icmpTimeExceededComment},
				{"ipv6-icmp", "--icmpv6-type", "icmpv6", "neighbor-solicitation", "allow icmp neighbor solicitation messages"},
				{"ipv6-icmp", "--icmpv6-type", "icmpv6", "neighbor-advertisement", "allow icmp neighbor advertisement messages"},
				{"ipv6-icmp", "--icmpv6-type", "icmpv6", "echo-reply", "allow icmp echo reply messages"},
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
