package svcip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1core "k8s.io/api/core/v1"
)

func mustParseCIDR(t *testing.T, cidr string) net.IPNet {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	require.NoError(t, err, "failed to parse CIDR %q", cidr)
	return *ipnet
}

func TestNewValidator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       Config
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid config with all ranges",
			cfg: Config{
				ExternalIPCIDRs:   []string{"10.243.0.0/24"},
				LoadBalancerCIDRs: []string{"10.255.0.0/24"},
				ClusterIPCIDRs:    []string{"10.96.0.0/12"},
				EnableIPv4:        true,
				EnableIPv6:        false,
			},
			wantErr: false,
		},
		{
			name: "valid dual-stack config",
			cfg: Config{
				ExternalIPCIDRs:   []string{"10.243.0.0/24", "fd00::/64"},
				LoadBalancerCIDRs: []string{"10.255.0.0/24", "fd01::/64"},
				ClusterIPCIDRs:    []string{"10.96.0.0/12", "fd02::/112"},
				EnableIPv4:        true,
				EnableIPv6:        true,
			},
			wantErr: false,
		},
		{
			name: "empty external and LB ranges are allowed",
			cfg: Config{
				ExternalIPCIDRs:   []string{},
				LoadBalancerCIDRs: []string{},
				ClusterIPCIDRs:    []string{"10.96.0.0/12"},
				EnableIPv4:        true,
				EnableIPv6:        false,
			},
			wantErr: false,
		},
		{
			name: "invalid external IP CIDR",
			cfg: Config{
				ExternalIPCIDRs: []string{"not-a-cidr"},
				ClusterIPCIDRs:  []string{"10.96.0.0/12"},
				EnableIPv4:      true,
			},
			wantErr:   true,
			errSubstr: "--service-external-ip-range",
		},
		{
			name: "invalid loadbalancer CIDR",
			cfg: Config{
				LoadBalancerCIDRs: []string{"also-not-valid"},
				ClusterIPCIDRs:    []string{"10.96.0.0/12"},
				EnableIPv4:        true,
			},
			wantErr:   true,
			errSubstr: "--loadbalancer-ip-range",
		},
		{
			name: "invalid cluster IP CIDR",
			cfg: Config{
				ClusterIPCIDRs: []string{"bad-cidr"},
				EnableIPv4:     true,
			},
			wantErr:   true,
			errSubstr: "--service-cluster-ip-range",
		},
		{
			name: "empty cluster IP CIDRs",
			cfg: Config{
				ClusterIPCIDRs: []string{},
				EnableIPv4:     true,
			},
			wantErr:   true,
			errSubstr: "the list is empty",
		},
		{
			name: "too many cluster IP CIDRs",
			cfg: Config{
				ClusterIPCIDRs: []string{"10.96.0.0/12", "10.97.0.0/12", "10.98.0.0/12"},
				EnableIPv4:     true,
			},
			wantErr:   true,
			errSubstr: "only two",
		},
		{
			name: "IPv4 external CIDR when IPv4 disabled",
			cfg: Config{
				ExternalIPCIDRs: []string{"10.243.0.0/24"},
				ClusterIPCIDRs:  []string{"fd00::/112"},
				EnableIPv4:      false,
				EnableIPv6:      true,
			},
			wantErr:   true,
			errSubstr: "IPv4 CIDR",
		},
		{
			name: "IPv6 external CIDR when IPv6 disabled",
			cfg: Config{
				ExternalIPCIDRs: []string{"fd00::/64"},
				ClusterIPCIDRs:  []string{"10.96.0.0/12"},
				EnableIPv4:      true,
				EnableIPv6:      false,
			},
			wantErr:   true,
			errSubstr: "IPv6 CIDR",
		},
		{
			name: "IPv4 LB CIDR when IPv4 disabled",
			cfg: Config{
				LoadBalancerCIDRs: []string{"10.255.0.0/24"},
				ClusterIPCIDRs:    []string{"fd00::/112"},
				EnableIPv4:        false,
				EnableIPv6:        true,
			},
			wantErr:   true,
			errSubstr: "IPv4 CIDR",
		},
		{
			name: "IPv6 LB CIDR when IPv6 disabled",
			cfg: Config{
				LoadBalancerCIDRs: []string{"fd01::/64"},
				ClusterIPCIDRs:    []string{"10.96.0.0/12"},
				EnableIPv4:        true,
				EnableIPv6:        false,
			},
			wantErr:   true,
			errSubstr: "IPv6 CIDR",
		},
		{
			name: "IPv4 cluster CIDR when IPv4 disabled",
			cfg: Config{
				ClusterIPCIDRs: []string{"10.96.0.0/12"},
				EnableIPv4:     false,
				EnableIPv6:     true,
			},
			wantErr:   true,
			errSubstr: "IPv4 CIDR",
		},
		{
			name: "IPv6 cluster CIDR when IPv6 disabled",
			cfg: Config{
				ClusterIPCIDRs: []string{"fd00::/112"},
				EnableIPv4:     true,
				EnableIPv6:     false,
			},
			wantErr:   true,
			errSubstr: "IPv6 CIDR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v, err := NewValidator(tt.cfg)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				assert.Nil(t, v)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, v)
			}
		})
	}
}

func TestRangeQuerier(t *testing.T) {
	t.Parallel()

	v, err := NewValidator(Config{
		ExternalIPCIDRs:   []string{"10.243.0.0/24", "fd00:1::/64"},
		LoadBalancerCIDRs: []string{"10.255.0.0/24", "fd00:2::/64"},
		ClusterIPCIDRs:    []string{"10.96.0.0/12", "fd00:3::/112"},
		EnableIPv4:        true,
		EnableIPv6:        true,
	})
	require.NoError(t, err)

	t.Run("ExternalIPRanges no args returns all", func(t *testing.T) {
		t.Parallel()
		ranges := v.ExternalIPRanges()
		assert.Len(t, ranges, 2)
		assert.Equal(t, mustParseCIDR(t, "10.243.0.0/24"), ranges[0])
		assert.Equal(t, mustParseCIDR(t, "fd00:1::/64"), ranges[1])
	})

	t.Run("ExternalIPRanges IPv4 only", func(t *testing.T) {
		t.Parallel()
		ranges := v.ExternalIPRanges(v1core.IPv4Protocol)
		assert.Len(t, ranges, 1)
		assert.Equal(t, mustParseCIDR(t, "10.243.0.0/24"), ranges[0])
	})

	t.Run("ExternalIPRanges IPv6 only", func(t *testing.T) {
		t.Parallel()
		ranges := v.ExternalIPRanges(v1core.IPv6Protocol)
		assert.Len(t, ranges, 1)
		assert.Equal(t, mustParseCIDR(t, "fd00:1::/64"), ranges[0])
	})

	t.Run("ExternalIPRanges both families explicit", func(t *testing.T) {
		t.Parallel()
		ranges := v.ExternalIPRanges(v1core.IPv4Protocol, v1core.IPv6Protocol)
		assert.Len(t, ranges, 2)
	})

	t.Run("LoadBalancerIPRanges no args returns all", func(t *testing.T) {
		t.Parallel()
		ranges := v.LoadBalancerIPRanges()
		assert.Len(t, ranges, 2)
		assert.Equal(t, mustParseCIDR(t, "10.255.0.0/24"), ranges[0])
		assert.Equal(t, mustParseCIDR(t, "fd00:2::/64"), ranges[1])
	})

	t.Run("LoadBalancerIPRanges IPv4 only", func(t *testing.T) {
		t.Parallel()
		ranges := v.LoadBalancerIPRanges(v1core.IPv4Protocol)
		assert.Len(t, ranges, 1)
		assert.Equal(t, mustParseCIDR(t, "10.255.0.0/24"), ranges[0])
	})

	t.Run("ClusterIPRanges no args returns all", func(t *testing.T) {
		t.Parallel()
		ranges := v.ClusterIPRanges()
		assert.Len(t, ranges, 2)
		assert.Equal(t, mustParseCIDR(t, "10.96.0.0/12"), ranges[0])
		assert.Equal(t, mustParseCIDR(t, "fd00:3::/112"), ranges[1])
	})

	t.Run("ClusterIPRanges IPv4 only", func(t *testing.T) {
		t.Parallel()
		ranges := v.ClusterIPRanges(v1core.IPv4Protocol)
		assert.Len(t, ranges, 1)
		assert.Equal(t, mustParseCIDR(t, "10.96.0.0/12"), ranges[0])
	})

	t.Run("ClusterIPRanges IPv6 only", func(t *testing.T) {
		t.Parallel()
		ranges := v.ClusterIPRanges(v1core.IPv6Protocol)
		assert.Len(t, ranges, 1)
		assert.Equal(t, mustParseCIDR(t, "fd00:3::/112"), ranges[0])
	})
}

func TestRangeQuerierEmpty(t *testing.T) {
	t.Parallel()

	v, err := NewValidator(Config{
		ClusterIPCIDRs: []string{"10.96.0.0/12"},
		EnableIPv4:     true,
	})
	require.NoError(t, err)

	assert.Empty(t, v.ExternalIPRanges())
	assert.Empty(t, v.ExternalIPRanges(v1core.IPv4Protocol))
	assert.Empty(t, v.ExternalIPRanges(v1core.IPv6Protocol))
	assert.Empty(t, v.LoadBalancerIPRanges())
	assert.Empty(t, v.LoadBalancerIPRanges(v1core.IPv4Protocol))
}

func TestFilterExternalIPs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		strictMode        bool
		externalIPRanges  []string
		clusterIPRanges   []string
		inputIPs          []string
		expectedOutputIPs []string
	}{
		{
			name:              "strict mode off - all IPs pass through",
			strictMode:        false,
			externalIPRanges:  []string{},
			inputIPs:          []string{"1.1.1.1", "2.2.2.2", "10.96.0.10"},
			expectedOutputIPs: []string{"1.1.1.1", "2.2.2.2", "10.96.0.10"},
		},
		{
			name:              "strict mode on, no ranges - all rejected (default-deny)",
			strictMode:        true,
			externalIPRanges:  []string{},
			inputIPs:          []string{"1.1.1.1", "2.2.2.2"},
			expectedOutputIPs: nil,
		},
		{
			name:              "strict mode on, no ranges, empty input - no error",
			strictMode:        true,
			externalIPRanges:  []string{},
			inputIPs:          []string{},
			expectedOutputIPs: nil,
		},
		{
			name:              "strict mode on, IP within range - accepted",
			strictMode:        true,
			externalIPRanges:  []string{"10.243.0.0/24"},
			inputIPs:          []string{"10.243.0.1"},
			expectedOutputIPs: []string{"10.243.0.1"},
		},
		{
			name:              "strict mode on, IP outside range - rejected",
			strictMode:        true,
			externalIPRanges:  []string{"10.243.0.0/24"},
			inputIPs:          []string{"192.168.1.1"},
			expectedOutputIPs: []string{},
		},
		{
			name:              "strict mode on, mixed valid and invalid IPs",
			strictMode:        true,
			externalIPRanges:  []string{"10.243.0.0/24"},
			inputIPs:          []string{"10.243.0.1", "192.168.1.1", "10.243.0.2"},
			expectedOutputIPs: []string{"10.243.0.1", "10.243.0.2"},
		},
		{
			name:              "strict mode on, IP conflicts with cluster IP range",
			strictMode:        true,
			externalIPRanges:  []string{"10.0.0.0/8"},
			clusterIPRanges:   []string{"10.96.0.0/12"},
			inputIPs:          []string{"10.96.0.10", "10.243.0.1"},
			expectedOutputIPs: []string{"10.243.0.1"},
		},
		{
			name:              "strict mode on, multiple ranges",
			strictMode:        true,
			externalIPRanges:  []string{"10.243.0.0/24", "172.16.0.0/16"},
			inputIPs:          []string{"10.243.0.5", "172.16.1.1", "8.8.8.8"},
			expectedOutputIPs: []string{"10.243.0.5", "172.16.1.1"},
		},
		{
			name:              "strict mode on, IPv6 IPs with IPv6 ranges",
			strictMode:        true,
			externalIPRanges:  []string{"fd00::/64"},
			inputIPs:          []string{"fd00::1", "fe80::1"},
			expectedOutputIPs: []string{"fd00::1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := &Validator{
				strictValidation: tt.strictMode,
			}

			for _, r := range tt.externalIPRanges {
				cidr := mustParseCIDR(t, r)
				if cidr.IP.To4() != nil {
					v.externalIPv4Ranges = append(v.externalIPv4Ranges, cidr)
				} else {
					v.externalIPv6Ranges = append(v.externalIPv6Ranges, cidr)
				}
			}
			for _, r := range tt.clusterIPRanges {
				cidr := mustParseCIDR(t, r)
				if cidr.IP.To4() != nil {
					v.clusterIPv4Ranges = append(v.clusterIPv4Ranges, cidr)
				} else {
					v.clusterIPv6Ranges = append(v.clusterIPv6Ranges, cidr)
				}
			}

			result := v.FilterExternalIPs(tt.inputIPs, "test-svc", "default")
			assert.Equal(t, tt.expectedOutputIPs, result)
		})
	}
}

func TestFilterLoadBalancerIPs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		strictMode        bool
		lbIPRanges        []string
		clusterIPRanges   []string
		inputIPs          []string
		expectedOutputIPs []string
	}{
		{
			name:              "strict mode off - all IPs pass through",
			strictMode:        false,
			lbIPRanges:        []string{},
			inputIPs:          []string{"10.255.0.1", "10.255.0.2"},
			expectedOutputIPs: []string{"10.255.0.1", "10.255.0.2"},
		},
		{
			name:              "strict mode on, no ranges - all rejected (default-deny)",
			strictMode:        true,
			lbIPRanges:        []string{},
			inputIPs:          []string{"10.255.0.1"},
			expectedOutputIPs: nil,
		},
		{
			name:              "strict mode on, IP within range - accepted",
			strictMode:        true,
			lbIPRanges:        []string{"10.255.0.0/24"},
			inputIPs:          []string{"10.255.0.1"},
			expectedOutputIPs: []string{"10.255.0.1"},
		},
		{
			name:              "strict mode on, IP outside range - rejected",
			strictMode:        true,
			lbIPRanges:        []string{"10.255.0.0/24"},
			inputIPs:          []string{"192.168.1.1"},
			expectedOutputIPs: []string{},
		},
		{
			name:              "strict mode on, IP conflicts with cluster IP range",
			strictMode:        true,
			lbIPRanges:        []string{"10.0.0.0/8"},
			clusterIPRanges:   []string{"10.96.0.0/12"},
			inputIPs:          []string{"10.96.0.10", "10.255.0.1"},
			expectedOutputIPs: []string{"10.255.0.1"},
		},
		{
			name:              "strict mode on, empty input - no error",
			strictMode:        true,
			lbIPRanges:        []string{"10.255.0.0/24"},
			inputIPs:          []string{},
			expectedOutputIPs: []string{},
		},
		{
			name:              "strict mode on, mixed valid and invalid IPs",
			strictMode:        true,
			lbIPRanges:        []string{"10.255.0.0/24"},
			inputIPs:          []string{"10.255.0.1", "8.8.8.8", "10.255.0.2"},
			expectedOutputIPs: []string{"10.255.0.1", "10.255.0.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := &Validator{
				strictValidation: tt.strictMode,
			}

			for _, r := range tt.lbIPRanges {
				cidr := mustParseCIDR(t, r)
				if cidr.IP.To4() != nil {
					v.loadBalancerIPv4Ranges = append(v.loadBalancerIPv4Ranges, cidr)
				} else {
					v.loadBalancerIPv6Ranges = append(v.loadBalancerIPv6Ranges, cidr)
				}
			}
			for _, r := range tt.clusterIPRanges {
				cidr := mustParseCIDR(t, r)
				if cidr.IP.To4() != nil {
					v.clusterIPv4Ranges = append(v.clusterIPv4Ranges, cidr)
				} else {
					v.clusterIPv6Ranges = append(v.clusterIPv6Ranges, cidr)
				}
			}

			result := v.FilterLoadBalancerIPs(tt.inputIPs, "test-svc", "default")
			assert.Equal(t, tt.expectedOutputIPs, result)
		})
	}
}
