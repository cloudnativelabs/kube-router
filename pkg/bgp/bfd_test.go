package bgp

import (
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	gobgpapi "github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
)

func TestBFDConfig_String(t *testing.T) {
	tests := []struct {
		name     string
		config   BFDConfig
		expected string
	}{
		{
			name:     "empty config",
			config:   BFDConfig{},
			expected: "BFDConfig{Enabled: false}",
		},
		{
			name: "Enabled",
			config: BFDConfig{
				Enabled: true,
			},
			expected: "BFDConfig{Enabled: true}",
		},
		{
			name: "Port",
			config: BFDConfig{
				Port: new(uint32(3784)),
			},
			expected: "BFDConfig{Enabled: false, Port: 3784}",
		},
		{
			name: "All fields set",
			config: BFDConfig{
				Enabled:               true,
				Port:                  new(uint32(3785)),
				DesiredMinTxInterval:  new(uint32(2000)),
				DetectionMultiplier:   new(uint32(5)),
				RequiredMinRxInterval: new(uint32(1000)),
			},
			expected: "BFDConfig{Enabled: true, Port: 3785, DesiredMinTxInterval: 2000, DetectionMultiplier: 5, RequiredMinRxInterval: 1000}",
		},
		{
			name: "Some fields set",
			config: BFDConfig{
				Enabled:              true,
				DetectionMultiplier:  new(uint32(3)),
				DesiredMinTxInterval: new(uint32(1000)),
			},
			expected: "BFDConfig{Enabled: true, DesiredMinTxInterval: 1000, DetectionMultiplier: 3}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(st *testing.T) {
			result := tt.config.String()
			assert.Equal(st, tt.expected, result)
		})
	}
}

func TestBFDConfig_ToGoBGP(t *testing.T) {
	tests := []struct {
		name     string
		peer     BFDConfig
		expected *gobgpapi.BfdPeerConfig
	}{
		{
			name: "bfd not enabled returns nil",
			peer: BFDConfig{Port: new(uint32(5000))},
		},
		{
			name: "no fields set, use defaults",
			peer: BFDConfig{
				Enabled: true,
			},
			expected: &gobgpapi.BfdPeerConfig{
				Enabled:                  true,
				Port:                     options.DefaultBFDPort,
				DetectionMultiplier:      options.DefaultBFDDetectionMultiplier,
				DesiredMinimumTxInterval: options.DefaultBFDDesiredMinTxInterval * 1000,
				RequiredMinimumReceive:   options.DefaultBFDRequiredMinRxInterval * 1000,
			},
		},
		{
			name: "fields not set are set with defaults",
			peer: BFDConfig{
				Enabled:              true,
				DetectionMultiplier:  new(uint32(5)),
				DesiredMinTxInterval: new(uint32(2000)),
			},
			expected: &gobgpapi.BfdPeerConfig{
				Enabled:                  true,
				Port:                     3784,
				DetectionMultiplier:      5,
				DesiredMinimumTxInterval: 2000000,
				RequiredMinimumReceive:   options.DefaultBFDRequiredMinRxInterval * 1000,
			},
		},
		{
			name: "all fields set, not overridden by defaults",
			peer: BFDConfig{
				Enabled:               true,
				Port:                  new(uint32(3785)),
				DetectionMultiplier:   new(uint32(2)),
				DesiredMinTxInterval:  new(uint32(2000)),
				RequiredMinRxInterval: new(uint32(2000)),
			},
			expected: &gobgpapi.BfdPeerConfig{
				Enabled:                  true,
				Port:                     3785,
				DetectionMultiplier:      2,
				DesiredMinimumTxInterval: 2000000,
				RequiredMinimumReceive:   2000000,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.peer.ToGoBGP()
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestBFDConfig_Validate(t *testing.T) {
	tests := []struct {
		name          string
		config        BFDConfig
		errorContains string
	}{
		{
			name: "valid config",
			config: BFDConfig{
				Enabled:               true,
				Port:                  new(uint32(65535)),
				DetectionMultiplier:   new(uint32(255)),
				DesiredMinTxInterval:  new(uint32(BFDIntervalMax)),
				RequiredMinRxInterval: new(uint32(BFDIntervalMax)),
			},
		},
		{
			name:   "empty config is valid",
			config: BFDConfig{},
		},
		{
			name:   "enabled with defaults is valid",
			config: BFDConfig{Enabled: true},
		},
		{
			name:          "port cannot be 0",
			config:        BFDConfig{Port: new(uint32(0))},
			errorContains: "bfd port must be between",
		},
		{
			name:          "port cannot be above 65535",
			config:        BFDConfig{Port: new(uint32(65536))},
			errorContains: "bfd port must be between",
		},
		{
			name:          "detection multiplier cannot be zero",
			config:        BFDConfig{DetectionMultiplier: new(uint32(0))},
			errorContains: "detection multiplier must be between",
		},
		{
			name:          "detection multiplier cannot be above 255",
			config:        BFDConfig{DetectionMultiplier: new(uint32(256))},
			errorContains: "detection multiplier must be between",
		},
		{
			name:          "desired min tx interval cannot be zero",
			config:        BFDConfig{DesiredMinTxInterval: new(uint32(0))},
			errorContains: "desired min tx interval must be between",
		},
		{
			name:          "desired min tx interval cannot be greater than value that would cause uint32 overflow as microseconds",
			config:        BFDConfig{DesiredMinTxInterval: new(uint32(BFDIntervalMax + 1))},
			errorContains: "desired min tx interval must be between",
		},
		{
			name:          "required rx interval cannot be zero",
			config:        BFDConfig{RequiredMinRxInterval: new(uint32(0))},
			errorContains: "required min rx interval must be between",
		},
		{
			name:          "required rx interval cannot be greater than value that would cause uint32 overflow as microseconds",
			config:        BFDConfig{RequiredMinRxInterval: new(uint32(BFDIntervalMax + 1))},
			errorContains: "required min rx interval must be between",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.errorContains != "" {
				assert.ErrorContains(t, err, tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
