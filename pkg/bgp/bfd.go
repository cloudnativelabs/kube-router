package bgp

import (
	"fmt"
	"strings"

	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	gobgpapi "github.com/osrg/gobgp/v4/api"
	"k8s.io/utils/ptr"
)

type BFDConfig struct {
	Enabled bool    `yaml:"enabled"`
	Port    *uint32 `yaml:"port"`

	DesiredMinTxInterval  *uint32 `yaml:"desired_min_tx_interval"`
	DetectionMultiplier   *uint32 `yaml:"detection_multiplier"`
	RequiredMinRxInterval *uint32 `yaml:"required_min_rx_interval"`
}

func (b BFDConfig) String() string {
	fields := []string{fmt.Sprintf("Enabled: %t", b.Enabled)}
	if b.Port != nil {
		fields = append(fields, fmt.Sprintf("Port: %d", *b.Port))
	}
	if b.DesiredMinTxInterval != nil {
		fields = append(fields, fmt.Sprintf("DesiredMinTxInterval: %d", *b.DesiredMinTxInterval))
	}
	if b.DetectionMultiplier != nil {
		fields = append(fields, fmt.Sprintf("DetectionMultiplier: %d", *b.DetectionMultiplier))
	}
	if b.RequiredMinRxInterval != nil {
		fields = append(fields, fmt.Sprintf("RequiredMinRxInterval: %d", *b.RequiredMinRxInterval))
	}
	return fmt.Sprintf("BFDConfig{%s}", strings.Join(fields, ", "))
}

// ToGoBGP builds the GoBGP API config for BFD settings. Returns nil
// if BFDConfig is not enabled.
func (b BFDConfig) ToGoBGP() *gobgpapi.BfdPeerConfig {
	if !b.Enabled {
		return nil
	}

	return &gobgpapi.BfdPeerConfig{
		Enabled:                  true,
		Port:                     ptr.Deref(b.Port, options.DefaultBFDPort),
		DetectionMultiplier:      ptr.Deref(b.DetectionMultiplier, options.DefaultBFDDetectionMultiplier),
		DesiredMinimumTxInterval: ptr.Deref(b.DesiredMinTxInterval, options.DefaultBFDDesiredMinTxInterval),
		RequiredMinimumReceive:   ptr.Deref(b.RequiredMinRxInterval, options.DefaultBFDRequiredMinRxInterval),
	}
}
