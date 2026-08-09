package bgp

import (
	"fmt"
	"math"
	"strings"

	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	gobgpapi "github.com/osrg/gobgp/v4/api"
	"k8s.io/utils/ptr"
)

const (
	BFDDetectionMultiplierMax = 255 // RFC 5880 defines detect_mult as an 8-bit field
	BFDPortMax                = 65535
	BFDIntervalMax            = math.MaxUint32 / msToMicroseconds
	msToMicroseconds          = 1000
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

func (b BFDConfig) Validate() error {
	if b.Port != nil {
		if *b.Port == 0 || *b.Port > BFDPortMax {
			return fmt.Errorf("bfd port must be between 1 and %d, got %d", BFDPortMax, *b.Port)
		}
	}
	if b.DetectionMultiplier != nil {
		if *b.DetectionMultiplier == 0 || *b.DetectionMultiplier > BFDDetectionMultiplierMax {
			return fmt.Errorf("bfd detection multiplier must be between 1 and %d, got %d",
				BFDDetectionMultiplierMax, *b.DetectionMultiplier)
		}
	}
	if b.DesiredMinTxInterval != nil {
		if *b.DesiredMinTxInterval == 0 || *b.DesiredMinTxInterval > BFDIntervalMax {
			return fmt.Errorf("bfd desired min tx interval must be between 1 and %d milliseconds, got %d",
				BFDIntervalMax, *b.DesiredMinTxInterval)
		}
	}
	if b.RequiredMinRxInterval != nil {
		if *b.RequiredMinRxInterval == 0 || *b.RequiredMinRxInterval > BFDIntervalMax {
			return fmt.Errorf("bfd required min rx interval must be between 1 and %d milliseconds, got %d",
				BFDIntervalMax, *b.RequiredMinRxInterval)
		}
	}
	return nil
}

// ToGoBGP builds the GoBGP API config for BFD settings. Returns nil
// if BFDConfig is not enabled.
func (b BFDConfig) ToGoBGP() *gobgpapi.BfdPeerConfig {
	if !b.Enabled {
		return nil
	}

	txMs := ptr.Deref(b.DesiredMinTxInterval, options.DefaultBFDDesiredMinTxInterval)
	rxMs := ptr.Deref(b.RequiredMinRxInterval, options.DefaultBFDRequiredMinRxInterval)
	return &gobgpapi.BfdPeerConfig{
		Enabled:                  true,
		Port:                     ptr.Deref(b.Port, options.DefaultBFDPort),
		DetectionMultiplier:      ptr.Deref(b.DetectionMultiplier, options.DefaultBFDDetectionMultiplier),
		DesiredMinimumTxInterval: txMs * msToMicroseconds,
		RequiredMinimumReceive:   rxMs * msToMicroseconds,
	}
}
