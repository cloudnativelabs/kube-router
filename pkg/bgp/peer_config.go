package bgp

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/goccy/go-yaml"
)

type PeerConfig struct {
	remoteASN uint32             `yaml:"remoteasn"`
	remoteIP  net.IP             `yaml:"remoteip"`
	localIP   string             `yaml:"localip"`
	password  utils.Base64String `yaml:"password"`
	port      *uint32            `yaml:"port"`
}

func NewPeerConfig(remoteIPStr string, remoteASN uint32, port *uint32, b64EncodedPassword utils.Base64String,
	localIP string,
) (PeerConfig, error) {
	remoteIP := net.ParseIP(remoteIPStr)
	if remoteIP == nil {
		return PeerConfig{}, fmt.Errorf("invalid IP address: %s", remoteIPStr)
	}
	if err := validateASN(remoteASN); err != nil {
		return PeerConfig{}, err
	}

	return PeerConfig{
		remoteIP:  remoteIP,
		remoteASN: remoteASN,
		localIP:   localIP,
		password:  b64EncodedPassword,
		port:      port,
	}, nil
}

func (p PeerConfig) RemoteASN() uint32 {
	return p.remoteASN
}

func (p PeerConfig) RemoteIP() net.IP {
	return p.remoteIP
}

func (p PeerConfig) LocalIP() string {
	return p.localIP
}

func (p PeerConfig) Password() string {
	return string(p.password)
}

func (p PeerConfig) Port() *uint32 {
	return p.port
}

// Custom Stringer to prevent leaking passwords when printed
func (p PeerConfig) String() string {
	var fields []string
	if p.localIP != "" {
		fields = append(fields, fmt.Sprintf("LocalIP: %s", p.localIP))
	}
	if p.port != nil {
		fields = append(fields, fmt.Sprintf("Port: %d", *p.port))
	}
	if p.remoteASN != uint32(0) {
		fields = append(fields, fmt.Sprintf("RemoteASN: %d", p.remoteASN))
	}
	if p.remoteIP != nil {
		fields = append(fields, fmt.Sprintf("RemoteIP: %v", p.remoteIP))
	}
	return fmt.Sprintf("PeerConfig{%s}", strings.Join(fields, ", "))
}

func (p *PeerConfig) UnmarshalYAML(raw []byte) error {
	tmp := struct {
		LocalIP   *string             `yaml:"localip"`
		Password  *utils.Base64String `yaml:"password"`
		Port      *uint32             `yaml:"port"`
		RemoteASN *uint32             `yaml:"remoteasn"`
		RemoteIP  *string             `yaml:"remoteip"`
	}{}

	if err := yaml.Unmarshal(raw, &tmp); err != nil {
		return fmt.Errorf("failed to unmarshal peer config: %w", err)
	}

	if tmp.RemoteIP == nil {
		return errors.New("remoteip cannot be empty")
	}
	if tmp.RemoteASN == nil {
		return errors.New("remoteasn cannot be empty")
	}
	if err := validateASN(*tmp.RemoteASN); err != nil {
		return err
	}
	if tmp.LocalIP != nil {
		p.localIP = *tmp.LocalIP
	}
	if tmp.Password != nil {
		p.password = *tmp.Password
	}
	p.port = tmp.Port
	p.remoteASN = *tmp.RemoteASN
	ip := net.ParseIP(*tmp.RemoteIP)
	if ip == nil {
		return fmt.Errorf("%s is not a valid IP address", *tmp.RemoteIP)
	}
	p.remoteIP = ip
	return nil
}

type PeerConfigs []PeerConfig

func (p PeerConfigs) RemoteIPStrings() []string {
	remoteIPs := make([]string, 0)
	for _, cfg := range p {
		remoteIPs = append(remoteIPs, cfg.RemoteIP().String())
	}
	return remoteIPs
}

// Prints the PeerConfigs without the passwords leaking
func (p PeerConfigs) String() string {
	pcs := make([]string, len(p))
	for i, pc := range p {
		pcs[i] = pc.String()
	}
	return fmt.Sprintf("PeerConfigs[%s]", strings.Join(pcs, ","))
}

func NewPeerConfigs(
	remoteIPs []string,
	remoteASNs []uint32,
	ports []uint32,
	b64EncodedPasswords []string,
	localIPs []string,
	localAddress string,
) (PeerConfigs, error) {
	if len(remoteIPs) != len(remoteASNs) {
		return nil, errors.New("invalid peer router config, the number of IPs and ASN numbers must be equal")
	}
	if len(remoteIPs) != len(b64EncodedPasswords) && len(b64EncodedPasswords) != 0 {
		return nil, errors.New("invalid peer router config. The number of passwords should either be zero, or " +
			"one per peer router. Use blank items if a router doesn't expect a password. Example: \"pass,,pass\" " +
			"OR [\"pass\",\"\",\"pass\"]")
	}
	if len(remoteIPs) != len(ports) && len(ports) != 0 {
		return nil, fmt.Errorf("invalid peer router config. The number of ports should either be zero, or "+
			"one per peer router. If blank items are used, it will default to standard BGP port, %s. ",
			strconv.Itoa(options.DefaultBgpPort))
	}
	if len(remoteIPs) != len(localIPs) && len(localIPs) != 0 {
		return nil, fmt.Errorf("invalid peer router config. The number of localIPs should either be zero, or "+
			"one per peer router. If blank items are used, it will default to nodeIP, %s. ", localAddress)
	}

	peerCfgs := make(PeerConfigs, len(remoteIPs))
	for i, remoteIP := range remoteIPs {
		var localIP string
		var pw utils.Base64String
		var port *uint32
		if len(ports) != 0 {
			port = &ports[i]
		}
		if len(b64EncodedPasswords) != 0 {
			pw = utils.Base64String(b64EncodedPasswords[i])
		}
		if len(localIPs) != 0 {
			localIP = localIPs[i]
		}
		peerCfg, err := NewPeerConfig(remoteIP, remoteASNs[i], port, pw, localIP)
		if err != nil {
			return nil, err
		}
		peerCfgs[i] = peerCfg
	}

	return peerCfgs, nil
}

func validateASN(asn uint32) error {
	if (asn < 1 || asn > 23455) &&
		(asn < 23457 || asn > 63999) &&
		(asn < 64512 || asn > 65534) &&
		(asn < 131072 || asn > 4199999999) &&
		(asn < 4200000000 || asn > 4294967294) {
		return fmt.Errorf("reserved ASN number \"%d\" for global BGP peer", asn)
	}
	return nil
}
