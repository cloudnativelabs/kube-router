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
	LocalIP   *string             `yaml:"localip"`
	Password  *utils.Base64String `yaml:"password"`
	Port      uint32              `yaml:"port"`
	RemoteASN *uint32             `yaml:"remoteasn"`
	RemoteIP  *net.IP             `yaml:"remoteip"`
}

// Custom Stringer to prevent leaking passwords when printed
func (p PeerConfig) String() string {
	var fields []string
	fields = append(fields, fmt.Sprintf("Port: %d", p.Port))

	if p.LocalIP != nil {
		fields = append(fields, fmt.Sprintf("LocalIP: %s", *p.LocalIP))
	}
	if p.RemoteASN != nil {
		fields = append(fields, fmt.Sprintf("RemoteASN: %d", *p.RemoteASN))
	}
	if p.RemoteIP != nil {
		fields = append(fields, fmt.Sprintf("RemoteIP: %v", *p.RemoteIP))
	}
	return fmt.Sprintf("PeerConfig{%s}", strings.Join(fields, ", "))
}

func (p *PeerConfig) UnmarshalYAML(raw []byte) error {
	tmp := struct {
		LocalIP   *string             `yaml:"localip"`
		Password  *utils.Base64String `yaml:"password"`
		Port      uint32              `yaml:"port"`
		RemoteASN *uint32             `yaml:"remoteasn"`
		RemoteIP  string              `yaml:"remoteip"`
	}{}

	if err := yaml.Unmarshal(raw, &tmp); err != nil {
		return fmt.Errorf("failed to unmarshal peer config: %w", err)
	}

	p.LocalIP = tmp.LocalIP
	p.Password = tmp.Password
	p.Port = tmp.Port
	p.RemoteASN = tmp.RemoteASN

	if tmp.RemoteIP != "" {
		ip := net.ParseIP(tmp.RemoteIP)
		if ip == nil {
			return fmt.Errorf("%s is not a valid IP address", tmp.RemoteIP)
		}
		p.RemoteIP = &ip
	}
	return nil
}

type PeerConfigs []PeerConfig

func (p PeerConfigs) LocalIPs() []string {
	localIPs := make([]string, 0)
	for _, cfg := range p {
		if cfg.LocalIP != nil {
			localIPs = append(localIPs, *cfg.LocalIP)
		}
	}
	return localIPs
}

// Returns b64 decoded passwords
func (p PeerConfigs) Passwords() []string {
	passwords := make([]string, 0)
	for _, cfg := range p {
		if cfg.Password != nil {
			passwords = append(passwords, string(*cfg.Password))
		}
	}
	return passwords
}

func (p PeerConfigs) Ports() []uint32 {
	ports := make([]uint32, 0)
	for _, cfg := range p {
		ports = append(ports, cfg.Port)
	}
	return ports
}

func (p PeerConfigs) RemoteASNs() []uint32 {
	asns := make([]uint32, 0)
	for _, cfg := range p {
		if cfg.RemoteASN != nil {
			asns = append(asns, *cfg.RemoteASN)
		}
	}
	return asns
}

func (p PeerConfigs) RemoteIPs() []net.IP {
	remoteIPs := make([]net.IP, 0)
	for _, cfg := range p {
		if cfg.RemoteIP != nil {
			remoteIPs = append(remoteIPs, *cfg.RemoteIP)
		}
	}
	return remoteIPs
}

func (p PeerConfigs) RemoteIPStrings() []string {
	remoteIPs := make([]string, 0)
	for _, cfg := range p {
		if cfg.RemoteIP != nil {
			remoteIPs = append(remoteIPs, cfg.RemoteIP.String())
		}
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

func (p *PeerConfigs) UnmarshalYAML(raw []byte) error {
	type tmpPeerConfigs PeerConfigs
	tmp := (*tmpPeerConfigs)(p)

	if err := yaml.Unmarshal(raw, tmp); err != nil {
		return err
	}

	return p.Validate()
}

func (p PeerConfigs) Validate() error {
	return validatePeerConfigs(p.RemoteIPStrings(), p.RemoteASNs(), p.Ports(), p.Passwords(), p.LocalIPs(), "")
}

func NewPeerConfigs(
	remoteIPs []string,
	remoteASNs []uint32,
	ports []uint32,
	b64EncodedPasswords []string,
	localIPs []string,
	localAddress string,
) (PeerConfigs, error) {
	if err := validatePeerConfigs(remoteIPs, remoteASNs, ports, b64EncodedPasswords, localIPs, localAddress); err != nil {
		return nil, err
	}

	peerCfgs := make(PeerConfigs, len(remoteIPs))
	for i, remoteIP := range remoteIPs {
		ip := net.ParseIP(remoteIP)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %s", remoteIP)
		}
		peerCfgs[i].RemoteIP = &ip
		peerCfgs[i].RemoteASN = &remoteASNs[i]

		if len(ports) != 0 {
			peerCfgs[i].Port = ports[i]
		}

		if len(b64EncodedPasswords) != 0 {
			pw := utils.Base64String(b64EncodedPasswords[i])
			peerCfgs[i].Password = &pw
		}

		if len(localIPs) != 0 && localIPs[i] != "" {
			peerCfgs[i].LocalIP = &localIPs[i]
		}
	}

	return peerCfgs, nil
}

func validatePeerConfigs(
	remoteIPs []string,
	remoteASNs []uint32,
	ports []uint32,
	b64EncodedPasswords []string,
	localIPs []string,
	localAddress string,
) error {
	if len(remoteIPs) != len(remoteASNs) {
		return errors.New("invalid peer router config, the number of IPs and ASN numbers must be equal")
	}
	if len(remoteIPs) != len(b64EncodedPasswords) && len(b64EncodedPasswords) != 0 {
		return errors.New("invalid peer router config. The number of passwords should either be zero, or " +
			"one per peer router. Use blank items if a router doesn't expect a password. Example: \"pass,,pass\" " +
			"OR [\"pass\",\"\",\"pass\"]")
	}
	if len(remoteIPs) != len(ports) && len(ports) != 0 {
		return fmt.Errorf("invalid peer router config. The number of ports should either be zero, or "+
			"one per peer router. If blank items are used, it will default to standard BGP port, %s. "+
			"Example: \"port,,port\" OR [\"port\",\"\",\"port\"]", strconv.Itoa(options.DefaultBgpPort))
	}
	if len(remoteIPs) != len(localIPs) && len(localIPs) != 0 {
		return fmt.Errorf("invalid peer router config. The number of localIPs should either be zero, or "+
			"one per peer router. If blank items are used, it will default to nodeIP, %s. "+
			"Example: \"10.1.1.1,,10.1.1.2\" OR [\"10.1.1.1\",\"\",\"10.1.1.2\"]", localAddress)
	}

	for _, asn := range remoteASNs {
		if (asn < 1 || asn > 23455) &&
			(asn < 23457 || asn > 63999) &&
			(asn < 64512 || asn > 65534) &&
			(asn < 131072 || asn > 4199999999) &&
			(asn < 4200000000 || asn > 4294967294) {
			return fmt.Errorf("reserved ASN number \"%d\" for global BGP peer",
				asn)
		}
	}

	return nil
}
