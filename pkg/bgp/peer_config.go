package bgp

import (
	"fmt"
	"net"

	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/goccy/go-yaml"
)

type PeerConfig struct {
	LocalIP   *string             `yaml:"localip"`
	Password  *utils.Base64String `yaml:"password"`
	Port      *uint32             `yaml:"port"`
	RemoteASN *uint32             `yaml:"remoteasn"`
	RemoteIP  *net.IP             `yaml:"remoteip"`
}

func (p *PeerConfig) UnmarshalYAML(raw []byte) error {
	tmp := struct {
		LocalIP   *string             `yaml:"localip"`
		Password  *utils.Base64String `yaml:"password"`
		Port      *uint32             `yaml:"port"`
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
		if cfg.Port != nil {
			ports = append(ports, *cfg.Port)
		}
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
