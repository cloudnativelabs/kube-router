package netpol

import (
	"bufio"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"text/template"
)

const (
	NFTABLES_FILE       = "/tmp/kube-router.nft"
	NFTABLES_TABLE_NAME = "kube-router"
	KUBE_BRIDGE_IF      = "kube-bridge"
	NFTABLES_TEMPLATE   = `
	delete table {{.TableName}}
	create table {{.TableName}}

	table {{.TableName}} {

		chain egress {
			type filter hook prerouting priority -120; policy accept
			{{template "accept" .}}

			{{range .EgressPods}}
				ip saddr {{.IP}} jump {{.Namespace}}-{{.Name}}-egress-fw
			{{end}}
			{{if defaultDeny}}ip saddr { {{podCIDR}} } {{template "drop"}}{{end}}
		}

		chain ingress-forward {
			type filter hook forward priority 0; policy accept
			{{template "accept" .}}
			meta mark 32760 {{template "reject"}}

			{{range .IngressPods}}
				ip daddr {{.IP}} jump {{.Namespace}}-{{.Name}}-ingress-fw
			{{end}}
			{{if defaultDeny}}ip daddr { {{podCIDR}} } {{template "drop"}}{{end}}
		}

		chain ingress-output {
			type filter hook output priority 0; policy accept
			{{template "accept" .}}
			meta mark 32760 reject

			{{range .IngressPods}}
				ip daddr {{.IP}} jump {{.Namespace}}-{{.Name}}-ingress-fw
			{{end}}
			{{if defaultDeny}}ip daddr { {{podCIDR}} } {{template "drop"}}{{end}}
		}

		{{$policies := .Policies}}
		{{range .IngressPods}}
		chain {{.Namespace}}-{{.Name}}-ingress-fw {
			ct state established,related accept
			ct state invalid {{template "drop"}}
			{{with $pod := .}}
			{{range $policies}}
				{{if .Matches $pod}}jump {{.Namespace}}-{{.Name}}-netpol-ingress{{end}}{{end}}
			{{end}}
			{{template "reject"}}
		}
		{{end}}
		{{range .EgressPods}}
		chain {{.Namespace}}-{{.Name}}-egress-fw {
			ct state established,related accept
			ct state invalid {{template "drop"}}
			{{with $pod := .}}
			{{range $policies}}
				{{if .Matches $pod}}jump {{.Namespace}}-{{.Name}}-netpol-egress{{end}}{{end}}
			{{end}}
			{{template "markforreject"}}
		}
		{{end}}

		{{range .Policies}}
			{{template "policy" .}}
		{{end}}
	}

	{{define "policy"}}
	{{if .TargetPods}}
	{{with $p := .}}
		chain {{.Namespace}}-{{.Name}}-netpol-ingress {
		{{range .IngressRules}}
			{{with $r := .}}
			{{if .MatchAllPorts}}
				ip daddr { {{ range $p.TargetPods }}{{ .IP }},{{end}} }{{if not $r.MatchAllSource}}{{genIPSetFromIngressRule $r}}{{end}} accept
			{{else}}
				{{range .Ports}}
					ip daddr { {{ range $p.TargetPods }}{{ .IP }},{{end}} }{{if not $r.MatchAllSource}}{{genIPSetFromIngressRule $r}}{{end}} {{template "port" .}} accept
				{{end}}
			{{end}}
			{{end}}
		{{end}}
		}
		chain {{.Namespace}}-{{.Name}}-netpol-egress {
		{{range .EgressRules}}
			{{with $r := .}}
			{{if .MatchAllPorts}}
				ip saddr { {{ range $p.TargetPods }}{{ .IP }},{{end}} }{{if not $r.MatchAllDestinations}}{{genIPSetFromEgressRule $r}}{{end}} accept
			{{else}}
				{{range .Ports}}
					ip saddr { {{ range $p.TargetPods }}{{ .IP }},{{end}} }{{if not $r.MatchAllDestinations}}{{genIPSetFromEgressRule $r}}{{end}} {{template "port" .}} accept
				{{end}}
			{{end}}
			{{end}}
		{{end}}
		}
	{{end}}
	{{end}}
	{{end}}

	{{define "port"}}{{$proto := toLower .Protocol}}{{if .Port}}{{ $proto }} dport {{.Port}}{{else}}ip protocol {{ $proto }}{{end}}{{end}}
	{{define "accept"}}
		ip protocol icmp accept
		{{if .LocalIp4}}ip saddr { {{range .LocalIp4}}{{.}},{{end}} } accept{{end}}
	{{end}}
	{{define "markforreject"}}nftrace set 1 mark set 32760{{end}}
	{{define "reject"}}nftrace set 1 reject{{end}}
	{{define "drop"}}nftrace set 1 drop{{end}}

`
)

type NFTablesInfo struct {
	IngressPods map[string]PodInfo
	EgressPods  map[string]PodInfo
	Policies    []NetworkPolicyInfo
	LocalIp4    []string
	LocalIp6    []string
	TableName   string
}

type NFTables struct {
	template *template.Template
	dead     bool
}

func NewNFTablesHandler(podCIDR string, defaultDeny bool) (*NFTables, error) {
	t, err := template.New("table").Funcs(template.FuncMap{
		"toLower":                 strings.ToLower,
		"genIPSetFromIngressRule": genIPSetFromIngressRule,
		"genIPSetFromEgressRule":  genIPSetFromEgressRule,
		"defaultDeny": func() bool {
			return defaultDeny
		},
		"podCIDR": func() string {
			return podCIDR
		},
	}).Parse(NFTABLES_TEMPLATE)
	if err != nil {
		return nil, err
	}

	nft := &NFTables{
		template: t,
		dead:     false,
	}

	return nft, nil
}

func (nft *NFTables) Init() {
	//TODO: Check for nftables binary in path, perhaps kernel version?

	nft.execNftablesCmd("create", "table", NFTABLES_TABLE_NAME)
}

func (nft *NFTables) Sync(networkPoliciesInfo *[]NetworkPolicyInfo, ingressPods, egressPods *map[string]PodInfo) error {
	if nft.dead {
		return errors.New("Cannot sync nftables with a killed NFTable handler")
	}

	glog.V(2).Infof("Flushing nftables configuration to file: %s", NFTABLES_FILE)

	ip4, ip6, err := getLocalAddrs()
	if err != nil {
		return err
	}

	file, _ := os.Create(NFTABLES_FILE)
	defer file.Close()
	writer := bufio.NewWriter(file)
	err = nft.Generate(writer, &NFTablesInfo{
		IngressPods: *ingressPods,
		EgressPods:  *egressPods,
		Policies:    *networkPoliciesInfo,
		LocalIp4:    *ip4,
		LocalIp6:    *ip6,
		TableName:   NFTABLES_TABLE_NAME,
	})
	if err != nil {
		return err
	}
	writer.Flush()

	return nft.execNftablesCmd("-f", NFTABLES_FILE)
}

func (nft *NFTables) Generate(writer *bufio.Writer, info *NFTablesInfo) error {
	return nft.template.Execute(writer, info)
}

func (nft *NFTables) execNftablesCmd(args ...string) error {
	cmd := exec.Command("nft", args...)
	glog.V(2).Infof("Execute nftables command: %s", strings.Join(args, " "))
	return cmd.Run()
}

func (nft *NFTables) Cleanup() {
	nft.Shutdown()
	os.Remove(NFTABLES_FILE)
	nft.execNftablesCmd("delete", "table", NFTABLES_TABLE_NAME)
}

func (nft *NFTables) Shutdown() {
	nft.dead = true
}

func getLocalAddrs() (*[]string, *[]string, error) {
	ifaces, err := net.InterfaceByName(KUBE_BRIDGE_IF)
	if err != nil {
		return nil, nil, err
	}
	addrs, err := ifaces.Addrs()
	if err != nil {
		return nil, nil, err
	}

	ip4 := make([]string, 0)
	ip6 := make([]string, 0)
	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPAddr:
			if v.IP.To4() != nil {
				ip4 = append(ip4, v.IP.String())
			} else {
				ip6 = append(ip6, v.IP.String())
			}
		case *net.IPNet:
			if v.IP.To4() != nil {
				ip4 = append(ip4, v.IP.String())
			} else {
				ip6 = append(ip6, v.IP.String())
			}
		}
	}

	return &ip4, &ip6, nil
}

func genIPSetFromIngressRule(rule IngressRule) string {
	var (
		positive []string
		negative []string
	)

	for _, p := range rule.SrcPods {
		positive = append(positive, p.IP)
	}
	for _, b := range rule.SrcIPBlocks {
		positive = append(positive, b.CIDR)
		negative = append(negative, b.Except...)
	}

	return genIpSet(positive, negative, "saddr")
}

func genIPSetFromEgressRule(rule EgressRule) string {
	var (
		positive []string
		negative []string
	)

	for _, p := range rule.DstPods {
		positive = append(positive, p.IP)
	}
	for _, b := range rule.DstIPBlocks {
		positive = append(positive, b.CIDR)
		negative = append(negative, b.Except...)
	}

	return genIpSet(positive, negative, "daddr")
}

func genIpSet(positive []string, negative []string, matches string) string {
	var builder strings.Builder

	if len(positive) > 0 {
		builder.WriteString(" ip ")
		builder.WriteString(matches)
		builder.WriteString(" { ")
		builder.WriteString(strings.Join(positive, ","))
		builder.WriteString(" }")
	}
	if len(negative) > 0 {
		builder.WriteString(" ip ")
		builder.WriteString(matches)
		builder.WriteString(" != { ")
		builder.WriteString(strings.Join(negative, ","))
		builder.WriteString(" }")
	}

	return builder.String()
}
