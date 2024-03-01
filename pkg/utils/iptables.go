package utils

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"k8s.io/klog/v2"

	"github.com/coreos/go-iptables/iptables"
	v1core "k8s.io/api/core/v1"
)

var hasWait bool

// IPTablesHandler interface based on the IPTables struct from github.com/coreos/go-iptables
// which allows to mock it.
type IPTablesHandler interface {
	Proto() iptables.Protocol
	Exists(table, chain string, rulespec ...string) (bool, error)
	Insert(table, chain string, pos int, rulespec ...string) error
	Append(table, chain string, rulespec ...string) error
	AppendUnique(table, chain string, rulespec ...string) error
	Delete(table, chain string, rulespec ...string) error
	DeleteIfExists(table, chain string, rulespec ...string) error
	List(table, chain string) ([]string, error)
	ListWithCounters(table, chain string) ([]string, error)
	ListChains(table string) ([]string, error)
	ChainExists(table, chain string) (bool, error)
	Stats(table, chain string) ([][]string, error)
	ParseStat(stat []string) (iptables.Stat, error)
	StructuredStats(table, chain string) ([]iptables.Stat, error)
	NewChain(table, chain string) error
	ClearChain(table, chain string) error
	RenameChain(table, oldChain, newChain string) error
	DeleteChain(table, chain string) error
	ClearAndDeleteChain(table, chain string) error
	ClearAll() error
	DeleteAll() error
	ChangePolicy(table, chain, target string) error
	HasRandomFully() bool
	GetIptablesVersion() (int, int, int)
}

//nolint:gochecknoinits // This is actually a good usage of the init() function
func init() {
	path, err := exec.LookPath("iptables-restore")
	if err != nil {
		return
	}
	args := []string{"iptables-restore", "--help"}
	cmd := exec.Cmd{
		Path: path,
		Args: args,
	}
	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		return
	}
	hasWait = strings.Contains(string(cmdOutput), "wait")
}

// SaveInto calls `iptables-save` for given table and stores result in a given buffer.
func SaveInto(iptablesBinary, table string, buffer *bytes.Buffer) error {
	path, err := exec.LookPath(iptablesBinary)
	if err != nil {
		return err
	}
	stderrBuffer := bytes.NewBuffer(nil)
	args := []string{iptablesBinary, "-t", table}
	klog.V(9).Infof("running iptables command: path=`%s` args=%+v", path, args)
	cmd := exec.Cmd{
		Path:   path,
		Args:   args,
		Stdout: buffer,
		Stderr: stderrBuffer,
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v (%s)", err, stderrBuffer)
	}
	return nil
}

// AppendUnique ensures that rule is in chain only once in the buffer and that the occurrence is at the end of the
// buffer
func AppendUnique(buffer *bytes.Buffer, chain string, rule []string) {
	// First we need to remove any previous instances of the rule that exist, so that we can be sure that our version
	// is unique and appended to the very end of the buffer
	rules := strings.Split(buffer.String(), "\n")
	if len(rules) > 0 && rules[len(rules)-1] == "" {
		rules = rules[:len(rules)-1]
	}
	buffer.Reset()

	for _, foundRule := range rules {
		if strings.Contains(foundRule, chain) && strings.Contains(foundRule, strings.Join(rule, " ")) {
			continue
		}
		buffer.WriteString(foundRule + "\n")
	}

	// Now append the rule that we wanted to be unique
	Append(buffer, chain, rule)
}

// Append appends rule to chain at the end of buffer
func Append(buffer *bytes.Buffer, chain string, rule []string) {
	ruleStr := strings.Join(append(append([]string{"-A", chain}, rule...), "\n"), " ")
	buffer.WriteString(ruleStr)
}

// IPTablesSaveRestorer interface that defines functions to save and restore tables
type IPTablesSaveRestorer interface {
	SaveInto(table string, buffer *bytes.Buffer) error
	Restore(table string, data []byte) error
}

// IPTablesSaveRestore struct stores shell commands to save and restore iptables state
type IPTablesSaveRestore struct {
	saveCmd    string
	restoreCmd string
}

// NewIPTablesSaveRestore returns an IPTablesSaveRestore
// with apparopriate commands based on ipFamily (IPv4 or IPv6)
func NewIPTablesSaveRestore(ipFamily v1core.IPFamily) *IPTablesSaveRestore {
	//nolint:exhaustive // we don't need exhaustive searching for IP Families
	switch ipFamily {
	case v1core.IPv6Protocol:
		return &IPTablesSaveRestore{
			saveCmd:    "ip6tables-save",
			restoreCmd: "ip6tables-restore",
		}
	case v1core.IPv4Protocol:
		fallthrough
	default:
		return &IPTablesSaveRestore{
			saveCmd:    "iptables-save",
			restoreCmd: "iptables-restore",
		}
	}
}

func (i *IPTablesSaveRestore) exec(cmdName string, args []string, data []byte, stdoutBuffer *bytes.Buffer) error {
	path, err := exec.LookPath(cmdName)
	if err != nil {
		return err
	}
	stderrBuffer := bytes.NewBuffer(nil)
	cmd := exec.Cmd{
		Path:   path,
		Args:   append([]string{cmdName}, args...),
		Stderr: stderrBuffer,
	}
	if data != nil {
		cmd.Stdin = bytes.NewBuffer(data)
	}
	if stdoutBuffer != nil {
		cmd.Stdout = stdoutBuffer
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to call %s: %v (%s)", cmdName, err, stderrBuffer)
	}

	return nil
}

// SaveInto saves the content of iptables table into buffer
func (i *IPTablesSaveRestore) SaveInto(table string, buffer *bytes.Buffer) error {
	return i.exec(i.saveCmd, []string{"-t", table}, nil, buffer)
}

// Restore updates table with the content of data
func (i *IPTablesSaveRestore) Restore(table string, data []byte) error {
	var args []string
	if hasWait {
		args = []string{"--wait", "-T", table}
	} else {
		args = []string{"-T", table}
	}
	return i.exec(i.restoreCmd, args, data, nil)
}
