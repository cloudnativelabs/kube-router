package utils

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	v1core "k8s.io/api/core/v1"
)

var hasWait bool

// Interface based on the IPTables struct from github.com/coreos/go-iptables
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
func SaveInto(table string, buffer *bytes.Buffer) error {
	path, err := exec.LookPath("iptables-save")
	if err != nil {
		return err
	}
	stderrBuffer := bytes.NewBuffer(nil)
	args := []string{"iptables-save", "-t", table}
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

// Restore runs `iptables-restore` passing data through []byte.
func Restore(table string, data []byte) error {
	path, err := exec.LookPath("iptables-restore")
	if err != nil {
		return err
	}
	var args []string
	if hasWait {
		args = []string{"iptables-restore", "--wait", "-T", table}
	} else {
		args = []string{"iptables-restore", "-T", table}
	}
	cmd := exec.Cmd{
		Path:  path,
		Args:  args,
		Stdin: bytes.NewBuffer(data),
	}
	b, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v (%s)", err, b)
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

type IPTablesSaveRestore struct {
	saveCmd    string
	restoreCmd string
}

func NewIPTablesSaveRestore(ipFamily v1core.IPFamily) *IPTablesSaveRestore {
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

func (i *IPTablesSaveRestore) SaveInto(table string, buffer *bytes.Buffer) error {
	return i.exec(i.saveCmd, []string{"-t", table}, nil, buffer)
}

func (i *IPTablesSaveRestore) Restore(table string, data []byte) error {
	var args []string
	if hasWait {
		args = []string{"--wait", "-T", table}
	} else {
		args = []string{"-T", table}
	}
	return i.exec(i.restoreCmd, args, data, nil)
}
