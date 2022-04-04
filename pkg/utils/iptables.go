package utils

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

var hasWait bool

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

// iptablesExec contains the common logic for calling save and restore
// commands.
func iptablesExec(cmdName string, args []string, data []byte, stdoutBuffer *bytes.Buffer) error {
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
		return fmt.Errorf("failed to call %s %v: %w, (%s)", cmdName, args, err, stderrBuffer.String())
	}
	return nil
}

// SaveInto calls `iptables-save` for given table and stores result in a given buffer.
func SaveInto(table string, buffer *bytes.Buffer) error {
	return iptablesExec("iptables-save", []string{"-t", table}, nil, buffer)
}

// Restore runs `iptables-restore` passing data through []byte.
func Restore(table string, data []byte) error {
	var args []string
	if hasWait {
		args = []string{"--wait", "-T", table}
	} else {
		args = []string{"-T", table}
	}

	return iptablesExec("iptables-restore", args, data, nil)
}

// AppendUnique ensures that rule is in chain only once in the buffer and that the occurrence is at the end of the
// buffer
func AppendUnique(buffer bytes.Buffer, chain string, rule []string) bytes.Buffer {
	var desiredBuffer bytes.Buffer

	// First we need to remove any previous instances of the rule that exist, so that we can be sure that our version
	// is unique and appended to the very end of the buffer
	rules := strings.Split(buffer.String(), "\n")
	if len(rules) > 0 && rules[len(rules)-1] == "" {
		rules = rules[:len(rules)-1]
	}
	for _, foundRule := range rules {
		if strings.Contains(foundRule, chain) && strings.Contains(foundRule, strings.Join(rule, " ")) {
			continue
		}
		desiredBuffer.WriteString(foundRule + "\n")
	}

	// Now append the rule that we wanted to be unique
	desiredBuffer = Append(desiredBuffer, chain, rule)
	return desiredBuffer
}

// Append appends rule to chain at the end of buffer
func Append(buffer bytes.Buffer, chain string, rule []string) bytes.Buffer {
	ruleStr := strings.Join(append([]string{"-A", chain}, rule...), " ")
	buffer.WriteString(ruleStr + "\n")
	return buffer
}
