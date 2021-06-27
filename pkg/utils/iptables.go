package utils

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

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
	args = []string{"iptables-restore", "--help"}
	cmd := exec.Cmd{
		Path: path,
		Args: args,
	}
	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v (%s)", err, cmdOutput)
	}
	if strings.Contains(string(cmdOutput), "wait") {
		args = []string{"iptables-restore", "--wait", "-T", table}
	} else {
		args = []string{"iptables-restore", "-T", table}
	}

	cmd = exec.Cmd{
		Path:  path,
		Args:  args,
		Stdin: bytes.NewBuffer(data),
	}
	cmdOutput, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v (%s)", err, cmdOutput)
	}

	return nil
}
