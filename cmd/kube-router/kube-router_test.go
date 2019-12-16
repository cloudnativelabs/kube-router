package main

import (
	"bytes"
	"io"
	"os"
	"sync"
	"testing"
)

func TestMainHelp(t *testing.T) {
	origStderr := os.Stderr
	stderrR, stderrW, _ := os.Pipe()
	os.Stderr = stderrW
	defer func() { os.Stderr = origStderr }()

	stderrBuf := bytes.NewBuffer(nil)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		io.Copy(stderrBuf, stderrR)
		wg.Done()
	}()

	origArgs := os.Args
	os.Args = []string{"kube-router", "--help"}
	defer func() { os.Args = origArgs }()

	if err := Main(); err != nil {
		t.Fatalf("kube-router exited with error: %s\n", err)
	}
	stderrW.Close()
	wg.Wait()

	docF, err := os.Open("../../docs/user-guide.md")
	if err != nil {
		t.Fatalf("could not open docs/user-guide.md: %s\n", err)
	}
	docBuf := bytes.NewBuffer(nil)
	docBuf.ReadFrom(docF)
	docF.Close()

	exp := append([]byte("```\n"), stderrBuf.Bytes()...)
	exp = append(exp, []byte("```\n")...)

	if !bytes.Contains(docBuf.Bytes(), exp) {
		t.Errorf("docs/user-guide.md 'command line options' section does not match `kube-router --help`.\nExpected:\n%s", exp)
		t.Errorf("\nGot:\n%s", docBuf.Bytes())
	}
}
