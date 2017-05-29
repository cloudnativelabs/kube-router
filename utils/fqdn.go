package utils

import (
	"bytes"
	"os/exec"
)

func GetFqdn() string {
	cmd := exec.Command("hostname", "-f")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Run()
	fqdn := out.String()
	fqdn = fqdn[:len(fqdn)-1]
	return fqdn
}
