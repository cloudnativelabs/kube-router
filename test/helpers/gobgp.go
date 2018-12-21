package helpers

import (
	"fmt"

	. "github.com/onsi/gomega"
)

// ExpectGobgpNeighEstabl asserts via gobgp that neighbor is in Established state
func (s *SSHMeta) ExpectGobgpNeighEstabl() {
	err := s.WaitUntilNeighborEstabl(100)
	ExpectWithOffset(1, err).To(BeNil(), "gobgp neighbor not in established state")
}

// ExecGobgpNeighCheck checks neighbor node via gobgp
func (s *SSHMeta) ExecGobgpNeighCheck() *CmdRes {
	command := fmt.Sprintf("gobgp neighbor")
	return s.Exec(command)
}

// WaitUntilNeighborEstabl waits until connection to neighbor is Established.
// Returns an error if that does not happend and timeout has elapsed.
func (s *SSHMeta) WaitUntilNeighborEstabl(timeout int64) error {

	body := func() bool {
		res := s.ExecGobgpNeighCheck()
		if res.ExpectContains("Establ", "neighbor *not* in established state: %s", res.Output()) {
			// TODO: we should add something better than just looking for Establ in the output.
			// Will not work with more than one neighbor.
			return true
		} else {
			return false
		}
	}
	err := WithTimeout(body, "neighbor connection not yet established", &TimeoutConfig{Timeout: timeout})
	return err
}
