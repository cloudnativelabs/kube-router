package routing

import (
	"errors"
	"fmt"

	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
)

// set up MASQUERADE rule so that egress traffic from the pods gets masquraded to node's IP

var (
	podEgressArgs = []string{"-m", "set", "--match-set", podSubnetsIPSetName, "src",
		"-m", "set", "!", "--match-set", podSubnetsIPSetName, "dst",
		"-m", "set", "!", "--match-set", nodeAddrsIPSetName, "dst",
		"-j", "MASQUERADE"}
	podEgressArgsBad = [][]string{{"-m", "set", "--match-set", podSubnetsIPSetName, "src",
		"-m", "set", "!", "--match-set", podSubnetsIPSetName, "dst",
		"-j", "MASQUERADE"}}
)

func createPodEgressRule() error {
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed create iptables handler:" + err.Error())
	}

	err = iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", podEgressArgs...)
	if err != nil {
		return errors.New("Failed to add iptable rule to masqurade outbound traffic from pods: " +
			err.Error() + "External connectivity will not work.")

	}

	glog.V(1).Infof("Added iptables rule to masqurade outbound traffic from pods.")
	return nil
}

func deletePodEgressRule() error {
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed create iptables handler:" + err.Error())
	}

	exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", podEgressArgs...)
	if err != nil {
		return errors.New("Failed to lookup iptable rule to masqurade outbound traffic from pods: " + err.Error())
	}

	if exists {
		err = iptablesCmdHandler.Delete("nat", "POSTROUTING", podEgressArgs...)
		if err != nil {
			return errors.New("Failed to delete iptable rule to masqurade outbound traffic from pods: " +
				err.Error() + ". Pod egress might still work...")
		}
		glog.Infof("Deleted iptables rule to masqurade outbound traffic from pods.")
	}

	return nil
}

func deleteBadPodEgressRules() error {
	iptablesCmdHandler, err := iptables.New()
	if err != nil {
		return errors.New("Failed create iptables handler:" + err.Error())
	}

	for _, args := range podEgressArgsBad {
		exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", args...)
		if err != nil {
			return fmt.Errorf("Failed to lookup iptables rule: %s", err.Error())
		}

		if exists {
			err = iptablesCmdHandler.Delete("nat", "POSTROUTING", args...)
			if err != nil {
				return fmt.Errorf("Failed to delete old/bad iptable rule to "+
					"masqurade outbound traffic from pods: %s.\n"+
					"Pod egress might still work, or bugs may persist after upgrade...",
					err)
			}
			glog.Infof("Deleted old/bad iptables rule to masqurade outbound traffic from pods.")
		}
	}

	return nil
}
