package routing

import (
	"errors"
	"fmt"

	"github.com/golang/glog"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
)

// set up MASQUERADE rule so that egress traffic from the pods gets masquraded to node's IP

var (
	podEgressArgs4 = []string{"-m", "set", "--match-set", podSubnetsIPSetName, "src",
		"-m", "set", "!", "--match-set", podSubnetsIPSetName, "dst",
		"-m", "set", "!", "--match-set", nodeAddrsIPSetName, "dst",
		"-j", "MASQUERADE"}
	podEgressArgs6 = []string{"-m", "set", "--match-set", "inet6:" + podSubnetsIPSetName, "src",
		"-m", "set", "!", "--match-set", "inet6:" + podSubnetsIPSetName, "dst",
		"-m", "set", "!", "--match-set", "inet6:" + nodeAddrsIPSetName, "dst",
		"-j", "MASQUERADE"}
	podEgressArgsBad4 = [][]string{{"-m", "set", "--match-set", podSubnetsIPSetName, "src",
		"-m", "set", "!", "--match-set", podSubnetsIPSetName, "dst",
		"-j", "MASQUERADE"}}
	podEgressArgsBad6 = [][]string{{"-m", "set", "--match-set", "inet6:" + podSubnetsIPSetName, "src",
		"-m", "set", "!", "--match-set", "inet6:" + podSubnetsIPSetName, "dst",
		"-j", "MASQUERADE"}}
)

func (nrc *NetworkRoutingController) createPodEgressRule() error {
	podEgressArgs := podEgressArgs4
	if nrc.isIpv6 {
		podEgressArgs = podEgressArgs6
	}

	if _, err := nrc.iptClient.EnsureRule(utiliptables.Append, utiliptables.TableNAT, utiliptables.ChainPostrouting, podEgressArgs...); err != nil {
		return errors.New("Failed to add iptable rule to masqurade outbound traffic from pods: " +
			err.Error() + "External connectivity will not work.")
	}

	glog.V(1).Infof("Added iptables rule to masqurade outbound traffic from pods.")
	return nil
}

func (nrc *NetworkRoutingController) deletePodEgressRule() error {
	podEgressArgs := podEgressArgs4
	if nrc.isIpv6 {
		podEgressArgs = podEgressArgs6
	}

	if err := nrc.iptClient.DeleteRule(utiliptables.TableNAT, utiliptables.ChainPostrouting, podEgressArgs...); err != nil {
		return errors.New("Failed to delete iptable rule to masqurade outbound traffic from pods: " +
			err.Error() + ". Pod egress might still work...")
	}

	glog.Infof("Deleted iptables rule to masqurade outbound traffic from pods.")

	return nil
}

func (nrc *NetworkRoutingController) deleteBadPodEgressRules() error {
	podEgressArgsBad := podEgressArgsBad4
	if nrc.isIpv6 {
		podEgressArgsBad = podEgressArgsBad6
	}

	for _, args := range podEgressArgsBad {
		if err := nrc.iptClient.DeleteRule(utiliptables.TableNAT, utiliptables.ChainPostrouting, args...); err != nil {
			return fmt.Errorf("Failed to delete old/bad iptable rule to "+
				"masqurade outbound traffic from pods: %s.\n"+
				"Pod egress might still work, or bugs may persist after upgrade...",
				err)
		}
		glog.Infof("Deleted old/bad iptables rule to masqurade outbound traffic from pods.")
	}

	return nil
}
