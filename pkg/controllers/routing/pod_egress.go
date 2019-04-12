package routing

import (
	"errors"
	"fmt"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/golang/glog"
	apiv1 "k8s.io/api/core/v1"
	"strings"
)

// set up MASQUERADE rule so that egress traffic from the pods gets masqueraded to node's IP
// or set up SNAT rule so that egress traffic from the pods uses external egress IP

var (
	podMasqueradeEgressArgs4 = [][]string{{"-m", "set", "--match-set", podSubnetsIPSetName, "src",
		"-m", "set", "!", "--match-set", podSubnetsIPSetName, "dst",
		"-m", "set", "!", "--match-set", nodeAddrsIPSetName, "dst",
		"-j", "MASQUERADE"}}
	podMasqueradeEgressArgs6 = [][]string{{"-m", "set", "--match-set", "inet6:" + podSubnetsIPSetName, "src",
		"-m", "set", "!", "--match-set", "inet6:" + podSubnetsIPSetName, "dst",
		"-m", "set", "!", "--match-set", "inet6:" + nodeAddrsIPSetName, "dst",
		"-j", "MASQUERADE"}}

	podEgressArgsBad4 = [][]string{{"-m", "set", "--match-set", podSubnetsIPSetName, "src",
		"-m", "set", "!", "--match-set", podSubnetsIPSetName, "dst",
		"-j", "MASQUERADE"}}
	podEgressArgsBad6 = [][]string{{"-m", "set", "--match-set", "inet6:" + podSubnetsIPSetName, "src",
		"-m", "set", "!", "--match-set", "inet6:" + podSubnetsIPSetName, "dst",
		"-j", "MASQUERADE"}}

	podSnatEgressArgs4 = [][]string{
		{"-m", "set", "!", "--match-set", podSubnetsIPSetName, "src", "-j", "RETURN"},
		{"-m", "set", "--match-set", podSubnetsIPSetName, "dst", "-j", "RETURN"},
		{"-m", "set", "--match-set", nodeAddrsIPSetName, "dst", "-j", "RETURN"},
		{"-d", "10.0.0.0/8", "-j", "MASQUERADE"},
	}
	podSnatEgressArgs6 = [][]string{
		{"-m", "set", "!", "--match-set", "inet6:" + podSubnetsIPSetName, "src", "-j", "RETURN"},
		{"-m", "set", "--match-set", "inet6:" + podSubnetsIPSetName, "dst", "-j", "RETURN"},
		{"-m", "set", "--match-set", "inet6:" + nodeAddrsIPSetName, "dst", "-j", "RETURN"},
		{"-d", "10.0.0.0/8", "-j", "MASQUERADE"},
	}
)

func (nrc *NetworkRoutingController) preparePodEgress(node *apiv1.Node, kubeRouterConfig *options.KubeRouterConfig) {
	if nrc.egressIP != nil {
		var args [][]string

		if nrc.isIpv6 {
			args = podSnatEgressArgs6
			podEgressArgsBad6 = append(podEgressArgsBad6, podMasqueradeEgressArgs6...)
		} else {
			args = podSnatEgressArgs4
			podEgressArgsBad4 = append(podEgressArgsBad4, podMasqueradeEgressArgs4...)
		}

		args = append(args, []string{"-j", "SNAT", "--to-source", nrc.egressIP.String()})

		if nrc.isIpv6 {
			podSnatEgressArgs6 = args
		} else {
			podSnatEgressArgs4 = args
		}

		glog.V(1).Infof("Using SNAT to '%s' instead of MASQUERADE for outbound traffic from pods.", nrc.egressIP.String())
	} else {
		if nrc.isIpv6 {
			podEgressArgsBad6 = append(podEgressArgsBad6, podSnatEgressArgs6...)
		} else {
			podEgressArgsBad4 = append(podEgressArgsBad4, podSnatEgressArgs4...)
		}

		iptablesCmdHandler, err := nrc.newIptablesCmdHandler()
		if err != nil {
			glog.Error("Failed create iptables handler: " + err.Error())
			return
		}

		rules, err := iptablesCmdHandler.List("nat", "POSTROUTING")
		if err != nil {
			glog.Error("Failed to list rules from 'nat' table in 'POSTROUTING' chain: " + err.Error())
			return
		}

		//find the snat rule and add it to the list of rules to be removed
		for _, rule := range rules {
			if strings.Contains(rule, "-j SNAT --to-source") {
				snatRuleArgs := strings.Split(rule, " ")[2:]
				if nrc.isIpv6 {
					podEgressArgsBad6 = append(podEgressArgsBad6, snatRuleArgs)
				} else {
					podEgressArgsBad4 = append(podEgressArgsBad4, snatRuleArgs)
				}
				break
			}
		}
	}
}

func (nrc *NetworkRoutingController) createPodEgressRules() error {
	iptablesCmdHandler, err := nrc.newIptablesCmdHandler()
	if err != nil {
		return errors.New("Failed create iptables handler:" + err.Error())
	}

	var podEgressArgs [][]string

	if nrc.egressIP != nil {
		podEgressArgs = podSnatEgressArgs4
		if nrc.isIpv6 {
			podEgressArgs = podSnatEgressArgs6
		}
	} else {
		podEgressArgs = podMasqueradeEgressArgs4
		if nrc.isIpv6 {
			podEgressArgs = podMasqueradeEgressArgs6
		}
	}

	var lastError error = nil

	for _, args := range podEgressArgs {
		err = iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", args...)
		if err != nil {
			lastError = errors.New("Failed to add iptables rule for outbound traffic from pods: " +
				err.Error() + "External connectivity will not work.")
		}
	}

	if lastError == nil {
		glog.V(1).Infof("Added iptables rules for outbound traffic from pods.")
	}

	return lastError
}

func (nrc *NetworkRoutingController) deletePodEgressRules() error {
	iptablesCmdHandler, err := nrc.newIptablesCmdHandler()
	if err != nil {
		return errors.New("Failed create iptables handler:" + err.Error())
	}

	var podEgressArgs [][]string

	if nrc.egressIP != nil {
		podEgressArgs = podSnatEgressArgs4
		if nrc.isIpv6 {
			podEgressArgs = podSnatEgressArgs6
		}
	} else {
		podEgressArgs = podMasqueradeEgressArgs4
		if nrc.isIpv6 {
			podEgressArgs = podMasqueradeEgressArgs6
		}
	}

	var lastError error = nil

	for _, args := range podEgressArgs {
		exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", args...)
		if err != nil {
			lastError = errors.New("Failed to lookup iptables rule for outbound traffic from pods: " + err.Error())
			continue
		}

		if exists {
			err = iptablesCmdHandler.Delete("nat", "POSTROUTING", args...)
			if err != nil {
				lastError = errors.New("Failed to delete iptables rule for outbound traffic from pods: " +
					err.Error() + ". Pod egress might still work...")
				continue
			}
			glog.Infof("Deleted iptables rule for outbound traffic from pods.")
		}
	}

	return lastError
}

func (nrc *NetworkRoutingController) deleteBadPodEgressRules() error {
	iptablesCmdHandler, err := nrc.newIptablesCmdHandler()
	if err != nil {
		return errors.New("Failed create iptables handler:" + err.Error())
	}
	podEgressArgsBad := podEgressArgsBad4
	if nrc.isIpv6 {
		podEgressArgsBad = podEgressArgsBad6
	}

	var lastError error = nil

	for _, args := range podEgressArgsBad {
		exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", args...)
		if err != nil {
			lastError = fmt.Errorf("Failed to lookup iptables rule: %s", err.Error())
			continue
		}

		if exists {
			err = iptablesCmdHandler.Delete("nat", "POSTROUTING", args...)
			if err != nil {
				lastError = fmt.Errorf("Failed to delete old/bad iptables rule to "+
					"masquerade outbound traffic from pods: %s.\n"+
					"Pod egress might still work, or bugs may persist after upgrade...",
					err)
				continue
			}
			glog.Infof("Deleted old/bad iptables rule to masquerade outbound traffic from pods.")
		}
	}

	return lastError
}
