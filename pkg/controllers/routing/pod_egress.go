package routing

import (
	"fmt"
	"strings"

	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	v1 "k8s.io/api/core/v1"
	v1core "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
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

func (nrc *NetworkRoutingController) preparePodEgress(node *v1.Node, kubeRouterConfig *options.KubeRouterConfig) {
	if nrc.egressIP != nil {
		var args [][]string

		if nrc.isIPv6Capable {
			args = podSnatEgressArgs6
			podEgressArgsBad6 = append(podEgressArgsBad6, podMasqueradeEgressArgs6...)
		} else {
			args = podSnatEgressArgs4
			podEgressArgsBad4 = append(podEgressArgsBad4, podMasqueradeEgressArgs4...)
		}

		args = append(args, []string{"-j", "SNAT", "--to-source", nrc.egressIP.String()})

		if nrc.isIPv6Capable {
			podSnatEgressArgs6 = args
		} else {
			podSnatEgressArgs4 = args
		}

		klog.V(1).Infof("Using SNAT to '%s' instead of MASQUERADE for outbound traffic from pods.", nrc.egressIP.String())
	} else {
		if nrc.isIPv6Capable {
			podEgressArgsBad6 = append(podEgressArgsBad6, podSnatEgressArgs6...)
		} else {
			podEgressArgsBad4 = append(podEgressArgsBad4, podSnatEgressArgs4...)
		}

		// If we are not using egressIP, we need to use MASQUERADE for outbound traffic from pods
		for family, iptablesCmdHandler := range nrc.iptablesCmdHandlers {
			rules, err := iptablesCmdHandler.List("nat", "POSTROUTING")
			if err != nil {
				klog.Error("Failed to list rules from 'nat' table in 'POSTROUTING' chain: " + err.Error())
				return
			}

			//find the snat rule and add it to the list of rules to be removed
			for _, rule := range rules {
				if strings.Contains(rule, "-j SNAT --to-source") {
					snatRuleArgs := strings.Split(rule, " ")[2:]
					if family == v1core.IPv6Protocol {
						podEgressArgsBad6 = append(podEgressArgsBad6, snatRuleArgs)
					} else {
						podEgressArgsBad4 = append(podEgressArgsBad4, snatRuleArgs)
					}
					break
				}
			}
		}
	}
}

func (nrc *NetworkRoutingController) createPodEgressRules() error {
	for family, iptablesCmdHandler := range nrc.iptablesCmdHandlers {
		var podEgressArgs [][]string
		if nrc.egressIP != nil {
			podEgressArgs = podSnatEgressArgs4
			if family == v1core.IPv6Protocol {
				podEgressArgs = podSnatEgressArgs6
			}
		} else {
			podEgressArgs = podMasqueradeEgressArgs4
			if family == v1core.IPv6Protocol {
				podEgressArgs = podMasqueradeEgressArgs6
			}
		}

		for _, args := range podEgressArgs {
			if iptablesCmdHandler.HasRandomFully() {
				args = append(args, "--random-fully")
			}

			err := iptablesCmdHandler.AppendUnique("nat", "POSTROUTING", args...)
			if err != nil {
				return fmt.Errorf("Failed to add iptables rule to masquerade outbound traffic from pods: %w "+
					"External connectivity will not work.", err)
			}
		}
	}

	klog.V(1).Infof("Added iptables rules for outbound traffic from pods.")

	return nil
}

func (nrc *NetworkRoutingController) deletePodEgressRules() error {
	for family, iptablesCmdHandler := range nrc.iptablesCmdHandlers {
		var podEgressArgs [][]string

		if nrc.egressIP != nil {
			podEgressArgs = podSnatEgressArgs4
			if family == v1core.IPv6Protocol {
				podEgressArgs = podSnatEgressArgs6
			}
		} else {
			podEgressArgs = podMasqueradeEgressArgs4
			if family == v1core.IPv6Protocol {
				podEgressArgs = podMasqueradeEgressArgs6
			}
		}

		for _, args := range podEgressArgs {
			if iptablesCmdHandler.HasRandomFully() {
				args = append(args, "--random-fully")
			}

			exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", args...)
			if err != nil {
				return fmt.Errorf("Failed to lookup iptables rule to masquerade outbound traffic from pods: %w", err)
			}

			if exists {
				err = iptablesCmdHandler.Delete("nat", "POSTROUTING", args...)
				if err != nil {
					return fmt.Errorf("Failed to delete iptables rule to masquerade outbound traffic from pods: %w"+
						". Pod egress might still work...", err)
				}
				klog.Infof("Deleted iptables rule to masquerade outbound traffic from pods.")
			}
		}
	}

	return nil
}

func (nrc *NetworkRoutingController) deleteBadPodEgressRules() error {
	for family, iptablesCmdHandler := range nrc.iptablesCmdHandlers {
		podEgressArgsBad := podEgressArgsBad4
		if family == v1core.IPv6Protocol {
			podEgressArgsBad = podEgressArgsBad6
		}

		// If random fully is supported remove the original rule as well
		if iptablesCmdHandler.HasRandomFully() {
			if family == v1core.IPv4Protocol {
				podEgressArgsBad = append(podEgressArgsBad, podMasqueradeEgressArgs4...)
			} else {
				podEgressArgsBad = append(podEgressArgsBad, podMasqueradeEgressArgs6...)
			}
		}

		for _, args := range podEgressArgsBad {
			exists, err := iptablesCmdHandler.Exists("nat", "POSTROUTING", args...)
			if err != nil {
				return fmt.Errorf("failed to lookup iptables rule: %s", err.Error())
			}

			if exists {
				err = iptablesCmdHandler.Delete("nat", "POSTROUTING", args...)
				if err != nil {
					return fmt.Errorf("failed to delete old/bad iptables rule to masquerade outbound traffic "+
						"from pods: %w. Pod egress might still work, or bugs may persist after upgrade", err)
				}
				klog.Infof("Deleted old/bad iptables rule to masquerade outbound traffic from pods.")
			}
		}
	}

	return nil
}
