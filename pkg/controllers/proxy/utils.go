package proxy

import (
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"k8s.io/klog/v2"
)

const (
	interfaceWaitSleepTime = 100 * time.Millisecond
)

func attemptNamespaceResetAfterError(hostNSHandle netns.NsHandle) {
	err := netns.Set(hostNSHandle)
	if err != nil {
		klog.Errorf("failed to set hostNetworkNamespace while resetting namespace after a previous error due to %v",
			err)
	}
	activeNetworkNamespaceHandle, err := netns.Get()
	if err != nil {
		klog.Errorf("failed to confirm activeNetworkNamespace while resetting namespace after "+
			"a previous error due to %v", err)
		return
	}
	klog.V(2).Infof("Current network namespace after revert namespace to host network namespace: %s",
		activeNetworkNamespaceHandle.String())
	_ = activeNetworkNamespaceHandle.Close()
}

func (ln *linuxNetworking) configureContainerForDSR(
	vip, endpointIP, containerID string, pid int, hostNetworkNamespaceHandle netns.NsHandle) error {
	endpointNamespaceHandle, err := netns.GetFromPid(pid)
	if err != nil {
		return fmt.Errorf("failed to get endpoint namespace (containerID=%s, pid=%d, error=%v)",
			containerID, pid, err)
	}
	defer utils.CloseCloserDisregardError(&endpointNamespaceHandle)

	err = netns.Set(endpointNamespaceHandle)
	if err != nil {
		return fmt.Errorf("failed to enter endpoint namespace (containerID=%s, pid=%d, error=%v)",
			containerID, pid, err)
	}

	activeNetworkNamespaceHandle, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get activeNetworkNamespace due to %v", err)
	}
	klog.V(2).Infof("Current network namespace after netns. Set to container network namespace: %s",
		activeNetworkNamespaceHandle.String())
	_ = activeNetworkNamespaceHandle.Close()

	// TODO: fix boilerplate `netns.Set(hostNetworkNamespaceHandle)` code. Need a robust
	// way to switch back to old namespace, pretty much all things will go wrong if we dont switch back

	// create an ipip tunnel interface inside the endpoint container
	tunIf, err := netlink.LinkByName(KubeTunnelIf)
	if err != nil {
		if err.Error() != IfaceNotFound {
			attemptNamespaceResetAfterError(hostNetworkNamespaceHandle)
			return fmt.Errorf("failed to verify if ipip tunnel interface exists in endpoint %s namespace due "+
				"to %v", endpointIP, err)
		}

		klog.V(2).Infof("Could not find tunnel interface %s in endpoint %s so creating one.",
			KubeTunnelIf, endpointIP)
		ipTunLink := netlink.Iptun{
			LinkAttrs: netlink.LinkAttrs{Name: KubeTunnelIf},
			Local:     net.ParseIP(endpointIP),
		}
		err = netlink.LinkAdd(&ipTunLink)
		if err != nil {
			attemptNamespaceResetAfterError(hostNetworkNamespaceHandle)
			return fmt.Errorf("failed to add ipip tunnel interface in endpoint namespace due to %v", err)
		}

		// this is ugly, but ran into issue multiple times where interface did not come up quickly.
		for retry := 0; retry < 60; retry++ {
			time.Sleep(interfaceWaitSleepTime)
			tunIf, err = netlink.LinkByName(KubeTunnelIf)
			if err == nil {
				break
			}
			if err.Error() == IfaceNotFound {
				klog.V(3).Infof("Waiting for tunnel interface %s to come up in the pod, retrying",
					KubeTunnelIf)
				continue
			} else {
				break
			}
		}

		if err != nil {
			attemptNamespaceResetAfterError(hostNetworkNamespaceHandle)
			return fmt.Errorf("failed to get %s tunnel interface handle due to %v", KubeTunnelIf, err)
		}

		klog.V(2).Infof("Successfully created tunnel interface %s in endpoint %s.",
			KubeTunnelIf, endpointIP)
	}

	// bring the tunnel interface up
	err = netlink.LinkSetUp(tunIf)
	if err != nil {
		attemptNamespaceResetAfterError(hostNetworkNamespaceHandle)
		return fmt.Errorf("failed to bring up ipip tunnel interface in endpoint namespace due to %v", err)
	}

	// assign VIP to the KUBE_TUNNEL_IF interface
	err = ln.ipAddrAdd(tunIf, vip, false)
	if err != nil && err.Error() != IfaceHasAddr {
		attemptNamespaceResetAfterError(hostNetworkNamespaceHandle)
		return fmt.Errorf("failed to assign vip %s to kube-tunnel-if interface", vip)
	}
	klog.Infof("Successfully assigned VIP: %s in endpoint %s.", vip, endpointIP)

	// disable rp_filter on all interface
	err = ioutil.WriteFile("/proc/sys/net/ipv4/conf/kube-tunnel-if/rp_filter",
		[]byte(strconv.Itoa(0)), 0640)
	if err != nil {
		attemptNamespaceResetAfterError(hostNetworkNamespaceHandle)
		return fmt.Errorf("failed to disable rp_filter on kube-tunnel-if in the endpoint container")
	}

	err = ioutil.WriteFile("/proc/sys/net/ipv4/conf/eth0/rp_filter", []byte(strconv.Itoa(0)), 0640)
	if err != nil {
		attemptNamespaceResetAfterError(hostNetworkNamespaceHandle)
		return fmt.Errorf("failed to disable rp_filter on eth0 in the endpoint container")
	}

	err = ioutil.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte(strconv.Itoa(0)), 0640)
	if err != nil {
		attemptNamespaceResetAfterError(hostNetworkNamespaceHandle)
		return fmt.Errorf("failed to disable rp_filter on `all` in the endpoint container")
	}

	klog.Infof("Successfully disabled rp_filter in endpoint %s.", endpointIP)

	err = netns.Set(hostNetworkNamespaceHandle)
	if err != nil {
		return fmt.Errorf("failed to set hostNetworkNamespace handle due to %v", err)
	}
	activeNetworkNamespaceHandle, err = netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get activeNetworkNamespace handle due to %v", err)
	}
	klog.Infof("Current network namespace after revert namespace to host network namespace: %s",
		activeNetworkNamespaceHandle.String())
	_ = activeNetworkNamespaceHandle.Close()
	return nil
}
