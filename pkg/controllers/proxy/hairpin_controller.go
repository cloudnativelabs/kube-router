package proxy

import (
	"fmt"
	"net"
	"os"
	"path"
	"runtime"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/v2/pkg/utils"
	"github.com/vishvananda/netns"
	"k8s.io/klog/v2"
)

// !!!! IMPORTANT !!!! - This code is not currently used
// Not creating the hairpin controller for now because this should be handled at the CNI level. The CNI bridge
// plugin ensures that hairpin mode is set much more reliably than we do. However, as a lot of work was put into
// the hairpin controller, and so that it is around to reference in the future if needed, I'm leaving the code
// for now.

type hairpinController struct {
	epC <-chan string
	nsc *NetworkServicesController
}

func (hpc *hairpinController) Run(stopCh <-chan struct{}, wg *sync.WaitGroup,
	healthChan chan<- *healthcheck.ControllerHeartbeat) {
	defer wg.Done()
	klog.Infof("Starting hairping controller (handles setting hairpin_mode for veth interfaces)")

	t := time.NewTicker(healthcheck.HPCSyncPeriod)
	defer t.Stop()
	for {
		// Add an additional non-blocking select to ensure that if the stopCh channel is closed it is handled first
		select {
		case <-stopCh:
			klog.Info("Shutting down Hairpin Controller goroutine")
			return
		default:
		}
		select {
		case <-stopCh:
			klog.Info("Shutting down Hairpin Controller goroutine")
			return
		case endpointIP := <-hpc.epC:
			klog.V(1).Infof("Received request for hairpin setup of endpoint %s, processing", endpointIP)
			err := hpc.ensureHairpinEnabledForPodInterface(endpointIP)
			if err != nil {
				klog.Errorf("unable to set hairpin mode for endpoint %s, its possible that hairpinning will not "+
					"work as expected. Error was: %v",
					endpointIP, err)
			}
		case <-t.C:
			healthcheck.SendHeartBeat(healthChan, healthcheck.HairpinController)
		}
	}
}

func (hpc *hairpinController) ensureHairpinEnabledForPodInterface(endpointIP string) error {
	klog.V(2).Infof("Attempting to enable hairpin mode for endpoint IP %s", endpointIP)
	crRuntime, containerID, err := hpc.nsc.findContainerRuntimeReferences(endpointIP)
	if err != nil {
		return err
	}
	klog.V(2).Infof("Detected runtime %s and container ID %s for endpoint IP %s", crRuntime, containerID, endpointIP)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNetworkNSHandle, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get namespace due to %v", err)
	}
	defer utils.CloseCloserDisregardError(&hostNetworkNSHandle)

	var pid int
	if crRuntime == "docker" {
		// WARN: This method is deprecated and will be removed once docker-shim is removed from kubelet.
		pid, err = hpc.nsc.ln.getContainerPidWithDocker(containerID)
		if err != nil {
			return fmt.Errorf("failed to get pod's (%s) pid for hairpinning due to %v", endpointIP, err)
		}
	} else {
		// We expect CRI compliant runtimes here
		// ugly workaround, refactoring of pkg/Proxy is required
		pid, err = hpc.nsc.ln.getContainerPidWithCRI(hpc.nsc.dsr.runtimeEndpoint, containerID)
		if err != nil {
			return fmt.Errorf("failed to get pod's (%s) pid for hairpinning due to %v", endpointIP, err)
		}
	}
	klog.V(2).Infof("Found PID %d for endpoint IP %s", pid, endpointIP)

	// Get the interface link ID from inside the container so that we can link it to the veth on the host namespace
	ifaceID, err := hpc.nsc.ln.findIfaceLinkForPid(pid)
	if err != nil {
		return fmt.Errorf("failed to find the interface ID inside the container NS for endpoint IP: %s, due to: %v",
			endpointIP, err)
	}
	klog.V(2).Infof("Found Interface Link ID %d for endpoint IP %s", ifaceID, endpointIP)

	ifaceName, err := net.InterfaceByIndex(ifaceID)
	if err != nil {
		return fmt.Errorf("failed to get the interface name from the link ID inside the container for endpoint IP: "+
			"%s and Interface ID: %d due to: %v", endpointIP, ifaceID, err)
	}

	klog.V(1).Infof("Enabling hairpin for interface %s for endpoint IP %s", ifaceName.Name, endpointIP)
	hpPath := path.Join(sysFSVirtualNetPath, ifaceName.Name, sysFSHairpinRelPath)
	if _, err := os.Stat(hpPath); err != nil {
		return fmt.Errorf("hairpin path %s doesn't appear to exist for us to set", hpPath)
	}

	return os.WriteFile(hpPath, []byte(hairpinEnable), 0644)
}

func NewHairpinController(nsc *NetworkServicesController, endpointCh <-chan string) *hairpinController {
	hpc := hairpinController{
		nsc: nsc,
		epC: endpointCh,
	}

	return &hpc
}
