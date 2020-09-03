package proxy

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/moby/ipvs"
)

type gracefulQueue struct {
	mu    sync.Mutex
	queue []gracefulRequest
}

type gracefulRequest struct {
	ipvsSvc                   *ipvs.Service
	ipvsDst                   *ipvs.Destination
	deletionTime              time.Time
	gracefulTerminationPeriod time.Duration
}

func (nsc *NetworkServicesController) ipvsDeleteDestination(svc *ipvs.Service, dst *ipvs.Destination) error {
	// If we have enabled graceful termination set the weight of the destination to 0
	// then add it to the queue for graceful termination
	if nsc.gracefulTermination {
		req := gracefulRequest{
			ipvsSvc:      svc,
			ipvsDst:      dst,
			deletionTime: time.Now(),
		}
		dst.Weight = 0
		err := nsc.ln.ipvsUpdateDestination(svc, dst)
		if err != nil {
			return err
		}
		nsc.addToGracefulQueue(&req)
	} else {
		err := nsc.ln.ipvsDelDestination(svc, dst)
		if err != nil {
			return err
		}
	}
	// flush conntrack when Destination for a UDP service changes
	if svc.Protocol == syscall.IPPROTO_UDP {
		if err := nsc.flushConntrackUDP(svc); err != nil {
			glog.Errorf("Failed to flush conntrack: %s", err.Error())
		}
	}
	return nil
}

func (nsc *NetworkServicesController) addToGracefulQueue(req *gracefulRequest) {
	nsc.gracefulQueue.mu.Lock()
	defer nsc.gracefulQueue.mu.Unlock()
	var alreadyExists bool
	for _, jobQitem := range nsc.gracefulQueue.queue {
		if jobQitem.ipvsSvc.Address.Equal(req.ipvsSvc.Address) && jobQitem.ipvsSvc.Port == req.ipvsSvc.Port && jobQitem.ipvsSvc.Protocol == req.ipvsSvc.Protocol {
			if jobQitem.ipvsDst.Address.Equal(req.ipvsDst.Address) && jobQitem.ipvsDst.Port == req.ipvsDst.Port {
				glog.V(2).Infof("Endpoint already scheduled for removal %+v %+v %s", *req.ipvsSvc, *req.ipvsDst, req.gracefulTerminationPeriod.String())
				alreadyExists = true
				break
			}
		}
	}
	if !alreadyExists {
		// try to get get Termination grace period from the pod, if unsuccesfull use the default timeout
		podObj, err := nsc.getPodObjectForEndpoint(req.ipvsDst.Address.String())
		if err != nil {
			glog.V(1).Infof("Failed to find endpoint with ip: %s err: %s", req.ipvsDst.Address.String(), err.Error())
			req.gracefulTerminationPeriod = nsc.gracefulPeriod
		} else {
			glog.V(1).Infof("Found pod termination grace period %d for pod %s", *podObj.Spec.TerminationGracePeriodSeconds, podObj.Name)
			req.gracefulTerminationPeriod = time.Duration(float64(*podObj.Spec.TerminationGracePeriodSeconds) * float64(time.Second))
		}
		nsc.gracefulQueue.queue = append(nsc.gracefulQueue.queue, *req)
	}
}

func (nsc *NetworkServicesController) gracefulSync() {
	nsc.gracefulQueue.mu.Lock()
	defer nsc.gracefulQueue.mu.Unlock()
	var newQueue []gracefulRequest
	// Itterate over our queued destination removals one by one, and don't add them back to the queue if they were processed
	for _, job := range nsc.gracefulQueue.queue {
		if removed := nsc.gracefulDeleteIpvsDestination(job); removed {
			continue
		}
		newQueue = append(newQueue, job)
	}
	nsc.gracefulQueue.queue = newQueue
}

func (nsc *NetworkServicesController) gracefulDeleteIpvsDestination(req gracefulRequest) bool {
	var deleteDestination bool
	// Get active and inactive connections for the destination
	aConn, iConn, err := nsc.getIpvsDestinationConnStats(req.ipvsSvc, req.ipvsDst)
	if err != nil {
		glog.V(1).Infof("Could not get connection stats for destination: %s", err.Error())
	} else {
		// Do we have active or inactive connections to this destination
		// if we don't, proceed and delete the destination ahead of graceful period
		if aConn == 0 && iConn == 0 {
			deleteDestination = true
		}
	}

	// Check if our destinations graceful termination period has passed
	if time.Since(req.deletionTime) > req.gracefulTerminationPeriod {
		deleteDestination = true
	}

	//Destination has has one or more conditions for deletion
	if deleteDestination {
		glog.V(2).Infof("Deleting IPVS destination: %s", ipvsDestinationString(req.ipvsDst))
		if err := nsc.ln.ipvsDelDestination(req.ipvsSvc, req.ipvsDst); err != nil {
			glog.Errorf("Failed to delete IPVS destination: %s, %s", ipvsDestinationString(req.ipvsDst), err.Error())
		}
	}
	return deleteDestination
}

// getConnStats returns the number of active & inactive connections for the IPVS destination
func (nsc *NetworkServicesController) getIpvsDestinationConnStats(ipvsSvc *ipvs.Service, dest *ipvs.Destination) (int, int, error) {
	destStats, err := nsc.ln.ipvsGetDestinations(ipvsSvc)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get IPVS destinations for service : %s : %s", ipvsServiceString(ipvsSvc), err.Error())
	}

	for _, destStat := range destStats {
		if destStat.Address.Equal(dest.Address) && destStat.Port == dest.Port {
			return destStat.ActiveConnections, destStat.InactiveConnections, nil
		}
	}
	return 0, 0, fmt.Errorf("destination %s not found on IPVS service %s ", ipvsDestinationString(dest), ipvsServiceString(ipvsSvc))
}

// flushConntrackUDP flushes UDP conntrack records for the given service destination
func (nsc *NetworkServicesController) flushConntrackUDP(svc *ipvs.Service) error {
	// Conntrack exits with non zero exit code when exiting if 0 flow entries have been deleted, use regex to check output and don't Error when matching
	re := regexp.MustCompile("([[:space:]]0 flow entries have been deleted.)")

	// Shell out and flush conntrack records
	out, err := exec.Command("conntrack", "-D", "--orig-dst", svc.Address.String(), "-p", "udp", "--dport", strconv.Itoa(int(svc.Port))).CombinedOutput()
	if err != nil {
		if matched := re.MatchString(string(out)); !matched {
			return fmt.Errorf("Failed to delete conntrack entry for endpoint: %s:%d due to %s", svc.Address.String(), svc.Port, err.Error())
		}
	}
	glog.V(1).Infof("Deleted conntrack entry for endpoint: %s:%d", svc.Address.String(), svc.Port)
	return nil
}
