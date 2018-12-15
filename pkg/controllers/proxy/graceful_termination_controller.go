package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/docker/libnetwork/ipvs"
	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
)

type gracefulRequestType int

const (
	// Static size for now, don't know if we will ever have to raise it
	gracefulQueueSize     = 10
	ipvsDestinationDelete = iota
	ipvsDestinationAdd
	ipvsServiceDelete
	ipvsServiceAdd
)

type lookupReq struct {
	ipaddr   net.IP
	callback chan bool
}

// gracefulRequest Holds our request to gracefully remove the backend
type gracefulRequest struct {
	ipvsSvc                   *ipvs.Service
	ipvsDst                   *ipvs.Destination
	deletionTime              time.Time
	gracefulTerminationPeriod time.Duration
	gracefulRequestType       gracefulRequestType
}

// TerminationController handles gracefully removing backends
type TerminationController struct {
	ipvsHandle *ipvs.Handle
	queueChan  chan gracefulRequest
	lookupChan chan lookupReq
	jobQueue   []gracefulRequest
	config     *options.KubeRouterConfig
}

//IsGracefulInProgress checks if there is any graceful operations pending for the IPVS service
func (gh *TerminationController) IsGracefulInProgress(ipaddr net.IP) bool {
	callbackChan := make(chan bool)
	lookupReq := lookupReq{
		ipaddr:   ipaddr,
		callback: callbackChan,
	}
	gh.lookupChan <- lookupReq
	return <-lookupReq.callback
}

// DeleteDestination removes a service destination gracefully
func (gh *TerminationController) DeleteDestination(svc *ipvs.Service, dst *ipvs.Destination, gtp time.Duration) error {
	// If we failed to lookup a gracefultermination time from annotation or TerminationGracePeriodSeconds from pod use the default value
	var gracefulPeriod time.Duration
	if gtp == 0 {
		gracefulPeriod = gh.config.IpvsGracefulPeriod
	} else {
		gracefulPeriod = gtp
	}

	deletionTime := time.Now()

	req := gracefulRequest{
		ipvsSvc:                   svc,
		ipvsDst:                   dst,
		deletionTime:              deletionTime,
		gracefulTerminationPeriod: gracefulPeriod,
		gracefulRequestType:       ipvsDestinationDelete,
	}

	//And push it to the controller queue
	gh.queueChan <- req
	return nil
}

// AddDestination adds a service destination and remove it from jobQueue if present
func (gh *TerminationController) AddDestination(service *ipvs.Service, dest *ipvs.Destination) error {
	respChan := make(chan error)
	defer close(respChan)

	req := gracefulRequest{
		ipvsSvc:             service,
		ipvsDst:             dest,
		gracefulRequestType: ipvsDestinationAdd,
	}

	// Push it to the queue and wait for the result
	gh.queueChan <- req
	return nil
}

// DeleteService removes a service gracefully by witing until any gracefull destination terminations has finnished
func (gh *TerminationController) DeleteService(svc *ipvs.Service, gtp time.Duration) error {
	// If we failed to lookup a gracefultermination time from annotation use config default
	var gracefulPeriod time.Duration
	if gtp == 0 {
		gracefulPeriod = gh.config.IpvsGracefulPeriod
	} else {
		gracefulPeriod = gtp
	}

	deletionTime := time.Now()

	req := gracefulRequest{
		ipvsSvc:                   svc,
		deletionTime:              deletionTime,
		gracefulTerminationPeriod: gracefulPeriod,
		gracefulRequestType:       ipvsServiceDelete,
	}

	//push it to the controller queue
	gh.queueChan <- req
	return nil
}

// AddService adds a service and removes any graceful termination requests for said service
func (gh *TerminationController) AddService(svcs []*ipvs.Service, vip net.IP, protocol, port uint16, persistent bool, scheduler string, flags schedFlags) (*ipvs.Service, error) {
	respChan := make(chan error)
	defer close(respChan)

	var err error
	for _, svc := range svcs {
		if vip.Equal(svc.Address) && protocol == svc.Protocol && port == svc.Port {
			if (persistent && (svc.Flags&0x0001) == 0) || (!persistent && (svc.Flags&0x0001) != 0) {
				ipvsSetPersistence(svc, persistent)

				if changedIpvsSchedFlags(svc, flags) {
					ipvsSetSchedFlags(svc, flags)
				}

				err = gh.ipvsHandle.UpdateService(svc)
				if err != nil {
					return nil, err
				}
				glog.V(2).Infof("Updated persistence/session-affinity for service: %s", ipvsServiceString(svc))
			}

			if changedIpvsSchedFlags(svc, flags) {
				ipvsSetSchedFlags(svc, flags)

				err = gh.ipvsHandle.UpdateService(svc)
				if err != nil {
					return nil, err
				}
				glog.V(2).Infof("Updated scheduler flags for service: %s", ipvsServiceString(svc))
			}

			if scheduler != svc.SchedName {
				svc.SchedName = scheduler
				err = gh.ipvsHandle.UpdateService(svc)
				if err != nil {
					return nil, errors.New("Failed to update the scheduler for the service due to " + err.Error())
				}
				glog.V(2).Infof("Updated schedule for the service: %s", ipvsServiceString(svc))
			}

			return svc, nil
		}
	}

	svc := &ipvs.Service{
		Address:       vip,
		AddressFamily: syscall.AF_INET,
		Protocol:      protocol,
		Port:          port,
		SchedName:     scheduler,
	}

	ipvsSetPersistence(svc, persistent)
	ipvsSetSchedFlags(svc, flags)
	/*
		err = gh.ipvsHandle.NewService(&svc)
		if err != nil {
			return nil, err
		}
	*/
	req := gracefulRequest{
		ipvsSvc:             svc,
		gracefulRequestType: ipvsServiceAdd,
	}
	gh.queueChan <- req

	glog.V(1).Infof("Successfully added service: %s", ipvsServiceString(svc))
	return svc, nil

}

// getConnStats returns the number of active & inactive connections for the IPVS destination
func (gh *TerminationController) getIpvsDestinationConnStats(ipvsSvc *ipvs.Service, dest *ipvs.Destination) (int, int, error) {
	destStats, err := gh.ipvsHandle.GetDestinations(ipvsSvc)
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

// cleanupipvsDeleteService i called from the periodic cleanup to evaluate if a service should
// be removed or not
func (gh *TerminationController) cleanupipvsDeleteService(req gracefulRequest) bool {
	deleteService := true

	// if we have pending graceful terminations for a destination in the service, don't delete the service
	for _, jobQitem := range gh.jobQueue {
		if jobQitem.gracefulRequestType == ipvsDestinationDelete {
			if req.ipvsSvc.Address.Equal(jobQitem.ipvsSvc.Address) && req.ipvsSvc.Port == jobQitem.ipvsSvc.Port && req.ipvsSvc.Protocol == jobQitem.ipvsSvc.Protocol {
				deleteService = false
			}
		}
	}

	// Is the graceful time passed?
	if time.Since(req.deletionTime) > req.gracefulTerminationPeriod {
		deleteService = true
	}

	if deleteService {
		err := gh.ipvsHandle.DelService(req.ipvsSvc)
		if err != nil {
			glog.Errorf("Failed to delete IPVS service %s : %s", ipvsServiceString(req.ipvsSvc), err.Error())
		}
	}

	return deleteService
}

func (gh *TerminationController) cleanupIpvsDeleteEndpoint(req gracefulRequest) bool {
	var deleteEndpoint bool

	// Get active and inactive connections for the destination
	aConn, iConn, err := gh.getIpvsDestinationConnStats(req.ipvsSvc, req.ipvsDst)
	if err != nil {
		glog.V(1).Infof("Could not get connection stats: %s", err.Error())
	} else {
		// Do we have active or inactive connections to this destination
		// if we don't, proceed and delete the destination ahead of graceful period
		if aConn == 0 && iConn == 0 {
			deleteEndpoint = true
		}
	}

	// Check if our destinations graceful termination period has passed
	if time.Since(req.deletionTime) > req.gracefulTerminationPeriod {
		deleteEndpoint = true
	}

	//Destination has has one or more conditions for deletion
	if deleteEndpoint {
		glog.V(2).Infof("Deleting IPVS destination: %s", ipvsDestinationString(req.ipvsDst))
		if err := gh.ipvsHandle.DelDestination(req.ipvsSvc, req.ipvsDst); err != nil {
			glog.Errorf("Failed to delete IPVS destination: %s, %s", ipvsDestinationString(req.ipvsDst), err.Error())
		}
		// flush conntrack when endpoint for a UDP service changes
		if req.ipvsSvc.Protocol == syscall.IPPROTO_UDP {
			if err := gh.flushConntrackUDP(req); err != nil {
				glog.Error(err.Error())
			}
		}
	}
	return deleteEndpoint
}

// cleanup does the lifting of removing destinations and cleaning conntrack records
func (gh *TerminationController) cleanup() {
	var newQueue []gracefulRequest
	for _, job := range gh.jobQueue {
		switch job.gracefulRequestType {

		case ipvsDestinationDelete:
			if removed := gh.cleanupIpvsDeleteEndpoint(job); removed {
				continue
			}
		case ipvsServiceDelete:
			if removed := gh.cleanupipvsDeleteService(job); removed {
				continue
			}
		}

		newQueue = append(newQueue, job)
	}
	gh.jobQueue = newQueue
}

// flushConntrackUDP flushes UDP conntrack records for the given service destination
func (gh *TerminationController) flushConntrackUDP(dest gracefulRequest) error {
	// Conntrack exits with non zero exit code when exiting if 0 flow entries have been deleted, use regex to check output and don't Error when matching
	re := regexp.MustCompile("([[:space:]]0 flow entries have been deleted.)")

	// Shell out and flush conntrack records
	out, err := exec.Command("conntrack", "-D", "--orig-dst", dest.ipvsSvc.Address.String(), "-p", "udp", "--dport", strconv.Itoa(int(dest.ipvsSvc.Port))).CombinedOutput()
	if err != nil {
		if matched := re.MatchString(string(out)); !matched {
			return fmt.Errorf("Failed to delete conntrack entry for endpoint: %s:%d due to %s", dest.ipvsSvc.Address.String(), dest.ipvsSvc.Port, err.Error())
		}
	}
	glog.V(1).Infof("Deleted conntrack entry for endpoint: %s:%d", dest.ipvsSvc.Address.String(), dest.ipvsSvc.Port)
	return nil
}

// ipvsAddDestination handles add ipvs destination requests
func (gh *TerminationController) ipvsAddDestination(req gracefulRequest) error {
	err := gh.ipvsHandle.NewDestination(req.ipvsSvc, req.ipvsDst)
	if err == nil {
		glog.V(2).Infof("Successfully added destination %s to the service %s",
			ipvsDestinationString(req.ipvsDst), ipvsServiceString(req.ipvsSvc))
		return nil
	}
	if strings.Contains(err.Error(), IPVS_SERVER_EXISTS) {
		err = gh.ipvsHandle.UpdateDestination(req.ipvsSvc, req.ipvsDst)
		if err != nil {
			return fmt.Errorf("Failed to update ipvs destination %s to the ipvs service %s due to : %s",
				ipvsDestinationString(req.ipvsDst), ipvsServiceString(req.ipvsSvc), err.Error())
		}
		glog.V(4).Infof("ipvs destination %s already exists in the ipvs service %s so not adding destination",
			ipvsDestinationString(req.ipvsDst), ipvsServiceString(req.ipvsSvc))
	} else {
		return fmt.Errorf("Failed to add ipvs destination %s to the ipvs service %s due to : %s",
			ipvsDestinationString(req.ipvsDst), ipvsServiceString(req.ipvsSvc), err.Error())
	}
	return nil
}

func (gh *TerminationController) handleIpvsDestinationDelete(req gracefulRequest) error {
	inQ := false
	for _, dst := range gh.jobQueue {
		if dst.gracefulRequestType == ipvsDestinationDelete {
			if req.ipvsSvc.Address.Equal(dst.ipvsSvc.Address) && req.ipvsSvc.Port == dst.ipvsSvc.Port && req.ipvsSvc.Protocol == dst.ipvsSvc.Protocol {
				if req.ipvsDst.Address.Equal(dst.ipvsDst.Address) && req.ipvsDst.Port == dst.ipvsDst.Port {
					inQ = true
					break
				}
			}
		}
	}
	if !inQ {
		glog.V(2).Infof("Got deletion request for svc: %s dst: %s gtp: %s", ipvsServiceString(req.ipvsSvc), ipvsDestinationString(req.ipvsDst), req.gracefulTerminationPeriod)
		// Set the destination weight to 0 so no new connections will come in, while old are allowed
		// to gracefully finnish while backend is shutting down if the backend has support for it
		req.ipvsDst.Weight = 0
		if err := gh.ipvsHandle.UpdateDestination(req.ipvsSvc, req.ipvsDst); err != nil {
			return fmt.Errorf("Unable to update IPVS destination svc: %s dst: %s due to: %s", ipvsServiceString(req.ipvsSvc), ipvsDestinationString(req.ipvsDst), err.Error())
		}
		// add the request to the termination queue
		gh.jobQueue = append(gh.jobQueue, req)
	} else {
		glog.V(2).Infof("Duplicate IPVS destination delete request svc: %s dst: %s, dropping it", ipvsServiceString(req.ipvsSvc), ipvsDestinationString(req.ipvsDst))
	}
	return nil
}

func (gh *TerminationController) handleipvsDestinationAdd(req gracefulRequest) error {
	var newQueue []gracefulRequest
	for _, jobQitem := range gh.jobQueue {
		if jobQitem.gracefulRequestType == ipvsDestinationDelete {
			if req.ipvsSvc.Address.Equal(jobQitem.ipvsSvc.Address) && req.ipvsSvc.Port == jobQitem.ipvsSvc.Port && req.ipvsSvc.Protocol == jobQitem.ipvsSvc.Protocol {
				if req.ipvsDst.Address.Equal(jobQitem.ipvsDst.Address) && req.ipvsDst.Port == jobQitem.ipvsDst.Port {
					glog.V(2).Infof("Removing deletion request for svc: %s dst: %s due to destination being re-added", ipvsServiceString(req.ipvsSvc), ipvsDestinationString(req.ipvsDst))
					continue
				}
			}
		}
		newQueue = append(newQueue, jobQitem)
	}
	gh.jobQueue = newQueue

	return gh.ipvsAddDestination(req)
}
func (gh *TerminationController) handleipvsServiceDelete(req gracefulRequest) error {
	inQ := false
	for _, jobQitem := range gh.jobQueue {
		if jobQitem.gracefulRequestType == ipvsServiceDelete {
			if req.ipvsSvc.Address.Equal(jobQitem.ipvsSvc.Address) && req.ipvsSvc.Port == jobQitem.ipvsSvc.Port && req.ipvsSvc.Protocol == jobQitem.ipvsSvc.Protocol {
				inQ = true
				break
			}
		}
	}
	if !inQ {
		glog.V(2).Infof("Got deletion request for svc: %s gtp: %s", ipvsServiceString(req.ipvsSvc), req.gracefulTerminationPeriod)
		gh.jobQueue = append(gh.jobQueue, req)
	} else {
		glog.V(2).Infof("Duplicate IPVS service delete request svc: %s, dropping it", ipvsServiceString(req.ipvsSvc))
	}
	return nil
}

func (gh *TerminationController) handleipvsServiceAdd(req gracefulRequest) error {
	var newQueue []gracefulRequest
	inQ := false
	for _, jobQitem := range gh.jobQueue {
		if jobQitem.gracefulRequestType == ipvsServiceDelete {
			if req.ipvsSvc.Address.Equal(jobQitem.ipvsSvc.Address) && req.ipvsSvc.Port == jobQitem.ipvsSvc.Port && req.ipvsSvc.Protocol == jobQitem.ipvsSvc.Protocol {
				glog.V(2).Infof("Removing graceful termination request for svc: %s due to service being re-added", ipvsServiceString(req.ipvsSvc))
				inQ = true
				continue
			}
		}
		newQueue = append(newQueue, jobQitem)
	}
	gh.jobQueue = newQueue

	if !inQ {
		err := gh.ipvsHandle.NewService(req.ipvsSvc)
		if err != nil {
			return err
		}
	}
	return nil
}
func (gh *TerminationController) handleLookup(lookup lookupReq) error {
	var found bool
	for _, jobQitem := range gh.jobQueue {
		if jobQitem.gracefulRequestType == ipvsServiceDelete || jobQitem.gracefulRequestType == ipvsDestinationDelete {
			if jobQitem.ipvsSvc.Address.Equal(lookup.ipaddr) {
				found = true
				break
			}
		}
	}
	lookup.callback <- found
	return nil
}

// handleReq is the function that processes incoming messages on the job queue
func (gh *TerminationController) handleReq(req gracefulRequest) error {
	switch req.gracefulRequestType {
	case ipvsDestinationDelete:
		if err := gh.handleIpvsDestinationDelete(req); err != nil {
			return err
		}
	case ipvsDestinationAdd:
		if err := gh.handleipvsDestinationAdd(req); err != nil {
			return err
		}
	case ipvsServiceDelete:
		if err := gh.handleipvsServiceDelete(req); err != nil {
			return err
		}
	case ipvsServiceAdd:
		if err := gh.handleipvsServiceAdd(req); err != nil {
			return err
		}
	}
	return nil
}

// Run starts the graceful handler
func (gh *TerminationController) Run(ctx context.Context) {
	defer close(gh.queueChan)
	defer close(gh.lookupChan)

	glog.Info("Starting IPVS graceful termination controller")

	ticker := time.NewTicker(10 * time.Second)

	for {
		select {
		// Receive jobs as well as de-duplicate them
		case req := <-gh.queueChan:
			if err := gh.handleReq(req); err != nil {
				glog.Errorf("Error handling request: %s", err.Error())
			}

		// Handle lookup requests to check if there are pending deletions that should prevent
		// the service VIP from being deleted from kube-dummy-if
		case lookup := <-gh.lookupChan:
			if err := gh.handleLookup(lookup); err != nil {
				glog.Errorf("Error handling lookup request: %s", err.Error())
			}

		// Perform periodic cleanup
		case <-ticker.C:
			if gh.config.MetricsEnabled {
				metrics.ControllerGracefulTerminationQueueSize.Set(float64(len(gh.jobQueue)))
			}
			gh.cleanup()

		// Handle shutdown signal
		case <-ctx.Done():
			glog.Info("Shutting down IPVS graceful termination controller")
			return
		}
	}
}

//NewTerminationController starts a new graceful termination controller
func NewTerminationController(config *options.KubeRouterConfig) (*TerminationController, error) {
	//Our incoming queue to serialize requests
	queue := make(chan gracefulRequest, gracefulQueueSize)

	//Our incoming channel for lookups
	lookupChan := make(chan lookupReq)

	// Get our own IPVS handle to talk to the kernel
	ipvsHandle, err := ipvs.New("")
	if err != nil {
		return nil, err
	}

	// Register our metrics
	if config.MetricsEnabled {
		prometheus.MustRegister(metrics.ControllerGracefulTerminationQueueSize)
	}

	// Return a new graceful termination controller
	return &TerminationController{
		ipvsHandle: ipvsHandle,
		queueChan:  queue,
		lookupChan: lookupChan,
		config:     config,
	}, nil
}
