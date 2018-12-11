package graceful

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/docker/libnetwork/ipvs"
	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
)

// Static size for now, don't know if we will ever have to raise it
const (
	gracefulQueueSize = 10
)

// gracefulRequest Holds our request to gracefully remove the backend
type gracefulRequest struct {
	ipvsSvc                   *ipvs.Service
	ipvsDst                   *ipvs.Destination
	deletionTime              time.Time
	gracefulTerminationPeriod time.Duration
}

// TerminationController handles gracefully removing backends
type TerminationController struct {
	ipvsHandle *ipvs.Handle
	queueChan  chan gracefulRequest
	jobQueue   []gracefulRequest
	config     *options.KubeRouterConfig
}

// Delete a service destination gracefully
func (gh *TerminationController) Delete(svc *ipvs.Service, dst *ipvs.Destination, gtp time.Duration) error {
	var gracefulPeriod time.Duration
	if gtp == 0 {
		gracefulPeriod = gh.config.IpvsGracefulPeriod
	} else {
		gracefulPeriod = gtp
	}

	newDest := &ipvs.Destination{
		Address:         dst.Address,
		Port:            dst.Port,
		Weight:          0,
		ConnectionFlags: dst.ConnectionFlags,
		AddressFamily:   dst.AddressFamily,
		UpperThreshold:  dst.UpperThreshold,
		LowerThreshold:  dst.LowerThreshold,
	}
	deletionTime := time.Now()

	req := gracefulRequest{
		ipvsSvc:                   svc,
		ipvsDst:                   newDest,
		deletionTime:              deletionTime,
		gracefulTerminationPeriod: gracefulPeriod,
	}

	//And push it to the controller queue
	gh.queueChan <- req
	return nil
}

// getConnStats returns the number of active & inactive connections for the IPVS destination
func (gh *TerminationController) getConnStats(ipvsSvc *ipvs.Service, dest *ipvs.Destination) (int, int, error) {
	destStats, err := gh.ipvsHandle.GetDestinations(ipvsSvc)
	if err != nil {
		return 0, 0, fmt.Errorf("Failed to get IPVS destinations for %v : %s", ipvsSvc, err.Error())
	}

	for _, destStat := range destStats {
		if destStat.Address.Equal(dest.Address) && destStat.Port == ipvsSvc.Port {
			return destStat.ActiveConnections, destStat.InactiveConnections, nil
		}
	}
	return 0, 0, fmt.Errorf("Destination not found on IPVS service svc: %v dst: %v", ipvsSvc, dest)
}

// cleanup does the lifting of removing destinations and cleaning conntrack records
func (gh *TerminationController) cleanup() {
	var newQueue []gracefulRequest
	for _, dest := range gh.jobQueue {
		var deleteEndpoint bool

		// Get active and inactive connections for the destination
		aConn, iConn, err := gh.getConnStats(dest.ipvsSvc, dest.ipvsDst)
		if err != nil {
			glog.Errorf("Could not get connection stats: %s", err.Error())
		}

		// Do we have active or inactive connections to this destination
		if aConn == 0 && iConn == 0 {
			deleteEndpoint = true
		}

		// Check if our destinations graceful termination period has passed
		if time.Since(dest.deletionTime) > dest.gracefulTerminationPeriod {
			deleteEndpoint = true
		}

		if deleteEndpoint {
			glog.V(2).Infof("Deleting IPVS destination: %v", dest.ipvsDst)
			if err := gh.ipvsHandle.DelDestination(dest.ipvsSvc, dest.ipvsDst); err != nil {
				glog.Errorf("Failed to delete IPVS destination: %v, %s", dest.ipvsDst, err.Error())
			}
			// flush conntrack when endpoint for a UDP service changes
			if dest.ipvsSvc.Protocol == syscall.IPPROTO_UDP {
				if err := gh.flushConntrackUDP(dest); err != nil {
					glog.Error(err.Error())
				}
			}
			continue
		}
		// There were no active connections to the destination or it's graceful termination period
		// had not expired so push it back to the queue for re-evaluation later
		newQueue = append(newQueue, dest)
	}
	gh.jobQueue = newQueue
}

// flushConntrackUDP flushes UDP conntrack records for the given service destination
func (gh *TerminationController) flushConntrackUDP(dest gracefulRequest) error {
	// Conntrack exits with non zero exit code when exiting if 0 flow entries have been deleted, use regex to check output and don't Error when matching
	re := regexp.MustCompile("([[:space:]]0 flow entries have been deleted.)")
	out, err := exec.Command("conntrack", "-D", "--orig-dst", dest.ipvsSvc.Address.String(), "-p", "udp", "--dport", strconv.Itoa(int(dest.ipvsSvc.Port))).CombinedOutput()
	if err != nil {
		if matched := re.MatchString(string(out)); !matched {
			return fmt.Errorf("Failed to delete conntrack entry for endpoint: %s:%d due to %s", dest.ipvsSvc.Address.String(), dest.ipvsSvc.Port, err.Error())
		}
	}
	glog.V(1).Infof("Deleted conntrack entry for endpoint: %s:%d", dest.ipvsSvc.Address.String(), dest.ipvsSvc.Port)
	return nil
}

// handleReq is the function that processes incoming messages on the job queue
func (gh *TerminationController) handleReq(req gracefulRequest) error {
	var found bool
	// This for loop is to check if the destination already is queued for deletion. If not, set it's weight to 0 so no new connections comes in
	for _, dst := range gh.jobQueue {
		if req.ipvsSvc.Address.Equal(dst.ipvsSvc.Address) && req.ipvsSvc.Port == dst.ipvsSvc.Port && req.ipvsSvc.Protocol == dst.ipvsSvc.Protocol {
			if req.ipvsDst.Address.Equal(dst.ipvsDst.Address) && req.ipvsDst.Port == dst.ipvsDst.Port {
				glog.V(2).Infof("Deletion request exists for svc: %v dst: %v", *req.ipvsSvc, *req.ipvsDst)
				found = true
				break
			}
		}
	}
	if !found {
		// Set the destination weight to 0 so no new connections will come in
		// but old are allowed to gracefully finnish while backend is shutting down
		// if the backend has support for it
		if err := gh.ipvsHandle.UpdateDestination(req.ipvsSvc, req.ipvsDst); err != nil {
			return fmt.Errorf("Unable to update IPVS destination svc: %v dst: %v due to: %s", *req.ipvsSvc, *req.ipvsDst, err.Error())
		}
		gh.jobQueue = append(gh.jobQueue, req)
	}
	return nil
}

// Run starts the graceful handler
func (gh *TerminationController) Run(ctx context.Context) {
	glog.Info("Starting IPVS graceful termination controller")

	ticker := time.NewTicker(10 * time.Second)

	for {
		select {

		// Receive graceful termination requests as well as de-duplicate them
		case req := <-gh.queueChan:
			glog.V(2).Infof("Got deletion request for svc: %v dst: %v", *req.ipvsSvc, *req.ipvsDst)
			if err := gh.handleReq(req); err != nil {
				glog.Error(err.Error())
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
		config:     config,
	}, nil
}
