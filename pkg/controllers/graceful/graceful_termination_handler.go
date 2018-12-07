package graceful

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/golang/glog"

	"github.com/docker/libnetwork/ipvs"
)

const (
	gracefulQueueSize = 10
)

// gracefulRequest Holds our request to gracefully remove the backend
type gracefulRequest struct {
	ipvsSvc      *ipvs.Service
	ipvsDst      *ipvs.Destination
	deletionTime time.Time
}

// Handler handles gracefully removing backends
type Handler struct {
	ipvsHandle *ipvs.Handle
	queueChan  chan gracefulRequest
	jobQueue   []gracefulRequest
	config     *options.KubeRouterConfig
}

// Delete a service destination gracefully
func (gh *Handler) Delete(svc *ipvs.Service, dst *ipvs.Destination) error {
	newDest := &ipvs.Destination{
		Address:         dst.Address,
		Port:            dst.Port,
		Weight:          0,
		ConnectionFlags: dst.ConnectionFlags,
		AddressFamily:   dst.AddressFamily,
		UpperThreshold:  dst.UpperThreshold,
		LowerThreshold:  dst.LowerThreshold,
	}

	err := gh.ipvsHandle.UpdateDestination(svc, newDest)
	if err != nil {
		return err
	}
	deletionTime := time.Now()
	req := gracefulRequest{
		ipvsSvc:      svc,
		ipvsDst:      newDest,
		deletionTime: deletionTime,
	}
	gh.queueChan <- req
	return nil
}

func (gh *Handler) cleanup() {
	// Conntrack exits with non zero exit code when exiting if 0 flow entries have been deleted, use regex to check output and don't Error when matching
	re := regexp.MustCompile("([[:space:]]0 flow entries have been deleted.)")
	var newQueue []gracefulRequest
	for _, dest := range gh.jobQueue {
		if time.Since(dest.deletionTime) > gh.config.IpvsGracefulPeriod {
			glog.V(2).Infof("Deleting IPVS destination: %v", dest.ipvsDst)
			err := gh.ipvsHandle.DelDestination(dest.ipvsSvc, dest.ipvsDst)
			if err != nil {
				glog.Errorf("Failed to delete IPVS destination: %v, %s", dest.ipvsDst, err.Error())
			}
			// flush conntrack when endpoint for a UDP service changes
			if dest.ipvsSvc.Protocol == uint16(syscall.IPPROTO_UDP) {
				out, err := exec.Command("conntrack", "-D", "--orig-dst", dest.ipvsSvc.Address.String(), "-p", "udp", "--dport", strconv.Itoa(int(dest.ipvsSvc.Port))).CombinedOutput()
				if err != nil {
					if matched := re.MatchString(string(out)); !matched {
						glog.Error("Failed to delete conntrack entry for endpoint: " + dest.ipvsSvc.Address.String() + ":" + strconv.Itoa(int(dest.ipvsSvc.Port)) + " due to " + err.Error())
					}
				}
				glog.V(1).Infof("Deleted conntrack entry for endpoint: " + dest.ipvsSvc.Address.String() + ":" + strconv.Itoa(int(dest.ipvsSvc.Port)))
			}
			continue
		}
		newQueue = append(newQueue, dest)
	}
	gh.jobQueue = newQueue
}

// Run starts the graceful handler
func (gh *Handler) Run(ctx context.Context) {
	glog.Info("Starting IPVS graceful manager")

	ticker := time.NewTicker(10 * time.Second)

	for {
		select {

		// Receive graceful termination requests
		case req := <-gh.queueChan:
			glog.V(2).Infof("Got deletion request for %v", req)
			for _, dst := range gh.jobQueue {
				if req.ipvsSvc.Address.String() == dst.ipvsSvc.Address.String() && req.ipvsSvc.Port == dst.ipvsSvc.Port && req.ipvsSvc.Protocol == dst.ipvsSvc.Protocol {
					if req.ipvsDst.Address.String() == dst.ipvsDst.Address.String() && req.ipvsDst.Port == dst.ipvsDst.Port {
						glog.V(2).Infof("IPVS destination already scheduled for deletion: %v", req.ipvsDst)
						break
					}
				}
			}
			gh.jobQueue = append(gh.jobQueue, req)

		// Perform periodic cleanup
		case <-ticker.C:
			glog.V(2).Info("Tick")
			gh.cleanup()

		// Handle shutdown signal
		case <-ctx.Done():
			glog.Info("Shutting down IPVS graceful manager")
			return
		}
	}
}

//NewGracefulHandler starts a new controller
func NewGracefulHandler(config *options.KubeRouterConfig) (*Handler, error) {
	queue := make(chan gracefulRequest, gracefulQueueSize)

	ipvsHandle, err := ipvs.New("")
	if err != nil {
		return nil, err
	}

	return &Handler{
		ipvsHandle: ipvsHandle,
		queueChan:  queue,
		config:     config,
	}, nil
}
