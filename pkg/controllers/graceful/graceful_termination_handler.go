package graceful

import (
	"context"
	"time"

	"github.com/golang/glog"

	"github.com/docker/libnetwork/ipvs"
)

const (
	gracefulQueueSize     = 10
	defaulGracefulTimeout = 3 * time.Minute
)

// gracefulRequest Holds our request to gracefully remove the backend
type gracefulRequest struct {
	ipvsSvc      *ipvs.Service
	ipvsDst      *ipvs.Destination
	deletionTime time.Time
	retries      int
}

// Handler handles gracefully removing backends
type Handler struct {
	ipvsHandle *ipvs.Handle
	queueChan  chan gracefulRequest
	jobQueue   []gracefulRequest
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

	req := gracefulRequest{
		ipvsSvc:      svc,
		ipvsDst:      newDest,
		deletionTime: time.Now(),
		retries:      0,
	}
	gh.queueChan <- req
	return nil
}

func (gh *Handler) cleanup() {
	var newQueue []gracefulRequest
	for _, dest := range gh.jobQueue {
		if dest.retries > 3 {
			glog.Errorf("Giving up on deleting IPVS destination: %v", dest.ipvsDst)
			continue
		}
		if time.Since(dest.deletionTime) > defaulGracefulTimeout {
			glog.V(2).Infof("Deleting IPVS destination %v", dest.ipvsDst)
			err := gh.ipvsHandle.DelDestination(dest.ipvsSvc, dest.ipvsDst)
			if err != nil {
				glog.Errorf("Failed to delete IPVS destination attempt %d : %v", dest.retries, dest.ipvsDst)
				dest.retries++
				newQueue = append(newQueue, dest)
				continue
			}
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
		case req := <-gh.queueChan:
			for _, dst := range gh.jobQueue {
				if req.ipvsSvc == dst.ipvsSvc && req.ipvsDst == dst.ipvsDst {
					break
				}
				gh.jobQueue = append(gh.jobQueue, req)

			}
		case <-ticker.C:
			gh.cleanup()
		case <-ctx.Done():
			glog.Info("Shutting down IPVS graceful manager")
			return
		}
	}
}

//NewGracefulHandler starts a new controller
func NewGracefulHandler() (*Handler, error) {
	queue := make(chan gracefulRequest, gracefulQueueSize)

	ipvsHandle, err := ipvs.New("")
	if err != nil {
		return nil, err
	}

	return &Handler{
		ipvsHandle: ipvsHandle,
		queueChan:  queue,
	}, nil
}
