package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

type nodePortHealthCheckController struct {
	nphcServicesInfo
	activeNPHC map[int](chan<- struct{})
	wg         *sync.WaitGroup
	stopCh     chan struct{}
}

type serviceHealthCheck struct {
	serviceID string
	nodePort  int
}

type nphcServicesInfo struct {
	serviceInfoMap   serviceInfoMap
	endpointsInfoMap endpointSliceInfoMap
}

type nphcHandler struct {
	svcHC *serviceHealthCheck
	nphc  *nodePortHealthCheckController
}

func (nphc *nodePortHealthCheckController) UpdateServicesInfo(serviceInfoMap serviceInfoMap,
	endpointsInfoMap endpointSliceInfoMap) error {
	klog.V(1).Info("Running UpdateServicesInfo for NodePort health check")
	nphc.serviceInfoMap = serviceInfoMap
	nphc.endpointsInfoMap = endpointsInfoMap

	newActiveServices := make(map[int]bool)

	for svcID, svc := range serviceInfoMap {
		if svc.healthCheckNodePort != 0 {
			newActiveServices[svc.healthCheckNodePort] = true
			svcHC := serviceHealthCheck{
				serviceID: svcID,
				nodePort:  svc.healthCheckNodePort,
			}
			if nphc.healthCheckExists(svcHC) {
				continue
			}
			err := nphc.addHealthCheck(svcHC)
			if err != nil {
				return err
			}
		}
	}

	for np := range nphc.activeNPHC {
		if !newActiveServices[np] {
			err := nphc.stopHealthCheck(np)
			if err != nil {
				klog.Errorf("error stopping the NodePort healthcheck on NodePort %d: %v", np, err)
			}
		}
	}

	klog.V(1).Info("Finished UpdateServicesInfo for NodePort health check")
	return nil
}

func (nphc *nodePortHealthCheckController) healthCheckExists(svcHC serviceHealthCheck) bool {
	if _, ok := nphc.activeNPHC[svcHC.nodePort]; ok {
		return true
	}
	return false
}

func (nphc *nodePortHealthCheckController) addHealthCheck(svcHC serviceHealthCheck) error {
	klog.V(1).Infof("Adding NodePort health check for port: %d with svcid: %s", svcHC.nodePort, svcHC.serviceID)
	if nphc.healthCheckExists(svcHC) {
		return fmt.Errorf("unable to add healthcheck for NodePort %d as it is already taken", svcHC.nodePort)
	}
	closingChan := make(chan struct{})
	nphc.activeNPHC[svcHC.nodePort] = closingChan

	nphc.wg.Add(1)
	go func(nphc *nodePortHealthCheckController, svcHC serviceHealthCheck, closingChan <-chan struct{}) {
		defer nphc.wg.Done()
		mux := http.NewServeMux()
		srv := &http.Server{
			Addr:              ":" + strconv.Itoa(svcHC.nodePort),
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}

		npHandler := nphcHandler{
			svcHC: &svcHC,
			nphc:  nphc,
		}
		mux.HandleFunc("/healthz", npHandler.Handler)

		nphc.wg.Add(1)
		go func(svcHC serviceHealthCheck) {
			defer nphc.wg.Done()
			klog.Infof("starting NodePort health controller on NodePort: %d", svcHC.nodePort)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				// cannot panic, because this probably is an intentional close
				klog.Errorf("could not start NodePort health controller on NodePort %d: %s", svcHC.nodePort, err)
			}
		}(svcHC)

		// block until we receive a shut down signal on either our private channel or the global channel
		select {
		case <-closingChan:
		case <-nphc.stopCh:
		}
		klog.Infof("shutting down NodePort health controller on NodePort: %d", svcHC.nodePort)
		if err := srv.Shutdown(context.Background()); err != nil {
			klog.Errorf("could not shutdown NodePort health controller on NodePort %d: %v", svcHC.nodePort, err)
		}

	}(nphc, svcHC, closingChan)

	return nil
}

func (nphc *nodePortHealthCheckController) stopHealthCheck(nodePort int) error {
	if _, ok := nphc.activeNPHC[nodePort]; !ok {
		return fmt.Errorf("no NodePort health check currently exists for NodePort: %d", nodePort)
	}

	svcStopCh := nphc.activeNPHC[nodePort]
	close(svcStopCh)

	delete(nphc.activeNPHC, nodePort)

	return nil
}

func (npHandler *nphcHandler) Handler(w http.ResponseWriter, r *http.Request) {
	eps := npHandler.nphc.endpointsInfoMap[npHandler.svcHC.serviceID]
	endpointsOnNode := hasActiveEndpoints(eps)

	var numActiveEndpoints int8
	for _, endpoint := range eps {
		if endpoint.isLocal && !endpoint.isTerminating {
			numActiveEndpoints++
		}
	}

	if endpointsOnNode && numActiveEndpoints > 0 {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(fmt.Sprintf("%d Service Endpoints found\n", numActiveEndpoints)))
		if err != nil {
			klog.Errorf("failed to write body: %s", err)
		}
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, err := w.Write([]byte("No Service Endpoints Found\n"))
		if err != nil {
			klog.Errorf("Failed to write body: %s", err)
		}
	}
}

func (nphc *nodePortHealthCheckController) StopAll() {
	klog.Info("Stopping all NodePort health checks")
	close(nphc.stopCh)
	klog.Info("Waiting for all NodePort health checks to finish shutting down")
	nphc.wg.Wait()
	klog.Info("All NodePort health checks are completely shut down, all done!")
}

func NewNodePortHealthCheck() *nodePortHealthCheckController {
	nphc := nodePortHealthCheckController{
		activeNPHC: make(map[int]chan<- struct{}),
		wg:         &sync.WaitGroup{},
		stopCh:     make(chan struct{}),
	}

	return &nphc
}
