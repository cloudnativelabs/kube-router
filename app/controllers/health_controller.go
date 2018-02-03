package controllers

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/app/options"
	"github.com/golang/glog"
	"golang.org/x/net/context"
)

type ControllerHeartbeat struct {
	Component     string
	Lastheartbeat time.Time
}

//HealthController reports the health of the controller loops as a http endpoint
type HealthController struct {
	HealthPort uint16
}

func sendHeartBeat(channel chan<- *ControllerHeartbeat, controller string) {
	glog.Infof("Send Heartbeat from %s", controller)
	heartbeat := ControllerHeartbeat{
		Component:     controller,
		Lastheartbeat: time.Now(),
	}
	channel <- &heartbeat
}

func (hc *HealthController) Handler(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("These aren't the droids you're looking for\n"))
}

func (hc *HealthController) Run(healthChan <-chan *ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) error {
	t := time.NewTicker(3 * time.Second)
	defer wg.Done()
	glog.Info("Starting health controller")

	srv := &http.Server{Addr: ":" + strconv.Itoa(int(hc.HealthPort)), Handler: http.DefaultServeMux}

	// add prometheus handler on metrics path
	http.HandleFunc("/healthz", hc.Handler)

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			// cannot panic, because this probably is an intentional close
			glog.Errorf("Health controller error: %s", err)
		}
	}()

	for {
		select {
		case <-stopCh:
			glog.Infof("Shutting down health controller")
			if err := srv.Shutdown(context.Background()); err != nil {
				glog.Errorf("could not shutdown: %v", err)
			}
			return nil
		case heartbeat := <-healthChan:
			glog.Infof("Received heartbeat from %s", heartbeat.Component)
		case <-t.C:
			glog.Infof("Health controller tick")
		}
	}

}

func NewHealthController(config *options.KubeRouterConfig) (*HealthController, error) {
	hc := HealthController{
		HealthPort: config.HealthPort,
	}
	return &hc, nil
}
