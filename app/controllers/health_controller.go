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
	Status     HealthStats
	Config     *options.KubeRouterConfig
}

type HealthStats struct {
	Healthy                        bool
	MetricsControllerAlive         time.Time
	NetworkPolicyControllerAlive   time.Time
	NetworkRoutingControllerAlive  time.Time
	NetworkServicesControllerAlive time.Time
}

func sendHeartBeat(channel chan<- *ControllerHeartbeat, controller string) {
	heartbeat := ControllerHeartbeat{
		Component:     controller,
		Lastheartbeat: time.Now(),
	}
	channel <- &heartbeat
}

func (hc *HealthController) Handler(w http.ResponseWriter, req *http.Request) {
	if hc.Status.Healthy {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("These aren't the droids you're looking for\n"))
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("These are the droids you're looking for\n"))
	}
}

func (hc *HealthController) HandleHeartbeat(beat *ControllerHeartbeat) {
	glog.Infof("Received heartbeat from %s", beat.Component)
	switch component := beat.Component; component {
	case "NSC":
		hc.Status.NetworkServicesControllerAlive = time.Now()
	case "NRC":
		hc.Status.NetworkRoutingControllerAlive = time.Now()
	case "NPC":
		hc.Status.NetworkPolicyControllerAlive = time.Now()
	case "MC":
		hc.Status.MetricsControllerAlive = time.Now()
	}
}

func (hc *HealthController) CheckHealth() bool {
	glog.V(4).Info("Checking components")
	health := true
	if time.Since(hc.Status.NetworkPolicyControllerAlive) > hc.Config.IPTablesSyncPeriod+3*time.Second {
		glog.Error("Network Policy Controller heartbeat timeout")
		health = false
	}

	if time.Since(hc.Status.NetworkRoutingControllerAlive) > hc.Config.RoutesSyncPeriod+3*time.Second {
		glog.Error("Network Routing Controller heartbeat timeout")
		health = false
	}

	if time.Since(hc.Status.NetworkServicesControllerAlive) > hc.Config.IpvsSyncPeriod+3*time.Second {
		glog.Error("NetworkService Controller heartbeat timeout")
		health = false
	}
	return health
}

func (hc *HealthController) Run(healthChan <-chan *ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) error {
	t := time.NewTicker(1 * time.Second)
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

		hc.Status.Healthy = hc.CheckHealth()

		select {
		case <-stopCh:
			glog.Infof("Shutting down health controller")
			if err := srv.Shutdown(context.Background()); err != nil {
				glog.Errorf("could not shutdown: %v", err)
			}
			return nil
		case heartbeat := <-healthChan:
			hc.HandleHeartbeat(heartbeat)
		case <-t.C:
			glog.V(4).Info("Health controller tick")
		}
	}

}

func NewHealthController(config *options.KubeRouterConfig) (*HealthController, error) {
	hc := HealthController{
		Config:     config,
		HealthPort: config.HealthPort,
	}
	return &hc, nil
}
