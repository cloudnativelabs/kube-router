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
		w.Write([]byte("OK\n"))
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		/*
			statusText := fmt.Sprintf("Service controller last alive %s\n ago"+
				"Routing controller last alive: %s\n ago"+
				"Policy controller last alive: %s\n ago"+
				"Metrics controller last alive: %s\n ago",
				time.Since(hc.Status.NetworkServicesControllerAlive),
				time.Since(hc.Status.NetworkRoutingControllerAlive),
				time.Since(hc.Status.NetworkPolicyControllerAlive),
				time.Since(hc.Status.MetricsControllerAlive))
			w.Write([]byte(statusText))
		*/
		w.Write([]byte("Unhealthy"))
	}
}

func (hc *HealthController) HandleHeartbeat(beat *ControllerHeartbeat) {
	glog.V(3).Infof("Received heartbeat from %s", beat.Component)

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
	health := true
	if hc.Config.RunFirewall {
		if time.Since(hc.Status.NetworkPolicyControllerAlive) > hc.Config.IPTablesSyncPeriod+5*time.Second {
			glog.Error("Network Policy Controller heartbeat missed")
			health = false
		}
	}

	if hc.Config.RunRouter {
		if time.Since(hc.Status.NetworkRoutingControllerAlive) > hc.Config.RoutesSyncPeriod+5*time.Second {
			glog.Error("Network Routing Controller heartbeat missed")
			health = false
		}
	}

	if hc.Config.RunServiceProxy {
		if time.Since(hc.Status.NetworkServicesControllerAlive) > hc.Config.IpvsSyncPeriod+5*time.Second {
			glog.Error("NetworkService Controller heartbeat missed")
			health = false
		}
	}

	if hc.Config.MetricsEnabled {
		if time.Since(hc.Status.MetricsControllerAlive) > 5*time.Second {
			glog.Error("Metrics Controller heartbeat missed")
			health = false
		}
	}

	return health
}

func (hc *HealthController) Run(healthChan <-chan *ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) error {
	t := time.NewTicker(500 * time.Millisecond)
	defer wg.Done()
	glog.Info("Starting health controller")

	srv := &http.Server{Addr: ":" + strconv.Itoa(int(hc.HealthPort)), Handler: http.DefaultServeMux}

	http.HandleFunc("/healthz", hc.Handler)
	if (hc.Config.HealthPort > 0) && (hc.Config.HealthPort <= 65535) {
		go func() {
			if err := srv.ListenAndServe(); err != nil {
				// cannot panic, because this probably is an intentional close
				glog.Errorf("Health controller error: %s", err)
			}
		}()
	} else if hc.Config.MetricsPort > 65535 {
		glog.Errorf("Metrics port must be over 0 and under 65535, given port: %d", hc.Config.MetricsPort)
	}
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
