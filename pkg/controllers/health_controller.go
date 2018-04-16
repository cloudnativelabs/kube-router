package controllers

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/golang/glog"
	"golang.org/x/net/context"
)

//ControllerHeartbeat is the structure to hold the heartbeats sent by controllers
type ControllerHeartbeat struct {
	Component     string
	LastHeartBeat time.Time
}

//HealthController reports the health of the controller loops as a http endpoint
type HealthController struct {
	HealthPort  uint16
	HTTPEnabled bool
	Status      HealthStats
	Config      *options.KubeRouterConfig
}

//HealthStats is holds the latest heartbeats
type HealthStats struct {
	sync.Mutex
	Healthy                        bool
	MetricsControllerAlive         time.Time
	NetworkPolicyControllerAlive   time.Time
	NetworkRoutingControllerAlive  time.Time
	NetworkServicesControllerAlive time.Time
}

//sendHeartBeat sends a heartbeat on the passed channel
func sendHeartBeat(channel chan<- *ControllerHeartbeat, controller string) {
	heartbeat := ControllerHeartbeat{
		Component:     controller,
		LastHeartBeat: time.Now(),
	}
	channel <- &heartbeat
}

//Handler writes HTTP responses to the health path
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

//HandleHeartbeat handles received heartbeats on the health channel
func (hc *HealthController) HandleHeartbeat(beat *ControllerHeartbeat) {
	glog.V(3).Infof("Received heartbeat from %s", beat.Component)

	hc.Status.Lock()
	defer hc.Status.Unlock()

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

//CheckHealth evaluates the time since last heartbeat to decide if the controller is running or not
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

//Run starts the HealthController
func (hc *HealthController) Run(healthChan <-chan *ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) error {
	Started := time.Now()
	t := time.NewTicker(500 * time.Millisecond)
	defer wg.Done()
	glog.Info("Starting health controller")

	srv := &http.Server{Addr: ":" + strconv.Itoa(int(hc.HealthPort)), Handler: http.DefaultServeMux}

	http.HandleFunc("/healthz", hc.Handler)

	if (hc.Config.HealthPort > 0) && (hc.Config.HealthPort <= 65535) {
		hc.HTTPEnabled = true
		go func() {
			if err := srv.ListenAndServe(); err != nil {
				// cannot panic, because this probably is an intentional close
				glog.Errorf("Health controller error: %s", err)
			}
		}()
	} else if hc.Config.MetricsPort > 65535 {
		glog.Errorf("Metrics port must be over 0 and under 65535, given port: %d", hc.Config.MetricsPort)
	} else {
		hc.HTTPEnabled = false
	}

	for {
		//Give the controllers a few seconds to start before checking health
		if time.Since(Started) > 5*time.Second {
			hc.Status.Healthy = hc.CheckHealth()
		}
		select {
		case <-stopCh:
			glog.Infof("Shutting down health controller")
			if hc.HTTPEnabled {
				if err := srv.Shutdown(context.Background()); err != nil {
					glog.Errorf("could not shutdown: %v", err)
				}
			}
			return nil
		case heartbeat := <-healthChan:
			hc.HandleHeartbeat(heartbeat)
		case <-t.C:
			glog.V(4).Info("Health controller tick")
		}
	}

}

//NewHealthController creates a new health controller and returns a reference to it
func NewHealthController(config *options.KubeRouterConfig) (*HealthController, error) {
	hc := HealthController{
		Config:     config,
		HealthPort: config.HealthPort,
		Status: HealthStats{
			Healthy: false,
		},
	}
	return &hc, nil
}
