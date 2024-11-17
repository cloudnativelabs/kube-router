package healthcheck

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"golang.org/x/net/context"
	"k8s.io/klog/v2"
)

const (
	HPCStaticSyncInterval    = 60
	HPCSyncPeriod            = time.Duration(HPCStaticSyncInterval) * time.Second
	defaultGraceTimeDuration = time.Duration(1500) * time.Millisecond
	healthControllerTickTime = 5000 * time.Millisecond

	// Defined health checks
	NetworkRoutesController = iota
	LoadBalancerController
	NetworkPolicyController
	NetworkServicesController
	HairpinController
	MetricsController
)

var (
	HeartBeatCompNames = map[int]string{
		NetworkRoutesController:   "NetworkRoutesController",
		LoadBalancerController:    "LoadBalancerController",
		NetworkPolicyController:   "NetworkPolicyController",
		NetworkServicesController: "NetworkServicesController",
		HairpinController:         "HairpinController",
		MetricsController:         "MetricsController",
	}
)

// ControllerHeartbeat is the structure to hold the heartbeats sent by controllers
type ControllerHeartbeat struct {
	Component     int
	LastHeartBeat time.Time
}

// HealthController reports the health of the controller loops as a http endpoint
type HealthController struct {
	HealthPort  uint16
	HTTPEnabled bool
	Status      HealthStats
	Config      *options.KubeRouterConfig
}

// HealthStats is holds the latest heartbeats
type HealthStats struct {
	sync.Mutex
	Healthy                           bool
	LoadBalancerControllerAlive       time.Time
	LoadBalancerControllerAliveTTL    time.Duration
	MetricsControllerAlive            time.Time
	NetworkPolicyControllerAlive      time.Time
	NetworkPolicyControllerAliveTTL   time.Duration
	NetworkRoutingControllerAlive     time.Time
	NetworkRoutingControllerAliveTTL  time.Duration
	NetworkServicesControllerAlive    time.Time
	NetworkServicesControllerAliveTTL time.Duration
	HairpinControllerAlive            time.Time
	HairpinControllerAliveTTL         time.Duration
}

// SendHeartBeat sends a heartbeat on the passed channel
func SendHeartBeat(channel chan<- *ControllerHeartbeat, component int) {
	heartbeat := ControllerHeartbeat{
		Component:     component,
		LastHeartBeat: time.Now(),
	}
	channel <- &heartbeat
}

// Handler writes HTTP responses to the health path
func (hc *HealthController) Handler(w http.ResponseWriter, _ *http.Request) {
	if hc.Status.Healthy {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK\n"))
		if err != nil {
			klog.Errorf("Failed to write body: %s", err)
		}
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
		_, err := w.Write([]byte("Unhealthy"))
		if err != nil {
			klog.Errorf("Failed to write body: %s", err)
		}
	}
}

// HandleHeartbeat handles received heartbeats on the health channel
func (hc *HealthController) HandleHeartbeat(beat *ControllerHeartbeat) {
	klog.V(3).Infof("Received heartbeat from %s", HeartBeatCompNames[beat.Component])

	hc.Status.Lock()
	defer hc.Status.Unlock()

	switch beat.Component {
	// The first heartbeat will set the initial gracetime the controller has to report in, A static time is added as
	// well when checking to allow for load variation in sync time
	case LoadBalancerController:
		if hc.Status.LoadBalancerControllerAliveTTL == 0 {
			hc.Status.LoadBalancerControllerAliveTTL = time.Since(hc.Status.LoadBalancerControllerAlive)
		}
		hc.Status.LoadBalancerControllerAlive = beat.LastHeartBeat

	case NetworkServicesController:
		if hc.Status.NetworkServicesControllerAliveTTL == 0 {
			hc.Status.NetworkServicesControllerAliveTTL = time.Since(hc.Status.NetworkServicesControllerAlive)
		}
		hc.Status.NetworkServicesControllerAlive = beat.LastHeartBeat

	case HairpinController:
		if hc.Status.HairpinControllerAliveTTL == 0 {
			hc.Status.HairpinControllerAliveTTL = time.Since(hc.Status.HairpinControllerAlive)
		}
		hc.Status.HairpinControllerAlive = beat.LastHeartBeat

	case NetworkRoutesController:
		if hc.Status.NetworkRoutingControllerAliveTTL == 0 {
			hc.Status.NetworkRoutingControllerAliveTTL = time.Since(hc.Status.NetworkRoutingControllerAlive)
		}
		hc.Status.NetworkRoutingControllerAlive = beat.LastHeartBeat

	case NetworkPolicyController:
		if hc.Status.NetworkPolicyControllerAliveTTL == 0 {
			hc.Status.NetworkPolicyControllerAliveTTL = time.Since(hc.Status.NetworkPolicyControllerAlive)
		}
		hc.Status.NetworkPolicyControllerAlive = beat.LastHeartBeat

	case MetricsController:
		hc.Status.MetricsControllerAlive = beat.LastHeartBeat
	}
}

// CheckHealth evaluates the time since last heartbeat to decide if the controller is running or not
func (hc *HealthController) CheckHealth() bool {
	health := true
	graceTime := defaultGraceTimeDuration

	if hc.Config.RunFirewall {
		if time.Since(hc.Status.NetworkPolicyControllerAlive) >
			hc.Config.IPTablesSyncPeriod+hc.Status.NetworkPolicyControllerAliveTTL+graceTime {
			klog.Error("Network Policy Controller heartbeat missed")
			health = false
		}
	}

	if hc.Config.RunLoadBalancer {
		if time.Since(hc.Status.LoadBalancerControllerAlive) >
			hc.Config.LoadBalancerSyncPeriod+hc.Status.LoadBalancerControllerAliveTTL+graceTime {
			klog.Error("Load Balancer Allocator Controller heartbeat missed")
			health = false
		}
	}

	if hc.Config.RunRouter {
		if time.Since(hc.Status.NetworkRoutingControllerAlive) >
			hc.Config.RoutesSyncPeriod+hc.Status.NetworkRoutingControllerAliveTTL+graceTime {
			klog.Error("Network Routing Controller heartbeat missed")
			health = false
		}
	}

	if hc.Config.RunServiceProxy {
		if time.Since(hc.Status.NetworkServicesControllerAlive) >
			hc.Config.IpvsSyncPeriod+hc.Status.NetworkServicesControllerAliveTTL+graceTime {
			klog.Error("NetworkService Controller heartbeat missed")
			health = false
		}
		// if time.Since(hc.Status.HairpinControllerAlive) >
		// 	HPCSyncPeriod+hc.Status.HairpinControllerAliveTTL+graceTime {
		//	klog.Error("Hairpin Controller heartbeat missed")
		//	health = false
		// }
	}

	if hc.Config.MetricsEnabled {
		if time.Since(hc.Status.MetricsControllerAlive) > 5*time.Second {
			klog.Error("Metrics Controller heartbeat missed")
			health = false
		}
	}

	return health
}

// RunServer starts the HealthController's server
func (hc *HealthController) RunServer(stopCh <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	srv := &http.Server{
		Addr:              ":" + strconv.Itoa(int(hc.HealthPort)),
		Handler:           http.DefaultServeMux,
		ReadHeaderTimeout: 5 * time.Second}
	http.HandleFunc("/healthz", hc.Handler)
	if hc.Config.HealthPort > 0 {
		hc.HTTPEnabled = true
		go func() {
			if err := srv.ListenAndServe(); err != nil {
				// cannot panic, because this probably is an intentional close
				klog.Errorf("Health controller error: %s", err)
			}
		}()
	} else {
		hc.HTTPEnabled = false
	}

	// block until we receive a shut down signal
	<-stopCh
	klog.Infof("Shutting down health controller")
	if hc.HTTPEnabled {
		if err := srv.Shutdown(context.Background()); err != nil {
			klog.Errorf("could not shutdown: %v", err)
		}
	}
}

// RunCheck starts the HealthController's check
func (hc *HealthController) RunCheck(healthChan <-chan *ControllerHeartbeat, stopCh <-chan struct{},
	wg *sync.WaitGroup) {
	t := time.NewTicker(healthControllerTickTime)
	defer wg.Done()
	for {
		select {
		case <-stopCh:
			klog.Infof("Shutting down HealthController RunCheck")
			return
		case heartbeat := <-healthChan:
			hc.HandleHeartbeat(heartbeat)
		case <-t.C:
			klog.V(4).Info("Health controller tick")
		}
		hc.Status.Healthy = hc.CheckHealth()
	}
}

func (hc *HealthController) SetAlive() {

	now := time.Now()

	hc.Status.LoadBalancerControllerAlive = now
	hc.Status.MetricsControllerAlive = now
	hc.Status.NetworkPolicyControllerAlive = now
	hc.Status.NetworkRoutingControllerAlive = now
	hc.Status.NetworkServicesControllerAlive = now
	hc.Status.HairpinControllerAlive = now
}

// NewHealthController creates a new health controller and returns a reference to it
func NewHealthController(config *options.KubeRouterConfig) (*HealthController, error) {
	hc := HealthController{
		Config:     config,
		HealthPort: config.HealthPort,
		Status: HealthStats{
			Healthy: true,
		},
	}
	return &hc, nil
}
