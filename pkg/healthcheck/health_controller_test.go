package healthcheck

import (
	"testing"
	"time"

	"github.com/cloudnativelabs/kube-router/v2/pkg/options"
	"github.com/stretchr/testify/assert"
)

const testSyncPeriod = 10 * time.Second

// newTestHealthController enables every loop and stamps every beat fresh, so a test only has to
// age the one component it cares about
func newTestHealthController(t *testing.T) *HealthController {
	t.Helper()

	config := options.NewKubeRouterConfig()
	config.RunFirewall = true
	config.RunRouter = true
	config.RunServiceProxy = true
	config.RunLoadBalancer = true
	config.MetricsEnabled = true
	config.IPTablesSyncPeriod = testSyncPeriod
	config.IpvsSyncPeriod = testSyncPeriod
	config.RoutesSyncPeriod = testSyncPeriod
	config.InjectedRoutesSyncPeriod = testSyncPeriod
	config.LoadBalancerSyncPeriod = testSyncPeriod

	hc, err := NewHealthController(config)
	if err != nil {
		t.Fatalf("failed to create health controller: %v", err)
	}
	hc.SetAlive()

	return hc
}

// Test_CheckHealthStaleness walks each controller's syncPeriod + TTL + graceTime boundary
func Test_CheckHealthStaleness(t *testing.T) {
	// Bracket the boundary rather than land on it, so wall clock jitter can't flake the test
	justInside := testSyncPeriod + defaultGraceTimeDuration - (500 * time.Millisecond)
	justOutside := testSyncPeriod + defaultGraceTimeDuration + (500 * time.Millisecond)

	tests := []struct {
		name string
		age  func(hs *HealthStats, age time.Duration)
	}{
		{
			name: "network policy controller",
			age:  func(hs *HealthStats, age time.Duration) { hs.NetworkPolicyControllerAlive = time.Now().Add(-age) },
		},
		{
			name: "network routes controller",
			age:  func(hs *HealthStats, age time.Duration) { hs.NetworkRoutingControllerAlive = time.Now().Add(-age) },
		},
		{
			name: "route sync controller",
			age:  func(hs *HealthStats, age time.Duration) { hs.RouteSyncControllerAlive = time.Now().Add(-age) },
		},
		{
			name: "network services controller",
			age:  func(hs *HealthStats, age time.Duration) { hs.NetworkServicesControllerAlive = time.Now().Add(-age) },
		},
		{
			name: "load balancer controller",
			age:  func(hs *HealthStats, age time.Duration) { hs.LoadBalancerControllerAlive = time.Now().Add(-age) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+" stays healthy inside its window", func(t *testing.T) {
			hc := newTestHealthController(t)
			tt.age(&hc.Status, justInside)
			assert.True(t, hc.CheckHealth(), "a heartbeat inside the staleness window should keep kube-router healthy")
		})

		t.Run(tt.name+" goes unhealthy outside its window", func(t *testing.T) {
			hc := newTestHealthController(t)
			tt.age(&hc.Status, justOutside)
			assert.False(t, hc.CheckHealth(), "a heartbeat past the staleness window should mark kube-router unhealthy")
		})
	}
}

// Test_CheckHealthIgnoresDisabledControllers guards against reporting unhealthy for a loop the
// operator never asked us to run, which therefore never beats
func Test_CheckHealthIgnoresDisabledControllers(t *testing.T) {
	stale := time.Now().Add(-time.Hour)

	tests := []struct {
		name    string
		disable func(config *options.KubeRouterConfig)
		age     func(hs *HealthStats)
	}{
		{
			name:    "firewall disabled",
			disable: func(config *options.KubeRouterConfig) { config.RunFirewall = false },
			age:     func(hs *HealthStats) { hs.NetworkPolicyControllerAlive = stale },
		},
		{
			name:    "router disabled",
			disable: func(config *options.KubeRouterConfig) { config.RunRouter = false },
			age: func(hs *HealthStats) {
				hs.NetworkRoutingControllerAlive = stale
				hs.RouteSyncControllerAlive = stale
			},
		},
		{
			name:    "service proxy disabled",
			disable: func(config *options.KubeRouterConfig) { config.RunServiceProxy = false },
			age:     func(hs *HealthStats) { hs.NetworkServicesControllerAlive = stale },
		},
		{
			name:    "load balancer disabled",
			disable: func(config *options.KubeRouterConfig) { config.RunLoadBalancer = false },
			age:     func(hs *HealthStats) { hs.LoadBalancerControllerAlive = stale },
		},
		{
			name:    "metrics disabled",
			disable: func(config *options.KubeRouterConfig) { config.MetricsEnabled = false },
			age:     func(hs *HealthStats) { hs.MetricsControllerAlive = stale },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hc := newTestHealthController(t)
			tt.disable(hc.Config)
			tt.age(&hc.Status)

			assert.True(t, hc.CheckHealth(), "a disabled controller's stale heartbeat should not affect health")
		})
	}
}

// Test_HandleHeartbeatSeedsTTL covers the only state carried between calls, which is that the first
// beat seeds the TTL and later beats advance the timestamp without touching it
func Test_HandleHeartbeatSeedsTTL(t *testing.T) {
	components := []struct {
		name      string
		component int
		alive     func(hs *HealthStats) time.Time
		ttl       func(hs *HealthStats) time.Duration
	}{
		{
			name:      "NetworkPolicyController",
			component: NetworkPolicyController,
			alive:     func(hs *HealthStats) time.Time { return hs.NetworkPolicyControllerAlive },
			ttl:       func(hs *HealthStats) time.Duration { return hs.NetworkPolicyControllerAliveTTL },
		},
		{
			name:      "NetworkRoutesController",
			component: NetworkRoutesController,
			alive:     func(hs *HealthStats) time.Time { return hs.NetworkRoutingControllerAlive },
			ttl:       func(hs *HealthStats) time.Duration { return hs.NetworkRoutingControllerAliveTTL },
		},
		{
			name:      "RouteSyncController",
			component: RouteSyncController,
			alive:     func(hs *HealthStats) time.Time { return hs.RouteSyncControllerAlive },
			ttl:       func(hs *HealthStats) time.Duration { return hs.RouteSyncControllerAliveTTL },
		},
		{
			name:      "NetworkServicesController",
			component: NetworkServicesController,
			alive:     func(hs *HealthStats) time.Time { return hs.NetworkServicesControllerAlive },
			ttl:       func(hs *HealthStats) time.Duration { return hs.NetworkServicesControllerAliveTTL },
		},
		{
			name:      "LoadBalancerController",
			component: LoadBalancerController,
			alive:     func(hs *HealthStats) time.Time { return hs.LoadBalancerControllerAlive },
			ttl:       func(hs *HealthStats) time.Duration { return hs.LoadBalancerControllerAliveTTL },
		},
		{
			name:      "HairpinController",
			component: HairpinController,
			alive:     func(hs *HealthStats) time.Time { return hs.HairpinControllerAlive },
			ttl:       func(hs *HealthStats) time.Duration { return hs.HairpinControllerAliveTTL },
		},
	}

	for _, tt := range components {
		t.Run(tt.name, func(t *testing.T) {
			hc, err := NewHealthController(options.NewKubeRouterConfig())
			if err != nil {
				t.Fatalf("failed to create health controller: %v", err)
			}

			first := time.Now()
			hc.HandleHeartbeat(&ControllerHeartbeat{Component: tt.component, LastHeartBeat: first})
			seededTTL := tt.ttl(&hc.Status)

			assert.Equal(t, first, tt.alive(&hc.Status), "the first heartbeat should be recorded verbatim")
			assert.NotZero(t, seededTTL, "the first heartbeat should seed a non-zero TTL from startup time")

			second := first.Add(time.Minute)
			hc.HandleHeartbeat(&ControllerHeartbeat{Component: tt.component, LastHeartBeat: second})

			assert.Equal(t, second, tt.alive(&hc.Status), "a later heartbeat should advance the timestamp")
			assert.Equal(t, seededTTL, tt.ttl(&hc.Status), "a later heartbeat should not re-seed the TTL")
		})
	}
}

// Test_SendHeartBeat checks the component id survives the channel, since that's what routes the beat
func Test_SendHeartBeat(t *testing.T) {
	for component, name := range HeartBeatCompNames {
		t.Run(name, func(t *testing.T) {
			channel := make(chan *ControllerHeartbeat, 1)
			before := time.Now()

			SendHeartBeat(channel, component)

			beat := <-channel
			assert.Equal(t, component, beat.Component, "the heartbeat should carry the component it was sent for")
			assert.False(t, beat.LastHeartBeat.Before(before), "the heartbeat should be stamped at send time")
		})
	}
}
