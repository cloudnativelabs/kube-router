package proxy

import (
	"sync"
	"testing"
)

func TestNodePortHealthCheckConcurrentAccess(t *testing.T) {
	// Verify that concurrent reads and writes to the healthcheck controller
	// do not cause a data race (this test is meaningful with -race flag)
	nphc := NewNodePortHealthCheck()

	svcMap := serviceInfoMap{
		"test-svc": &serviceInfo{
			healthCheckNodePort: 0, // no actual listener needed
		},
	}
	epMap := endpointSliceInfoMap{
		"test-svc": {
			{ip: "10.0.0.1", port: 80, isLocal: true},
		},
	}

	var wg sync.WaitGroup
	// Concurrent writes
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = nphc.UpdateServicesInfo(svcMap, epMap)
		}
	}()

	// Concurrent reads (simulating what the HTTP handler does)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			nphc.mu.RLock()
			_ = nphc.endpointsInfoMap["test-svc"]
			nphc.mu.RUnlock()
		}
	}()

	wg.Wait()
}
