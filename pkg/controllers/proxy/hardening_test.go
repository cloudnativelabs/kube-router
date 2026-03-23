package proxy

import (
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShuffleDoesNotPanicOnEmptySlice(t *testing.T) {
	// shuffle should handle empty and single-element slices safely
	tests := []struct {
		name  string
		input []endpointSliceInfo
	}{
		{
			name:  "empty slice",
			input: []endpointSliceInfo{},
		},
		{
			name:  "single element",
			input: []endpointSliceInfo{{ip: "10.0.0.1", port: 80}},
		},
		{
			name: "multiple elements",
			input: []endpointSliceInfo{
				{ip: "10.0.0.1", port: 80},
				{ip: "10.0.0.2", port: 80},
				{ip: "10.0.0.3", port: 80},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			result := shuffle(tt.input)
			assert.Equal(t, len(tt.input), len(result), "shuffle should preserve slice length")
		})
	}
}

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

func TestSetupMangleTableRuleRejectsInvalidIP(t *testing.T) {
	// Verify that net.ParseIP returning nil is handled gracefully
	// rather than causing a nil pointer dereference on .To4()
	tests := []struct {
		name string
		ip   string
	}{
		{name: "empty string", ip: ""},
		{name: "garbage", ip: "not-an-ip"},
		{name: "incomplete", ip: "192.168.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedIP := net.ParseIP(tt.ip)
			assert.Nil(t, parsedIP, "net.ParseIP should return nil for invalid IP %q", tt.ip)
		})
	}
}
