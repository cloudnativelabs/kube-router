package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	discoveryv1 "k8s.io/api/discovery/v1"
)

func TestEndpointIsReadyOrServing(t *testing.T) {
	tests := []struct {
		name       string
		conditions discoveryv1.EndpointConditions
		want       bool
	}{
		{
			name:       "nil conditions are interpreted as usable",
			conditions: discoveryv1.EndpointConditions{},
			want:       true,
		},
		{
			name:       "ready endpoint is usable",
			conditions: discoveryv1.EndpointConditions{Ready: new(true)},
			want:       true,
		},
		{
			name:       "not ready endpoint with nil serving is usable",
			conditions: discoveryv1.EndpointConditions{Ready: new(false)},
			want:       true,
		},
		{
			name:       "nil ready endpoint with serving disabled is usable",
			conditions: discoveryv1.EndpointConditions{Serving: new(false)},
			want:       true,
		},
		{
			name:       "serving endpoint is usable even when not ready",
			conditions: discoveryv1.EndpointConditions{Ready: new(false), Serving: new(true)},
			want:       true,
		},
		{
			name:       "terminating endpoint that is still serving is usable",
			conditions: discoveryv1.EndpointConditions{Ready: new(false), Serving: new(true), Terminating: new(true)},
			want:       true,
		},
		{
			name:       "not ready and not serving endpoint is not usable",
			conditions: discoveryv1.EndpointConditions{Ready: new(false), Serving: new(false)},
			want:       false,
		},
		{
			name:       "terminating endpoint that is not serving is not usable",
			conditions: discoveryv1.EndpointConditions{Ready: new(false), Serving: new(false), Terminating: new(true)},
			want:       false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, EndpointIsReadyOrServing(discoveryv1.Endpoint{Conditions: test.conditions}))
		})
	}
}
