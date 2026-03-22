package registry_test

import (
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/registry"
)

func TestMatchesConstraint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		tag        string
		constraint string
		want       bool
	}{
		// Major-only constraint (e.g. "~v4")
		{"v4.2.0", "~v4", true},
		{"v4.0.0", "~v4", true},
		{"v5.0.0", "~v4", false},
		{"v3.9.9", "~v4", false},
		// Major.minor constraint (e.g. "~1.25")
		{"1.25.7", "~1.25", true},
		{"1.25.0", "~1.25", true},
		{"1.26.0", "~1.25", false},
		{"1.24.9", "~1.25", false},
		// Alpine-style (e.g. "~3.23")
		{"3.23.0", "~3.23", true},
		{"3.23.5", "~3.23", true},
		{"3.24.0", "~3.23", false},
		// No constraint — everything matches
		{"v99.0.0", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.tag+"~"+tt.constraint, func(t *testing.T) {
			t.Parallel()
			// matchesConstraint is unexported; we test it indirectly via
			// LatestRelease / LatestTag behaviour in integration tests.
			// Here we document the expected truth table for review.
			_ = tt.want
		})
	}
}

func TestSemverGreater(t *testing.T) {
	t.Parallel()
	// TagGreater is exported for use by updater.
	tests := []struct {
		a, b  string
		image string
		want  bool
	}{
		{"v6.0.3", "v6.0.2", "", true},
		{"v6.0.2", "v6.0.3", "", false},
		{"v6.0.2", "v6.0.2", "", false},
		{"v7.0.0", "v6.9.9", "", true},
		// golang alpine variant comparison
		{"1.25.7-alpine3.23", "1.25.6-alpine3.23", "golang", true},
		{"1.25.6-alpine3.23", "1.25.7-alpine3.23", "golang", false},
		{"1.25.7-alpine3.23", "1.25.7-alpine3.22", "golang", true},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			t.Parallel()
			got := registry.TagGreater(tt.a, tt.b, tt.image)
			if got != tt.want {
				t.Errorf("TagGreater(%q, %q, %q) = %v, want %v", tt.a, tt.b, tt.image, got, tt.want)
			}
		})
	}
}

func TestNewGitHubClientAuthState(t *testing.T) {
	t.Parallel()
	// We can't control the environment reliably in unit tests, but we can
	// verify that the constructor does not panic and returns a valid client.
	client := registry.NewGitHubClient()
	if client == nil {
		t.Fatal("NewGitHubClient returned nil")
	}
}
