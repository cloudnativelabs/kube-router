package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/config"
)

func TestLoadMissingFile(t *testing.T) {
	t.Parallel()
	lf, err := config.Load("/nonexistent/versions.lock.yaml")
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
	if lf.GetConstraint("golang") != "" {
		t.Errorf("expected empty constraint for missing file")
	}
}

func TestLoadConstraints(t *testing.T) {
	t.Parallel()
	content := `
constraints:
  golang:
    constraint: "~1.25"
  alpine:
    constraint: "~3.23"
  gobgp:
    constraint: "~v4"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "versions.lock.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	lf, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name string
		want string
	}{
		{"golang", "~1.25"},
		{"alpine", "~3.23"},
		{"gobgp", "~v4"},
		{"unknown", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := lf.GetConstraint(tt.name)
			if got != tt.want {
				t.Errorf("GetConstraint(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestLookupToolRepo(t *testing.T) {
	t.Parallel()
	tests := []struct {
		varName string
		want    string
		found   bool
	}{
		{"GOBGP_VERSION", "osrg/gobgp", true},
		{"GORELEASER_VERSION", "goreleaser/goreleaser", true},
		{"CNI_VERSION", "containernetworking/plugins", true},
		{"TYPOS_VERSION", "crate-ci/typos", true},
		{"GRYPE_VERSION", "anchore/grype", true},
		{"UNKNOWN_VERSION", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.varName, func(t *testing.T) {
			t.Parallel()
			got, ok := config.LookupToolRepo(tt.varName)
			if ok != tt.found {
				t.Errorf("LookupToolRepo(%q) found=%v, want %v", tt.varName, ok, tt.found)
			}
			if ok && got != tt.want {
				t.Errorf("LookupToolRepo(%q) = %q, want %q", tt.varName, got, tt.want)
			}
		})
	}
}
