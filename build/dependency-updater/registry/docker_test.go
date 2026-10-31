package registry_test

import (
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/registry"
)

func TestTrimArchSuffix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		tag  string
		want string
	}{
		{"v0.121.0-s390x", "v0.121.0"},
		{"v0.121.0-arm64v8", "v0.121.0"},
		{"v0.121.0-AMD64", "v0.121.0"},
		{"v0.121.0-debug-ppc64le", "v0.121.0-debug"},
		{"1.2.3-armv7", "1.2.3"},
		{"v0.121.0", "v0.121.0"},
		{"v0.121.0-debug", "v0.121.0-debug"},
		{"1.27.3-alpine3.24", "1.27.3-alpine3.24"},
		// Only a trailing suffix counts, so an arch name in the middle of a tag is left alone
		{"v1.0.0-s390x-debug", "v1.0.0-s390x-debug"},
	}
	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			t.Parallel()
			if got := registry.TrimArchSuffix(tt.tag); got != tt.want {
				t.Errorf("TrimArchSuffix(%q) = %q, want %q", tt.tag, got, tt.want)
			}
		})
	}
}

// TestPickLatestTagGrype uses grype's real tag shapes: every version also ships -debug and -nonroot flavors plus a
// single-arch tag of each, and an unstable sort used to hand back whichever one the registry listed last
func TestPickLatestTagGrype(t *testing.T) {
	t.Parallel()
	var tags []string
	for _, version := range []string{"v0.120.0", "v0.121.0"} {
		for _, flavor := range []string{"", "-debug", "-nonroot"} {
			for _, arch := range []string{"-s390x", "-ppc64le", "-arm64v8", "-amd64", ""} {
				tags = append(tags, version+flavor+arch)
			}
		}
	}

	// Run it a few times with the list rotated so that a lucky input order can't hide a tie-break bug
	for i := range len(tags) {
		rotated := append(append([]string{}, tags[i:]...), tags[:i]...)
		got, err := registry.PickLatestTag(rotated, "anchore/grype", "")
		if err != nil {
			t.Fatalf("PickLatestTag: %v", err)
		}
		if got != "v0.121.0" {
			t.Fatalf("PickLatestTag with input rotated by %d = %q, want v0.121.0", i, got)
		}
	}
}

func TestPickLatestTag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		tags       []string
		image      string
		constraint string
		want       string
		wantErr    bool
	}{
		{
			name:  "only single-arch tags for the newest version",
			tags:  []string{"v1.0.0", "v1.1.0-amd64", "v1.1.0-s390x"},
			image: "example/tool",
			want:  "v1.0.0",
		},
		{
			name:       "golang keeps its alpine variant",
			tags:       []string{"1.27.3-alpine3.24", "1.27.3-alpine3.23", "1.27.2-alpine3.24", "1.27.3"},
			image:      "golang",
			constraint: "~1.27",
			want:       "1.27.3-alpine3.24",
		},
		{
			name:    "nothing but single-arch tags",
			tags:    []string{"v1.0.0-amd64", "v1.0.0-arm64v8"},
			image:   "example/tool",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := registry.PickLatestTag(tt.tags, tt.image, tt.constraint)
			if (err != nil) != tt.wantErr {
				t.Fatalf("PickLatestTag() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("PickLatestTag() = %q, want %q", got, tt.want)
			}
		})
	}
}
