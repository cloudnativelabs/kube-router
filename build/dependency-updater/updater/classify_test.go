package updater_test

import (
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/updater"
)

func TestClassifyMakeVar(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		want  updater.DepKind
	}{
		// Docker images — by suffix
		{"DOCKER_BUILD_IMAGE", "golang:1.25.7-alpine3.23", updater.KindDockerImage},
		{"RUNTIME_BASE", "alpine:3.23", updater.KindDockerImage},
		{"DOCKER_LINT_IMAGE", "golangci/golangci-lint:v2.8.0", updater.KindDockerImage},
		{"GRYPE_IMAGE", "anchore/grype:v0.110.0", updater.KindDockerImage},
		{"QEMU_IMAGE", "multiarch/qemu-user-static", updater.KindDockerImage},
		// Docker images — already digest-pinned
		{"DOCKER_BUILD_IMAGE", "golang:1.25.7-alpine3.23@sha256:abc123def456", updater.KindDockerImage},
		// Tool versions
		{"GOBGP_VERSION", "v4.2.0", updater.KindToolVersion},
		{"GORELEASER_VERSION", "v2.13.3", updater.KindToolVersion},
		{"DOCTOC_VERSION", "2.3.0", updater.KindToolVersion},
		{"CNI_VERSION", "v1.9.0", updater.KindToolVersion},
		// Derived (Makefile expansion)
		{"GRYPE_IMAGE", "anchore/grype:$(GRYPE_VERSION)", updater.KindDerived},
		{"BUILDTIME_BASE", "$(DOCKER_BUILD_IMAGE)", updater.KindDerived},
		// Unknown / non-dep
		{"GIT_COMMIT", "$(shell git describe --tags --dirty)", updater.KindDerived},
		{"NAME", "kube-router", updater.KindUnknown},
		{"UID", "1000", updater.KindUnknown},
		{"BUILD_IN_DOCKER", "true", updater.KindUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name+"="+tt.value, func(t *testing.T) {
			t.Parallel()
			got := updater.ClassifyMakeVar(tt.name, tt.value)
			if got != tt.want {
				t.Errorf("ClassifyMakeVar(%q, %q) = %v, want %v", tt.name, tt.value, got, tt.want)
			}
		})
	}
}

func TestParseImageRef(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ref        string
		wantName   string
		wantTag    string
		wantDigest string
	}{
		{
			ref:      "golang:1.25.7-alpine3.23",
			wantName: "golang", wantTag: "1.25.7-alpine3.23",
		},
		{
			ref:      "golang:1.25.7-alpine3.23@sha256:abc123",
			wantName: "golang", wantTag: "1.25.7-alpine3.23", wantDigest: "sha256:abc123",
		},
		{
			ref:      "alpine:3.23",
			wantName: "alpine", wantTag: "3.23",
		},
		{
			ref:      "multiarch/qemu-user-static",
			wantName: "multiarch/qemu-user-static", wantTag: "",
		},
		{
			ref:      "golangci/golangci-lint:v2.8.0",
			wantName: "golangci/golangci-lint", wantTag: "v2.8.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			t.Parallel()
			name, tag, digest := updater.ParseImageRef(tt.ref)
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if tag != tt.wantTag {
				t.Errorf("tag = %q, want %q", tag, tt.wantTag)
			}
			if digest != tt.wantDigest {
				t.Errorf("digest = %q, want %q", digest, tt.wantDigest)
			}
		})
	}
}
