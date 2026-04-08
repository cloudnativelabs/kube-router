// Package updater contains file-specific parsers and updaters, plus the
// heuristic classifier that decides what kind of dependency a Makefile variable
// represents.
package updater

import (
	"regexp"
	"strings"
)

// DepKind describes the category of a discovered dependency.
type DepKind int

const (
	// KindUnknown means the variable does not look like a managed dependency.
	KindUnknown DepKind = iota
	// KindDockerImage means the value is (or should become) a Docker image reference.
	KindDockerImage
	// KindToolVersion means the value is a tool version string sourced from GitHub Releases.
	KindToolVersion
	// KindDerived means the value is a Makefile expansion of another variable — skip.
	KindDerived
)

var (
	// imageTagPattern matches bare image:tag or image:tag@sha256:digest values.
	// Examples: golang:1.25.7-alpine3.23  alpine:3.23  anchore/grype:v0.110.0
	//           golang:1.25.7@sha256:abc123
	// Must not start with '/' (which would be an absolute filesystem path).
	imageTagPattern = regexp.MustCompile(
		`^[a-z0-9._/-]+:[a-z0-9._:@+/-]+$`,
	)

	// imageNoTagPattern matches a bare image name with no colon (no tag, no digest).
	// Must be of the form "owner/image" or "registry/owner/image" — no leading slash,
	// no more than two slashes (to exclude filesystem paths like /home/runner/...).
	// Example: multiarch/qemu-user-static
	imageNoTagPattern = regexp.MustCompile(
		`^[a-z0-9._-]+/[a-z0-9._-]+(?:/[a-z0-9._-]+)?$`,
	)

	// versionPattern matches values that look like semver release tags.
	// Examples: v4.2.0  v2.13.3  2.3.0  v1.33.1
	versionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]`)

	// makefileExpansion matches values that contain $(VAR) expansions.
	makefileExpansion = regexp.MustCompile(`\$\(`)

	// imageVarSuffixes are variable name suffixes that identify Docker image variables.
	imageVarSuffixes = []string{"_IMAGE", "_BASE"}

	// imageVarNames are full variable names that are always treated as Docker images
	// regardless of suffix.
	imageVarNames = map[string]bool{
		"DOCKER_BUILD_IMAGE": true,
		"BUILDTIME_BASE":     true,
		"RUNTIME_BASE":       true,
	}
)

// ClassifyMakeVar returns the DepKind for a Makefile variable given its name and value.
func ClassifyMakeVar(name, value string) DepKind {
	// Skip empty values.
	if value == "" {
		return KindUnknown
	}

	// Skip values that are Makefile variable expansions — these are derived.
	if makefileExpansion.MatchString(value) {
		return KindDerived
	}

	// Check if the variable is a known Docker image variable by exact name.
	if imageVarNames[name] {
		if looksLikeImage(value) {
			return KindDockerImage
		}
	}

	// Check by suffix.
	upperName := strings.ToUpper(name)
	for _, suffix := range imageVarSuffixes {
		if strings.HasSuffix(upperName, suffix) {
			if looksLikeImage(value) {
				return KindDockerImage
			}
		}
	}

	// Check for tool version variables.
	if strings.HasSuffix(upperName, "_VERSION") && versionPattern.MatchString(value) {
		return KindToolVersion
	}

	return KindUnknown
}

// looksLikeImage returns true if the value looks like a Docker image reference
// (either image:tag, image:tag@sha256:digest, or bare image/name with no tag).
// Absolute filesystem paths (starting with '/') are explicitly rejected.
func looksLikeImage(value string) bool {
	if strings.HasPrefix(value, "/") {
		return false
	}
	return imageTagPattern.MatchString(value) || imageNoTagPattern.MatchString(value)
}

// ParseImageRef breaks an image reference into its component parts.
// It handles the following forms:
//
//	image:tag
//	image:tag@sha256:digest
//	image             (no tag, no digest — implies "latest")
//	registry/image:tag
//
// Returns name, tag, digest (digest may be empty).
func ParseImageRef(ref string) (name, tag, digest string) {
	// Strip digest if present.
	if before, after, found := strings.Cut(ref, "@sha256:"); found {
		digest = "sha256:" + after
		ref = before
	}

	// Split on last colon for tag (but avoid splitting registry:port).
	// A tag never contains a slash, so we check that the part after the last
	// colon has no slash.
	if idx := strings.LastIndex(ref, ":"); idx != -1 {
		possibleTag := ref[idx+1:]
		if !strings.Contains(possibleTag, "/") {
			tag = possibleTag
			name = ref[:idx]
			return
		}
	}

	// No tag found.
	name = ref
	return
}
