package updater

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/diff"
	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/registry"
)

// ownImageRe matches an image: field referencing the project's own image.
// Handles lines like:
//
//	image: docker.io/cloudnativelabs/kube-router
//	image: docker.io/cloudnativelabs/kube-router:v2.3.0
//	image: cloudnativelabs/kube-router
var ownImageRe = regexp.MustCompile(
	`^(\s*image:\s+(?:docker\.io/)?(cloudnativelabs/kube-router))(:.*)?$`,
)

// UpdateDaemonsets updates the kube-router image tag in all discovered daemonset
// YAML files to the given release tag. The release tag should be the full semver
// tag like "v2.3.0".
func UpdateDaemonsets(
	paths []string,
	releaseTag string,
	docker *registry.DockerClient,
	dryRun bool,
	verbose bool,
) ([]diff.Result, []string, error) {
	var results []diff.Result
	var warnings []string

	// Resolve digest for the release tag.
	digest, err := docker.ResolveDigest("cloudnativelabs/kube-router", releaseTag)
	if err != nil {
		return nil, []string{fmt.Sprintf("could not resolve digest for kube-router:%s: %v", releaseTag, err)}, nil
	}
	pinned := "cloudnativelabs/kube-router:" + releaseTag + "@" + digest

	for _, path := range paths {
		result, w, err := updateDaemonsetFile(path, pinned, dryRun, verbose)
		warnings = append(warnings, w...)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skipping %s: %v", path, err))
			continue
		}
		if result.Changed() {
			results = append(results, result)
		}
	}
	return results, warnings, nil
}

func updateDaemonsetFile(path, pinnedImage string, dryRun, verbose bool) (diff.Result, []string, error) {
	original, err := os.ReadFile(path)
	if err != nil {
		return diff.Result{Path: path}, nil, fmt.Errorf("reading %s: %w", path, err)
	}

	lines := strings.Split(string(original), "\n")
	var warnings []string

	for i, line := range lines {
		m := ownImageRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// m[1] = leading whitespace + "image: " + optional "docker.io/"
		// m[2] = "cloudnativelabs/kube-router"
		// m[3] = optional ":tag"
		prefix := m[1]
		// Reconstruct keeping the docker.io/ prefix if it was present.
		var newLine string
		if strings.Contains(prefix, "docker.io/") {
			newLine = strings.Replace(prefix, "cloudnativelabs/kube-router", "", 1) + "docker.io/" + pinnedImage
		} else {
			newLine = strings.Replace(prefix, "cloudnativelabs/kube-router", pinnedImage, 1)
		}

		if verbose && newLine != line {
			fmt.Printf("  %s: updating kube-router image\n", path)
		}
		lines[i] = newLine
	}

	updated := strings.Join(lines, "\n")
	result := diff.Compute(path, string(original), updated)

	if !dryRun && result.Changed() {
		if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
			return result, warnings, fmt.Errorf("writing %s: %w", path, err)
		}
	}
	return result, warnings, nil
}
