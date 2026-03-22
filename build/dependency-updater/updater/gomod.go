package updater

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/diff"
	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/registry"
)

// toolchainRe matches the toolchain directive in go.mod.
var toolchainRe = regexp.MustCompile(`^(toolchain\s+go)([0-9]+\.[0-9]+\.[0-9]+.*)$`)

// goDirectiveRe matches the go directive in go.mod.
var goDirectiveRe = regexp.MustCompile(`^(go\s+)([0-9]+\.[0-9]+.*)$`)

// UpdateGoMod updates the toolchain directive in go.mod to match the latest Go
// version. If the file does not have a toolchain directive it is left unchanged.
func UpdateGoMod(
	path string,
	goClient *registry.GoVersionClient,
	constraint string,
	dryRun bool,
	verbose bool,
) (diff.Result, []string, error) {
	original, err := os.ReadFile(path)
	if err != nil {
		return diff.Result{Path: path}, nil, fmt.Errorf("reading %s: %w", path, err)
	}

	latest, err := goClient.LatestVersion(constraint)
	if err != nil {
		return diff.Result{Path: path}, []string{fmt.Sprintf("skipping go.mod: %v", err)}, nil
	}

	lines := strings.Split(string(original), "\n")
	var warnings []string

	for i, line := range lines {
		if m := toolchainRe.FindStringSubmatch(line); m != nil {
			current := m[2]
			if current != latest {
				if verbose {
					fmt.Printf("  go.mod toolchain: go%s -> go%s\n", current, latest)
				}
				lines[i] = m[1] + latest
			}
			break
		}
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
