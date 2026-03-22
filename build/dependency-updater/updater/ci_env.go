package updater

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/config"
	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/diff"
	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/registry"
)

// envLineRe matches a top-level env block value line in a GitHub workflow YAML.
// It handles both plain values and lines that carry a YAML anchor (e.g. &my_anchor)
// between the key and the quoted value — the anchor token is captured as part of
// the preamble and round-tripped verbatim so that anchor aliases elsewhere in the
// file continue to resolve correctly after the value is updated.
//
// Examples matched:
//
//	BUILDTIME_BASE: "golang:1.25.7-alpine3.23"
//	BUILDTIME_BASE: &buildtime_base "golang:1.25.7-alpine3.23"
//	GO_VERSION: "~1.25.7"
//	GO_VERSION: &go_version "~1.25.7"
//
// Capture groups: (1) leading whitespace + key + colon + optional anchor token + whitespace,
// (2) optional opening quote, (3) value, (4) optional closing quote, (5) optional trailing comment.
var envLineRe = regexp.MustCompile(
	`^(\s+[A-Z_][A-Z0-9_]*:\s+(?:&\S+\s+)?)("?)([^"#\n]+)("?)(\s*#.*)?$`,
)

// semverRangeRe matches a version or semver range value like "~1.25.7" or "1.25.7".
var semverRangeRe = regexp.MustCompile(`^~?v?\d+\.\d+`)

// UpdateCIEnv processes all YAML files in paths and updates Docker image values
// and Go version values found in top-level env: blocks.
// Only files that contain a top-level "env:" section are modified.
//
// resolvedGoVersion, if non-empty, is used as the authoritative Go version
// instead of querying go.dev. This ensures the CI Go version stays in sync
// with the golang Docker image tag resolved earlier in the same run.
func UpdateCIEnv(
	paths []string,
	lf *config.LockFile,
	docker *registry.DockerClient,
	goClient *registry.GoVersionClient,
	resolvedGoVersion string,
	categories Categories,
	dryRun bool,
	verbose bool,
) ([]diff.Result, []string, error) {
	var results []diff.Result
	var warnings []string

	for _, path := range paths {
		result, w, err := updateCIEnvFile(path, lf, docker, goClient, resolvedGoVersion, categories, dryRun, verbose)
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

func updateCIEnvFile(
	path string,
	lf *config.LockFile,
	docker *registry.DockerClient,
	goClient *registry.GoVersionClient,
	resolvedGoVersion string,
	categories Categories,
	dryRun bool,
	verbose bool,
) (diff.Result, []string, error) {
	original, err := os.ReadFile(path)
	if err != nil {
		return diff.Result{Path: path}, nil, fmt.Errorf("reading %s: %w", path, err)
	}

	content := string(original)
	lines := strings.Split(content, "\n")
	var warnings []string

	// Only process files that have a top-level "env:" block.
	inEnvBlock := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect top-level "env:" line (no leading whitespace).
		if line == "env:" {
			inEnvBlock = true
			continue
		}
		// A non-indented non-empty line ends the env block.
		if inEnvBlock && trimmed != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inEnvBlock = false
		}
		if !inEnvBlock {
			continue
		}

		m := envLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		preamble := m[1]
		openQuote := m[2]
		value := strings.TrimSpace(m[3])
		closeQuote := m[4]
		trailingComment := m[5]

		// Determine what this value is.
		if categories.Docker && looksLikeImage(value) {
			imageName, tag, _ := ParseImageRef(value)
			constraint := lf.GetConstraint(imageBaseName(imageName))

			if tag == "" {
				latest, err := docker.LatestTag(imageName, constraint)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("skipping %s in %s: %v", value, path, err))
					continue
				}
				tag = latest
			} else if isSemverTag(tag) {
				latest, err := docker.LatestTag(imageName, constraint)
				if err == nil && registry.TagGreater(latest, tag, imageName) {
					tag = latest
				}
			}
			// else: non-semver tag (e.g. "alpine", "latest") — only pin digest.

			digest, err := docker.ResolveDigest(imageName, tag)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("skipping digest for %s: %v", value, err))
				continue
			}
			pinned := imageName + ":" + tag + "@" + digest
			if verbose && pinned != value {
				fmt.Printf("  %s (env): %s -> %s\n", path, value, pinned)
			}
			lines[i] = preamble + openQuote + pinned + closeQuote + trailingComment

		} else if categories.Go && semverRangeRe.MatchString(value) {
			// This looks like a Go version range (e.g. "~1.25.7").
			prefix := ""
			bare := value
			if strings.HasPrefix(value, "~") {
				prefix = "~"
				bare = value[1:]
			}

			var latest string
			if resolvedGoVersion != "" {
				// Use the Go version extracted from the golang Docker image tag
				// resolved earlier in this run — guarantees atomicity with the
				// Docker image update.
				latest = resolvedGoVersion
			} else {
				constraint := lf.GetConstraint("golang")
				if constraint == "" {
					constraint = "~" + strings.Join(strings.Split(bare, ".")[:2], ".")
				}
				var err error
				latest, err = goClient.LatestVersion(strings.TrimPrefix(constraint, "~"))
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("skipping Go version in %s: %v", path, err))
					continue
				}
			}

			updated := prefix + latest
			if verbose && updated != value {
				fmt.Printf("  %s (env): %s -> %s\n", path, value, updated)
			}
			lines[i] = preamble + openQuote + updated + closeQuote + trailingComment
		}
	}

	updatedContent := strings.Join(lines, "\n")
	result := diff.Compute(path, content, updatedContent)

	if !dryRun && result.Changed() {
		if err := os.WriteFile(path, []byte(updatedContent), 0o644); err != nil {
			return result, warnings, fmt.Errorf("writing %s: %w", path, err)
		}
	}
	return result, warnings, nil
}
