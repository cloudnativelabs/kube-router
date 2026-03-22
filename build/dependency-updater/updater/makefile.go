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

// makeVarRe matches a Makefile variable assignment line.
// Captures: (1) variable name, (2) assignment operator (?= or =), (3) value, (4) optional comment.
var makeVarRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(\s*\??=\s*)([^\s#]+)(\s*#.*)?$`)

// MakefileResult holds the output of UpdateMakefile.
type MakefileResult struct {
	Diff diff.Result
	// ResolvedGolangImage is the fully-pinned golang image value after update
	// (e.g. "golang:1.25.8-alpine3.23@sha256:..."). Empty if no golang image
	// variable was processed. Used by callers to derive the canonical Go version
	// for CI env and go.mod updates, ensuring all three stay in sync.
	ResolvedGolangImage string
}

// UpdateMakefile reads the Makefile at path, updates all discovered dependency
// variables, and returns a MakefileResult. If dryRun is false the file is
// written back in place.
func UpdateMakefile(
	path string,
	lf *config.LockFile,
	docker *registry.DockerClient,
	gh *registry.GitHubClient,
	categories Categories,
	dryRun bool,
	verbose bool,
) (MakefileResult, []string, error) {
	original, err := os.ReadFile(path)
	if err != nil {
		return MakefileResult{Diff: diff.Result{Path: path}}, nil, fmt.Errorf("reading %s: %w", path, err)
	}

	lines := strings.Split(string(original), "\n")
	var warnings []string
	var resolvedGolangImage string

	for i, line := range lines {
		m := makeVarRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		varName := m[1]
		operator := m[2]
		value := m[3]
		comment := m[4]

		kind := ClassifyMakeVar(varName, value)

		switch kind {
		case KindDockerImage:
			if !categories.Docker {
				continue
			}
			updated, warn, err := updateDockerImageValue(varName, value, lf, docker, verbose)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("skipping %s: %v", varName, err))
				continue
			}
			if warn != "" {
				warnings = append(warnings, warn)
			}
			if updated != value {
				lines[i] = varName + operator + updated + comment
			}
			// Capture the resolved golang image value so the caller can derive
			// the canonical Go version from it.
			imageName, _, _ := ParseImageRef(value)
			if imageBaseName(imageName) == "golang" {
				resolvedGolangImage = updated
			}

		case KindToolVersion:
			if !categories.Tools {
				continue
			}
			repo, ok := config.LookupToolRepo(varName)
			if !ok {
				warnings = append(warnings, fmt.Sprintf("skipping %s: no upstream repo mapping", varName))
				continue
			}
			constraint := lf.GetConstraint(repoBaseName(repo))
			latest, err := gh.LatestRelease(repo, constraint)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("skipping %s: %v", varName, err))
				continue
			}
			// Preserve the v-prefix style of the original value: if the original
			// had no leading 'v' (e.g. "2.3.0") strip it from the fetched tag.
			latest = matchVPrefix(value, latest)
			if verbose {
				fmt.Printf("  %s: %s -> %s\n", varName, value, latest)
			}
			if latest != value {
				lines[i] = varName + operator + latest + comment
			}

		case KindDerived, KindUnknown:
			// Nothing to do.
		}
	}

	updated := strings.Join(lines, "\n")
	result := diff.Compute(path, string(original), updated)

	if !dryRun && result.Changed() {
		if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
			return MakefileResult{}, warnings, fmt.Errorf("writing %s: %w", path, err)
		}
	}

	return MakefileResult{Diff: result, ResolvedGolangImage: resolvedGolangImage}, warnings, nil
}

// updateDockerImageValue resolves the latest tag and digest for a Docker image value
// and returns the pinned form "image:tag@sha256:digest".
func updateDockerImageValue(
	varName, value string,
	lf *config.LockFile,
	docker *registry.DockerClient,
	verbose bool,
) (string, string, error) {
	imageName, tag, _ := ParseImageRef(value)
	constraint := lf.GetConstraint(imageBaseName(imageName))

	// If no tag is present, find the latest.
	if tag == "" {
		latest, err := docker.LatestTag(imageName, constraint)
		if err != nil {
			return value, "", fmt.Errorf("finding latest tag for %s: %w", imageName, err)
		}
		tag = latest
	} else {
		// Check if a newer tag exists within the constraint.
		latest, err := docker.LatestTag(imageName, constraint)
		if err == nil && tagIsNewer(latest, tag, imageName) {
			if verbose {
				fmt.Printf("  %s: updating tag %s -> %s\n", varName, tag, latest)
			}
			tag = latest
		}
	}

	digest, err := docker.ResolveDigest(imageName, tag)
	if err != nil {
		return value, "", fmt.Errorf("resolving digest for %s:%s: %w", imageName, tag, err)
	}

	pinned := imageName + ":" + tag + "@" + digest
	if verbose {
		fmt.Printf("  %s: %s -> %s\n", varName, value, pinned)
	}
	return pinned, "", nil
}

// matchVPrefix returns newVer with its leading 'v' stripped if original has no
// leading 'v', or unchanged otherwise. This preserves the formatting convention
// of the original value (e.g. "2.3.0" stays "2.3.0" rather than becoming "v2.3.0").
func matchVPrefix(original, newVer string) string {
	hasV := strings.HasPrefix(original, "v")
	newHasV := strings.HasPrefix(newVer, "v")
	if !hasV && newHasV {
		return strings.TrimPrefix(newVer, "v")
	}
	return newVer
}

// imageBaseName returns the simple name portion of an image for constraint lookup.
// "golang", "library/alpine" -> "alpine", "golangci/golangci-lint" -> "golangci-lint".
func imageBaseName(image string) string {
	parts := strings.Split(image, "/")
	name := parts[len(parts)-1]
	// Special case: the constraint key for the official golang image is "golang".
	if name == "golang" || image == "golang" {
		return "golang"
	}
	return name
}

// repoBaseName returns the repo name portion of "owner/repo" for constraint lookup.
func repoBaseName(repo string) string {
	parts := strings.Split(repo, "/")
	if len(parts) == 2 {
		return parts[1]
	}
	return repo
}

// tagIsNewer returns true if candidate is a strictly newer version than current
// for the given image.
func tagIsNewer(candidate, current, image string) bool {
	if candidate == current {
		return false
	}
	return registry.TagGreater(candidate, current, image)
}
