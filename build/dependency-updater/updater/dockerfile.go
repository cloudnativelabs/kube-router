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

// argDefaultRe matches a Dockerfile ARG line with a default value.
// Example: ARG BUILDTIME_BASE=golang:1-alpine
// Captures: (1) "ARG NAME=", (2) value.
var argDefaultRe = regexp.MustCompile(`^(ARG\s+[A-Za-z_][A-Za-z0-9_]*=)(.+)$`)

// envSHARe matches a Dockerfile ENV line whose value is a 40-char hex SHA,
// optionally followed by a comment referencing a GitHub repo.
// Example: ENV IPTABLES_WRAPPERS_VERSION=c6b9b2d4ee8701f3d476768ab8732d1b85ec7fef
// Captures: (1) "ENV NAME=", (2) 40-char SHA, (3) optional trailing comment.
var envSHARe = regexp.MustCompile(`^(ENV\s+[A-Za-z_][A-Za-z0-9_]*=)([0-9a-f]{40})(\s*#.*)?$`)

// repoCommentRe extracts a "owner/repo" reference from a comment.
var repoCommentRe = regexp.MustCompile(`([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)`)

// UpdateDockerfiles processes all Dockerfiles in paths, updating ARG default
// values and ENV commit-SHA pins.
func UpdateDockerfiles(
	paths []string,
	lf *config.LockFile,
	docker *registry.DockerClient,
	gh *registry.GitHubClient,
	categories Categories,
	dryRun bool,
	verbose bool,
) ([]diff.Result, []string, error) {
	var results []diff.Result
	var warnings []string

	for _, path := range paths {
		result, w, err := updateDockerfile(path, lf, docker, gh, categories, dryRun, verbose)
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

func updateDockerfile(
	path string,
	lf *config.LockFile,
	docker *registry.DockerClient,
	gh *registry.GitHubClient,
	categories Categories,
	dryRun bool,
	verbose bool,
) (diff.Result, []string, error) {
	original, err := os.ReadFile(path)
	if err != nil {
		return diff.Result{Path: path}, nil, fmt.Errorf("reading %s: %w", path, err)
	}

	lines := strings.Split(string(original), "\n")
	var warnings []string

	for i, line := range lines {
		// Handle ARG lines with Docker image defaults.
		if categories.Docker {
			if m := argDefaultRe.FindStringSubmatch(line); m != nil {
				value := m[2]
				if looksLikeImage(value) {
					updated, _, err := updateDockerImageValue("ARG", value, lf, docker, verbose)
					if err != nil {
						warnings = append(warnings, fmt.Sprintf("skipping ARG in %s: %v", path, err))
						continue
					}
					if updated != value {
						lines[i] = m[1] + updated
					}
				}
			}
		}

		// Handle ENV lines with commit SHA pins.
		if categories.Dockerfile {
			if m := envSHARe.FindStringSubmatch(line); m != nil {
				currentSHA := m[2]
				comment := m[3]

				// Try to extract a GitHub repo reference from the preceding comment line
				// or the same line's comment.
				repo := extractRepoFromContext(lines, i, comment)
				if repo == "" {
					continue // can't determine upstream, skip
				}

				newSHA, err := gh.ResolveHeadSHA(repo, "master")
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("skipping ENV SHA in %s (%s): %v", path, repo, err))
					continue
				}
				if verbose && newSHA != currentSHA {
					fmt.Printf("  %s: %s -> %s (HEAD of %s)\n", path, currentSHA[:7], newSHA[:7], repo)
				}
				if newSHA != currentSHA {
					lines[i] = m[1] + newSHA + comment
				}
			}
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

// extractRepoFromContext looks for a GitHub repo reference in the comment on
// the current line or the nearest preceding comment line.
func extractRepoFromContext(lines []string, idx int, inlineComment string) string {
	// Check inline comment first.
	if repo := findRepoInText(inlineComment); repo != "" {
		return repo
	}
	// Walk backwards up to 3 lines looking for a comment.
	for j := idx - 1; j >= 0 && j >= idx-3; j-- {
		trimmed := strings.TrimSpace(lines[j])
		if strings.HasPrefix(trimmed, "#") {
			if repo := findRepoInText(trimmed); repo != "" {
				return repo
			}
		}
	}
	return ""
}

// findRepoInText extracts the first "owner/repo" pattern from text, filtering
// out obvious non-repo patterns.
func findRepoInText(text string) string {
	matches := repoCommentRe.FindAllString(text, -1)
	for _, m := range matches {
		// Filter out things that look like file paths or version strings.
		if strings.Contains(m, ".") {
			continue
		}
		return m
	}
	// Second pass: allow dots in repo names (e.g. kubernetes-sigs/iptables-wrappers).
	for _, m := range matches {
		parts := strings.Split(m, "/")
		if len(parts) == 2 && len(parts[0]) > 2 && len(parts[1]) > 2 {
			return m
		}
	}
	return ""
}
