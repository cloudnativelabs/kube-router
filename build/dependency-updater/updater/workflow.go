package updater

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/diff"
	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/registry"
)

// usesRe matches GitHub Action uses: lines in both forms:
//
//	uses: owner/repo@ref
//	uses: owner/repo/subpath@ref
//
// It does NOT match local refs (uses: ./).
//
// Capture groups:
//
//	1: leading whitespace + "uses: "
//	2: owner/repo (and optional /subpath)
//	3: ref (SHA, tag like v6, or exact tag like v6.0.2)
//	4: optional trailing comment (e.g. "  # v6.0.2")
var usesRe = regexp.MustCompile(
	`^(\s*-?\s*uses:\s+)` + // group 1: preamble
		`([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_./.-]*)?)` + // group 2: owner/repo[/sub]
		`@([^\s#]+)` + // group 3: ref
		`(\s*#.*)?$`, // group 4: optional comment
)

// shaRe matches a 40-character hex commit SHA.
var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// exactTagRe matches a full semver tag like v6.0.2 or v4.34.1.
var exactTagRe = regexp.MustCompile(`^v?(\d+\.\d+\.\d+.*)$`)

// majorTagRe matches a bare major tag like v6 or v4.
var majorTagRe = regexp.MustCompile(`^v?(\d+)$`)

// UpdateWorkflows processes all YAML files in paths, updating GitHub Action
// uses: lines to SHA-pinned form. Returns one diff.Result per file that changed,
// plus accumulated warnings.
func UpdateWorkflows(
	paths []string,
	gh *registry.GitHubClient,
	dryRun bool,
	verbose bool,
) ([]diff.Result, []string, error) {
	var results []diff.Result
	var warnings []string

	for _, path := range paths {
		result, w, err := updateWorkflowFile(path, gh, dryRun, verbose)
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

// updateWorkflowFile processes a single YAML file.
func updateWorkflowFile(
	path string,
	gh *registry.GitHubClient,
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
		m := usesRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		preamble := m[1]
		actionRef := m[2] // e.g. "actions/checkout" or "github/codeql-action/init"
		ref := m[3]       // e.g. "v6", "v6.0.2", or a 40-char SHA
		existingComment := m[4]

		// Skip local refs.
		if strings.HasPrefix(actionRef, ".") {
			continue
		}

		// Parse owner/repo from actionRef (subpath may follow).
		owner, repo, subpath := parseActionRef(actionRef)
		ghRepo := owner + "/" + repo
		_ = subpath // kept for display only

		newSHA, newTag, warn, err := resolveAction(ghRepo, ref, existingComment, gh)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skipping %s in %s: %v", actionRef, path, err))
			continue
		}
		if warn != "" {
			warnings = append(warnings, warn)
		}

		// Build the new line.
		var fullAction string
		if subpath != "" {
			fullAction = owner + "/" + repo + "/" + subpath
		} else {
			fullAction = owner + "/" + repo
		}
		newLine := preamble + fullAction + "@" + newSHA + "  # " + newTag

		if verbose && newLine != line {
			fmt.Printf("  %s: %s -> %s\n", actionRef, ref, newTag)
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

// resolveAction takes a GitHub repo and its current ref (may be a bare major
// tag, exact tag, or SHA), and returns the best SHA and tag to pin to.
func resolveAction(ghRepo, ref, existingComment string, gh *registry.GitHubClient) (sha, tag string, warn string, err error) {
	var currentTag string
	var majorPrefix string

	switch {
	case shaRe.MatchString(ref):
		// Already a SHA — extract the current tag from the comment.
		currentTag = extractTagFromComment(existingComment)
		if currentTag == "" {
			// No comment tag; we can't determine what version to upgrade within.
			// Re-resolve the existing SHA just to ensure it's current.
			warn = fmt.Sprintf("no version comment on %s@%s; SHA unchanged", ghRepo, ref[:7])
			return ref, ref[:7], warn, nil
		}
		majorPrefix = majorVersionPrefix(currentTag)

	case exactTagRe.MatchString(ref):
		currentTag = ref
		majorPrefix = majorVersionPrefix(ref)

	case majorTagRe.MatchString(ref):
		// Bare major tag like "v6".
		majorPrefix = strings.TrimPrefix(ref, "v")
		majorPrefix = "v" + majorPrefix

	default:
		return ref, ref, fmt.Sprintf("unrecognised ref format %q for %s", ref, ghRepo), nil
	}

	// Find the latest tag within the same major version.
	latestTag, err := gh.LatestTag(ghRepo, majorPrefix)
	if err != nil {
		return "", "", "", fmt.Errorf("finding latest tag for %s: %w", ghRepo, err)
	}

	// Resolve to commit SHA.
	latestSHA, err := gh.ResolveTagToSHA(ghRepo, latestTag)
	if err != nil {
		return "", "", "", fmt.Errorf("resolving SHA for %s@%s: %w", ghRepo, latestTag, err)
	}

	return latestSHA, latestTag, "", nil
}

// parseActionRef splits "owner/repo" or "owner/repo/subpath" into its parts.
func parseActionRef(actionRef string) (owner, repo, subpath string) {
	parts := strings.SplitN(actionRef, "/", 3)
	switch len(parts) {
	case 1:
		return parts[0], "", ""
	case 2:
		return parts[0], parts[1], ""
	default:
		return parts[0], parts[1], parts[2]
	}
}

// extractTagFromComment parses a version tag from a trailing comment like "  # v6.0.2".
func extractTagFromComment(comment string) string {
	comment = strings.TrimSpace(comment)
	comment = strings.TrimPrefix(comment, "#")
	comment = strings.TrimSpace(comment)
	// Expect something like "v6.0.2" or "v4.34.1".
	if exactTagRe.MatchString(comment) {
		return comment
	}
	return ""
}

// majorVersionPrefix returns a string like "v6" from a full tag like "v6.0.2".
func majorVersionPrefix(tag string) string {
	t := strings.TrimPrefix(tag, "v")
	parts := strings.SplitN(t, ".", 2)
	return "v" + parts[0]
}
