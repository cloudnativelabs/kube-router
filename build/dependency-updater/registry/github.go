// Package registry provides clients for querying upstream registries and APIs
// to discover latest versions and resolve tags to digests / commit SHAs.
package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// GitHubClient queries the GitHub API for releases, tags, and commit SHAs.
type GitHubClient struct {
	httpClient *http.Client
	token      string
}

// NewGitHubClient creates a GitHubClient. If GITHUB_TOKEN or GH_TOKEN is set
// in the environment it is used for authenticated requests (5000 req/hr);
// otherwise requests are unauthenticated (60 req/hr).
// GITHUB_TOKEN takes precedence over GH_TOKEN when both are set.
func NewGitHubClient() *GitHubClient {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	return &GitHubClient{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		token:      token,
	}
}

// IsAuthenticated reports whether the client has a GitHub token.
func (c *GitHubClient) IsAuthenticated() bool {
	return c.token != ""
}

// LatestRelease returns the latest non-prerelease tag for a GitHub repo
// (owner/repo), optionally filtered by a semver constraint string.
// constraint may be "" to mean "absolute latest".
func (c *GitHubClient) LatestRelease(repo, constraint string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases", repo)
	body, err := c.get(url)
	if err != nil {
		return "", fmt.Errorf("fetching releases for %s: %w", repo, err)
	}

	var releases []struct {
		TagName    string `json:"tag_name"`
		Prerelease bool   `json:"prerelease"`
		Draft      bool   `json:"draft"`
	}
	if err := json.Unmarshal(body, &releases); err != nil {
		return "", fmt.Errorf("parsing releases for %s: %w", repo, err)
	}

	for _, r := range releases {
		if r.Prerelease || r.Draft {
			continue
		}
		if constraint == "" || matchesConstraint(r.TagName, constraint) {
			return r.TagName, nil
		}
	}
	return "", fmt.Errorf("no matching release found for %s with constraint %q", repo, constraint)
}

// LatestTag returns the latest tag for a GitHub repo matching the given major
// version prefix (e.g. "v6" returns the latest "v6.x.y" tag).
// If majorPrefix is "" it returns the overall latest semver tag.
func (c *GitHubClient) LatestTag(repo, majorPrefix string) (string, error) {
	// Use the tags API with pagination — fetch up to 100 tags.
	url := fmt.Sprintf("https://api.github.com/repos/%s/tags?per_page=100", repo)
	body, err := c.get(url)
	if err != nil {
		return "", fmt.Errorf("fetching tags for %s: %w", repo, err)
	}

	var tags []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &tags); err != nil {
		return "", fmt.Errorf("parsing tags for %s: %w", repo, err)
	}

	var candidates []string
	for _, t := range tags {
		if !isSemverTag(t.Name) {
			continue
		}
		if majorPrefix == "" || hasMajorPrefix(t.Name, majorPrefix) {
			candidates = append(candidates, t.Name)
		}
	}

	if len(candidates) == 0 {
		return "", fmt.Errorf("no semver tags found for %s with prefix %q", repo, majorPrefix)
	}

	sort.Slice(candidates, func(i, j int) bool {
		return semverGreater(candidates[i], candidates[j])
	})
	return candidates[0], nil
}

// ResolveTagToSHA returns the commit SHA that a tag points to for a GitHub repo.
func (c *GitHubClient) ResolveTagToSHA(repo, tag string) (string, error) {
	// Try lightweight tag ref first.
	url := fmt.Sprintf("https://api.github.com/repos/%s/git/ref/tags/%s", repo, tag)
	body, err := c.get(url)
	if err != nil {
		return "", fmt.Errorf("resolving tag %s for %s: %w", tag, repo, err)
	}

	var ref struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	if err := json.Unmarshal(body, &ref); err != nil {
		return "", fmt.Errorf("parsing tag ref for %s@%s: %w", repo, tag, err)
	}

	// If the ref object is an annotated tag, we need to dereference it to get
	// the commit SHA.
	if ref.Object.Type == "tag" {
		return c.dereferenceTag(repo, ref.Object.SHA)
	}
	return ref.Object.SHA, nil
}

// ResolveHeadSHA returns the current HEAD commit SHA for a branch of a repo.
func (c *GitHubClient) ResolveHeadSHA(repo, branch string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", repo, branch)
	body, err := c.get(url)
	if err != nil {
		return "", fmt.Errorf("fetching HEAD of %s/%s: %w", repo, branch, err)
	}

	var commit struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &commit); err != nil {
		return "", fmt.Errorf("parsing commit for %s/%s: %w", repo, branch, err)
	}
	if commit.SHA == "" {
		return "", fmt.Errorf("empty SHA for %s/%s", repo, branch)
	}
	return commit.SHA, nil
}

// dereferenceTag follows an annotated tag object to its underlying commit SHA.
func (c *GitHubClient) dereferenceTag(repo, tagObjectSHA string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/git/tags/%s", repo, tagObjectSHA)
	body, err := c.get(url)
	if err != nil {
		return "", fmt.Errorf("dereferencing tag object %s for %s: %w", tagObjectSHA, repo, err)
	}

	var tag struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := json.Unmarshal(body, &tag); err != nil {
		return "", fmt.Errorf("parsing tag object for %s: %w", repo, err)
	}
	return tag.Object.SHA, nil
}

// get performs an authenticated GET request and returns the response body.
func (c *GitHubClient) get(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d for %s: %s", resp.StatusCode, url, truncate(string(body), 200))
	}
	return body, nil
}

// --- semver helpers ----------------------------------------------------------

var (
	semverRe      = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)
	semverShortRe = regexp.MustCompile(`^v?(\d+)\.(\d+)$`)
)

func isSemverTag(tag string) bool {
	return semverRe.MatchString(tag) || semverShortRe.MatchString(tag)
}

// hasMajorPrefix returns true if tag starts with the given major prefix,
// e.g. hasMajorPrefix("v6.0.2", "v6") == true.
func hasMajorPrefix(tag, prefix string) bool {
	// Normalise both to lower-case and ensure prefix ends before minor version.
	t := strings.TrimPrefix(tag, "v")
	p := strings.TrimPrefix(prefix, "v")
	return strings.HasPrefix(t, p+".")
}

// semverGreater returns true if a is a higher semver than b.
// Non-semver strings are treated as less than any semver.
func semverGreater(a, b string) bool {
	av := parseSemver(a)
	bv := parseSemver(b)
	for i := range av {
		if av[i] != bv[i] {
			return av[i] > bv[i]
		}
	}
	return false
}

func parseSemver(s string) [3]int {
	if m := semverRe.FindStringSubmatch(s); m != nil {
		var v [3]int
		fmt.Sscanf(m[1], "%d", &v[0])
		fmt.Sscanf(m[2], "%d", &v[1])
		fmt.Sscanf(m[3], "%d", &v[2])
		return v
	}
	// Two-part version like "3.23" or "1.25".
	if m := semverShortRe.FindStringSubmatch(s); m != nil {
		var v [3]int
		fmt.Sscanf(m[1], "%d", &v[0])
		fmt.Sscanf(m[2], "%d", &v[1])
		return v
	}
	return [3]int{}
}

// matchesConstraint returns true if tag satisfies the constraint string.
// Supported forms: "~1.25" (patch), "~v4" (major only), "~3.23" (patch).
func matchesConstraint(tag, constraint string) bool {
	c := strings.TrimPrefix(constraint, "~")
	c = strings.TrimPrefix(c, "v")
	t := strings.TrimPrefix(tag, "v")

	parts := strings.Split(c, ".")
	switch len(parts) {
	case 1:
		// Major only constraint e.g. "4" — accept any v4.x.y.
		return strings.HasPrefix(t, parts[0]+".")
	case 2:
		// Major.minor constraint e.g. "1.25" — accept any v1.25.x.
		return strings.HasPrefix(t, parts[0]+"."+parts[1]+".")
	default:
		// Exact version.
		return t == c
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
