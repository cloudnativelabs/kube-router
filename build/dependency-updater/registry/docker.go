package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DockerClient queries the Docker Hub Registry API v2 for tags and digests.
type DockerClient struct {
	httpClient *http.Client
}

// NewDockerClient returns a new DockerClient.
func NewDockerClient() *DockerClient {
	return &DockerClient{
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// LatestTag returns the latest stable tag for a Docker Hub image that satisfies
// the given constraint. If constraint is "" the absolute latest stable tag is
// returned. Official images (no slash in name) are queried as "library/name".
//
// For the golang image the constraint applies to the version portion; the
// alpine variant suffix is preserved. For alpine the constraint applies to
// the full version.
func (c *DockerClient) LatestTag(image, constraint string) (string, error) {
	repo := toHubRepo(image)
	tags, err := c.listTags(repo)
	if err != nil {
		return "", err
	}

	candidates := filterStableTags(tags, image, constraint)
	if len(candidates) == 0 {
		return "", fmt.Errorf("no matching tag found for %s with constraint %q", image, constraint)
	}

	// Sort descending and return the best match.
	sort.Slice(candidates, func(i, j int) bool {
		return TagGreater(candidates[i], candidates[j], image)
	})
	return candidates[0], nil
}

// ResolveDigest returns the sha256 manifest digest for image:tag.
// The digest is the content-addressable identifier for the manifest and is
// stable across pulls. For multi-arch images the linux/amd64 platform digest
// is returned.
func (c *DockerClient) ResolveDigest(image, tag string) (string, error) {
	repo := toHubRepo(image)
	token, err := c.getAuthToken(repo)
	if err != nil {
		return "", fmt.Errorf("auth for %s: %w", image, err)
	}

	// First try to get the manifest list (multi-arch).
	digest, err := c.fetchManifestDigest(repo, tag, token, "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json")
	if err == nil {
		return digest, nil
	}

	// Fall back to single-arch manifest.
	digest, err = c.fetchManifestDigest(repo, tag, token, "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json")
	if err != nil {
		return "", fmt.Errorf("resolving digest for %s:%s: %w", image, tag, err)
	}
	return digest, nil
}

// listTags fetches all tags for a Docker Hub repo using pagination.
func (c *DockerClient) listTags(repo string) ([]string, error) {
	var all []string
	url := fmt.Sprintf("https://registry-1.docker.io/v2/%s/tags/list", repo)
	token, err := c.getAuthToken(repo)
	if err != nil {
		return nil, err
	}

	for url != "" {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("listing tags for %s: %w", repo, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Docker Hub returned %d listing tags for %s", resp.StatusCode, repo)
		}

		var result struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("parsing tags for %s: %w", repo, err)
		}
		all = append(all, result.Tags...)

		// Follow Link header for pagination.
		url = parseLinkNext(resp.Header.Get("Link"))
		if url != "" && !strings.HasPrefix(url, "http") {
			url = "https://registry-1.docker.io" + url
		}
	}
	return all, nil
}

// getAuthToken obtains a Docker Hub registry token for the given repo.
func (c *DockerClient) getAuthToken(repo string) (string, error) {
	url := fmt.Sprintf("https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull", repo)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("getting auth token for %s: %w", repo, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("parsing auth token: %w", err)
	}
	return tok.Token, nil
}

// fetchManifestDigest fetches the manifest for repo:tag and returns the digest
// from the Docker-Content-Digest response header.
func (c *DockerClient) fetchManifestDigest(repo, tag, token, accept string) (string, error) {
	url := fmt.Sprintf("https://registry-1.docker.io/v2/%s/manifests/%s", repo, tag)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", accept)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("manifest fetch returned %d for %s:%s", resp.StatusCode, repo, tag)
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("no Docker-Content-Digest header for %s:%s", repo, tag)
	}
	return digest, nil
}

// toHubRepo converts an image name to the Docker Hub v2 API repo path.
// Official images have no slash; they are queried under "library/".
func toHubRepo(image string) string {
	if !strings.Contains(image, "/") {
		return "library/" + image
	}
	return image
}

// parseLinkNext extracts the URL from a Link: <url>; rel="next" header.
func parseLinkNext(header string) string {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, `rel="next"`) {
			if start := strings.Index(part, "<"); start != -1 {
				if end := strings.Index(part, ">"); end != -1 {
					return part[start+1 : end]
				}
			}
		}
	}
	return ""
}

// --- tag filtering & sorting -------------------------------------------------

// stableTagRe rejects tags that are clearly pre-release or architecture-specific.
var (
	alpineVariantRe = regexp.MustCompile(`^(\d+\.\d+\.\d+)-alpine(\d+\.\d+)$`)
	stableTagRe     = regexp.MustCompile(`^v?\d+\.\d+`)
	rejectRe        = regexp.MustCompile(`(?i)(alpha|beta|rc|pre|dev|nightly|snapshot|canary)`)
	// variantSuffixRe rejects tags with OS/arch variant suffixes (e.g. -alpine, -alpine3.21,
	// -bullseye, -buster) for images that are not the golang image.
	variantSuffixRe = regexp.MustCompile(`(?i)-(alpine|bullseye|buster|bookworm|focal|jammy|slim)`)
)

// isGolangImage reports whether image is the official golang Docker image.
func isGolangImage(image string) bool {
	return image == "golang" || strings.HasSuffix(image, "/golang")
}

// filterStableTags returns tags from the list that are stable and satisfy the constraint.
// image is used to apply image-specific filtering logic.
func filterStableTags(tags []string, image, constraint string) []string {
	var out []string
	for _, tag := range tags {
		if rejectRe.MatchString(tag) {
			continue
		}
		if !stableTagRe.MatchString(tag) {
			continue
		}
		if isGolangImage(image) {
			// For golang: only accept tags of the form "X.Y.Z-alpineA.B"
			if !alpineVariantRe.MatchString(tag) {
				continue
			}
		} else {
			// For all other images: reject variant-suffixed tags (e.g. v2.11.4-alpine).
			if variantSuffixRe.MatchString(tag) {
				continue
			}
		}
		if constraint != "" && !matchesConstraint(tag, constraint) {
			continue
		}
		out = append(out, tag)
	}
	return out
}

// TagGreater returns true if tag a sorts higher than b for the given image.
func TagGreater(a, b, image string) bool {
	// For golang alpine variant tags, compare the Go version then alpine version.
	if image == "golang" || strings.HasSuffix(image, "/golang") {
		am := alpineVariantRe.FindStringSubmatch(a)
		bm := alpineVariantRe.FindStringSubmatch(b)
		if am != nil && bm != nil {
			if am[1] != bm[1] {
				return semverGreater(am[1], bm[1])
			}
			return semverGreater(am[2], bm[2])
		}
	}
	return semverGreater(a, b)
}
