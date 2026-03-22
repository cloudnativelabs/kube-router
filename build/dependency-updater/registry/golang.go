package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// GoVersionClient fetches available Go releases from go.dev.
type GoVersionClient struct {
	httpClient *http.Client
}

// NewGoVersionClient returns a new GoVersionClient.
func NewGoVersionClient() *GoVersionClient {
	return &GoVersionClient{
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// LatestVersion returns the latest stable Go version matching the given constraint.
// constraint may be "" for absolute latest. The returned string is a bare version
// like "1.25.7" (no "go" prefix).
func (c *GoVersionClient) LatestVersion(constraint string) (string, error) {
	resp, err := c.httpClient.Get("https://go.dev/dl/?mode=json")
	if err != nil {
		return "", fmt.Errorf("fetching Go releases: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading Go releases: %w", err)
	}

	var releases []struct {
		Version string `json:"version"` // e.g. "go1.25.7"
		Stable  bool   `json:"stable"`
	}
	if err := json.Unmarshal(body, &releases); err != nil {
		return "", fmt.Errorf("parsing Go releases: %w", err)
	}

	var candidates []string
	for _, r := range releases {
		if !r.Stable {
			continue
		}
		// Strip the "go" prefix.
		ver := strings.TrimPrefix(r.Version, "go")
		if constraint == "" || matchesConstraint(ver, constraint) {
			candidates = append(candidates, ver)
		}
	}

	if len(candidates) == 0 {
		return "", fmt.Errorf("no stable Go release found matching constraint %q", constraint)
	}

	sort.Slice(candidates, func(i, j int) bool {
		return semverGreater(candidates[i], candidates[j])
	})
	return candidates[0], nil
}
