// Package config loads the versions.lock.yaml constraint file and provides the
// known tool→GitHub-repo mapping used by the heuristic classifier.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Constraint holds a semver range string for a single dependency.
type Constraint struct {
	Constraint string `yaml:"constraint"`
}

// LockFile is the parsed representation of versions.lock.yaml.
type LockFile struct {
	Constraints map[string]Constraint `yaml:"constraints"`
}

// Load reads and parses a versions.lock.yaml file at the given path.
// If the file does not exist it returns an empty LockFile (all deps unconstrained).
func Load(path string) (*LockFile, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &LockFile{Constraints: map[string]Constraint{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading lock file %s: %w", path, err)
	}
	var lf LockFile
	if err := yaml.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("parsing lock file %s: %w", path, err)
	}
	if lf.Constraints == nil {
		lf.Constraints = map[string]Constraint{}
	}
	return &lf, nil
}

// GetConstraint returns the constraint string for a dependency name, or "" if unconstrained.
// The name is matched case-insensitively (e.g. "golang", "alpine", "gobgp").
func (lf *LockFile) GetConstraint(name string) string {
	c, ok := lf.Constraints[strings.ToLower(name)]
	if !ok {
		return ""
	}
	return c.Constraint
}

// ToolRepo maps a known Makefile _VERSION variable name to its upstream GitHub repo (owner/repo).
var ToolRepo = map[string]string{
	"GOBGP_VERSION":      "osrg/gobgp",
	"GORELEASER_VERSION": "goreleaser/goreleaser",
	"CNI_VERSION":        "containernetworking/plugins",
	"DOCTOC_VERSION":     "thlorenz/doctoc",
	"TYPOS_VERSION":      "crate-ci/typos",
	"GRYPE_VERSION":      "anchore/grype",
}

// LookupToolRepo returns the GitHub repo for a _VERSION variable, and whether it was found.
func LookupToolRepo(varName string) (string, bool) {
	repo, ok := ToolRepo[varName]
	return repo, ok
}
