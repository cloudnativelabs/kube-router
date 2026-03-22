// Package discovery provides a project tree scanner that locates all files
// relevant to the dependency-updater tool without requiring a static file list.
package discovery

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Files holds the categorised paths discovered by Scan.
type Files struct {
	// Makefile is the path to the project's root Makefile (may be empty).
	Makefile string
	// GitHubYAMLs contains all *.yml / *.yaml files under .github/.
	GitHubYAMLs []string
	// Dockerfiles contains all Dockerfile and Dockerfile.* files.
	Dockerfiles []string
	// DaemonsetYAMLs contains all *.yaml files under daemonset/.
	DaemonsetYAMLs []string
	// GoMod is the path to the project's root go.mod (may be empty).
	GoMod string
}

// Scan walks the project root and returns a Files struct containing all
// paths relevant to the dependency-updater. It skips vendor/ directories,
// the build/ directory itself, and hidden dot-directories other than .github/.
func Scan(root string) (*Files, error) {
	f := &Files{}

	// Makefile at project root.
	if _, err := os.Stat(filepath.Join(root, "Makefile")); err == nil {
		f.Makefile = filepath.Join(root, "Makefile")
	}

	// go.mod at project root.
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
		f.GoMod = filepath.Join(root, "go.mod")
	}

	// Walk .github/ for workflow and action YAML files.
	githubDir := filepath.Join(root, ".github")
	if _, err := os.Stat(githubDir); err == nil {
		if err := filepath.WalkDir(githubDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // skip unreadable entries
			}
			if d.IsDir() {
				return nil
			}
			if isYAML(path) {
				f.GitHubYAMLs = append(f.GitHubYAMLs, path)
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	// Walk the project root for Dockerfiles (any depth, skip vendor/build/).
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return skipDir(path, root)
		}
		base := filepath.Base(path)
		if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
			f.Dockerfiles = append(f.Dockerfiles, path)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Walk daemonset/ for Kubernetes manifest YAML files.
	daemonsetDir := filepath.Join(root, "daemonset")
	if _, err := os.Stat(daemonsetDir); err == nil {
		if err := filepath.WalkDir(daemonsetDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !d.IsDir() && isYAML(path) {
				f.DaemonsetYAMLs = append(f.DaemonsetYAMLs, path)
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	return f, nil
}

// skipDir returns fs.SkipDir for directories that should not be walked.
func skipDir(path, root string) error {
	base := filepath.Base(path)
	rel, _ := filepath.Rel(root, path)

	// Always skip vendor/.
	if base == "vendor" {
		return fs.SkipDir
	}
	// Skip the build/ directory (we live there).
	if base == "build" && rel == "build" {
		return fs.SkipDir
	}
	// Skip hidden directories except .github/ which we walk separately.
	if strings.HasPrefix(base, ".") && base != ".github" {
		return fs.SkipDir
	}
	// Skip common non-source output directories.
	switch base {
	case "cni-download", "dist", "node_modules":
		return fs.SkipDir
	}
	return nil
}

// isYAML reports whether the file has a .yml or .yaml extension.
func isYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yml" || ext == ".yaml"
}
