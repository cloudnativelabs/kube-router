package discovery_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/discovery"
)

func makeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
}

func TestScanFindsBasicFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	makeTree(t, root, map[string]string{
		"Makefile":                            "NAME?=kube-router\n",
		"go.mod":                              "module example.com/foo\ngo 1.25.0\n",
		"Dockerfile":                          "FROM alpine:3.23\n",
		".github/workflows/ci.yml":            "name: ci\n",
		".github/actions/setup-go/action.yml": "name: Setup Go\n",
		"daemonset/kuberouter.yaml":           "apiVersion: apps/v1\n",
	})

	files, err := discovery.Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if files.Makefile == "" {
		t.Error("expected Makefile to be found")
	}
	if files.GoMod == "" {
		t.Error("expected go.mod to be found")
	}
	if len(files.Dockerfiles) == 0 {
		t.Error("expected Dockerfile to be found")
	}
	if len(files.GitHubYAMLs) != 2 {
		t.Errorf("expected 2 GitHub YAMLs, got %d: %v", len(files.GitHubYAMLs), files.GitHubYAMLs)
	}
	if len(files.DaemonsetYAMLs) != 1 {
		t.Errorf("expected 1 daemonset YAML, got %d", len(files.DaemonsetYAMLs))
	}
}

func TestScanSkipsVendorAndBuild(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	makeTree(t, root, map[string]string{
		"Makefile":                   "NAME?=kube-router\n",
		"vendor/foo/bar.go":          "package foo\n",
		"build/image-assets/bashrc":  "# bash config\n",
		"build/Dockerfile.something": "FROM alpine\n",
	})

	files, err := discovery.Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	for _, d := range files.Dockerfiles {
		if filepath.Dir(d) == filepath.Join(root, "build") {
			t.Errorf("expected build/ Dockerfile to be skipped, found %s", d)
		}
	}
}

func TestScanEmptyRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	files, err := discovery.Scan(root)
	if err != nil {
		t.Fatalf("Scan on empty root: %v", err)
	}
	if files.Makefile != "" {
		t.Errorf("expected no Makefile in empty root")
	}
	if len(files.GitHubYAMLs) != 0 {
		t.Errorf("expected no YAMLs in empty root")
	}
}

func TestScanFindsDockerfileVariants(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	makeTree(t, root, map[string]string{
		"Dockerfile":         "FROM alpine\n",
		"Dockerfile.dev":     "FROM golang\n",
		"Dockerfile.release": "FROM alpine\n",
	})

	files, err := discovery.Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(files.Dockerfiles) != 3 {
		t.Errorf("expected 3 Dockerfiles, got %d: %v", len(files.Dockerfiles), files.Dockerfiles)
	}
}
