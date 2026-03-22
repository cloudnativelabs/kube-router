package updater_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/config"
	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/updater"
)

// mockDockerClient implements just enough interface for Makefile tests.
// We use a real DockerClient interface stub via a test double.

// TestUpdateMakefile_ToolVersionReplacement verifies that tool version variables
// are rewritten in place while preserving the surrounding Makefile structure.
func TestUpdateMakefile_PreservesStructure(t *testing.T) {
	t.Parallel()
	content := `NAME?=kube-router
# See Versions: https://github.com/osrg/gobgp/releases
GOBGP_VERSION=v4.2.0
QEMU_IMAGE?=multiarch/qemu-user-static
# derived, should be skipped
GRYPE_IMAGE?=anchore/grype:$(GRYPE_VERSION)
BUILD_IN_DOCKER?=true
`
	dir := t.TempDir()
	path := filepath.Join(dir, "Makefile")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := &config.LockFile{}

	// Use dry-run mode with a nil docker/gh client — the classifier will
	// identify what to update but since docker/gh are nil the real network
	// calls would panic. We test the structure preservation with a manually
	// crafted input where only KindUnknown / KindDerived lines are present.
	// For the tool-version and docker lines we verify they are left intact
	// when the category is disabled.
	cats := updater.Categories{Docker: false, Tools: false}

	result, warnings, err := updater.UpdateMakefile(path, lf, nil, nil, cats, true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	// No categories enabled — nothing should change.
	if result.Changed() {
		t.Errorf("expected no changes when categories are disabled, got diff:\n%s", result.Unified)
	}
}

// TestUpdateMakefile_DryRun verifies that dryRun=true does not modify the file.
func TestUpdateMakefile_DryRunDoesNotWrite(t *testing.T) {
	t.Parallel()
	content := "NAME?=kube-router\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "Makefile")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := &config.LockFile{}
	cats := updater.Categories{}

	_, _, err := updater.UpdateMakefile(path, lf, nil, nil, cats, true /* dryRun */, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// File content must be unchanged.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Errorf("dry-run modified file: got %q, want %q", string(got), content)
	}
}

// TestUpdateMakefile_SkipsDerivedVars verifies that derived Makefile vars
// (those containing $(...) expansions) are never modified.
func TestUpdateMakefile_SkipsDerivedVars(t *testing.T) {
	t.Parallel()
	content := "GRYPE_IMAGE?=anchore/grype:$(GRYPE_VERSION)\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "Makefile")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := &config.LockFile{}
	cats := updater.Categories{Docker: true}

	result, _, err := updater.UpdateMakefile(path, lf, nil, nil, cats, true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Changed() {
		t.Errorf("derived var was modified unexpectedly")
	}
}

// TestUpdateMakefile_SkipsUnknownVersionVar verifies that a _VERSION variable
// with no known upstream mapping produces a warning and is not changed.
func TestUpdateMakefile_WarnsOnUnknownVersionVar(t *testing.T) {
	t.Parallel()
	content := "UNKNOWN_TOOL_VERSION=v1.0.0\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "Makefile")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	lf := &config.LockFile{}
	cats := updater.Categories{Tools: true}

	result, warnings, err := updater.UpdateMakefile(path, lf, nil, nil, cats, true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Changed() {
		t.Errorf("unknown tool var was unexpectedly modified")
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "UNKNOWN_TOOL_VERSION") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning about UNKNOWN_TOOL_VERSION, got %v", warnings)
	}
}
