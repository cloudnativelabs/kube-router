package diff_test

import (
	"strings"
	"testing"

	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/diff"
)

func TestComputeNoChange(t *testing.T) {
	t.Parallel()
	result := diff.Compute("file.txt", "hello\nworld\n", "hello\nworld\n")
	if result.Changed() {
		t.Errorf("expected no change, got diff:\n%s", result.Unified)
	}
}

func TestComputeSimpleChange(t *testing.T) {
	t.Parallel()
	original := "line1\nold-value\nline3\n"
	updated := "line1\nnew-value\nline3\n"
	result := diff.Compute("test.txt", original, updated)
	if !result.Changed() {
		t.Fatal("expected a change but got none")
	}
	if !strings.Contains(result.Unified, "-old-value") {
		t.Errorf("expected removed line in diff, got:\n%s", result.Unified)
	}
	if !strings.Contains(result.Unified, "+new-value") {
		t.Errorf("expected added line in diff, got:\n%s", result.Unified)
	}
}

func TestComputeHunkHeader(t *testing.T) {
	t.Parallel()
	original := "a\nb\nc\n"
	updated := "a\nB\nc\n"
	result := diff.Compute("f.txt", original, updated)
	if !strings.Contains(result.Unified, "@@") {
		t.Errorf("expected hunk header @@ in diff, got:\n%s", result.Unified)
	}
}

func TestComputePathInHeader(t *testing.T) {
	t.Parallel()
	result := diff.Compute("Makefile", "a=1\n", "a=2\n")
	if !strings.Contains(result.Unified, "Makefile") {
		t.Errorf("expected path in diff header, got:\n%s", result.Unified)
	}
}

func TestColorizedStringContainsANSI(t *testing.T) {
	t.Parallel()
	original := "old\n"
	updated := "new\n"
	result := diff.Compute("f.txt", original, updated)
	colorized := diff.ColorizedString(result.Unified)
	// ANSI escape codes start with \033[
	if !strings.Contains(colorized, "\033[") {
		t.Errorf("expected ANSI codes in colorized output, got:\n%s", colorized)
	}
}

func TestComputeMultipleHunks(t *testing.T) {
	t.Parallel()
	// Two separate changes far apart should produce two hunks.
	lines := make([]string, 20)
	for i := range lines {
		lines[i] = "unchanged"
	}
	original := strings.Join(lines, "\n") + "\n"
	linesNew := make([]string, 20)
	copy(linesNew, lines)
	linesNew[0] = "changed-top"
	linesNew[19] = "changed-bottom"
	updated := strings.Join(linesNew, "\n") + "\n"

	result := diff.Compute("f.txt", original, updated)
	if !result.Changed() {
		t.Fatal("expected changes")
	}
	hunkCount := strings.Count(result.Unified, "@@")
	if hunkCount < 2 {
		t.Errorf("expected at least 2 hunks for widely separated changes, got %d", hunkCount)
	}
}
