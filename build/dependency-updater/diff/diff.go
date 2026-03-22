// Package diff provides a simple unified diff generator for dry-run output.
package diff

import (
	"fmt"
	"strings"
)

// Result holds the diff output for a single file.
type Result struct {
	Path    string
	Unified string // empty if no changes
}

// Changed returns true if the file has changes.
func (r Result) Changed() bool {
	return r.Unified != ""
}

// Compute produces a unified diff between original and updated content for the
// given file path. Returns an empty Result if the content is identical.
func Compute(path, original, updated string) Result {
	if original == updated {
		return Result{Path: path}
	}

	origLines := strings.Split(original, "\n")
	newLines := strings.Split(updated, "\n")

	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s\n", path)
	fmt.Fprintf(&sb, "+++ %s\n", path)

	hunks := computeHunks(origLines, newLines)
	for _, h := range hunks {
		sb.WriteString(h)
	}

	return Result{Path: path, Unified: sb.String()}
}

// hunk context lines shown around each change.
const contextLines = 3

// computeHunks generates the hunk sections of a unified diff.
func computeHunks(orig, updated []string) []string {
	// Build an edit script: for each position record whether lines are equal,
	// removed, or added. We use a simple line-by-line LCS-based approach.
	type edit struct {
		kind rune // ' ' unchanged, '-' removed, '+' added
		line string
	}

	edits := lcs(orig, updated)

	var hunks []string
	i := 0
	for i < len(edits) {
		// Find the next changed line.
		for i < len(edits) && edits[i].kind == ' ' {
			i++
		}
		if i >= len(edits) {
			break
		}

		// Collect context before.
		start := i - contextLines
		if start < 0 {
			start = 0
		}
		// Collect until no more changes within contextLines.
		end := i
		for end < len(edits) {
			if edits[end].kind != ' ' {
				end++
				// extend context after
				for k := 0; k < contextLines && end < len(edits); k++ {
					end++
				}
			} else {
				// Check if there's another change within contextLines.
				next := end + 1
				for next < end+contextLines+1 && next < len(edits) {
					if edits[next].kind != ' ' {
						break
					}
					next++
				}
				if next < end+contextLines+1 && next < len(edits) && edits[next].kind != ' ' {
					end = next
				} else {
					break
				}
			}
		}
		if end > len(edits) {
			end = len(edits)
		}

		// Compute hunk header counts.
		origStart, origCount, newStart, newCount := 0, 0, 0, 0
		for _, e := range edits[:start] {
			if e.kind == ' ' || e.kind == '-' {
				origStart++
			}
			if e.kind == ' ' || e.kind == '+' {
				newStart++
			}
		}
		for _, e := range edits[start:end] {
			if e.kind == ' ' || e.kind == '-' {
				origCount++
			}
			if e.kind == ' ' || e.kind == '+' {
				newCount++
			}
		}

		var hunk strings.Builder
		fmt.Fprintf(&hunk, "@@ -%d,%d +%d,%d @@\n",
			origStart+1, origCount, newStart+1, newCount)
		for _, e := range edits[start:end] {
			fmt.Fprintf(&hunk, "%c%s\n", e.kind, e.line)
		}
		hunks = append(hunks, hunk.String())
		i = end
	}
	return hunks
}

type edit struct {
	kind rune
	line string
}

// lcs computes an edit script using a simple Myers-diff inspired approach.
// For our use case (config files) this is fast enough.
func lcs(orig, updated []string) []edit {
	n, m := len(orig), len(updated)

	// dp[i][j] = length of LCS of orig[:i] and updated[:j]
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if orig[i] == updated[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] > dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}

	var result []edit
	i, j := 0, 0
	for i < n && j < m {
		if orig[i] == updated[j] {
			result = append(result, edit{' ', orig[i]})
			i++
			j++
		} else if dp[i+1][j] >= dp[i][j+1] {
			result = append(result, edit{'-', orig[i]})
			i++
		} else {
			result = append(result, edit{'+', updated[j]})
			j++
		}
	}
	for ; i < n; i++ {
		result = append(result, edit{'-', orig[i]})
	}
	for ; j < m; j++ {
		result = append(result, edit{'+', updated[j]})
	}
	return result
}

// ColorizedString returns the unified diff with ANSI colour codes for terminal
// display. Red for removals, green for additions.
func ColorizedString(unified string) string {
	var sb strings.Builder
	for _, line := range strings.Split(unified, "\n") {
		switch {
		case strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++"):
			sb.WriteString("\033[1m" + line + "\033[0m\n")
		case strings.HasPrefix(line, "-"):
			sb.WriteString("\033[31m" + line + "\033[0m\n")
		case strings.HasPrefix(line, "+"):
			sb.WriteString("\033[32m" + line + "\033[0m\n")
		case strings.HasPrefix(line, "@@"):
			sb.WriteString("\033[36m" + line + "\033[0m\n")
		default:
			sb.WriteString(line + "\n")
		}
	}
	return sb.String()
}
