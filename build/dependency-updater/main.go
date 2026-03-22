// dependency-updater automatically discovers, updates, and digest-pins all
// external dependencies referenced across the kube-router project: Docker
// images, tool versions, GitHub Action SHA pins, Go version, and more.
//
// Usage:
//
//	go run ./build/dependency-updater [flags]
//
// See --help for all flags.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/config"
	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/diff"
	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/discovery"
	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/registry"
	"github.com/cloudnativelabs/kube-router/v2/build/dependency-updater/updater"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// --- Flags ---------------------------------------------------------------
	var (
		flagAll        = flag.Bool("all", false, "Update all categories (default when no category flag given)")
		flagDocker     = flag.Bool("docker", false, "Update Docker image tags and digests")
		flagTools      = flag.Bool("tools", false, "Update tool version variables")
		flagActions    = flag.Bool("actions", false, "Update GitHub Action SHA pins")
		flagGo         = flag.Bool("go", false, "Update Go version references")
		flagDockerfile = flag.Bool("dockerfile", false, "Update Dockerfile-specific pins")
		flagDaemonsets = flag.Bool("daemonsets", false, "Update daemonset image tags (release-time only)")
		flagDryRun     = flag.Bool("dry-run", false, "Show diff without writing files")
		flagVerbose    = flag.Bool("verbose", false, "Show detailed progress")
		flagLockFile   = flag.String("lock-file", "", "Path to versions.lock.yaml (default: <project-root>/build/dependency-updater/versions.lock.yaml)")
		flagRoot       = flag.String("project-root", ".", "Path to project root directory")
	)
	flag.Parse()

	root, err := filepath.Abs(*flagRoot)
	if err != nil {
		return fmt.Errorf("resolving project root: %w", err)
	}

	// Determine which categories are active.
	anySpecific := *flagDocker || *flagTools || *flagActions || *flagGo || *flagDockerfile || *flagDaemonsets
	if !anySpecific {
		*flagAll = true
	}

	cats := updater.Categories{}
	if *flagAll {
		cats = updater.All()
	}
	if *flagDocker {
		cats.Docker = true
	}
	if *flagTools {
		cats.Tools = true
	}
	if *flagActions {
		cats.Actions = true
	}
	if *flagGo {
		cats.Go = true
	}
	if *flagDockerfile {
		cats.Dockerfile = true
	}
	if *flagDaemonsets {
		cats.Daemonsets = true
	}

	// --- Setup ---------------------------------------------------------------

	// Warn if no GitHub token is set.
	gh := registry.NewGitHubClient()
	if !gh.IsAuthenticated() {
		fmt.Fprintln(os.Stderr, "warning: GITHUB_TOKEN/GH_TOKEN not set; GitHub API rate limit is 60 req/hr (unauthenticated)")
	}

	docker := registry.NewDockerClient()
	goClient := registry.NewGoVersionClient()

	// Load constraint file.
	lockFilePath := *flagLockFile
	if lockFilePath == "" {
		lockFilePath = filepath.Join(root, "build", "dependency-updater", "versions.lock.yaml")
	}
	lf, err := config.Load(lockFilePath)
	if err != nil {
		return fmt.Errorf("loading lock file: %w", err)
	}

	// Discover files.
	files, err := discovery.Scan(root)
	if err != nil {
		return fmt.Errorf("scanning project tree: %w", err)
	}

	if *flagVerbose {
		fmt.Printf("Project root: %s\n", root)
		fmt.Printf("Makefile: %s\n", files.Makefile)
		fmt.Printf("GitHub YAMLs: %d files\n", len(files.GitHubYAMLs))
		fmt.Printf("Dockerfiles: %d files\n", len(files.Dockerfiles))
		fmt.Printf("Daemonset YAMLs: %d files\n", len(files.DaemonsetYAMLs))
	}

	// --- Run updaters --------------------------------------------------------

	var allDiffs []diff.Result
	var allWarnings []string

	// resolvedGoVersion is extracted from the golang Docker image tag after the
	// Makefile is processed. It is then used as the authoritative Go version for
	// all derived locations (GO_VERSION in ci.yml, toolchain in go.mod), ensuring
	// they stay in sync with the Docker image even if go.dev has a newer patch
	// release for which no alpine Docker image exists yet.
	var resolvedGoVersion string

	// 1. Makefile — must run first so we can extract the canonical Go version.
	if files.Makefile != "" && (cats.Docker || cats.Tools) {
		if *flagVerbose {
			fmt.Printf("\nProcessing Makefile...\n")
		}
		mkResult, warns, err := updater.UpdateMakefile(files.Makefile, lf, docker, gh, cats, *flagDryRun, *flagVerbose)
		allWarnings = append(allWarnings, warns...)
		if err != nil {
			allWarnings = append(allWarnings, fmt.Sprintf("Makefile: %v", err))
		} else if mkResult.Diff.Changed() {
			allDiffs = append(allDiffs, mkResult.Diff)
		}
		// Extract the Go version from the resolved golang image tag so that
		// GO_VERSION in ci.yml and toolchain in go.mod are derived from the
		// same source rather than queried independently.
		if mkResult.ResolvedGolangImage != "" {
			if ver, ok := registry.GoVersionFromImageTag(mkResult.ResolvedGolangImage); ok {
				resolvedGoVersion = ver
				if *flagVerbose {
					fmt.Printf("  Canonical Go version from Docker image: %s\n", resolvedGoVersion)
				}
			}
		}
	}

	// 2. GitHub Action SHA pins (workflow + action YAML files).
	if len(files.GitHubYAMLs) > 0 && cats.Actions {
		if *flagVerbose {
			fmt.Printf("\nProcessing GitHub Action pins (%d files)...\n", len(files.GitHubYAMLs))
		}
		results, warns, err := updater.UpdateWorkflows(files.GitHubYAMLs, gh, *flagDryRun, *flagVerbose)
		allWarnings = append(allWarnings, warns...)
		if err != nil {
			allWarnings = append(allWarnings, fmt.Sprintf("workflows: %v", err))
		}
		allDiffs = append(allDiffs, results...)
	}

	// 3. CI env: blocks (Docker images + Go version in workflow files).
	// Pass resolvedGoVersion so GO_VERSION is derived from the Docker image tag,
	// not fetched independently from go.dev.
	if len(files.GitHubYAMLs) > 0 && (cats.Docker || cats.Go) {
		if *flagVerbose {
			fmt.Printf("\nProcessing CI env blocks...\n")
		}
		results, warns, err := updater.UpdateCIEnv(files.GitHubYAMLs, lf, docker, goClient, resolvedGoVersion, cats, *flagDryRun, *flagVerbose)
		allWarnings = append(allWarnings, warns...)
		if err != nil {
			allWarnings = append(allWarnings, fmt.Sprintf("CI env: %v", err))
		}
		allDiffs = append(allDiffs, results...)
	}

	// 4. Dockerfiles.
	if len(files.Dockerfiles) > 0 && (cats.Docker || cats.Dockerfile) {
		if *flagVerbose {
			fmt.Printf("\nProcessing Dockerfiles (%d files)...\n", len(files.Dockerfiles))
		}
		results, warns, err := updater.UpdateDockerfiles(files.Dockerfiles, lf, docker, gh, cats, *flagDryRun, *flagVerbose)
		allWarnings = append(allWarnings, warns...)
		if err != nil {
			allWarnings = append(allWarnings, fmt.Sprintf("Dockerfiles: %v", err))
		}
		allDiffs = append(allDiffs, results...)
	}

	// 5. go.mod toolchain directive.
	// Pass resolvedGoVersion so toolchain matches the Docker image, not go.dev.
	if files.GoMod != "" && cats.Go {
		if *flagVerbose {
			fmt.Printf("\nProcessing go.mod...\n")
		}
		constraint := lf.GetConstraint("golang")
		result, warns, err := updater.UpdateGoMod(files.GoMod, goClient, resolvedGoVersion, constraint, *flagDryRun, *flagVerbose)
		allWarnings = append(allWarnings, warns...)
		if err != nil {
			allWarnings = append(allWarnings, fmt.Sprintf("go.mod: %v", err))
		} else if result.Changed() {
			allDiffs = append(allDiffs, result)
		}
	}

	// 6. Daemonset manifests (explicit opt-in only).
	if len(files.DaemonsetYAMLs) > 0 && cats.Daemonsets {
		fmt.Println("\nNote: --daemonsets requires a release tag; use --daemonsets with a tagged release.")
		// Daemonset updates require a release tag which is provided separately.
		// The actual update call is: updater.UpdateDaemonsets(files.DaemonsetYAMLs, releaseTag, docker, ...)
		// For now this is a placeholder.
	}

	// --- Output --------------------------------------------------------------

	// Print warnings.
	if len(allWarnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, w := range allWarnings {
			fmt.Fprintf(os.Stderr, "  warning: %s\n", w)
		}
	}

	// Print diffs in dry-run mode.
	if *flagDryRun {
		if len(allDiffs) == 0 {
			fmt.Println("\nAll dependencies are up to date.")
			return nil
		}
		fmt.Printf("\n%d file(s) would be updated:\n", len(allDiffs))
		for _, d := range allDiffs {
			fmt.Println()
			fmt.Print(diff.ColorizedString(d.Unified))
		}
		return nil
	}

	// Print summary.
	if len(allDiffs) == 0 {
		fmt.Println("\nAll dependencies are up to date.")
	} else {
		fmt.Printf("\nUpdated %d file(s):\n", len(allDiffs))
		for _, d := range allDiffs {
			fmt.Printf("  %s\n", d.Path)
		}
	}

	return nil
}
