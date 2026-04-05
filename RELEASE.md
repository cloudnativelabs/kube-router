# Process for creating a kube-router release

## New major/minor release

### Preparing for the release

Run the following command from the project root:

```sh
make prep-release
```

This single command will:

1. **Update all dependencies** — Docker base image tags (golang, alpine, golangci-lint, etc.),
   tool versions (GoBGP, GoReleaser, CNI plugins, etc.), and GitHub Action SHA pins are all
   fetched from their upstream sources and pinned to their latest stable versions. Version
   constraints in `build/dependency-updater/versions.lock.yaml` control which major/minor
   boundaries are respected (e.g. golang stays on `~1.25.x`).
2. **Run all standard checks** — doctoc, lint, tests, binary build, and container image build
   are run in sequence against the updated dependency set.

After `prep-release` completes, review and commit the changes. Use `git add --patch` (`-p`) to
stage each dependency update as a separate commit, which keeps the history readable and makes it
easy to bisect or revert individual updates:

```sh
git diff
git add -p
```

For each hunk, press `y` to stage it or `n` to skip it. Commit after each logical group of
changes (e.g. one commit per tool or image updated). Follow the conventional commit format:

```sh
git commit -m "build(deps): bump golang from 1.25.6-alpine3.23 to 1.25.7-alpine3.23"
git add -p
git commit -m "build(deps): bump actions/checkout from v6.0.1 to v6.0.2"
# ... and so on for each dependency
```

Then proceed to tag the release as described below.

If you only want to preview what would change without applying it, run:

```sh
make update-deps-dry
```

**Updating Go module dependencies** (separate from the above) — to check for available updates
to Go module dependencies in `go.mod` / `go.sum`:

```sh
go list -mod=mod -u -m -f '{{.}}{{if .Indirect}} IAMINDIRECT{{end}}' all | grep -v IAMINDIRECT
```

**Checking Kubernetes manifests** — ensure that the Kubernetes object definitions in the
[daemonset](daemonset) folder do not use deprecated API types before tagging a release.

### Performing major/minor release

* Create a branch named v$MAJOR.$MINOR from the default branch (currently: master)
* Create a new tag with the release tag v$MAJOR.$MINOR.0

```sh
git tag <tag_name>
git push origin <tag_name>
```

Note: your remote for the main kube-router repo may not be origin, please correct it to whatever you have called the
official kube-router remote.

## New patch release

Patch releases are typically kept minimal, containing only key fixes that are critical to kube-router's functionality or
improving the security posture of the current release.

kube-router generally only supports the current major.minor release. Patch releases for previous minor versions are
only created in exceptional cases. See the [supported versions](docs/upgrading.md#supported-versions) policy for
details.

* Change to the `master` branch
* Use `git log` to identify which commits you want to bring to the new patch release
* Change to the major/minor release branch that was created for this release
* Cherry-Pick the changes from the `master` branch into the release branch
* Create a new tag from the v$MAJOR.$MINOR release branch with the release tag v$MAJOR.$MINOR.$PATCH

Example:

```sh
git checkout master
git log --color --pretty=format:'%h - %s (%cr) <%an>' --abbrev-commit --decorate
git checkout <release_branch>
git cherry-pick <commit_hash_from_above_log>
git tag <tag_name>
git push origin <tag_name>
```

Note: your remote for the main kube-router repo may not be origin, please correct it to whatever you have called the
official kube-router remote.

## Release Candidates

* Follow above instructions and ensure that the tag contains `-rc`. Don't mark the pre-release as a proper release.

## Release Build Process

Once the tag is pushed to GitHub, GitHub Actions will be triggered and several things will happen:

* kube-router will be linted
* kube-router will be tested
* The actions will run a test build of the kube-router binary
* Containers for [defined architectures](https://github.com/cloudnativelabs/kube-router/blob/master/.github/workflows/ci.yml)
  (see `platforms` section in yaml) will be built and pushed to
  [DockerHub](https://hub.docker.com/r/cloudnativelabs/kube-router) via the `docker buildx` command
* [goreleaser](https://goreleaser.com) will be run and will:
  * Generate a draft release on GitHub where maintainers can later choose to update it and release it
  * Brief release notes will be added to the draft release
  * Build all of the binary releases for [defined architectures](https://github.com/cloudnativelabs/kube-router/blob/master/.goreleaser.yml)
    and attach them to the draft release on GitHub

## After the release

* Go to the [GitHub releases page for the kube-router project](https://github.com/cloudnativelabs/kube-router/releases)
* Find the draft release
* Consistent Changelog Syntax can be retrieved by running the following Git command:

```sh
git log --format='* %h - %s `<%an>`' --cherry-pick --right-only <tag>...<tag>
```

* Announce the release in [#kube-router](https://app.slack.com/client/T09NY5SBT/C8DCQGTSB) on Kubernetes Slack.
