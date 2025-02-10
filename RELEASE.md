# Process for creating a kube-router release

## Preparing for the release

* Ensure that the Golang release used is still supported. Definition happens currently in
  [Github Workflow](.github/workflow/ci.yml) and [Makefile](Makefile).
* Ensure that the Alpine version used in container builds is still supported. Definition happens currently in
  [Github Workflow](.github/workflow/ci.yml) and [Makefile](Makefile).
* Ensure that Golang dependencies are updated.
  `go list -mod=mod -u -m -f '{{.}}{{if .Indirect}} IAMINDIRECT{{end}}' all | grep -v IAMINDIRECT` lists possible
  updates.
* Ensure that the GoBGP version is updated. See [upstream](https://github.com/osrg/gobgp/releases) and GoBGP definition
  in [Makefile](Makefile) and [go.mod](go.mod).
* Ensure that the Kubernetes object definitions do not contain deprecated object types. Definition currently is in
  kube-router's [Daemonset](daemonset) folder.
* Ensure GitHub actions are updated:
```sh
dependabot update github_actions cloudnativelabs/kube-router
```

## New major/minor release

* Create a branch named v$MAJOR.$MINOR from the default branch (currently: master)
* Create a new tag with the release tag v$MAJOR.$MINOR.0

```sh
git tag <tag_name>
git push origin <tag_name>
```

Note: your remote for the main kube-router repo may not be origin, please correct it to whatever you have called the
official kube-router remote.

## New patch release

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

Once the tag is pushed to GitHub GitHub Actions will be triggered and several things will happen:

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
git log --format='* %h - %s `<%an>`' <tag>..<tag>
```

* Announce the release in [#kube-router](https://app.slack.com/client/T09NY5SBT/C8DCQGTSB) on Kubernetes Slack.
