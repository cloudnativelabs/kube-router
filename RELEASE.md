# Process for creating a Kube-Router release

## Preparing for the release
* Ensure that the Golang release used is still supported. Definition happens currently in [Github Workflow](.github/workflow/ci.yml).
* Ensure that the Alpine version used in container builds is still supported. Definition happens currently in [Github Workflow](.github/workflow/ci.yml).
* Ensure that Golang dependencies are updated. `go list -mod=mod -u -m -f '{{.}}{{if .Indirect}} IAMINDIRECT{{end}}' all | grep -v IAMINDIRECT` lists possible updates.
* Ensure that the GoBGP version is updated. See [upstream](https://github.com/osrg/gobgp/releases) and GoBGP definition in [Makefile](Makefile) and [go.mod](go.mod).
* Ensure that the Kubernetes object definitions do not contain deprecated object types. Definition currently is in kube-router's [Daemonset](daemonset) folder.

## New major/minor release
* Create a branch named v$MAJOR.$MINOR from the default branch (currently: master)
* Create a new prerelease on Github with the release tag v$MAJOR.$MINOR.0

## New patch release
* Create a new prerelease on Github from the v$MAJOR.$MINOR release branch with the release tag v$MAJOR.$MINOR.$PATCH

A goreleaser command will be executed via Github Actions and it will add binaries to the release.
A docker buildx command will be executed via Github Actions and it will push new container builds to [DockerHub](https://hub.docker.com/repository/docker/cloudnativelabs/kube-router).

## After the release
* Mark the draft release as a proper release.
* Announce the release in [#kube-router](https://app.slack.com/client/T09NY5SBT/C8DCQGTSB) on Kubernetes Slack.

## Release Candidates

* Follow above instructions and ensure that the tag contains `-rc`. Don't mark the pre-release as a proper release.
