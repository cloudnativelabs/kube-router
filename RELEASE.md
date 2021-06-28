# Process for creating a Kube-Router release

## Preparing for the release
* Ensure that the Golang release used is still supported.
* Ensure that the Alpine version used for containers is still supported
* Ensure that Golang dependencies are updated.
* Ensure that the GoBGP version is updated.
* Ensure that the Kubernetes object definitions do not contain deprecated object types.

## New major/minor release
* Create a new release on Github from the default branch (currently: master) with the release tag v$MAJOR.$MINOR.0
* Create a branch named v$MAJOR.$MINOR

## New patch release
* Create a new release on Github from the v$MAJOR.$MINOR release with the release tag v$MAJOR.$MINOR.$PATCH

A goreleaser command will be executed via Github Actions and it will add binaries to the release.
A docker buildx command will be executed via Github Actions and it will push new container builds to [DockerHub](https://hub.docker.com/repository/docker/cloudnativelabs/kube-router).

## After the release
* Announce the release in [#kube-router](https://app.slack.com/client/T09NY5SBT/C8DCQGTSB) on Kubernetes Slack.
