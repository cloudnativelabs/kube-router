# Developer's Guide

We aim to make local development and testing as straightforward as possible. For
basic guidelines around contributing, see the [CONTRIBUTING](/CONTRIBUTING.md) document.

There are a number of automation tools available to help with testing and
building your changes, detailed below.

## Building kube-router

**Go version 1.13 or above is required to build kube-router**

All the dependencies are specified as Go modules and will be fetched into your cache, so just run `make` or `go build -o kube-router kube-router.go` to build.

### Building A Docker Image

Running `make container` will compile kube-router (if needed) and build a Docker
image.  By default the container will be tagged with the last release version,
and current commit ID.

For example:
```console
$ make container
docker build -t "cloudnativelabs/kube-router-git:0.0.4-22-gd782e89-dirty-build-release"
Sending build context to Docker daemon  151.5MB
Step 1/4 : FROM alpine
 ---> a41a7446062d
Step 2/4 : RUN apk add --no-cache iptables ipset
 ---> Using cache
 ---> 30e25a7640de
Step 3/4 : COPY kube-router /
 ---> Using cache
 ---> c06f78fd02e8
Step 4/4 : ENTRYPOINT /kube-router
 ---> Using cache
 ---> 5cfcfe54623e
Successfully built 5cfcfe54623e
Successfully tagged cloudnativelabs/kube-router-git:0.0.4-22-gd782e89-dirty-build-release
```

The `-dirty` part of the tag means there are uncommitted changes in your local
git repo.

### Pushing A Docker Image

Running `make push` will push your container image to a Docker registry.  The
default configuration will use the Docker Hub repository for the official
kube-router images, cloudnativelabs/kube-router. You can push to a different
repository by changing a couple settings, as described in [Image Options](#image-options)
below.

### Makefile Options

There are several variables which can be modified in the Makefile to customize
your builds. They are specified after your make command like this: `make OPTION=VALUE`.
These options can also be set in your environment variables.
For more details beyond the scope of this document, see the
[Makefile](/Makefile) and run `make help`.

#### Image Options

You can configure the name and tag of the Docker image with a few variables
passed to `make container` and `make push`.

Example:
```console
$ make container IMG_FQDN=quay.io IMG_NAMESPACE=bzub IMG_TAG=custom
docker build -t "quay.io/bzub/kube-router-git:custom" .
Sending build context to Docker daemon  151.5MB
Step 1/4 : FROM alpine
 ---> a41a7446062d
Step 2/4 : RUN apk add --no-cache iptables ipset
 ---> Using cache
 ---> 30e25a7640de
Step 3/4 : COPY kube-router /
 ---> Using cache
 ---> c06f78fd02e8
Step 4/4 : ENTRYPOINT /kube-router
 ---> Using cache
 ---> 5cfcfe54623e
Successfully built 5cfcfe54623e
Successfully tagged quay.io/bzub/kube-router-git:custom
```

- `REGISTRY` is derived from other options. Set this to something else to
  quickly override the Docker image registry used to tag and push images.
  - Note: This will override other variables below that make up the image
    name/tag.
- `IMG_FQDN` should be set if you are not using Docker Hub for images. In
  the examples above `IMG_FQDN` is set to `quay.io`.
- `IMG_NAMESPACE` is the Docker registry user or organization.  It is used in
  URLs.
  - Example: quay.io/IMG_NAMESPACE/kube-router
- `NAME` goes onto the end of the Docker registry URL that will be used.
  - Example: quay.io/cloudnativelabs/NAME
- `IMG_TAG` is used to override the tag of the Docker image being built.
- `DEV_SUFFIX` is appended to Docker image names that are not for release.  By
  default these images get a name ending with `-git` to signify that they are
  for testing purposes.
  Example (DEV-SUFFIX=master-latest): quay.io/cloudnativelabs/kube-router-git:master-latest

## Release Workflow

These instructions show how official kube-router releases are performed.

First, you must tag a git commit with the release version.
This will cause the CI system to:
- Build kube-router
- Build a Docker image with ${VERSION} and `latest` tags
- Push the Docker image to the official registry
- Submits a draft release to GitHub

Example:
```
VERSION=v0.5.0
git tag -a ${VERSION} -m "Brief release note" && git push origin ${VERSION}
```

Then the only thing left to do is edit the release notes on the GitHub release
and publish it.

### Manual Releases

These instructions show how To perform a custom or test release outside of the
CI system, using a local git commit.

First tag a commit:
```
VERSION=v0.5.0_bzub
git tag -a ${VERSION} -m "Brief release note"
```

Then you can provide
[options](#makefile-options) to `make release`.

This does the following:
- Builds kube-router
- Builds a Docker image
- Tags the image with the current git commit's tag
- Tags the image with `latest`
- Pushes the image to a docker registry

If you'd like to test the GitHub release functionality as well, you will need to
pass in the `GITHUB_TOKEN` variable with a value of an API token you've
[generated](https://github.com/settings/tokens/new). This Access Token must have
the "repo" OAuth scope enabled.

NOTE: For added security when running a command that contains secure
credentials, add a space before the entire command to prevent it from being
added to your shell history file.

Example:
```console
$  make release IMG_FQDN=quay.io IMG_NAMESPACE=bzub GITHUB_TOKEN=b1ahbl1ahb1ahba1hahb1ah
```

## Dependency Management

kube-router uses `dep` for managing dependencies. Instructions on installing and using dep can be found [here](https://golang.github.io/dep/docs/introduction.html). 
