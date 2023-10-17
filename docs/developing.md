# Developer's Guide

We aim to make local development and testing as straightforward as possible. For
basic guidelines around contributing, see the [CONTRIBUTING](/CONTRIBUTING.md) document.

There are a number of automation tools available to help with testing and
building your changes, detailed below.

## Building kube-router

### Go version 1.19 or above is required to build kube-router

All the dependencies are specified as Go modules and will be fetched into your cache, so just run `make kube-router` or
`go build pkg/cmd/kube-router.go` to build.

### Building A Docker Image

Running `make container` will compile kube-router (if needed) and build a Docker
image.  By default the container will be tagged with the last release version,
and current commit ID.

For example:

```sh
$ make container
Building for GOARCH=amd64
Verifying kube-router gobgp for ARCH=x86-64 ...
Starting kube-router container image build for amd64 on amd64
docker build -t "cloudnativelabs/kube-router-git:amd64-bug_fixes_for_v2.0.0" -f Dockerfile --build-arg ARCH="" \
        --build-arg BUILDTIME_BASE="golang:1.20.9-alpine3.18" --build-arg RUNTIME_BASE="alpine:3.18" .
Sending build context to Docker daemon  198.6MB
Step 1/19 : ARG BUILDTIME_BASE=golang:1-alpine
Step 2/19 : ARG RUNTIME_BASE=alpine:latest
Step 3/19 : FROM ${BUILDTIME_BASE} as builder
 ---> 6cbc3ac54aa3
Step 4/19 : ENV BUILD_IN_DOCKER=false
 ---> Using cache
 ---> aec11cc4a0cd

...

Removing intermediate container 371a162930f5
 ---> 1d3f742d559e
Step 19/19 : ENTRYPOINT ["/usr/local/bin/kube-router"]
 ---> Running in d5ea6fda9fe4
Removing intermediate container d5ea6fda9fe4
 ---> 17cfbc77e293
[Warning] One or more build-args [ARCH] were not consumed
Successfully built 17cfbc77e293
Successfully tagged cloudnativelabs/kube-router-git:amd64-bug_fixes_for_v2.0.0
Finished kube-router container image build.
```

The following describes the rest of the portions of the container naming convention

* `kube-router-git` indicates that the container was built from git and not from a tag.
* `amd64` indicates that it was built for the `amd64` architecture
* `bug_fixes_for_v2.0.0` indicates the branch that the user was on when it was built

### Pushing A Docker Image

Running `make push` will push your container image to a Docker registry.  The default configuration will use the
Docker Hub repository for the official kube-router images, cloudnativelabs/kube-router. You can push to a different
repository by changing a couple settings, as described in [Image Options](#image-options)
below.

### Makefile Options

There are several variables which can be modified in the Makefile to customize your builds. They are specified after
your make command like this: `make OPTION=VALUE`. These options can also be set in your environment variables.

For more details beyond the scope of this document, see the [Makefile](/Makefile) and run `make help`.

#### Image Options

You can configure the name and tag of the Docker image with a few variables
passed to `make container` and `make push`.

Example:

```sh
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

* `REGISTRY` is derived from other options. Set this to something else to
  quickly override the Docker image registry used to tag and push images.
  * Note: This will override other variables below that make up the image
    name/tag.
* `IMG_FQDN` should be set if you are not using Docker Hub for images. In
  the examples above `IMG_FQDN` is set to `quay.io`.
* `IMG_NAMESPACE` is the Docker registry user or organization.  It is used in
  URLs.
  * Example: quay.io/IMG_NAMESPACE/kube-router
* `NAME` goes onto the end of the Docker registry URL that will be used.
  * Example: quay.io/cloudnativelabs/NAME
* `IMG_TAG` is used to override the tag of the Docker image being built.
* `DEV_SUFFIX` is appended to Docker image names that are not for release.  By
  default these images get a name ending with `-git` to signify that they are
  for testing purposes.
  Example (DEV-SUFFIX=master-latest): quay.io/cloudnativelabs/kube-router-git:master-latest

## Release Workflow

See [Release Documentation](/RELEASE.md) for more information

## Dependency Management

kube-router uses go modules for managing dependencies see [upstream documentation](https://go.dev/blog/using-go-modules)
for more information
