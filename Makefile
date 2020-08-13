NAME?=kube-router
GOARCH?=$(shell go env GOARCH)
DEV_SUFFIX?=-git
OSX=$(filter Darwin,$(shell uname))
BUILD_DATE?=$(shell date +%Y-%m-%dT%H:%M:%S%z)
LOCAL_PACKAGES?=app app/controllers app/options app/watchers utils
IMG_NAMESPACE?=cloudnativelabs
GIT_COMMIT=$(shell git describe --tags --dirty)
GIT_BRANCH?=$(shell git rev-parse --abbrev-ref HEAD)
IMG_TAG?=$(if $(IMG_TAG_PREFIX),$(IMG_TAG_PREFIX)-)$(if $(ARCH_TAG_PREFIX),$(ARCH_TAG_PREFIX)-)$(GIT_BRANCH)
MANIFEST_TAG?=$(if $(IMG_TAG_PREFIX),$(IMG_TAG_PREFIX)-)$(GIT_BRANCH)
RELEASE_TAG?=$(GOARCH)-$(shell build/get-git-tag.sh)
REGISTRY?=$(if $(IMG_FQDN),$(IMG_FQDN)/$(IMG_NAMESPACE)/$(NAME),$(IMG_NAMESPACE)/$(NAME))
REGISTRY_DEV?=$(REGISTRY)$(DEV_SUFFIX)
IN_DOCKER_GROUP=$(filter docker,$(shell groups))
IS_ROOT=$(filter 0,$(shell id -u))
DOCKER=$(if $(or $(IN_DOCKER_GROUP),$(IS_ROOT),$(OSX)),docker,sudo docker)
MAKEFILE_DIR=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))
UPSTREAM_IMPORT_PATH=$(GOPATH)/src/github.com/cloudnativelabs/kube-router/
BUILD_IN_DOCKER?=true
DOCKER_BUILD_IMAGE?=golang:1.13.13-alpine3.12
DOCKER_LINT_IMAGE?=golangci/golangci-lint:v1.27.0
QEMU_IMAGE?=multiarch/qemu-user-static
ifeq ($(GOARCH), arm)
ARCH_TAG_PREFIX=$(GOARCH)
FILE_ARCH=ARM
DOCKERFILE_SED_EXPR?=s,FROM alpine,FROM arm32v6/alpine,
else ifeq ($(GOARCH), arm64)
ARCH_TAG_PREFIX=$(GOARCH)
FILE_ARCH=ARM aarch64
DOCKERFILE_SED_EXPR?=s,FROM alpine,FROM arm64v8/alpine,
else ifeq ($(GOARCH), s390x)
ARCH_TAG_PREFIX=$(GOARCH)
FILE_ARCH=IBM S/390
DOCKERFILE_SED_EXPR?=s,FROM alpine,FROM s390x/alpine,
else ifeq ($(GOARCH), ppc64le)
ARCH_TAG_PREFIX=$(GOARCH)
FILE_ARCH=64-bit PowerPC
DOCKERFILE_SED_EXPR?=s,FROM alpine,FROM ppc64le/alpine,
else
ARCH_TAG_PREFIX=amd64
DOCKERFILE_SED_EXPR?=
FILE_ARCH=x86-64
endif
$(info Building for GOARCH=$(GOARCH))
all: test kube-router container ## Default target. Runs tests, builds binaries and images.

kube-router:
ifeq "$(BUILD_IN_DOCKER)" "true"
	@echo Starting kube-router binary build.
	$(DOCKER) run -v $(PWD):/go/src/github.com/cloudnativelabs/kube-router -w /go/src/github.com/cloudnativelabs/kube-router $(DOCKER_BUILD_IMAGE) \
	    sh -c ' \
	    GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
		-ldflags "-X github.com/cloudnativelabs/kube-router/pkg/cmd.version=$(GIT_COMMIT) -X github.com/cloudnativelabs/kube-router/pkg/cmd.buildDate=$(BUILD_DATE)" \
		-o kube-router cmd/kube-router/kube-router.go'
	@echo Finished kube-router binary build.
else
	GOARCH=$(GOARCH) CGO_ENABLED=0 go build -ldflags '-X github.com/cloudnativelabs/kube-router/pkg/cmd.version=$(GIT_COMMIT) -X github.com/cloudnativelabs/kube-router/pkg/cmd.buildDate=$(BUILD_DATE)' -o kube-router cmd/kube-router/kube-router.go
endif

test: gofmt ## Runs code quality pipelines (gofmt, tests, coverage, etc)
ifeq "$(BUILD_IN_DOCKER)" "true"
	$(DOCKER) run -v $(PWD):/go/src/github.com/cloudnativelabs/kube-router -w /go/src/github.com/cloudnativelabs/kube-router $(DOCKER_BUILD_IMAGE) \
	    sh -c 'go test -v -timeout 30s github.com/cloudnativelabs/kube-router/cmd/kube-router/ github.com/cloudnativelabs/kube-router/pkg/...'
else
		go test -v -timeout 30s github.com/cloudnativelabs/kube-router/cmd/kube-router/ github.com/cloudnativelabs/kube-router/pkg/...
endif

lint: gofmt
ifeq "$(BUILD_IN_DOCKER)" "true"
	$(DOCKER) run -v $(PWD):/go/src/github.com/cloudnativelabs/kube-router -w /go/src/github.com/cloudnativelabs/kube-router $(DOCKER_LINT_IMAGE) \
	     sh -c 'golangci-lint run ./...'
else
	golangci-lint run ./...
endif

vagrant-up: export docker=$(DOCKER)
vagrant-up: export DEV_IMG=$(REGISTRY_DEV):$(IMG_TAG)
vagrant-up: all vagrant-destroy
	@hack/vagrant-up.sh

vagrant-up-single-node: vagrant-up ## Test the current codebase in a local VM single-node cluster

vagrant-up-multi-node: export HACK_MULTI_NODE=true
vagrant-up-multi-node: vagrant-up ## Test the current codebase in a local VM multi-node cluster

vagrant: ## Run vagrant against a previously up'd cluster. Example: make vagrant status
	@hack/vagrant.sh $(VAGRANT_RUN_ARGS)

vagrant-destroy: ## Destroy a previously created local VM cluster
	@hack/vagrant-destroy.sh

vagrant-clean: vagrant-destroy ## Destroy a previously created local VM cluster and remove all downloaded/generated assets
	@rm -rf hack/_output

vagrant-image-update: export docker=$(DOCKER)
vagrant-image-update: export DEV_IMG=$(REGISTRY_DEV):$(IMG_TAG)
vagrant-image-update: all ## Rebuild kube-router, update image in local VMs, and restart kube-router pods.
	@hack/vagrant-image-update.sh

run: kube-router ## Runs "kube-router --help".
	./kube-router --help

container: Dockerfile.$(GOARCH).run kube-router gobgp multiarch-binverify ## Builds a Docker container image.
	@echo Starting kube-router container image build for $(GOARCH) on $(shell go env GOHOSTARCH)
	@if [ "$(GOARCH)" != "$(shell go env GOHOSTARCH)" ]; then \
	    echo "Using qemu to build non-native container"; \
	    $(DOCKER) run --rm --privileged $(QEMU_IMAGE) --reset -p yes; \
	fi
	$(DOCKER) build -t "$(REGISTRY_DEV):$(subst /,,$(IMG_TAG))" -f Dockerfile.$(GOARCH).run .
	@if [ "$(GIT_BRANCH)" = "master" ]; then \
	    $(DOCKER) tag "$(REGISTRY_DEV):$(IMG_TAG)" "$(REGISTRY_DEV)"; \
	fi
	@echo Finished kube-router container image build.

Dockerfile.$(GOARCH).run: Dockerfile Makefile
	@sed -e "$(DOCKERFILE_SED_EXPR)" Dockerfile > $(@)

docker-login: ## Logs into a docker registry using {DOCKER,QUAY}_{USERNAME,PASSWORD} variables.
	@echo Starting docker login target.
	@if [ -n "$(DOCKER_USERNAME)" ] && [ -n "$(DOCKER_PASSWORD)" ]; then \
	    echo Starting DockerHub registry login.; \
	    $(DOCKER) login -u="$(value DOCKER_USERNAME)" -p="$(value DOCKER_PASSWORD)"; \
	    echo Finished DockerHub registry login.; \
	fi

	@if [ -n "$(QUAY_USERNAME)" ] && [ -n "$(QUAY_PASSWORD)" ]; then \
	    echo Starting quay.io registry login.; \
	    $(DOCKER) login -u="$(value QUAY_USERNAME)" -p="$(value QUAY_PASSWORD)" quay.io; \
	    echo Finished quay.io registry login.; \
	fi
	@echo Finished docker login target.

push: container docker-login ## Pushes a Docker container image to a registry.
	@echo Starting kube-router container image push.
	$(DOCKER) push "$(REGISTRY_DEV):$(IMG_TAG)"
	@echo Finished kube-router container image push.

push-manifest:
	@echo Starting kube-router manifest push.
	./manifest-tool push from-args \
		--platforms linux/amd64,linux/arm64,linux/arm,linux/s390x,linux/ppc64le \
		--template "$(REGISTRY_DEV):ARCH-$(MANIFEST_TAG)" \
		--target "$(REGISTRY_DEV):$(MANIFEST_TAG)"

push-release: push
	@echo Starting kube-router release container image push.
	@test -n "$(RELEASE_TAG)"
	$(DOCKER) tag "$(REGISTRY_DEV):$(IMG_TAG)" "$(REGISTRY):$(RELEASE_TAG)"
	$(DOCKER) push "$(REGISTRY)"
	@echo Finished kube-router release container image push.

push-manifest-release:
	@echo Starting kube-router manifest push.
	./manifest-tool push from-args \
		--platforms linux/amd64,linux/arm64,linux/arm,linux/s390x,linux/ppc64le \
		--template "$(REGISTRY):ARCH-${RELEASE_TAG}" \
		--target "$(REGISTRY):$(RELEASE_TAG)"

	./manifest-tool push from-args \
		--platforms linux/amd64,linux/arm64,linux/arm,linux/s390x,linux/ppc64le \
		--template "$(REGISTRY):ARCH-${RELEASE_TAG}" \
		--target "$(REGISTRY):latest"

github-release:
	@echo Starting kube-router GitHub release creation.
	@[ -n "$(value GITHUB_TOKEN)" ] && \
	  GITHUB_TOKEN=$(value GITHUB_TOKEN); \
	  curl -sL https://git.io/goreleaser | bash
	@echo Finished kube-router GitHub release creation.

release: push-release github-release ## Pushes a release to DockerHub and GitHub
	@echo Finished kube-router release target.

clean: ## Removes the kube-router binary and Docker images
	rm -f kube-router
	rm -f gobgp
	rm -f Dockerfile.$(GOARCH).run
	if [ $(shell $(DOCKER) images -q $(REGISTRY_DEV):$(IMG_TAG) 2> /dev/null) ]; then \
		 $(DOCKER) rmi $(REGISTRY_DEV):$(IMG_TAG); \
	fi
gofmt: ## Tells you what files need to be gofmt'd.
	@build/verify-gofmt.sh

gofmt-fix: ## Fixes files that need to be gofmt'd.
	gofmt -s -w $(LOCAL_PACKAGES)

# List of all file_moq.go files which would need to be regenerated
# from file.go if changed
gomoqs: ./pkg/controllers/proxy/network_services_controller_moq.go

# file_moq.go file is generated from file.go "//go:generate moq ..." in-file
# annotation, as it needs to know which interfaces to create mock stubs for
%_moq.go: %.go
ifeq "$(BUILD_IN_DOCKER)" "true"
	$(DOCKER) run -v $(PWD):/go/src/github.com/cloudnativelabs/kube-router -w /go/src/github.com/cloudnativelabs/kube-router $(DOCKER_BUILD_IMAGE) \
			sh -c 'apk add --no-cache git build-base && go get github.com/matryer/moq && go generate -v $(*).go'
else
	@test -x $(lastword $(subst :, ,$(GOPATH)))/bin/moq && exit 0; echo "ERROR: 'moq' tool is needed to update mock test files, install it with: \ngo get github.com/matryer/moq\n"; exit 1
	go generate -v $(*).go
endif

gopath: ## Warns about issues building from a directory that does not match upstream.
	@echo 'Checking project path for import issues...'
	@echo '- Project dir: $(MAKEFILE_DIR)'
	@echo '- Import dir:  $(UPSTREAM_IMPORT_PATH)'
	@echo
ifeq ($(MAKEFILE_DIR),$(UPSTREAM_IMPORT_PATH))
	@echo 'Looks good!'
else
	@echo 'The project directory does not match $(UPSTREAM_IMPORT_PATH)'
	@echo
	@echo 'This could cause build issues. Consider moving this project'
	@echo 'directory to $(UPSTREAM_IMPORT_PATH) and work from there.'
	@echo 'This could be done for you by running: "make gopath-fix".'
	@echo
endif

# This fixes GOPATH issues for contributers using their own Travis-CI account
# with their forked kube-router repo. It's also useful for contributors testing
# code and CI changes with their own Travis account.
gopath-fix: ## Copies this project directory to the upstream import path.
ifneq ($(wildcard $(UPSTREAM_IMPORT_PATH)/.*),)
	@echo
	@echo '$(UPSTREAM_IMPORT_PATH) already exists.'
	@echo 'Aborting gopath-fix.'
	@echo
else
	@echo
	@echo 'Copying $(MAKEFILE_DIR) to $(UPSTREAM_IMPORT_PATH)'
	@echo
	mkdir -p "$(UPSTREAM_IMPORT_PATH)"
	cp -ar $(MAKEFILE_DIR)/. "$(UPSTREAM_IMPORT_PATH)"
	@echo
	@echo 'Success! Please use $(UPSTREAM_IMPORT_PATH)'
	@echo
endif

gobgp:
ifeq "$(BUILD_IN_DOCKER)" "true"
	@echo Building gobgp
	$(DOCKER) run -v $(PWD)/vendor:/go/src -w /go/src/github.com/osrg/gobgp/cmd/gobgp $(DOCKER_BUILD_IMAGE) \
    sh -c 'GOARCH=$(GOARCH) CGO_ENABLED=0 go build -o gobgp'
	@echo Finished building gobgp.
else
	cd vendor/github.com/osrg/gobgp/gobgp && \
	CGO_ENABLED=0 GOARCH=$(GOARCH) GOOS=linux go build -o gobgp
endif
	cp -f vendor/github.com/osrg/gobgp/cmd/gobgp/gobgp gobgp

multiarch-binverify:
	@echo 'Verifying kube-router gobgp for ARCH=$(FILE_ARCH) ...'
	@[ `file kube-router gobgp| cut -d, -f2 |grep -cw "$(FILE_ARCH)"` -eq 2 ]

# http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

# TODO: Uncomment this target when all deps are version-pinned in glide.yaml
# update-glide:
# 	# go get -d -u github.com/Masterminds/glide
# 	glide update --strip-vendor
# 	# go get -d -u github.com/sgotti/glide-vc
# 	glide vc --only-code --no-tests

# If the first argument is "vagrant"...
ifeq (vagrant,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "vagrant"
  VAGRANT_RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(VAGRANT_RUN_ARGS):;@:)
endif

.PHONY: build clean container run release goreleaser push gofmt gofmt-fix gomoqs
.PHONY: update-glide test lint docker-login push-manifest push-manifest-release
.PHONY: push-release github-release help gopath gopath-fix vagrant-up-single-node
.PHONY: vagrant-up-multi-node vagrant-destroy vagrant-clean vagrant
.PHONY: multiarch-binverify

.DEFAULT: all
