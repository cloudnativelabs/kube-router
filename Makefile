NAME?=kube-router
GOARCH?=amd64
DEV_SUFFIX?=-git
BUILD_DATE?=$(shell date --iso-8601)
LOCAL_PACKAGES?=app app/controllers app/options app/watchers utils
IMG_NAMESPACE?=cloudnativelabs
GIT_COMMIT=$(shell git describe --tags --dirty)
GIT_BRANCH?=$(shell git rev-parse --abbrev-ref HEAD)
IMG_TAG?=$(if $(IMG_TAG_PREFIX),$(IMG_TAG_PREFIX)-)$(if $(ARCH_TAG_PREFIX),$(ARCH_TAG_PREFIX)-)$(GIT_BRANCH)
RELEASE_TAG?=$(shell build/get-git-tag.sh)
REGISTRY?=$(if $(IMG_FQDN),$(IMG_FQDN)/$(IMG_NAMESPACE)/$(NAME),$(IMG_NAMESPACE)/$(NAME))
REGISTRY_DEV?=$(REGISTRY)$(DEV_SUFFIX)
IN_DOCKER_GROUP=$(filter docker,$(shell groups))
IS_ROOT=$(filter 0,$(shell id -u))
DOCKER=$(if $(or $(IN_DOCKER_GROUP),$(IS_ROOT)),docker,sudo docker)
MAKEFILE_DIR=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))
UPSTREAM_IMPORT_PATH=$(GOPATH)/src/github.com/cloudnativelabs/kube-router/

ifeq ($(GOARCH), arm)
QEMU_ARCH=arm
ARCH_TAG_PREFIX=$(GOARCH)
FILE_ARCH=ARM
DOCKERFILE_SED_EXPR?=s,FROM alpine:,FROM multiarch/alpine:armhf-v,
else ifeq ($(GOARCH), arm64)
QEMU_ARCH=aarch64
ARCH_TAG_PREFIX=$(GOARCH)
FILE_ARCH=ARM aarch64
DOCKERFILE_SED_EXPR?=s,FROM alpine:,FROM multiarch/alpine:aarch64-v,
else
DOCKERFILE_SED_EXPR?=
FILE_ARCH=x86-64
endif
$(info Building for GOARCH=$(GOARCH))
all: test kube-router container ## Default target. Runs tests, builds binaries and images.

kube-router:
	@echo Starting kube-router binary build.
	GOARCH=$(GOARCH) CGO_ENABLED=0 go build -ldflags '-X github.com/cloudnativelabs/kube-router/app.version=$(GIT_COMMIT) -X github.com/cloudnativelabs/kube-router/app.buildDate=$(BUILD_DATE)' -o kube-router kube-router.go
	@echo Finished kube-router binary build.

test: gofmt gomoqs ## Runs code quality pipelines (gofmt, tests, coverage, lint, etc)
	go test github.com/cloudnativelabs/kube-router github.com/cloudnativelabs/kube-router/app/... github.com/cloudnativelabs/kube-router/utils/

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

container: multiarch-check Dockerfile.$(GOARCH).run kube-router gobgp multiarch-binverify ## Builds a Docker container image.
	@echo Starting kube-router container image build.
	$(DOCKER) build -t "$(REGISTRY_DEV):$(IMG_TAG)" -f Dockerfile.$(GOARCH).run .
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

push-release: push
	@echo Starting kube-router release container image push.
	@test -n "$(RELEASE_TAG)"
	$(DOCKER) tag "$(REGISTRY_DEV):$(IMG_TAG)" "$(REGISTRY):$(RELEASE_TAG)"
	$(DOCKER) tag "$(REGISTRY):$(RELEASE_TAG)" "$(REGISTRY):latest"
	$(DOCKER) push "$(REGISTRY)"
	@echo Finished kube-router release container image push.

github-release: kube-router
	@echo Starting kube-router GitHub release creation.
	@[ -n "$(value GITHUB_TOKEN)" ] && \
	  GITHUB_TOKEN=$(value GITHUB_TOKEN); \
	  curl -sL https://git.io/goreleaser | bash
	@echo Finished kube-router GitHub release creation.

release: push-release github-release ## Pushes a release to DockerHub and GitHub
	@echo Finished kube-router release target.

clean: ## Removes the kube-router binary and Docker images
	rm -f kube-router
	$(DOCKER) rmi $(REGISTRY_DEV)

gofmt: ## Tells you what files need to be gofmt'd.
	@build/verify-gofmt.sh

gofmt-fix: ## Fixes files that need to be gofmt'd.
	gofmt -s -w $(LOCAL_PACKAGES)

# List of all file_moq.go files which would need to be regenerated
# from file.go if changed
gomoqs: ./app/controllers/network_services_controller_moq.go

# file_moq.go file is generated from file.go "//go:generate moq ..." in-file
# annotation, as it needs to know which interfaces to create mock stubs for
%_moq.go: %.go
	@test -x $(GOPATH)/bin/moq && exit 0; echo "ERROR: 'moq' tool is needed to update mock test files, install it with: \ngo get github.com/matryer/moq\n"; exit 1
	go generate -v $(*).go

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

gobgp: vendor/github.com/osrg/gobgp/gobgp
	$(DOCKER) run -v $(PWD):/pwd golang:alpine \
	    sh -c ' \
	    apk add -U git && \
	    ln -s /pwd/vendor /go/src && \
	    CGO_ENABLED=0 GOARCH=$(GOARCH) go get github.com/osrg/gobgp/gobgp && \
	    cp `find /go/bin -type f -name gobgp` /pwd'

multiarch-check:
	@[ -z "$(QEMU_ARCH)" ] && exit 0; \
	  QEMU_RUNTIME=$$(sed -n '/interpreter/s/.* //p' /proc/sys/fs/binfmt_misc/qemu-$(QEMU_ARCH)); \
	  trap 'rc=$$?; [ $$rc -ne 0 ] && echo "To fix below, try running: make multiarch-setup\n"; exit $$rc' 0 ;\
	  echo "Checking for QEMU_RUNTIME=$${QEMU_RUNTIME} ..." ;\
	  test -x "$${QEMU_RUNTIME}"

multiarch-binverify:
	@echo 'Verifying kube-router gobgp for ARCH=$(FILE_ARCH) ...'
	@[ `file kube-router gobgp| cut -d, -f2 |grep -cw "$(FILE_ARCH)"` -eq 2 ]

multiarch-setup:
	$(DOCKER) run --rm --privileged multiarch/qemu-user-static:register

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
.PHONY: update-glide test docker-login push-release github-release help
.PHONY: gopath gopath-fix vagrant-up-single-node
.PHONY: vagrant-up-multi-node vagrant-destroy vagrant-clean vagrant
.PHONY: multiarch-setup multiarch-check multiarch-binverify

.DEFAULT: all
