NAME?=kube-router
GOARCH?=$(shell go env GOARCH)
DEV_SUFFIX?=-git
OSX=$(filter Darwin,$(shell uname))
BUILD_DATE?=$(shell date +%Y-%m-%dT%H:%M:%S%z)
IMG_NAMESPACE?=cloudnativelabs
GIT_COMMIT=$(shell git describe --tags --dirty)
GIT_BRANCH?=$(shell git rev-parse --abbrev-ref HEAD)
IMG_TAG?=$(if $(IMG_TAG_PREFIX),$(IMG_TAG_PREFIX)-)$(if $(ARCH_TAG_PREFIX),$(ARCH_TAG_PREFIX)-)$(GIT_BRANCH)
MANIFEST_TAG?=$(if $(IMG_TAG_PREFIX),$(IMG_TAG_PREFIX)-)$(GIT_BRANCH)
RELEASE_TAG?=$(GOARCH)-$(shell git describe --exact-match || echo -n)
REGISTRY?=$(if $(IMG_FQDN),$(IMG_FQDN)/$(IMG_NAMESPACE)/$(NAME),$(IMG_NAMESPACE)/$(NAME))
REGISTRY_DEV?=$(REGISTRY)$(DEV_SUFFIX)
IN_DOCKER_GROUP=$(filter docker,$(shell groups))
IS_ROOT=$(filter 0,$(shell id -u))
DOCKER=$(if $(or $(IN_DOCKER_GROUP),$(IS_ROOT),$(OSX)),docker,sudo docker)
MAKEFILE_DIR=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))
UPSTREAM_IMPORT_PATH=$(GOPATH)/src/github.com/cloudnativelabs/kube-router/
BUILD_IN_DOCKER?=true
DOCKER_BUILD_IMAGE?=golang:1.22.3-alpine3.18
## These variables are used by the Dockerfile as the bases for building and creating the runtime container
## During CI these come from .github/workflows/ci.yaml below we define for local builds as well
GO_CACHE?=$(shell go env GOCACHE)
GO_MOD_CACHE?=$(shell go env GOMODCACHE)
BUILDTIME_BASE?=$(DOCKER_BUILD_IMAGE)
# Do not bump past Alpine 3.18 until upstream netfilter problems in iptables v1.8.10 are resolved. See:
# https://github.com/cloudnativelabs/kube-router/issues/1676
RUNTIME_BASE?=alpine:3.18
DOCKER_LINT_IMAGE?=golangci/golangci-lint:v1.56.2
DOCKER_MARKDOWNLINT_IMAGE?=tmknom/markdownlint:0.39.0
GOBGP_VERSION=v3.29.0
QEMU_IMAGE?=multiarch/qemu-user-static
GORELEASER_VERSION=v1.24.0
MOQ_VERSION=v0.3.4
CNI_VERSION=v1.4.0
UID?=$(shell id -u)
ifeq ($(GOARCH), arm)
ARCH_TAG_PREFIX=$(GOARCH)
FILE_ARCH=ARM
DOCKER_ARCH=arm32v6/
else ifeq ($(GOARCH), arm64)
ARCH_TAG_PREFIX=$(GOARCH)
FILE_ARCH=ARM aarch64
DOCKER_ARCH=arm64v8/
else ifeq ($(GOARCH), s390x)
ARCH_TAG_PREFIX=$(GOARCH)
FILE_ARCH=IBM S/390
DOCKER_ARCH=s390x/
else ifeq ($(GOARCH), ppc64le)
ARCH_TAG_PREFIX=$(GOARCH)
FILE_ARCH=64-bit PowerPC
DOCKER_ARCH=ppc64le/
else ifeq ($(GOARCH), riscv64)
ARCH_TAG_PREFIX=$(GOARCH)
FILE_ARCH=UCB RISC-V, RVC, double-float ABI
DOCKER_ARCH=riscv64/
else
ARCH_TAG_PREFIX=amd64
FILE_ARCH=x86-64
DOCKER_ARCH=
endif
$(info Building for GOARCH=$(GOARCH))
all: lint test kube-router container ## Default target. Lints code, runs tests, builds binaries and images.

kube-router:
	@echo Starting kube-router binary build.
ifeq "$(BUILD_IN_DOCKER)" "true"
	$(DOCKER) run -v $(PWD):/go/src/github.com/cloudnativelabs/kube-router \
		-v $(GO_CACHE):/root/.cache/go-build \
		-v $(GO_MOD_CACHE):/go/pkg/mod \
		-w /go/src/github.com/cloudnativelabs/kube-router $(DOCKER_BUILD_IMAGE) \
		sh -c \
		'GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
		-ldflags "-X github.com/cloudnativelabs/kube-router/v2/pkg/version.Version=$(GIT_COMMIT) -X github.com/cloudnativelabs/kube-router/v2/pkg/version.BuildDate=$(BUILD_DATE)" \
		-o kube-router cmd/kube-router/kube-router.go'
else
	GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
	-ldflags "-X github.com/cloudnativelabs/kube-router/v2/pkg/version.Version=$(GIT_COMMIT) -X github.com/cloudnativelabs/kube-router/v2/pkg/version.BuildDate=$(BUILD_DATE)" \
	-o kube-router cmd/kube-router/kube-router.go
endif
	@echo Finished kube-router binary build.

test: gofmt ## Runs code quality pipelines (gofmt, tests, coverage, etc)
ifeq "$(BUILD_IN_DOCKER)" "true"
	$(DOCKER) run -v $(PWD):/go/src/github.com/cloudnativelabs/kube-router \
		-v $(GO_CACHE):/root/.cache/go-build \
		-v $(GO_MOD_CACHE):/go/pkg/mod \
		-w /go/src/github.com/cloudnativelabs/kube-router $(DOCKER_BUILD_IMAGE) \
		sh -c \
		'CGO_ENABLED=0 go test -v -timeout 30s github.com/cloudnativelabs/kube-router/v2/cmd/kube-router/ github.com/cloudnativelabs/kube-router/v2/pkg/...'
else
	go test -v -timeout 30s github.com/cloudnativelabs/kube-router/v2/cmd/kube-router/ github.com/cloudnativelabs/kube-router/v2/pkg/...
endif

lint: gofmt markdownlint
ifeq "$(BUILD_IN_DOCKER)" "true"
	$(DOCKER) run -v $(PWD):/go/src/github.com/cloudnativelabs/kube-router \
		-v $(GO_CACHE):/root/.cache/go-build \
		-v $(GO_MOD_CACHE):/go/pkg/mod \
		-w /go/src/github.com/cloudnativelabs/kube-router $(DOCKER_LINT_IMAGE) \
		bash -c \
		'golangci-lint run ./...'
else
	golangci-lint run ./...
endif

markdownlint:
	$(DOCKER) run -v $(PWD):/work $(DOCKER_MARKDOWNLINT_IMAGE) -- README.md docs

run: kube-router ## Runs "kube-router --help".
	./kube-router --help

container: kube-router gobgp multiarch-binverify cni-download ## Builds a Docker container image.
	@echo Starting kube-router container image build for $(GOARCH) on $(shell go env GOHOSTARCH)
	@if [ "$(GOARCH)" != "$(shell go env GOHOSTARCH)" ]; then \
		echo "Using qemu to build non-native container"; \
		$(DOCKER) run --rm --privileged $(QEMU_IMAGE) --reset -p yes; \
	fi
	$(DOCKER) build -t "$(REGISTRY_DEV):$(subst /,,$(IMG_TAG))" -f Dockerfile --build-arg ARCH="$(DOCKER_ARCH)" \
		--build-arg BUILDTIME_BASE="$(BUILDTIME_BASE)" --build-arg RUNTIME_BASE="$(RUNTIME_BASE)" .
	@if [ "$(GIT_BRANCH)" = "master" ]; then \
		$(DOCKER) tag "$(REGISTRY_DEV):$(IMG_TAG)" "$(REGISTRY_DEV)"; \
	fi
	@echo Finished kube-router container image build.

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
		curl -sL https://git.io/goreleaser | VERSION=$(GORELEASER_VERSION) bash
	@echo Finished kube-router GitHub release creation.

release: push-release github-release ## Pushes a release to DockerHub and GitHub
	@echo Finished kube-router release target.

clean: ## Removes the kube-router binary and Docker images
	rm -f kube-router
	rm -f gobgp
	rm -rf cni-download
	if [ $(shell $(DOCKER) images -q $(REGISTRY_DEV):$(IMG_TAG) 2> /dev/null) ]; then \
		 $(DOCKER) rmi $(REGISTRY_DEV):$(IMG_TAG); \
	fi
gofmt: ## Tells you what files need to be gofmt'd.
	gofmt -l -s $(shell find . -not \( \( -wholename '*/vendor/*' \) -prune \) -name '*.go')

gofmt-fix: ## Fixes files that need to be gofmt'd.
	gofmt -s -w $(shell find . -not \( \( -wholename '*/vendor/*' \) -prune \) -name '*.go')
	goimports -w $(shell find . -not \( \( -wholename '*/vendor/*' \) -prune \) -name '*.go')

# List of all file_moq.go files which would need to be regenerated
# from file.go if changed
gomoqs: ./pkg/controllers/proxy/linux_networking_moq.go

# file_moq.go file is generated from file.go "//go:generate moq ..." in-file
# annotation, as it needs to know which interfaces to create mock stubs for
%_moq.go: %.go
	rm -f $(*)_moq.go
ifeq "$(BUILD_IN_DOCKER)" "true"
	$(DOCKER) run -v $(PWD):/go/src/github.com/cloudnativelabs/kube-router \
		-v $(GO_CACHE):/root/.cache/go-build \
		-v $(GO_MOD_CACHE):/go/pkg/mod \
		-w /go/src/github.com/cloudnativelabs/kube-router $(DOCKER_BUILD_IMAGE) \
		sh -c 'go install github.com/matryer/moq@$(MOQ_VERSION) && go generate -v $(*).go && chown $(UID) $(*)_moq.go'
else
	@test -x $(lastword $(subst :, ,$(GOPATH)))/bin/moq && exit 0; echo "ERROR: 'moq' tool is needed to update mock test files, install it with: \ngo get github.com/matryer/moq\n"; exit 1
	go generate -v $(*).go
endif

gobgp:
	@echo Building gobgp
ifeq "$(BUILD_IN_DOCKER)" "true"
	$(DOCKER) run -v $(PWD):/go/src/github.com/cloudnativelabs/kube-router \
		-v $(GO_CACHE):/root/.cache/go-build \
		-v $(GO_MOD_CACHE):/go/pkg/mod \
		-w /go/src/github.com/cloudnativelabs/kube-router $(DOCKER_BUILD_IMAGE) \
		sh -c \
		'CGO_ENABLED=0 GOARCH=$(GOARCH) GOOS=linux go install github.com/osrg/gobgp/v3/cmd/gobgp@$(GOBGP_VERSION) && if [ ${GOARCH} != $$(go env GOHOSTARCH) ]; then PREFIX=linux_${GOARCH}; fi && cp $$(go env GOPATH)/bin/$${PREFIX}/gobgp .'
else
	CGO_ENABLED=0 GOARCH=$(GOARCH) GOOS=linux go install github.com/osrg/gobgp/v3/cmd/gobgp@$(GOBGP_VERSION) && if [ ${GOARCH} != $$(go env GOHOSTARCH) ]; then PREFIX=linux_${GOARCH}; fi && cp $$(go env GOPATH)/bin/$${PREFIX}/gobgp .
endif
	@echo Finished building gobgp.

multiarch-binverify:
	@echo 'Verifying kube-router gobgp for ARCH=$(FILE_ARCH) ...'
	@[ `file kube-router gobgp| cut -d, -f2 |grep -cw "$(FILE_ARCH)"` -eq 2 ]

cni-download:
	@echo Downloading CNI Plugins for $(GOARCH)
		curl -L -o cni-plugins-$(GOARCH).tgz \
			https://github.com/containernetworking/plugins/releases/download/$(CNI_VERSION)/cni-plugins-linux-$(GOARCH)-$(CNI_VERSION).tgz
		mkdir -p cni-download
		tar -xf cni-plugins-$(GOARCH).tgz -C cni-download
		rm -f cni-plugins-$(GOARCH).tgz

# http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: clean container run release goreleaser push gofmt gofmt-fix gomoqs
.PHONY: test lint docker-login push-manifest push-manifest-release
.PHONY: push-release github-release help multiarch-binverify markdownlint

.DEFAULT: all
