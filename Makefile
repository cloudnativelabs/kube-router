NAME?=kube-router
DEV_SUFFIX?=-git
LOCAL_PACKAGES?=app app/controllers app/options app/watchers
IMG_NAMESPACE?=cloudnativelabs
IMG_TAG?=$(shell git describe --tags --dirty)
GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
RELEASE_TAG?=$(shell build/get-git-tag.sh)
REGISTRY?=$(if $(IMG_FQDN),$(IMG_FQDN)/$(IMG_NAMESPACE)/$(NAME),$(IMG_NAMESPACE)/$(NAME))
REGISTRY_DEV?=$(REGISTRY)$(DEV_SUFFIX)
IN_DOCKER_GROUP=$(filter docker,$(shell groups))
IS_ROOT=$(filter 0,$(shell id -u))
DOCKER=$(if $(or $(IN_DOCKER_GROUP),$(IS_ROOT)),docker,sudo docker)
MAKEFILE_DIR=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))
UPSTREAM_IMPORT_PATH=$(GOPATH)/src/github.com/cloudnativelabs/kube-router/

all: test kube-router container ## Default target. Runs tests, builds binaries and images.

kube-router: $(shell find . -name \*.go) ## Builds kube-router.
	CGO_ENABLED=0 go build -o kube-router kube-router.go

test: gofmt ## Runs code quality pipelines (gofmt, tests, coverage, lint, etc)

run: kube-router ## Runs "kube-router --help".
	./kube-router --help

container: kube-router ## Builds a Docker container image.
	$(DOCKER) build -t "$(REGISTRY_DEV):$(IMG_PREFIX)$(IMG_TAG)" .

docker-login:
	@if [ -z "$(NO_DOCKER_LOGIN)" ]; then \
	    $(DOCKER) login -u="$(value DOCKER_USERNAME)" -p="$(value DOCKER_PASSWORD)"; \
	fi

	@if [ -z "$(NO_QUAY_LOGIN)" ]; then \
	    $(DOCKER) login -u="$(value QUAY_USERNAME)" -p="$(value QUAY_PASSWORD)" quay.io; \
	fi

push: container docker-login ## Pushes a Docker container image to a registry.
	$(DOCKER) tag "$(REGISTRY_DEV):$(IMG_TAG)" "$(REGISTRY_DEV):$(GIT_BRANCH)-latest"
	$(DOCKER) push "$(REGISTRY_DEV)"

push-release: push
	@test -n "$(RELEASE_TAG)"
	$(DOCKER) tag "$(REGISTRY_DEV):$(IMG_TAG)" "$(REGISTRY):$(RELEASE_TAG)"
	$(DOCKER) tag "$(REGISTRY):$(RELEASE_TAG)" "$(REGISTRY):latest"
	$(DOCKER) push "$(REGISTRY)"

github-release: kube-router
	@[ -n "$(value GITHUB_TOKEN)" ] && \
	  GITHUB_TOKEN=$(value GITHUB_TOKEN); \
	  curl -sL https://git.io/goreleaser | bash

release: push-release github-release ## Pushes a release to DockerHub and GitHub

clean: ## Removes the kube-router binary and Docker images
	rm -f kube-router
	$(DOCKER) rmi $(REGISTRY_DEV)
	$(DOCKER) rmi $(REGISTRY)

gofmt: ## Tells you what files need to be gofmt'd.
	@build/verify-gofmt.sh

gofmt-fix: ## Fixes files that need to be gofmt'd.
	gofmt -s -w $(LOCAL_PACKAGES)

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

# http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

# TODO: Uncomment this target when all deps are version-pinned in glide.yaml
# update-glide:
# 	# go get -d -u github.com/Masterminds/glide
# 	glide update --strip-vendor
# 	# go get -d -u github.com/sgotti/glide-vc
# 	glide vc --only-code --no-tests

.PHONY: build clean container run release goreleaser push gofmt gofmt-fix
.PHONY: update-glide test docker-login push-release github-release help
.PHONY: gopath gopath-fix

.DEFAULT: all
