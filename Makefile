NAME?=kube-router
DEV_SUFFIX?=-git
LOCAL_PACKAGES?=app app/controllers app/options app/watchers
IMG_NAMESPACE?=cloudnativelabs
GIT_COMMIT=$(shell git describe --tags --dirty)
GIT_BRANCH?=$(shell git rev-parse --abbrev-ref HEAD)
IMG_TAG?=$(if $(IMG_TAG_PREFIX),$(IMG_TAG_PREFIX)-)$(GIT_BRANCH)
RELEASE_TAG?=$(shell build/get-git-tag.sh)
REGISTRY?=$(if $(IMG_FQDN),$(IMG_FQDN)/$(IMG_NAMESPACE)/$(NAME),$(IMG_NAMESPACE)/$(NAME))
REGISTRY_DEV?=$(REGISTRY)$(DEV_SUFFIX)
IN_DOCKER_GROUP=$(filter docker,$(shell groups))
IS_ROOT=$(filter 0,$(shell id -u))
DOCKER=$(if $(or $(IN_DOCKER_GROUP),$(IS_ROOT)),docker,sudo docker)
MAKEFILE_DIR=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))
UPSTREAM_IMPORT_PATH=$(GOPATH)/src/github.com/cloudnativelabs/kube-router/
KUBE_VERSION?=v1.7
KUBE_V=$(shell echo $(KUBE_VERSION)|sed -e 's/^v//')
kube_version_full = $(shell curl -Ss https://storage.googleapis.com/kubernetes-release/release/stable-$(KUBE_V).txt)
UID_CMD=id | sed 's/^uid=//;s/(.*$//'
UID=$(shell $(value $(UID_CMD)))
BUILD_FILES=$(shell find app vendor kube-router.go -name \*.go)
FMT_FILES=$(shell find app kube-router.go -name \*.go)

all: test kube-router images/kube-router ## Default target. Runs tests, builds binaries and images.

kube-router: $(BUILD_FILES) ## Builds kube-router.
	@echo Starting kube-router binary build.
	CGO_ENABLED=0 go build -o kube-router kube-router.go
	@echo Finished kube-router binary build.

test: gofmt ## Runs code quality pipelines (gofmt, tests, coverage, lint, etc)

test-e2e: _cache/hosts _cache/kube-metal/assets/auth/kubeconfig
	$(DOCKER) run \
	  --volume="$(MAKEFILE_DIR)/_cache/kube-metal:/tf" \
	  --volume="$(MAKEFILE_DIR)/test/e2e:/e2e" \
	  --add-host=$(file < _cache/hosts) \
	  --workdir="/e2e" \
	  --env="KUBECONFIG=/tf/assets/auth/kubeconfig" \
	  lachlanevenson/k8s-kubectl:$(kube_version_full) \
	    apply -f /e2e/common
	ADD_HOSTS=$(file < _cache/hosts) \
	KUBECONFIG="$(MAKEFILE_DIR)/_cache/kube-metal/assets/auth/kubeconfig" \
	E2E_FOCUS="$(E2E_FOCUS)" \
	E2E_SKIP="$(E2E_SKIP)" \
	KUBECTL='' \
	NODE_COUNT="1" \
	test/e2e/run-e2e.sh --clean-start

_cache:
	@mkdir _cache

_cache/.terraformrc: | _cache
	echo 'providers { ct = "/go/bin/terraform-provider-ct"' > _cache/.terraformrc
	echo 'packet = "/go/bin/terraform-provider-packet"}' >> _cache/.terraformrc

_cache/hosts: _cache/kube-metal/assets/auth/kubeconfig | _cache
	$(DOCKER) run \
	  --volume $(MAKEFILE_DIR)/_cache/kube-metal:/tf \
	  --volume $(MAKEFILE_DIR)/_cache/.terraformrc:/root/.terraformrc \
	  --volume $(MAKEFILE_DIR)/_cache/go:/go \
	  --env="FORMAT=docker" \
	  --workdir "/tf" \
	  --entrypoint "/tf/etc-hosts.sh" \
	  hashicorp/terraform > _cache/hosts

_cache/go/src/github.com/coreos/terraform-provider-ct: | _cache/go
	mkdir -p _cache/go/src/github.com/coreos
	git clone \
	  https://github.com/coreos/terraform-provider-ct.git \
	  _cache/go/src/github.com/coreos/terraform-provider-ct

_cache/go/bin/terraform-provider-ct: _cache/go/src/github.com/coreos/terraform-provider-ct
	$(DOCKER) run \
	  --volume="$(MAKEFILE_DIR)/_cache/go:/go" \
	  --env="CGO_ENABLED=0" \
	  golang:alpine \
	    sh -c ' \
	      go install github.com/coreos/terraform-provider-ct \
	    '

_cache/go/src/github.com/terraform-providers/terraform-provider-packet: | _cache/go
	mkdir -p _cache/go/src/github.com/terraform-providers
	git clone \
	  --branch=device-spot-market \
	  https://github.com/cloudnativelabs/terraform-provider-packet.git \
	  _cache/go/src/github.com/terraform-providers/terraform-provider-packet

_cache/go/bin/terraform-provider-packet: _cache/go/src/github.com/terraform-providers/terraform-provider-packet
	$(DOCKER) run \
	  --volume="$(MAKEFILE_DIR)/_cache/go:/go" \
	  --env="CGO_ENABLED=0" \
	  golang:alpine \
	    sh -c ' \
	      go install github.com/terraform-providers/terraform-provider-packet \
	    '

tf-destroy:
	$(DOCKER) run \
	  --volume $(MAKEFILE_DIR)/_cache/kube-metal:/tf \
	  --volume $(MAKEFILE_DIR)/_cache/.terraformrc:/root/.terraformrc \
	  --volume $(MAKEFILE_DIR)/_cache/go:/go \
	  --workdir=/tf \
	  hashicorp/terraform \
	    destroy \
	    --var 'auth_token=$(PACKET_TOKEN)' \
	    --var 'project_id=$(PACKET_PROJECT_ID)' \
	    --var 'controller_count=1' \
	    --var 'worker_count=1' \
	    --var 'server_domain=test.kube-router.io' \
	    --var 'spot_instance=true' \
	    --var 'spot_price_max=.02' \
	    --force

_cache/go:
	@mkdir -p _cache/go/bin _cache/go/src

_cache/kube-metal: _cache/.terraformrc _cache/go/bin/terraform-provider-ct
_cache/kube-metal: _cache/go/bin/terraform-provider-packet
	git clone --branch=spot-market https://github.com/cloudnativelabs/kube-metal.git _cache/kube-metal

_cache/kube-metal/assets/auth/kubeconfig: _cache/kube-metal
	$(DOCKER) run \
	  --volume $(MAKEFILE_DIR)/_cache/kube-metal:/tf \
	  --volume $(MAKEFILE_DIR)/_cache/.terraformrc:/root/.terraformrc \
	  --volume $(MAKEFILE_DIR)/_cache/go:/go \
	  --workdir=/tf \
	  hashicorp/terraform \
	    init \
	    --force-copy \
	    --input=false \
	    --upgrade=true
	$(DOCKER) run \
	  --volume $(MAKEFILE_DIR)/_cache/kube-metal:/tf \
	  --volume $(MAKEFILE_DIR)/_cache/.terraformrc:/root/.terraformrc \
	  --volume $(MAKEFILE_DIR)/_cache/go:/go \
	  --workdir=/tf \
	  hashicorp/terraform \
	    get \
	    --update=true
	$(DOCKER) run \
	  --volume $(MAKEFILE_DIR)/_cache/kube-metal:/tf \
	  --volume $(MAKEFILE_DIR)/_cache/.terraformrc:/root/.terraformrc \
	  --volume $(MAKEFILE_DIR)/_cache/go:/go \
	  --workdir=/tf \
	  hashicorp/terraform \
	    apply \
	    --input=false \
	    --auto-approve=true \
	    --var 'auth_token=$(PACKET_TOKEN)' \
	    --var 'project_id=$(PACKET_PROJECT_ID)' \
	    --var 'controller_count=1' \
	    --var 'worker_count=1' \
	    --var 'server_domain=test.kube-router.io' \
	    --var 'spot_instance=true' \
	    --var 'spot_price_max=.02'

_cache/kube-router/images: images/kube-router
	@mkdir -p _cache/kube-router/images
	@$(DOCKER) save test.kube-router.io -o _cache/kube-router/images/kube-router.docker

images/kube-router: kube-router gobgp $(shell find images/kube-router/*) ## Builds a kube-router Docker container
	@echo Starting kube-router container image build.
	$(DOCKER) build -t "$(REGISTRY_DEV):$(IMG_TAG)" --file=images/kube-router/Dockerfile .
	@$(DOCKER) tag "$(REGISTRY_DEV):$(IMG_TAG)" test.kube-router.io
	@if [ "$(GIT_BRANCH)" = "master" ]; then \
	    $(DOCKER) tag "$(REGISTRY_DEV):$(IMG_TAG)" "$(REGISTRY_DEV)"; \
	fi
	@echo Finished kube-router container image build.
	@touch images/kube-router

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

push: images/kube-router docker-login ## Pushes a Docker container image to a registry.
	@echo Starting kube-router container image push.
	$(DOCKER) push "$(REGISTRY_DEV)"
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
	gofmt -l -s $(FMT_FILES)

gofmt-fix: ## Fixes files that need to be gofmt'd.
	gofmt -w -s $(FMT_FILES)

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

gobgp: $(shell find vendor/github.com/osrg/gobgp/gobgp)
	$(DOCKER) run -v $(PWD):/pwd golang:alpine \
	    sh -c ' \
	    apk add -U git && \
	    ln -s /pwd/vendor /go/src && \
	    CGO_ENABLED=0 go get github.com/osrg/gobgp/gobgp && \
	    gobgp --version && \
	    cp /go/bin/gobgp /pwd'

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

.PHONY: build clean run release goreleaser push gofmt gofmt-fix
.PHONY: update-glide test docker-login push-release github-release help
.PHONY: gopath gopath-fix vagrant-up-single-node
.PHONY: vagrant-up-multi-node vagrant-destroy vagrant-clean vagrant
.PHONY: tf-destroy

.DEFAULT: all
