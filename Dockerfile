ARG BUILDTIME_BASE=golang:1-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d
ARG RUNTIME_BASE=alpine:latest@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
ARG TARGETPLATFORM
ARG CNI_VERSION

# Builder runs on BUILDPLATFORM (the runner's native arch) and cross-compiles Go for each
# TARGETPLATFORM, avoiding QEMU-emulated `go build`. See:
# https://docs.docker.com/build/building/multi-platform/#cross-compilation
FROM --platform=$BUILDPLATFORM ${BUILDTIME_BASE} AS builder
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ENV BUILD_IN_DOCKER=false \
    CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH

WORKDIR /build
# Cache `go mod download` in its own layer; source-only changes won't invalidate it.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# GOARM is "v7" -> "7" (Dockerfile ENV can't do ${VAR#prefix}); empty on non-arm targets.
RUN apk add --no-cache make git tar curl \
    && export GOARM="${TARGETVARIANT#v}" \
    && make kube-router \
    && make gobgp \
    && make cni-download

WORKDIR /iptables-wrappers
# This is the latest commit on the master branch.
ENV IPTABLES_WRAPPERS_VERSION=bfef9e5087a198b50a4124bb9ce9d2c7c99025dd
# Pure-Go CGO_ENABLED=0 build, cross-compiles via the env vars set above.
RUN export GOARM="${TARGETVARIANT#v}" \
    && git clone https://github.com/kubernetes-sigs/iptables-wrappers.git . \
    && git checkout "${IPTABLES_WRAPPERS_VERSION}" \
    && make build \
    && test -x bin/iptables-wrapper

# Runtime stage runs on TARGETPLATFORM (QEMU for non-native), so apk pulls per-arch packages
# and `iptables-wrapper install` runs target-arch scripts — both fast.
FROM ${RUNTIME_BASE}

RUN apk add --no-cache \
      iptables \
      iptables-legacy \
      ipset \
      iproute2 \
      ipvsadm \
      conntrack-tools \
      curl \
      bash && \
    mkdir -p /var/lib/gobgp && \
    mkdir -p /usr/local/share/bash-completion && \
    curl -L -o /usr/local/share/bash-completion/bash-completion \
        https://raw.githubusercontent.com/scop/bash-completion/master/bash_completion

COPY build/image-assets/bashrc /root/.bashrc
COPY build/image-assets/profile /root/.profile
COPY build/image-assets/vimrc /root/.vimrc
COPY build/image-assets/motd-kube-router.sh /etc/motd-kube-router.sh
COPY build/image-assets/cni-install /usr/local/bin/cni-install
COPY --from=builder /build/kube-router /build/gobgp /usr/local/bin/
COPY --from=builder /build/cni-download /usr/libexec/cni

# Use iptables-wrappers so that correct version of iptables-legacy or iptables-nft gets used. Alpine contains both, but
# which version is used should be based on the host system as well as where rules that may have been added before
# kube-router are being placed. For more information see: https://github.com/kubernetes-sigs/iptables-wrappers
COPY --from=builder /iptables-wrappers/bin/iptables-wrapper /
# This is necessary because of the bug reported here: https://github.com/flannel-io/flannel/pull/1340/files
# Basically even under QEMU emulation, it still doesn't have an ARM kernel in-play which means that calls to
# iptables-nft will fail in the build process. The sanity check here only makes sure that iptables-nft and iptables-legacy
# are installed and that we are not using iptables-1.8.0-1.8.3. For now we'll manage that on our own.
RUN if ! command -v iptables-nft > /dev/null; then \
        echo "ERROR: iptables-nft is not installed" 1>&2; \
        exit 1; \
    fi && \
    if ! command -v iptables-legacy > /dev/null; then \
        echo "ERROR: iptables-legacy is not installed" 1>&2; \
        exit 1; \
    fi && \
    if ! command -v ip6tables > /dev/null; then \
        echo "ERROR: ip6tables is not installed" 1>&2; \
        exit 1; \
    fi && \
    /iptables-wrapper install

WORKDIR /root
ENTRYPOINT ["/usr/local/bin/kube-router"]
