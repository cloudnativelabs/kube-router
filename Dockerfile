ARG BUILDTIME_BASE=golang:1-alpine
ARG RUNTIME_BASE=alpine:latest
ARG TARGETPLATFORM
ARG CNI_VERSION
FROM ${BUILDTIME_BASE} as builder
ENV BUILD_IN_DOCKER=false

WORKDIR /build
COPY . /build
RUN apk add --no-cache make git tar curl \
    && make kube-router \
    && make gobgp \
    && make cni-download

WORKDIR /iptables-wrappers
# This is the latest commit on the master branch.
ENV IPTABLES_WRAPPERS_VERSION=f6ef44b2c449cca8f005b32dea9a4b497202dbef
RUN git clone https://github.com/kubernetes-sigs/iptables-wrappers.git . \
    && git checkout "${IPTABLES_WRAPPERS_VERSION}" \
    && make build \
    && test -x bin/iptables-wrapper \
    && test -x iptables-wrapper-installer.sh

FROM ${RUNTIME_BASE}

RUN apk add --no-cache \
      iptables \
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
COPY --from=builder /iptables-wrappers/iptables-wrapper-installer.sh /
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
    /iptables-wrapper-installer.sh --no-sanity-check

WORKDIR /root
ENTRYPOINT ["/usr/local/bin/kube-router"]
