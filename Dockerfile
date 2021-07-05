ARG BUILDTIME_BASE=golang:1-alpine
ARG RUNTIME_BASE=alpine:latest
FROM ${BUILDTIME_BASE} as builder
ENV BUILD_IN_DOCKER=false

WORKDIR /build
COPY . /build
RUN apk add --no-cache make git \
    && make kube-router \
    && make gobgp

FROM ${RUNTIME_BASE}

RUN apk add --no-cache \
      iptables \
      ip6tables \
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
COPY --from=builder /build/kube-router /build/gobgp /usr/local/bin/

# Use iptables-wrappers so that correct version of iptables-legacy or iptables-nft gets used. Alpine contains both, but
# which version is used should be based on the host system as well as where rules that may have been added before
# kube-router are being placed. For more information see: https://github.com/kubernetes-sigs/iptables-wrappers
COPY build/image-assets/iptables-wrapper-installer.sh /
# This is necessary because of the bug reported here: https://github.com/flannel-io/flannel/pull/1340/files
# Basically even under QEMU emulation, it still doesn't have an ARM kernel in-play which means that calls to
# iptables-nft will fail in the build process. The sanity check here only makes sure that we are not using
# iptables-1.8.0-1.8.2. For now we'll manage that on our own.
RUN /iptables-wrapper-installer.sh --no-sanity-check


# Since alpine image doesn't contain /etc/nsswitch.conf, the hosts in /etc/hosts (e.g. localhost)
# cannot be used. So manually add /etc/nsswitch.conf to work around this issue.
RUN echo "hosts: files dns" > /etc/nsswitch.conf

WORKDIR /root
ENTRYPOINT ["/usr/local/bin/kube-router"]
