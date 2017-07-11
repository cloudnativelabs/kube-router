FROM alpine:3.6

COPY kube-router gobgp /usr/local/bin/
COPY build/image-assets/bashrc /root/.bashrc
COPY build/image-assets/profile /root/.profile
COPY build/image-assets/vimrc /root/.vimrc
COPY build/image-assets/motd-kube-router.sh /etc/motd-kube-router.sh

RUN apk add --no-cache \
      iptables \
      ipset \
      ipvsadm \
      curl \
      bash && \
    mkdir -p /var/lib/gobgp && \
    mkdir -p /usr/local/share/bash-completion && \
    curl -L -o /usr/local/share/bash-completion/bash-completion \
        https://raw.githubusercontent.com/scop/bash-completion/master/bash_completion && \
    cd && \
    /usr/local/bin/gobgp --gen-cmpl --bash-cmpl-file /var/lib/gobgp/gobgp-completion.bash

WORKDIR "/root"
ENTRYPOINT ["/usr/local/bin/kube-router"]
