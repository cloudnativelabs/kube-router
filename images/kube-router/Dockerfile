FROM alpine:3.6

COPY kube-router gobgp /usr/local/bin/
COPY images/kube-router/bashrc /root/.bashrc
COPY images/kube-router/profile /root/.profile
COPY images/kube-router/vimrc /root/.vimrc
COPY images/kube-router/motd-kube-router.sh /etc/motd-kube-router.sh

RUN apk add --no-cache \
      iptables \
      ipset \
      iproute2 \
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
