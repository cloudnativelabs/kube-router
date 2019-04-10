FROM alpine:3.9

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

ADD build/image-assets/bashrc /root/.bashrc
ADD build/image-assets/profile /root/.profile
ADD build/image-assets/vimrc /root/.vimrc
ADD build/image-assets/motd-kube-router.sh /etc/motd-kube-router.sh
ADD kube-router gobgp /usr/local/bin/
RUN cd && \
    /usr/local/bin/gobgp --gen-cmpl --bash-cmpl-file /var/lib/gobgp/gobgp-completion.bash

WORKDIR "/root"
ENTRYPOINT ["/usr/local/bin/kube-router"]
