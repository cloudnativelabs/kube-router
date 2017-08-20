from centos:7

RUN yum -y install git make

ENV GO_VERSION 1.8.3
ENV GO_OS   linux
ENV GO_ARCH amd64 

RUN curl -O -L https://storage.googleapis.com/golang/go$GO_VERSION.$GO_OS-$GO_ARCH.tar.gz && \
    tar -C /usr/local -xzf go$GO_VERSION.$GO_OS-$GO_ARCH.tar.gz && \
    mkdir -p /data/go && \
    export GOPATH=/data/go

COPY entrypoint.sh /bin/

VOLUME [ "/data/go" ]

ENTRYPOINT [ "entrypoint.sh" ]
