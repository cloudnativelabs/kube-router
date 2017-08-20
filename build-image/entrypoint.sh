#! /bin/bash

export GOPATH=/data/go
export PATH=$PATH:/usr/local/go/bin
cd /data/go/src/github.com/cloudnativelabs/kube-router
make "$@"
