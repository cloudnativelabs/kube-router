#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $SCRIPT_DIR/utils.sh

if [[ -z $KOPS_CLUSTER_NAME ]]; then
  echo "KOPS_CLUSTER_NAME is required for e2e tests"
  exit 1
fi

if [[ -z $KUBE_ROUTER_DOCKER_IMAGE ]]; then
  echo "KUBE_ROUTER_DOCKER_IMAGE is required for e2e tests"
  exit 1
fi

SSH_PUBLIC_KEYFILE="${SSH_PUBLIC_KEYFILE:-~/.ssh/id_rsa.pub}"
KOPS_REGION="${KOPS_REGION:-tor1}"

install_kubectl
get_kops
create_template $version

cd $GOPATH/src/k8s.io/kops
make clean && make kops && cp $GOPATH/src/k8s.io/kops/.build/local/kops $GOPATH/bin/

export PATH=$PATH:$GOPATH/bin/

kops create cluster --cloud=digitalocean \
  --name=$KOPS_CLUSTER_NAME \
  --zones=$KOPS_REGION \
  --ssh-public-key=$SSH_PUBLIC_KEYFILE \
  --networking=kube-router \
  --yes

echo "==> waiting until kubernetes cluster is ready..."

n=0
until [ $n -ge 300 ]
do
  if [[ $(kubectl -n kube-system get po | grep kube-router | grep Running | wc -l) -eq 3 ]]; then
    echo "==> kubernetes cluster is ready"
    exit 0
  fi

  n=$[$n+1]
  sleep 5
done

echo "==> timed out waiting for kubernetes cluster to be ready"
exit 1
