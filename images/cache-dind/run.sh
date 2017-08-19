#!/usr/bin/env sh
set -e

curl -LO https://rawgit.com/cloudnativelabs/kubeadm-dind-cluster/kube-router/dind-cluster.sh
chmod +x dind-cluster.sh
curl -LO https://rawgit.com/cloudnativelabs/kubeadm-dind-cluster/kube-router/config.sh

if [ -n "${CHOWN_UID}" ]; then
    chown -R "${CHOWN_UID}" "${PWD}"
fi
