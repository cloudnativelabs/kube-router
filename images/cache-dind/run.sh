#!/usr/bin/env sh
set -e

curl -LO https://rawgit.com/cloudnativelabs/kubeadm-dind-cluster/master/dind-cluster.sh
chmod +x dind-cluster.sh
curl -LO https://rawgit.com/cloudnativelabs/kubeadm-dind-cluster/master/config.sh

if [ -n "${CHOWN_UID}" ]; then
    chown -R "${CHOWN_UID}" "${PWD}"
fi
