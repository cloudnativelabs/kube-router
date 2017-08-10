#!/usr/bin/env sh
# vim: noai:ts=2:sw=2:set expandtab
set -e

HACK_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
export HACK_DIR

# shellcheck source=vagrant-common.sh
. "${HACK_DIR}/vagrant-common.sh"

if [ ! -d "${BK_SHORTCUT_DIR}" ]; then
  echo "INFO: bootkube hack shortcut is not initialized."
  echo "INFO: \"vagrant up\" has not been run yet."
  exit 0
fi

echo "INFO: Exporting your kube-router container image."
export_latest_image

cd "${BK_SHORTCUT_DIR}"

if [ "$(basename "$(readlink "${PWD}")")" = "single-node" ]; then
    NODES="default"
else # multi-node
    NODES="c1 w1"
fi

for i in ${NODES}; do
  echo "INFO: Importing your kube-router container image in VM \"${i}\""
  update_image_in_vm "${i}"
done

echo "INFO: Restarting all kube-router pods"
kubectl --kubeconfig="${BK_SHORTCUT_DIR}/cluster/auth/kubeconfig" \
  --namespace=kube-system delete pod -l k8s-app=kube-router
