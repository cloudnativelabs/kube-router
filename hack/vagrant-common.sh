#!/usr/bin/env sh
# vim: noai:ts=2:sw=2:set expandtab
set -e

if [ -z "${HACK_DIR}" ]; then
  echo "ERROR: HACK_DIR must be specified."
  echo
  echo "## Example"
  echo "HACK_DIR=\"\$\(CDPATH=i\'\' cd -- \"\$\(dirname -- \"\$0\"\)\" \&\& pwd -P\)\""
  echo "export HACK_DIR"
  echo ". ${0}"
  echo
  exit 1
fi

REPO_DIR="$(dirname "${HACK_DIR}")"
HACK_TMP_DIR="${HACK_DIR}/_cache"
HACK_MANIFEST_DIRS="${REPO_DIR}/contrib/bootkube"
export HACK_MANIFEST_DIRS

[ -z "${DEV_IMG}" ]      && DEV_IMG="cloudnativelabs/kube-router-git:latest"
[ -z "${BK_VERSION}" ]   && BK_VERSION="v0.6.0_kube-router"
[ -z "${BK_CLONE_URL}" ] && BK_CLONE_URL="https://github.com/bzub/bootkube.git"
[ -z "${BK_CLONE_DIR}" ] && BK_CLONE_DIR="${HACK_TMP_DIR}/bootkube"

if [ -z "${HACK_MULTI_NODE}" ]; then
  BK_HACK_DIR="${BK_CLONE_DIR}/hack/single-node"
else
  BK_HACK_DIR="${BK_CLONE_DIR}/hack/multi-node"
fi
export BK_HACK_DIR

BK_SHORTCUT_DIR="/tmp/kr-vagrant-shortcut"
export BK_SHORTCUT_DIR

[ -z "${KR_IMAGE_TAG}" ] && KR_IMAGE_TAG="test.kube-router.io"
[ -z "${KR_MANIFEST}" ]  && KR_MANIFEST="kube-router.yaml"
[ -z "${docker}" ] && docker="sudo docker"
KR_MANIFEST_PATH="${BK_CLONE_DIR}/hack/custom-manifests/${KR_MANIFEST}"
export KR_MANIFEST_PATH

# TODO: Dynamically determine this from Bootkube version/source
[ -z "${HYPERKUBE_IMG}" ]     && HYPERKUBE_IMG="quay.io/coreos/hyperkube"
[ -z "${HYPERKUBE_IMG_TAG}" ] && HYPERKUBE_IMG_TAG="v1.7.1_coreos.0"
HYPERKUBE_IMG_URL="${HYPERKUBE_IMG}:${HYPERKUBE_IMG_TAG}"
export HYPERKUBE_IMG_URL
HACK_IMG_CACHE_DIR="${BK_CLONE_DIR}/hack/local-images"
export HACK_IMG_CACHE_DIR
HACK_ACI_CACHE_FILE="${HACK_IMG_CACHE_DIR}/hyperkube-${HYPERKUBE_IMG_TAG}.aci"
export HACK_ACI_CACHE_FILE
HACK_DOCKER_CACHE_FILE="${HACK_IMG_CACHE_DIR}/hyperkube-${HYPERKUBE_IMG_TAG}.docker"
export HACK_DOCKER_CACHE_FILE

# Export the kube-router container image
export_latest_image() {
  mkdir -p "${HACK_IMG_CACHE_DIR}"
  eval "${docker}" tag ${DEV_IMG} "${KR_IMAGE_TAG}"
  eval "${docker}" save "${KR_IMAGE_TAG}" -o "${HACK_IMG_CACHE_DIR}/kube-router.docker"
}

# Re-pull the kube-router container image file within the VM
# Usage: update_image_in_vm() VM_NAME
update_image_in_vm() {
  if [ -z "${1}" ]; then
    echo "ERROR: VM name required."
    echo "Usage: update_image_in_vm() VM_NAME"
    return 1
  fi

  vagrant rsync "${i}"
  vagrant ssh "${i}" -c "docker load -i /var/tmp/images/kube-router.docker"
}
