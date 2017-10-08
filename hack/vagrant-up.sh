#!/usr/bin/env sh
# vim: noai:ts=2:sw=2:set expandtab
set -e

HACK_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
export HACK_DIR

# shellcheck source=vagrant-common.sh
. "${HACK_DIR}/vagrant-common.sh"

if [ -n "${1}" ]; then
  echo "### Usage ###"
  echo "# Single node cluster."
  echo "${0}"
  echo
  echo "# Multi node cluster."
  echo "HACK_MULTI_NODE=\"true\" ${0}"
  echo
  echo "# Use custom k8s manifests."
  echo "HACK_MANIFEST_DIRS=\"/path/to/yaml/files\" ${0}"
  echo
  echo "# HACK_MANIFEST_DIRS is one or more space separated directories and"
  echo "# should at least include kube-router.yaml and kube-router-cfg.yaml"
  echo "# or equivalent."
  echo
  exit 0
fi

# Get bootkube
if [ -d "${BK_CLONE_DIR}/.git" ]; then
  echo "INFO: Bootkube repo already cloned."
  echo "INFO: Checking out version ${BK_VERSION}."
  cd "${BK_CLONE_DIR}"
  git fetch
  git checkout "${BK_VERSION}"
else
  echo "INFO: Bootkube repo not found."
  echo "INFO: Cloning bootkube version ${BK_VERSION}."
  git clone --depth=1 --branch "${BK_VERSION}" "${BK_CLONE_URL}" "${BK_CLONE_DIR}"
fi

echo "INFO: Exporting your kube-router container image."
export_latest_image

echo "INFO: Caching hyperkube images to Bootkube local-images directory."
"${HACK_DIR}/sync-image-cache.sh"

# Copy custom manifests for Bootkube to use
echo "INFO: Using custom manifests from ${HACK_MANIFEST_DIRS}"
mkdir -p "${BK_CLONE_DIR}/hack/custom-manifests"
for i in ${HACK_MANIFEST_DIRS}
do
  cp -f "${i}"/*.yaml "${BK_CLONE_DIR}/hack/custom-manifests" \
    || echo "INFO: No custom .yaml files found."
  cp -f "${i}"/*.yml "${BK_CLONE_DIR}/hack/custom-manifests" \
    || echo "INFO: No custom .yml files found."

  if [ -f "${KR_MANIFEST_PATH}" ]; then
    echo "Modifying image attribute in ${KR_MANIFEST_PATH}"
    sed -i -e "s/image: cloudnativelabs\/kube-router/image: ${KR_IMAGE_TAG}/" \
      "${KR_MANIFEST_PATH}"
    sed -i -e "s/imagePullPolicy: Always/imagePullPolicy: IfNotPresent/" "${KR_MANIFEST_PATH}"
    echo "Verify modification:"
    grep -F "image: " "${KR_MANIFEST_PATH}"
    grep -F "imagePullPolicy: " "${KR_MANIFEST_PATH}"
  else
    echo "kube-router manifest not found at ${KR_MANIFEST_PATH}"
    echo "Couldn't modify."
  fi
done

# Build Bootkube
echo "INFO: Building Bootkube"
make -C "${BK_CLONE_DIR}"

# Start cluster
echo "INFO: Starting VM(s) and cluster"
cd "${BK_HACK_DIR}"
KUBE_ROUTER="true" ./bootkube-up

# Create symlink to bootkube hack dir
ln -sf "${BK_HACK_DIR}" "${BK_SHORTCUT_DIR}"

echo
echo "SUCCESS! The local cluster is ready."
echo
echo "### kubectl usage ###"
echo "# Quickstart - Use this kubeconfig for individual commands"
echo "KUBECONFIG=${BK_SHORTCUT_DIR}/cluster/auth/kubeconfig kubectl get pods --all-namespaces -o wide"
echo "#"
echo "## OR ##"
echo "#"
echo "# Use this kubeconfig for the current terminal session"
echo "KUBECONFIG=${BK_SHORTCUT_DIR}/cluster/auth/kubeconfig"
echo "export KUBECONFIG"
echo "kubectl get pods --all-namespaces -o wide"
echo "#"
echo "## OR ##"
echo "#"
echo "# Backup and replace your default kubeconfig"
echo "# Note: This will continue to work on recreated local clusters"
echo "mv ~/.kube/config ~/.kube/config-backup"
echo "ln -s ${BK_SHORTCUT_DIR}/cluster/auth/kubeconfig ~/.kube/config"
echo
echo "### SSH ###"
echo "# Get node names"
echo "make vagrant status"
echo "# SSH into a the controller node (c1)"
echo "make vagrant ssh c1"
echo
echo "Enjoy!"
