#!/usr/bin/env sh
# vim: noai:ts=2:sw=2:set expandtab
set -e

HACK_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
export HACK_DIR

# shellcheck source=vagrant-common.sh
. "${HACK_DIR}/vagrant-common.sh"

command -v rkt >/dev/null 2>&1    && RKT_INSTALLED=1
command -v docker >/dev/null 2>&1 && DOCKER_INSTALLED=1

if [ -z "${RKT_INSTALLED}" ]; then
  echo "WARN: rkt not found. Skipping rkt ACI image caching."
else
  if [ -f "${HACK_ACI_CACHE_FILE}" ]; then
    echo "INFO: Cached hyperkube ACI already exists."
    echo "INFO: Location: ${HACK_ACI_CACHE_FILE}"
  else
    echo "INFO: Fetching ${HYPERKUBE_IMG_URL} ACI."
    sudo rkt --trust-keys-from-https fetch "${HYPERKUBE_IMG_URL}"

    HYPERKUBE_ACI_ID="$(sudo rkt image list | grep -F "${HYPERKUBE_IMG_URL}" | awk '{print $1}')"

    echo "INFO: Saving ${HYPERKUBE_IMG_URL} ACI to cache directory."
    sudo rkt image export "${HYPERKUBE_ACI_ID}" "${HACK_ACI_CACHE_FILE}"
  fi
fi

if [ -z "${DOCKER_INSTALLED}" ]; then
  echo "WARN: docker not found. Skipping docker image caching."
else
  if [ -f "${HACK_DOCKER_CACHE_FILE}" ]; then
    echo "INFO: Cached hyperkube Docker image already exists."
    echo "INFO: Location: ${HACK_DOCKER_CACHE_FILE}"
  else
    echo "INFO: Fetching ${HYPERKUBE_IMG_URL} Docker image."
    eval "${docker}" pull "${HYPERKUBE_IMG_URL}"

    echo "INFO: Saving ${HYPERKUBE_IMG_URL} Docker image to cache directory."
    eval "${docker}" save "${HYPERKUBE_IMG_URL}" -o "${HACK_DOCKER_CACHE_FILE}"
  fi
fi
