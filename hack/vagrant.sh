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

cd "${BK_SHORTCUT_DIR}"
vagrant "${@}"
