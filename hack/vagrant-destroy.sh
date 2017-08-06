#!/usr/bin/env sh
# vim: noai:ts=2:sw=2:set expandtab
set -e

HACK_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
export HACK_DIR

# shellcheck source=vagrant-common.sh
. "${HACK_DIR}/vagrant-common.sh"

if [ ! -d "${BK_SHORTCUT_DIR}" ]; then
  echo "INFO: bootkube hack shortcut not found."
  exit 0
fi

echo "INFO: Running vagrant destroy -f"
cd "${BK_SHORTCUT_DIR}"
vagrant destroy -f

echo "INFO: Removing cluster assets."
rm -rf "${BK_SHORTCUT_DIR}/cluster"

echo "INFO: Removing symbolic link to Bootkube hack directory"
rm -rf "${BK_SHORTCUT_DIR}"
