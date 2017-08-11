#!/usr/bin/env sh
# vim: noai:ts=2:sw=2:set expandtab
set -e

HACK_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
export HACK_DIR

# shellcheck source=vagrant-common.sh
. "${HACK_DIR}/vagrant-common.sh"

if [ ! -d "${BK_CLONE_DIR}" ]; then
  echo "INFO: Bootkube repo not found. Nothing to destroy."
  exit 0
fi

for i in "${BK_CLONE_DIR}/hack/single-node" "${BK_CLONE_DIR}/hack/multi-node"; do
  echo "INFO: Running vagrant destroy -f in ${i}"
  cd "${i}"
  vagrant destroy -f

  echo "INFO: Removing cluster assets in ${i}"
  rm -rf "${i}/cluster"
done

echo "INFO: Removing symbolic link to Bootkube hack directory"
rm -rf "${BK_SHORTCUT_DIR}"
