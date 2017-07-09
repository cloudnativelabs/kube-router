#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

git describe --exact-match || echo -n

# if [ -z "${RELEASE_TAG}" ]; then
#     echo "Commit is not tagged. Release aborted."
#     exit 1
# else
#     echo "${RELEASE_TAG}"
# fi
