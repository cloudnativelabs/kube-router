#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

find_files() {
  find . -not \( \
      \( \
        -wholename '*/vendor/*' \
      \) -prune \
    \) -name '*.go'
}

GOFMT="gofmt -s"
bad_files=$(find_files | xargs $GOFMT -l)
if [[ -n "${bad_files}" ]]; then
  echo "gofmt wants to change the following files: "
  echo "${bad_files}"
  echo
  echo "Run \"make gofmt-fix\"."
  echo "or"
  echo "Run \"${GOFMT} -w\" on each file."
  exit 1
else
  echo 'Everything is gofmt approved!'
fi
