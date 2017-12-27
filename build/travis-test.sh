#!/usr/bin/env bash
set -o errexit
set -o pipefail

echo "Running tests on Travis"
make test
