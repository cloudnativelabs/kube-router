#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

function destroy_cluster {
  $SCRIPT_DIR/scripts/destroy_cluster.sh
}

$SCRIPT_DIR/scripts/setup_cluster.sh
trap destroy_cluster EXIT

echo "==> running kube-router E2E tests..."
go test github.com/cloudnativelabs/kube-router/e2e/... 
