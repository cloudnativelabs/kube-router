#!/bin/bash

if [ -z $KOPS_CLUSTER_NAME ]; then
  echo "KOPS_CLUSTER_NAME is required for e2e tests"
fi

kops delete cluster --name $KOPS_CLUSTER_NAME --yes

