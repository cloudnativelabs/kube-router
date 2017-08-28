#!/usr/bin/env sh
set -ex

[ -z "${E2E_SKIP}" ] && E2E_SKIP="Disruptive|Kubectl"
[ -z "${E2E_FOCUS}" ] && E2E_FOCUS="Conformance"
[ -z "${E2E_PROVIDER}" ] && E2E_PROVIDER="local"
[ -z "${LOG_DUMP_SSH_KEY}" ] && LOG_DUMP_SSH_KEY="/pwd/assets/auth/id_rsa"
[ -z "${LOG_DUMP_SSH_USER}" ] && LOG_DUMP_SSH_USER="core"
[ -z "${KUBECTL}" ] && KUBECTL="/usr/local/bin/kubectl"
[ -z "${TEST_NAME}" ] && TEST_NAME="e2e"

docker run \
    -v $PWD:/pwd \
    --workdir /pwd \
    --net=host \
    --rm \
    --env E2E_SKIP \
    --env E2E_FOCUS \
    --env E2E_PROVIDER \
    --env LOG_DUMP_SSH_USER \
    --env LOG_DUMP_SSH_KEY \
    quay.io/cloudnativelabs/kube-conformance:v1.7 \
        /usr/local/bin/e2e.test \
        --logtostderr \
        --repo-root="/kubernetes" \
        --ginkgo.skip="${E2E_SKIP}" \
        --ginkgo.focus="${E2E_FOCUS}" \
        --provider="${E2E_PROVIDER}" \
        --num-nodes=1 \
        --report-dir="/pwd/e2e-logs" \
        --ginkgo.noColor="true" \
        --output-print-type="hr" \
        --kubectl-path="/pwd/kubectl.sh" \
        --kubeconfig="/pwd/assets/auth/kubeconfig" \
        "${@}"

# "${KUBECTL}" create namespace "${TEST_NAME}"
# "${KUBECTL}" -n "${NAMESPACE}" create serviceaccount "${TEST_NAME}"
# "${KUBECTL}" -n 
#
# "${KUBECTL}" run e2e \
#     --image="quay.io/cloudnativelabs/kube-conformance:v1.7" \
#     --restart="Never" \
#     --labels="app=kube-test" \
#     --overrides='{ "apiVersion": "v1",
#                    "spec": {
#                      "} }'
#     --env="E2E_SKIP=${E2E_SKIP}" \
#     --env="E2E_FOCUS=${E2E_FOCUS}" \
#     --env="E2E_PROVIDER=${E2E_PROVIDER}" \
#     "${@}"
