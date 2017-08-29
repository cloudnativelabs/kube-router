#!/usr/bin/env sh
set -ex

[ -z "${E2E_SKIP}" ] && E2E_SKIP="Disruptive|Kubectl"
[ -z "${E2E_FOCUS}" ] && E2E_FOCUS="Conformance"
[ -z "${E2E_PROVIDER}" ] && E2E_PROVIDER="local"
[ -z "${LOG_DUMP_SSH_KEY}" ] && LOG_DUMP_SSH_KEY="/pwd/assets/auth/id_rsa"
[ -z "${LOG_DUMP_SSH_USER}" ] && LOG_DUMP_SSH_USER="core"
[ -z "${KUBECONFIG}" ] && KUBECONFIG="$HOME/.kube/config"
[ -z "${KUBECTL}" ] && KUBECTL="/usr/local/bin/kubectl"
[ -z "${TEST_NAME}" ] && TEST_NAME="e2e"

if [ -n "${ADD_HOSTS}" ]; then
    for i in ${ADD_HOSTS}; do
        add_host_flag="${add_host_flag} --add-host=${i}"
    done
fi

docker run \
    -v "${PWD}":/pwd \
    -v "${KUBECONFIG}":/kubeconfig \
    --workdir /pwd \
    --net=host \
    --rm \
    --env E2E_SKIP \
    --env E2E_FOCUS \
    --env E2E_PROVIDER \
    --env LOG_DUMP_SSH_USER \
    --env LOG_DUMP_SSH_KEY \
    ${add_host_flag} \
    quay.io/cloudnativelabs/kube-conformance:v1.7 \
        /usr/local/bin/e2e.test \
        --logtostderr \
        --repo-root="/kubernetes" \
        --ginkgo.skip="${E2E_SKIP}" \
        --ginkgo.focus="${E2E_FOCUS}" \
        --provider="${E2E_PROVIDER}" \
        --num-nodes="${NODE_COUNT}" \
        --report-dir="/pwd/e2e-logs" \
        --ginkgo.noColor="true" \
        --output-print-type="hr" \
        --kubectl-path="${KUBECTL}" \
        --kubeconfig="/kubeconfig" \
        "${@}"
