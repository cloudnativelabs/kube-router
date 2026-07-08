#!/usr/bin/env bash
# hack/e2e-netpol.sh – Drive the kube-router NetworkPolicy e2e test suite.
#
# Subcommands (pass exactly one as the first argument, or "all" for a full local run):
#   build-image      Build the kube-router container image via Docker Buildx.
#   create-cluster   Create a dual-stack Kind cluster with default CNI disabled.
#   load-image       Load the container image into the Kind cluster.
#   deploy           Apply a mutated kube-router DaemonSet manifest to the cluster.
#   wait             Wait for the kube-router DaemonSet to roll out.
#   dump-initial     Print initial cluster state (nodes / pods / daemonset / logs).
#   run-tests        Execute the NetworkPolicy e2e test suite.
#   dump-debug       Collect debug info (logs, events, nft ruleset). Intended for
#                    use on failure.
#   delete-cluster   Delete the Kind cluster.
#   all              Run the full sequence locally with cleanup on exit and debug
#                    dump on error.
#
# Environment variables (all optional):
#   BACKEND            iptables | nftables   (default: iptables)
#   DEFAULT_DENY       true | false          (default: false)
#   KUBE_ROUTER_IMAGE  image:tag             (default: kube-router:e2e-test)
#   KIND_CLUSTER_NAME  name                  (default: e2e)
#   KIND_NODE_IMAGE    kindest/node:vX.Y.Z   (default: kindest/node:v1.32.2)
#   BUILDTIME_BASE     docker image ref      (default: golang:alpine)
#   RUNTIME_BASE       docker image ref      (default: alpine:3)
#   SKIP_CLEANUP       1                     Skip cluster deletion on exit ("all" mode only)

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (env with defaults)
# ---------------------------------------------------------------------------
BACKEND="${BACKEND:-iptables}"
DEFAULT_DENY="${DEFAULT_DENY:-false}"
KUBE_ROUTER_IMAGE="${KUBE_ROUTER_IMAGE:-kube-router:e2e-test}"
KIND_VERSION="${KIND_VERSION:-v0.27.0}"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-e2e}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.32.2}"
BUILDTIME_BASE="${BUILDTIME_BASE:-golang:alpine}"
RUNTIME_BASE="${RUNTIME_BASE:-alpine:3}"
SKIP_CLEANUP="${SKIP_CLEANUP:-0}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo "=== [e2e-netpol] $* ==="; }

# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------
cmd_build_image() {
    log "Building kube-router image: ${KUBE_ROUTER_IMAGE}"
    docker buildx build \
        --load \
        --build-arg "BUILDTIME_BASE=${BUILDTIME_BASE}" \
        --build-arg "RUNTIME_BASE=${RUNTIME_BASE}" \
        -t "${KUBE_ROUTER_IMAGE}" \
        .
}

cmd_install_kind() {
    log "Installing Kind"
    curl -sSLo ./kind https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64
    chmod +x ./kind
    sudo mv ./kind /usr/local/bin/kind
}

cmd_create_cluster() {
    log "Creating Kind cluster '${KIND_CLUSTER_NAME}' (dual-stack, no default CNI)"
    kind create cluster \
        --image "${KIND_NODE_IMAGE}" \
        --name "${KIND_CLUSTER_NAME}" \
        --config - <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  ipFamily: dual
nodes:
  - role: control-plane
  - role: worker
EOF
}

cmd_load_image() {
    log "Loading image '${KUBE_ROUTER_IMAGE}' into Kind cluster '${KIND_CLUSTER_NAME}'"
    kind load docker-image "${KUBE_ROUTER_IMAGE}" --name "${KIND_CLUSTER_NAME}"
}

cmd_deploy() {
    log "Deploying kube-router (backend=${BACKEND}, default-deny=${DEFAULT_DENY})"
    MANIFEST=$(
        sed 's|[^ ]*cloudnativelabs/kube-router[^ ]*|'"${KUBE_ROUTER_IMAGE}"'|g' \
            daemonset/generic-kuberouter.yaml \
        | sed 's|imagePullPolicy: Always|imagePullPolicy: Never|g'
    )
    if [[ "${BACKEND}" == "nftables" ]]; then
        MANIFEST=$(echo "${MANIFEST}" \
            | sed 's|"--bgp-graceful-restart=true"|"--bgp-graceful-restart=true"\n        - "--use-nftables-for-netpol=true"|')
    fi
    if [[ "${DEFAULT_DENY}" == "true" ]]; then
        MANIFEST=$(echo "${MANIFEST}" \
            | sed 's|"--bgp-graceful-restart=true"|"--bgp-graceful-restart=true"\n        - "--netpol-default-deny=true"|')
    fi
    echo "=== Final kube-router DaemonSet manifest ==="
    echo "${MANIFEST}"
    echo "${MANIFEST}" | kubectl apply -f -
}

cmd_wait() {
    log "Waiting for kube-router DaemonSet to become ready"
    kubectl rollout status daemonset/kube-router -n kube-system --timeout=120s
}

cmd_dump_initial() {
    log "Initial cluster state"
    echo "=== Nodes ==="
    kubectl get nodes -o wide
    echo ""
    echo "=== Pods (all namespaces) ==="
    kubectl get pods -A -o wide
    echo ""
    echo "=== kube-router DaemonSet ==="
    kubectl -n kube-system describe daemonset/kube-router
    echo ""
    echo "=== kube-router initial logs ==="
    kubectl -n kube-system logs -l k8s-app=kube-router --tail=100
}

cmd_run_tests() {
    log "Running NetworkPolicy e2e tests"
    E2E=1 go test -v ./test/e2e/netpol/... -timeout 600s
}

cmd_dump_debug() {
    log "Collecting debug info"
    echo "=== Nodes ==="
    kubectl get nodes -o wide || true
    echo ""
    echo "=== Node descriptions ==="
    kubectl describe nodes || true
    echo ""
    echo "=== All pods ==="
    kubectl get pods -A -o wide || true
    echo ""
    echo "=== Events (all namespaces, sorted by time) ==="
    kubectl get events -A --sort-by='.lastTimestamp' || true
    echo ""
    echo "=== kube-router DaemonSet description ==="
    kubectl -n kube-system describe daemonset/kube-router || true
    echo ""
    echo "=== kube-router pod descriptions ==="
    kubectl -n kube-system describe pods -l k8s-app=kube-router || true
    echo ""
    echo "=== kube-router full logs ==="
    kubectl -n kube-system logs -l k8s-app=kube-router --tail=500 || true
    echo ""
    echo "=== nftables ruleset (per kube-router pod) ==="
    for pod in $(kubectl -n kube-system get pods -l k8s-app=kube-router \
            -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        echo "--- ${pod} ---"
        kubectl -n kube-system exec "${pod}" -- nft list ruleset 2>&1 || true
        echo ""
    done
}

cmd_delete_cluster() {
    log "Deleting Kind cluster '${KIND_CLUSTER_NAME}'"
    kind delete cluster --name "${KIND_CLUSTER_NAME}"
}

cmd_all() {
    _debug_dumped=0

    _on_error() {
        if [[ "${_debug_dumped}" -eq 0 ]]; then
            _debug_dumped=1
            cmd_dump_debug || true
        fi
    }

    _on_exit() {
        if [[ "${SKIP_CLEANUP}" != "1" ]]; then
            cmd_delete_cluster || true
        else
            log "SKIP_CLEANUP=1: leaving cluster '${KIND_CLUSTER_NAME}' intact"
        fi
    }

    trap _on_error ERR
    trap _on_exit EXIT

    cmd_build_image
    cmd_install_kind
    cmd_create_cluster
    cmd_load_image
    cmd_deploy
    cmd_wait
    cmd_dump_initial
    cmd_run_tests
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
SUBCOMMAND="${1:-all}"

case "${SUBCOMMAND}" in
    build-image)    cmd_build_image ;;
    install-kind)   cmd_install_kind ;;
    create-cluster) cmd_create_cluster ;;
    load-image)     cmd_load_image ;;
    deploy)         cmd_deploy ;;
    wait)           cmd_wait ;;
    dump-initial)   cmd_dump_initial ;;
    run-tests)      cmd_run_tests ;;
    dump-debug)     cmd_dump_debug ;;
    delete-cluster) cmd_delete_cluster ;;
    all)            cmd_all ;;
    *)
        echo "Unknown subcommand: ${SUBCOMMAND}" >&2
        echo "Usage: $0 {build-image|create-cluster|load-image|deploy|wait|dump-initial|run-tests|dump-debug|delete-cluster|all}" >&2
        exit 1
        ;;
esac
