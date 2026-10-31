#!/usr/bin/env bash
# hack/e2e-netpol.sh – Drive the kube-router NetworkPolicy e2e test suite.
#
# Subcommands (pass exactly one as the first argument, or "all" for a full local run):
#   build-image      Build the kube-router container image via Docker Buildx.
#   create-cluster   Create a dual-stack Kind cluster (control plane plus two
#                    workers) with default CNI disabled.
#   load-image       Load the kube-router image and the test pod image into the
#                    Kind cluster.
#   deploy           Apply a mutated kube-router DaemonSet manifest to the cluster.
#   wait             Wait for the kube-router DaemonSet to roll out.
#   dump-initial     Print initial cluster state (nodes / pods / daemonset / logs).
#   run-tests        Execute the NetworkPolicy e2e test suite.
#   refresh          Rebuild the image, reload it into the cluster, and restart
#                    the kube-router DaemonSet. For iterating on code changes.
#   dump-debug       Collect debug info (logs, events, nft ruleset). Intended for
#                    use on failure.
#   delete-cluster   Delete the Kind cluster.
#   suite            Run create-cluster through run-tests against an image that's
#                    already built, with debug dump on error and cleanup on exit.
#   all              Build the image, then run "suite". The full sequence locally.
#   matrix           Build the image once, then run "suite" for every BACKEND and
#                    DEFAULT_DENY combination, same as the CI matrix, as many at
#                    once as the machine has room for. Each suite gets its own
#                    cluster, and its log lands in _output/e2e-matrix/.
#                    SKIP_CLEANUP is ignored.
#
# Environment variables (all optional):
#   BACKEND            iptables | nftables   (default: iptables)
#   DEFAULT_DENY       true | false          (default: false)
#   E2E_LONG           1                     Run the slow lifecycle specs
#                                            (controller restart, chain GC).
#                                            Left unset on PRs; CI sets it on
#                                            push/tag/dispatch. (default: unset)
#   E2E_PROCS          N                     Ginkgo parallel processes (default: 4,
#                                            matching free GitHub runners' 4 vCPU;
#                                            set 1 to run fully serial)
#   E2E_FOCUS          regex                 Only run specs matching the regex
#                                            (ginkgo --focus)
#   E2E_SKIP           regex                 Skip specs matching the regex
#                                            (ginkgo --skip)
#   KUBE_ROUTER_IMAGE  image:tag             (default: kube-router:e2e-test)
#   KIND_VERSION       vX.Y.Z                (default: from ci-e2e-netpol.yml)
#   KIND_CLUSTER_NAME  name                  (default: e2e)
#   KIND_NODE_IMAGE    kindest/node:vX.Y.Z   (default: from ci-e2e-netpol.yml)
#   BUILDTIME_BASE     docker image ref      (default: golang:alpine)
#   RUNTIME_BASE       docker image ref      (default: alpine:3)
#   SKIP_CLEANUP       1                     Skip cluster deletion on exit ("all" and "suite" only)
#   E2E_PARALLEL       N                     How many suites "matrix" runs at once
#                                            (default: what the machine has room for)
#
# Iterating on a failing spec (human or AI agent) without rerunning "all":
#
#   SKIP_CLEANUP=1 BACKEND=nftables DEFAULT_DENY=true make e2e-netpol   # once, keeps cluster
#   # ...edit code or tests, then:
#   hack/e2e-netpol.sh refresh                                          # only if kube-router code changed
#   E2E_LONG=1 BACKEND=nftables E2E_FOCUS='chain GC' hack/e2e-netpol.sh run-tests
#   hack/e2e-netpol.sh delete-cluster                                   # when done
#
# Nothing in the loop needs sudo as long as your user can talk to the docker
# daemon, since the script downloads its own copy of kind into _output/.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CI_WORKFLOW="${REPO_ROOT}/.github/workflows/ci-e2e-netpol.yml"

# ci_env_default prints a key from the top-level env block of the e2e workflow. We declare kind's version and node
# image there and nowhere else, so that local runs use the same pair as CI.
ci_env_default() {
    awk -v key="$1:" '
        $0 == "env:" { in_env = 1; next }
        in_env && /^[^[:space:]]/ { exit }
        in_env && $1 == key { gsub(/"/, "", $2); print $2; exit }
    ' "${CI_WORKFLOW}"
}

# ---------------------------------------------------------------------------
# Configuration (env with defaults)
# ---------------------------------------------------------------------------
BACKEND="${BACKEND:-iptables}"
DEFAULT_DENY="${DEFAULT_DENY:-false}"
E2E_LONG="${E2E_LONG:-}"
E2E_PROCS="${E2E_PROCS:-4}"
E2E_FOCUS="${E2E_FOCUS:-}"
E2E_SKIP="${E2E_SKIP:-}"
KUBE_ROUTER_IMAGE="${KUBE_ROUTER_IMAGE:-kube-router:e2e-test}"
# The image the suite runs its test pods from, declared once in framework_test.go
TEST_IMAGE="$(sed -n 's/^[[:space:]]*testImage[[:space:]]*=[[:space:]]*"\(.*\)"$/\1/p' \
    "${REPO_ROOT}/test/e2e/netpol/framework_test.go")"
KIND_VERSION="${KIND_VERSION:-$(ci_env_default KIND_VERSION)}"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-e2e}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-$(ci_env_default KIND_NODE_IMAGE)}"
BUILDTIME_BASE="${BUILDTIME_BASE:-golang:alpine}"
RUNTIME_BASE="${RUNTIME_BASE:-alpine:3}"
SKIP_CLEANUP="${SKIP_CLEANUP:-0}"
: "${KIND_VERSION:?is unset and not declared in ${CI_WORKFLOW}}"
: "${KIND_NODE_IMAGE:?is unset and not declared in ${CI_WORKFLOW}}"
: "${TEST_IMAGE:?could not be read from test/e2e/netpol/framework_test.go}"
# We always run this copy rather than whatever kind is on PATH (GitHub's runners ship their own), so that the version
# we declare is the version we use
KIND="${REPO_ROOT}/_output/kind/${KIND_VERSION}/kind"
# Where matrix keeps each suite's log, exit status, and kubeconfig
MATRIX_DIR="${REPO_ROOT}/_output/e2e-matrix"
# What one suite needs, so that matrix knows how many it can run at once. A suite (three kind nodes plus ginkgo)
# measured about 1.25 cores on average, 2.6 at p90, 1.4GiB at peak, and 90 inotify instances at peak, so these leave
# some headroom. The inotify instances all count against root's fs.inotify.max_user_instances, which is often just
# 128, and an idle desktop's root processes already held about 35 of those.
SUITE_CPUS=2
SUITE_MEM_MIB=2048
SUITE_INOTIFY=100
HOST_INOTIFY_RESERVE=48

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo "=== [e2e-netpol] $* ==="; }

# ensure_kind downloads KIND_VERSION into place if it isn't there yet, checking it against the release's checksum
ensure_kind() {
    if [[ ! -x "${KIND}" ]]; then
        local os arch
        os="$(uname -s | tr '[:upper:]' '[:lower:]')"
        case "$(uname -m)" in
            x86_64 | amd64) arch=amd64 ;;
            aarch64 | arm64) arch=arm64 ;;
            *) echo "No kind release for architecture $(uname -m)" >&2; return 1 ;;
        esac
        local url="https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-${os}-${arch}"
        log "Installing kind ${KIND_VERSION} into ${KIND#"${REPO_ROOT}/"}"
        mkdir -p "$(dirname "${KIND}")"
        # -f so that a bad version fails here, rather than saving the 404 page as the binary
        curl -fsSLo "${KIND}.download" "${url}"
        local want got
        want="$(curl -fsSL "${url}.sha256sum" | awk '{print $1}')"
        got="$(sha256sum "${KIND}.download" | awk '{print $1}')"
        if [[ -z "${want}" || "${want}" != "${got}" ]]; then
            echo "Checksum mismatch for ${url}: want '${want}', got '${got}'" >&2
            return 1
        fi
        chmod +x "${KIND}.download"
        mv "${KIND}.download" "${KIND}"
    fi
    if [[ "$("${KIND}" version)" != "kind ${KIND_VERSION} "* ]]; then
        echo "${KIND} reports '$("${KIND}" version)', expected kind ${KIND_VERSION}" >&2
        return 1
    fi
}

# run_kind runs our pinned copy of kind, installing it first if this is the first time we need it
run_kind() {
    ensure_kind
    "${KIND}" "$@"
}

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
    ensure_kind
    log "Using $("${KIND}" version) from ${KIND#"${REPO_ROOT}/"} with node image ${KIND_NODE_IMAGE}"
}

cmd_create_cluster() {
    log "Creating Kind cluster '${KIND_CLUSTER_NAME}' (dual-stack, no default CNI, two workers)"
    run_kind create cluster \
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
  # kind keeps the control plane tainted, so we need two workers for the suite to put servers and clients on
  # different nodes and exercise cross-node traffic
  - role: worker
  - role: worker
EOF
}

# ensure_test_image pulls the test pod image into the local docker cache, once per machine
ensure_test_image() {
    if ! docker image inspect "${TEST_IMAGE}" > /dev/null 2>&1; then
        log "Pulling test image '${TEST_IMAGE}'"
        docker pull "${TEST_IMAGE}"
    fi
}

cmd_load_image() {
    # Loading the test image from the host's cache keeps every node from pulling it from the registry in the middle
    # of the suite, which once hung for minutes and timed out every spec that was waiting on a pod
    ensure_test_image
    log "Loading images '${KUBE_ROUTER_IMAGE}' and '${TEST_IMAGE}' into Kind cluster '${KIND_CLUSTER_NAME}'"
    run_kind load docker-image "${KUBE_ROUTER_IMAGE}" "${TEST_IMAGE}" --name "${KIND_CLUSTER_NAME}"
}

cmd_deploy() {
    log "Deploying kube-router (backend=${BACKEND}, default-deny=${DEFAULT_DENY})"
    MANIFEST=$(
        sed 's|[^ ]*cloudnativelabs/kube-router[^ ]*|'"${KUBE_ROUTER_IMAGE}"'|g' \
            daemonset/generic-kuberouter.yaml \
        | sed 's|imagePullPolicy: Always|imagePullPolicy: Never|g'
    )
    # The Kind cluster is always created dual-stack (see cmd_create_cluster), so we enable IPv6 in
    # kube-router to match. Without this the netpol controller runs IPv4-only and silently ignores
    # IPv6 ipBlock peers, which breaks the dual-stack / IPv6 specs.
    MANIFEST=$(echo "${MANIFEST}" \
        | sed 's|"--run-router=true"|"--run-router=true"\n        - "--enable-ipv6=true"|')
    # The manifest inherits the 1s default probe timeout, which got kube-router liveness-killed
    # mid-suite on a loaded machine at least once, so we relax it for e2e only
    MANIFEST=$(echo "${MANIFEST}" \
        | sed 's|periodSeconds: 3|periodSeconds: 3\n          timeoutSeconds: 5|')
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
    log "Running NetworkPolicy e2e tests (E2E_LONG='${E2E_LONG}', BACKEND='${BACKEND}'," \
        "procs=${E2E_PROCS}, focus='${E2E_FOCUS}', skip='${E2E_SKIP}')"
    # The slow lifecycle specs (restart, GC) can each take minutes, so give the
    # suite a longer timeout when E2E_LONG is set.
    local timeout="600s"
    if [[ -n "${E2E_LONG}" ]]; then
        timeout="1800s"
    fi

    # We run through the ginkgo CLI rather than `go test` because parallelism
    # (--procs) and focus/skip filtering are only available there
    local ginkgo_args=(-r --procs="${E2E_PROCS}" --timeout="${timeout}" -v)
    if [[ -n "${E2E_FOCUS}" ]]; then
        ginkgo_args+=(--focus="${E2E_FOCUS}")
    fi
    if [[ -n "${E2E_SKIP}" ]]; then
        ginkgo_args+=(--skip="${E2E_SKIP}")
    fi
    E2E=1 E2E_LONG="${E2E_LONG}" BACKEND="${BACKEND}" \
        go run github.com/onsi/ginkgo/v2/ginkgo "${ginkgo_args[@]}" ./test/e2e/netpol
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

# refresh rebuilds the image, reloads it into the running cluster, and rolls the
# DaemonSet so code changes take effect without recreating the cluster
cmd_refresh() {
    cmd_build_image
    cmd_load_image
    log "Restarting kube-router DaemonSet to pick up the new image"
    kubectl -n kube-system rollout restart daemonset/kube-router
    cmd_wait
}

cmd_delete_cluster() {
    log "Deleting Kind cluster '${KIND_CLUSTER_NAME}'"
    run_kind delete cluster --name "${KIND_CLUSTER_NAME}"
}

cmd_suite() {
    _on_exit() {
        local rc=$?
        # The functions we call don't inherit an ERR trap without errtrace, so we key the dump off the exit status
        if [[ "${rc}" -ne 0 ]]; then
            cmd_dump_debug || true
        fi
        if [[ "${SKIP_CLEANUP}" != "1" ]]; then
            cmd_delete_cluster || true
        else
            log "SKIP_CLEANUP=1: leaving cluster '${KIND_CLUSTER_NAME}' intact"
        fi
    }
    trap _on_exit EXIT

    cmd_create_cluster
    cmd_load_image
    cmd_deploy
    cmd_wait
    cmd_dump_initial
    cmd_run_tests
}

cmd_all() {
    cmd_build_image
    cmd_install_kind
    cmd_suite
}

# matrix_parallelism prints how many suites the machine can run at once, from the CPUs and memory docker can use
matrix_parallelism() {
    if [[ -n "${E2E_PARALLEL:-}" ]]; then
        echo "${E2E_PARALLEL}"
        return
    fi
    local cpus mem_bytes avail_kib
    read -r cpus mem_bytes < <(docker info --format '{{.NCPU}} {{.MemTotal}}')
    local mem_mib=$((mem_bytes / 1048576))
    # On Linux, MemAvailable leaves out whatever else the machine is already running
    if [[ -r /proc/meminfo ]]; then
        avail_kib="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
        if ((avail_kib / 1024 < mem_mib)); then
            mem_mib=$((avail_kib / 1024))
        fi
    fi
    local by_cpu=$((cpus / SUITE_CPUS)) by_mem=$((mem_mib / SUITE_MEM_MIB)) by_inotify=4 max_instances=""
    # Only readable when docker runs on this kernel, which is also the only case where the limit is ours to read
    if [[ -r /proc/sys/fs/inotify/max_user_instances ]]; then
        max_instances="$(cat /proc/sys/fs/inotify/max_user_instances)"
        by_inotify=$(((max_instances - HOST_INOTIFY_RESERVE) / SUITE_INOTIFY))
    fi
    log "Room for ${by_cpu} suites by CPU (${cpus}), ${by_mem} by memory ($((mem_mib / 1024))GiB available)," \
        "and ${by_inotify} by fs.inotify.max_user_instances (${max_instances:-unknown})" >&2
    if ((by_inotify < 2 && by_cpu >= 2 && by_mem >= 2)); then
        log "Raising fs.inotify.max_user_instances would let more suites run at once, as kind recommends:" \
            "sudo sysctl fs.inotify.max_user_instances=512" >&2
    fi
    local n=4
    ((by_cpu < n)) && n=${by_cpu}
    ((by_mem < n)) && n=${by_mem}
    ((by_inotify < n)) && n=${by_inotify}
    ((n < 1)) && n=1
    echo "${n}"
}

cmd_matrix() {
    cmd_build_image
    cmd_install_kind
    ensure_test_image
    # Every suite compiles ginkgo and the test binary, so we fill the build cache once rather than four times at once
    go build -o /dev/null github.com/onsi/ginkgo/v2/ginkgo
    go test -c -o /dev/null ./test/e2e/netpol

    local parallel
    parallel="$(matrix_parallelism)"
    log "Running the 4 matrix suites ${parallel} at a time (set E2E_PARALLEL to override)"
    rm -rf "${MATRIX_DIR}"
    mkdir -p "${MATRIX_DIR}"
    # Each suite runs in its own process so that its errexit and traps behave, and one failure doesn't stop the rest
    printf '%s\n' iptables:false iptables:true nftables:false nftables:true \
        | xargs -n 1 -P "${parallel}" "${BASH_SOURCE[0]}" matrix-suite || true

    local failed=() name
    for name in e2e-iptables e2e-iptables-dd e2e-nftables e2e-nftables-dd; do
        if [[ "$(cat "${MATRIX_DIR}/${name}.rc" 2>/dev/null)" != "0" ]]; then
            failed+=("${name}")
            echo "--- ${name} (${MATRIX_DIR#"${REPO_ROOT}/"}/${name}.log) ---"
            # The ginkgo summary if the specs ran, otherwise whatever failed while standing the cluster up
            grep -A 20 'Summarizing [0-9]* Failure' "${MATRIX_DIR}/${name}.log" \
                || grep -m 5 -E '^(ERROR|error):' "${MATRIX_DIR}/${name}.log" \
                || tail -n 20 "${MATRIX_DIR}/${name}.log"
        fi
    done
    if [[ ${#failed[@]} -gt 0 ]]; then
        log "Failed matrix suites: ${failed[*]}"
        return 1
    fi
    log "All matrix suites passed"
}

# cmd_matrix_suite runs one matrix suite on its own cluster and kubeconfig, given "<backend>:<default-deny>"
cmd_matrix_suite() {
    local backend="${1%%:*}" default_deny="${1#*:}"
    local name="e2e-${backend}"
    [[ "${default_deny}" == "true" ]] && name+="-dd"
    log "Starting ${name} (backend=${backend}, default-deny=${default_deny})"

    local start=${SECONDS} rc=0
    BACKEND="${backend}" DEFAULT_DENY="${default_deny}" SKIP_CLEANUP=0 KIND_CLUSTER_NAME="${name}" \
        KUBECONFIG="${MATRIX_DIR}/${name}.kubeconfig" "${BASH_SOURCE[0]}" suite > "${MATRIX_DIR}/${name}.log" 2>&1 \
        || rc=$?
    echo "${rc}" > "${MATRIX_DIR}/${name}.rc"
    local result="Passed"
    ((rc == 0)) || result="FAILED"
    log "${result} ${name} in $(((SECONDS - start) / 60))m$(((SECONDS - start) % 60))s"
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
    refresh)        cmd_refresh ;;
    dump-debug)     cmd_dump_debug ;;
    delete-cluster) cmd_delete_cluster ;;
    suite)          cmd_suite ;;
    all)            cmd_all ;;
    matrix)         cmd_matrix ;;
    matrix-suite)   cmd_matrix_suite "${2:?matrix-suite needs <backend>:<default-deny>}" ;;
    *)
        echo "Unknown subcommand: ${SUBCOMMAND}" >&2
        echo "Usage: $0 {build-image|install-kind|create-cluster|load-image|deploy|wait|dump-initial|run-tests|refresh|dump-debug|delete-cluster|suite|all|matrix}" >&2
        exit 1
        ;;
esac
