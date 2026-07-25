# Developer's Guide

For basic guidelines around contributing, see the [CONTRIBUTING](/CONTRIBUTING.md) document.

## Prerequisites

- Go 1.25+ (see [go.mod](/go.mod) for the exact version)
- Docker (builds run inside containers by default)
- Make

## Building

All dependencies are managed as Go modules. To build:

```bash
make kube-router
```

By default, builds run inside Docker for consistency. To build locally:

```bash
BUILD_IN_DOCKER=false make kube-router
```

(Adding `BUILD_IN_DOCKER=false` will work for most other steps that utilize docker as well)

### Building a Docker Image

```bash
make container
```

This compiles kube-router and builds a Docker image tagged with the current branch and architecture.

### Pushing a Docker Image

```bash
make push
```

By default this pushes to the official `cloudnativelabs/kube-router` Docker Hub repository which most users will likely
not have access to.
Push to a different registry by setting image options:

```bash
make container IMG_FQDN=quay.io IMG_NAMESPACE=youruser IMG_TAG=custom
```

### Multi-Architecture Builds

Specify the target architecture with `GOARCH`:

```bash
GOARCH=arm64 make kube-router
GOARCH=s390x make container
```

Supported architectures: amd64 (default), arm64, arm, s390x, ppc64le, riscv64.

## Testing

kube-router has four levels of testing, each with its own Makefile target, and each entering the automatic
pipelines at a different point:

| Level | Target | Scope | Runs in CI on |
|-------|--------|-------|---------------|
| Unit | `make test` | Pure Go, no root, no kernel, mocked interfaces | Every PR and push (`ci.yml` checks phase) |
| Privileged | `make test-privileged` | Real netlink/netns calls, needs root | Not wired into CI yet; run locally |
| nftables integration | `make test-integration` | Real `nft` + kernel, no Kubernetes API | Every PR and push |
| NetworkPolicy e2e | `make e2e-netpol` | Full kube-router deployed to a Kind cluster | Every PR and push, 4-way matrix |

Canonically, the inner development loop is `make gofmt-fix && make lint && make test-pretty`, and that's
also the first CI gate: the checks phase of [ci.yml](/.github/workflows/ci.yml) runs lint, unit tests, and a
binary build on every PR and push, and the container build and release phases only run after it passes.
The integration and e2e levels live in [ci-e2e-netpol.yml](/.github/workflows/ci-e2e-netpol.yml), which
also triggers on every PR and push: integration tests run bare on the runner (`BUILD_IN_DOCKER=false`
under sudo), while the e2e job fans out across a `{iptables, nftables} x {default-deny on, off}` matrix.
The slow e2e lifecycle specs (controller restart, chain GC) are gated behind `E2E_LONG`, which CI sets only
on push, tag, and manual dispatch - never on PRs - so PR feedback stays fast while merges to `master`,
version branches, and release tags get the full regression coverage.

Currently the privileged tests are the one level you have to remember to run yourself when touching
netlink-heavy code (`pkg/routes`, for example), since CI doesn't run them anywhere yet.

If you want to run every host-local level in one shot, `make test-all` chains the unit, privileged, and
integration targets. The e2e suite is deliberately not part of it, since it stands up a Kind cluster and
covering its full matrix takes several runs, but `make test-all e2e-netpol` composes the two when you want
everything.

### Unit Tests

Run the full unit test suite:

```bash
make test
```

Or with formatted output (easier to understand for humans, uses `gotestsum`):

```bash
make test-pretty
```

### Privileged Tests

A few tests (netlink, netns) need root to run, so they're excluded from `make test` and live in
`*_privileged_test.go` files behind the `privileged` build tag. They run in a privileged container by
default:

```bash
make test-privileged
```

### nftables Integration Tests

The nftables backend of the NetworkPolicy controller has integration tests
(`pkg/controllers/netpol/npc_nftables_integration_test.go`) that exercise it against the real `nft` binary
and kernel via netlink, with no Kubernetes API server involved. They're behind the `integration` build tag,
so `make test` skips them. By default they run in a privileged container that has `nftables` installed:

```bash
make test-integration
```

If you'd rather run them bare, you'll need root (or `CAP_NET_ADMIN`), `nft` 1.0.1 or newer, and a 5.2+
kernel. The tests skip themselves gracefully when nftables isn't usable:

```bash
BUILD_IN_DOCKER=false make test-integration
```

Each test creates an isolated, uniquely named nftables table and deletes it via `t.Cleanup`, so no kernel
state leaks between tests, even on failure. Because they talk to the real kernel, be sure to run them on a
Linux machine (or let the default in-Docker mode handle that for you).

### NetworkPolicy e2e Tests

The NetworkPolicy e2e suite runs against a local dual-stack Kind cluster and needs `docker` plus `kind` (the
harness installs `kind` for you if it's missing, which is the only step that needs sudo). A full run builds
the image, creates the cluster, deploys kube-router, and runs the suite:

```bash
make e2e-netpol E2E_LONG=1 BACKEND=nftables DEFAULT_DENY=true
```

The suite runs specs in parallel via the ginkgo CLI. In order of precedence, the knobs you'll want are:

- **`BACKEND`** - `iptables` - Which netpol backend to deploy (`iptables` or `nftables`).
- **`DEFAULT_DENY`** - `false` - Deploy kube-router with `--netpol-default-deny=true`; the 10 default-deny
  specs skip without it.
- **`E2E_LONG`** - `NO_DEFAULT_SET` - Set to `1` to run the slow lifecycle specs (controller restart, chain
  GC).
- **`E2E_PROCS`** - `4` - Ginkgo parallel processes. The default matches free GitHub runners; set `1` for a
  fully serial run.
- **`E2E_FOCUS`** / **`E2E_SKIP`** - `NO_DEFAULT_SET` - Regexes passed to ginkgo `--focus` / `--skip` so you
  can run a single spec instead of the whole suite.

Because a given deployment is either default-deny or not, and either iptables or nftables, covering all 48
specs takes a few runs with different combinations - any spec whose gate isn't met reports as skipped, not
failed.

When you're iterating on a failing spec (this works equally well for a human or an AI agent, since nothing
in the loop needs sudo once `kind` is installed), keep the cluster alive and rerun just the tests:

```bash
# once, to stand the cluster up and keep it around
SKIP_CLEANUP=1 make e2e-netpol BACKEND=nftables DEFAULT_DENY=true

# rebuild + reload + restart kube-router, only needed if you changed kube-router code
hack/e2e-netpol.sh refresh

# rerun a single spec by name
E2E_LONG=1 BACKEND=nftables E2E_FOCUS='chain GC' hack/e2e-netpol.sh run-tests

# when you're done
hack/e2e-netpol.sh delete-cluster
```

## Linting and Formatting

Check formatting:

```bash
make gofmt
```

Auto-fix formatting:

```bash
make gofmt-fix
```

Run all linters (golangci-lint + markdownlint):

```bash
make lint
```

## Mock Generation

When modifying interfaces that have associated mocks, regenerate them:

```bash
make gomoqs
```

Or regenerate a specific mock:

```bash
make pkg/controllers/proxy/linux_networking_moq.go
```

## Commit Messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
Every commit message should follow the format `<type>(<scope>): <description>`.

Common types: `feat`, `fix`, `doc`, `test`, `build`, `chore`, `fact` (refactor).

The following scope abbreviations are used for the main controllers:

- **NSC** -- Network Services Controller (`pkg/controllers/proxy/`)
- **NRC** -- Network Routes Controller (`pkg/controllers/routing/`)
- **NPC** -- Network Policy Controller (`pkg/controllers/netpol/`)

Examples:

```text
feat(gobgp): add kube_router_bgp_peer_info metric
fix(aws.go): load region before attempting to assume a role
test(NSC): add comprehensive TCPMSS unit tests
```

## Development Workflow

```bash
git checkout -b feature_x

# Make changes...

make clean
make gofmt-fix
make
```

Run `make help` for a full list of available targets.

## Release Workflow

See [RELEASE.md](/RELEASE.md) for more information.

## Dependency Management

kube-router uses Go modules. See the
[upstream documentation](https://go.dev/blog/using-go-modules) for more information.
