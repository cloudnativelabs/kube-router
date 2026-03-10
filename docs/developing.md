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

Run the full test suite:

```bash
make test
```

Or with formatted output (easier to understand for humans, uses `gotestsum`):

```bash
make test-pretty
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
