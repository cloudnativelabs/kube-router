# AI Agent Guidelines for kube-router

This document provides comprehensive guidelines for AI coding agents working on the kube-router project. It consolidates
project-specific coding standards, best practices, and workflows to ensure consistent, high-quality contributions.

## Table of Contents

- [Project Overview](#project-overview)
- [Project Structure](#project-structure)
- [Build System and Makefile](#build-system-and-makefile)
- [Go Coding Standards](#go-coding-standards)
- [Error Handling](#error-handling)
- [Logging Practices](#logging-practices)
- [Testing](#testing)
- [Refactoring Guidelines](#refactoring-guidelines)
- [Code Review Process](#code-review-process)
- [Development Workflow](#development-workflow)
- [Planning Guidelines](#planning-guidelines)
- [Markdown Formatting](#markdown-formatting)
- [Kubernetes-Specific Considerations](#kubernetes-specific-considerations)
- [Additional Best Practices](#additional-best-practices)
- [References](#references)
- [Support](#support)

## Project Overview

kube-router is a turnkey solution for Kubernetes networking that provides:

- **IPVS/LVS-based Service Proxy**: High-performance load balancing using Linux kernel features
- **Pod Networking**: Direct routing with BGP protocol via GoBGP
- **Network Policy Controller**: Firewall rules using ipsets and iptables
- **Advanced BGP Capabilities**: Integration with external networking devices

### Key Technologies

- **Language**: Go
- **Kubernetes API**: v0.34.2 or latest
- **Key Libraries**: GoBGP, Netlink, iptables, ipset, IPVS
- **Logging**: klog/v2
- **Testing**: Testify, Ginkgo, Gomega

## Project Structure

```text
.
├── cmd/                    # Main applications
│   └── kube-router/        # Main application entry point
├── pkg/                    # Public library code
│   ├── healthcheck/        # Logic for monitoring control loops
│   └── controllers/        # Main control loop logic
│        ├── lballoc/       # LoadBalancer controller IPAM logic
│        ├── netpol/        # NetworkPolicy enforcement logic
│        ├── proxy/         # Services controller logic
│        └── routing/       # Pod & Service routing logic
├── internal/               # Private implementation code
│   ├── nlretry/            # Netlink retry logic
│   └── testutils/          # Internal test utilities
├── testdata/               # Test fixtures and data
├── daemonset/              # Kubernetes deployment manifests
├── cni/                    # Kubernetes CNI configuration files
└── docs/                   # Documentation in markdown format
```

### File Naming Conventions

1. Use snake_case for file names:

```golang
// Good
api_handler.go
user_service.go

// Bad
apiHandler.go
UserService.go
```

1. Test files should use _test suffix:

```golang
// Good
api_handler_test.go

// Bad
api_handler_tests.go
```

1. Package names should be short and clear:

```golang
// Good
package api
package validator

// Bad
package apihandlers
package utility_functions
```

## Build System and Makefile

kube-router uses a comprehensive Makefile for building, testing, linting, and releasing. **Always use Makefile targets
instead of running commands directly** when available.

### Common Makefile Targets

#### Building

- `make kube-router` - Build the kube-router binary
- `make container` - Build the container image
- `make gobgp` - Build the gobgp binary
- `make all` - Default target: lint, test, build binaries and images

#### Testing and Formatting

- `make test` - Run all tests with verbose output
- `make test-pretty` - Run tests with formatted output using gotestsum
- `make gofmt` - Check which files need formatting
- `make gofmt-fix` - Automatically fix formatting issues

#### Linting

- `make lint` - Run golangci-lint and markdownlint
- `make markdownlint` - Run markdown linting on README and docs

#### Code Generation

- `make gomoqs` - Generate all mock files using moq
- Individual mocks: `make pkg/controllers/proxy/linux_networking_moq.go`

#### Dependency Management

- `make update-deps` - Update all dependency versions, resolve digests, and pin SHAs
- `make update-deps-dry` - Preview what dependency updates would be made (dry-run with diff output)

The `update-deps` target runs the `build/dependency-updater` Go tool, which:

- Discovers all managed files dynamically (no static file list)
- Updates Docker image tags to their latest versions within constraints defined in
  `build/dependency-updater/versions.lock.yaml`
- Resolves Docker image tags to `image:tag@sha256:digest` format for reproducibility
- Updates tool version variables (e.g. `GOBGP_VERSION`) to their latest GitHub releases
- Updates GitHub Action `uses:` lines from bare tags (`@v6`) or existing SHA pins to the
  latest SHA-pinned form (`@sha256...  # vX.Y.Z`)
- Updates the `toolchain` directive in `go.mod`

Set `GITHUB_TOKEN` in your environment to avoid GitHub API rate limits (60/hr unauthenticated
vs 5000/hr authenticated):

```bash
GITHUB_TOKEN=ghp_... make update-deps
```

#### Release Preparation

- `make prep-release` - Full release preparation: update deps, run all checks, build container

This is the single command to run before tagging a new release. It calls `update-deps` first,
then runs the same steps as `all` (`doctoc lint test-pretty kube-router container`).

#### Release and Distribution

- `make push` - Push container image to registry
- `make release` - Create and push a release
- `make clean` - Remove build artifacts

#### Help

- `make help` - Display all available targets with descriptions

### Build Configuration

The Makefile supports several environment variables:

- `BUILD_IN_DOCKER` (default: true) - Build inside Docker container
- `GOARCH` - Target architecture (amd64, arm64, arm, s390x, ppc64le, riscv64)
- `IMG_NAMESPACE` - Container registry namespace
- `IMG_TAG` - Container image tag
- `DOCKER_BUILD_IMAGE` - Docker image for building
- `GO_CACHE` - Go build cache directory
- `GO_MOD_CACHE` - Go module cache directory

### Build Modes

#### In-Docker Build (default)

By default, builds run inside Docker containers for consistency:

```bash
make kube-router  # Builds in Docker
make test         # Tests in Docker
```

#### Local Build

To build locally without Docker:

```bash
BUILD_IN_DOCKER=false make kube-router
BUILD_IN_DOCKER=false make test
```

### Multi-Architecture Support

kube-router supports multiple architectures. Specify with `GOARCH`:

```bash
GOARCH=arm64 make kube-router
GOARCH=s390x make container
```

Supported architectures:

- amd64 (default)
- arm64
- arm
- s390x
- ppc64le
- riscv64

### Version Information

The build system automatically injects version information:

- `GIT_COMMIT` - Git commit hash/tag
- `BUILD_DATE` - Build timestamp
- `GIT_BRANCH` - Current Git branch

### Mock Generation

When modifying interfaces that have mocks:

1. Update the interface in the source file
2. Ensure the file has the `//go:generate moq` directive
3. Run `make gomoqs` to regenerate all mocks
4. Or regenerate a specific mock: `make pkg/controllers/proxy/linux_networking_moq.go`

Example from code:

```golang
//go:generate moq -out linux_networking_moq.go . LinuxNetworking
type LinuxNetworking interface {
    ipvsCalls
    netlinkCalls
}
```

### Tool Versions

The Makefile pins specific versions of tools for reproducibility:

- Go: 1.25.1 or latest
- golangci-lint: v2.4.0 or latest
- GoBGP: v3.37.0 or latest
- moq: v0.6.0 or latest
- CNI plugins: v1.8.0 or latest

### Makefile Best Practices

1. **Always use Makefile targets** - Don't run `go build`, `go test`, etc. directly
1. **Run tests before committing** - `make test-pretty` or `make test`
1. **Lint before submitting** - `make lint` to catch issues early
1. **Clean before release builds** - `make clean` then `make all`
1. **Check formatting** - `make gofmt` to see what needs fixing
1. **Auto-fix formatting** - `make gofmt-fix` before committing
1. **Regenerate mocks after interface changes** - `make gomoqs`

### Development Workflow with Makefile

```bash
# Start development
git checkout -b feature_x

# Make code changes
# ...

# Format code
make gofmt-fix

# Run linters
make lint

# Run tests
make test-pretty

# Build binary
make kube-router

# Build container (if needed)
make container

# Clean up
make clean
```

## Go Coding Standards

### Code Organization

1. Group related files in packages
2. Keep packages focused and cohesive
3. Follow standard Go project layout
4. Use internal/ for private implementation
5. Place reusable code in pkg/

### Import Order

Organize imports in the following order:

1. Standard library packages
1. External dependencies
1. Kubernetes dependencies
1. Project-internal packages

```golang
import (
    "context"
    "fmt"
    
    "github.com/vishvananda/netlink"
    
    "k8s.io/api/core/v1"
    "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/klog/v2"
    
    "github.com/cloudnativelabs/kube-router/v2/pkg/utils"
)
```

## Error Handling

### Error Types

1. **Custom error types** for specific errors:

```golang
// Good
type ValidationError struct {
    Field string
    Error string
}

func (v *ValidationError) Error() string {
    return fmt.Sprintf("validation failed on %s: %s", v.Field, v.Error)
}

// Usage
if !isValid {
    return &ValidationError{
        Field: "email",
        Error: "invalid format",
    }
}
```

1. **Error wrapping** for context:

```golang
// Good
if err := db.QueryRow(query, id).Scan(&user); err != nil {
    return fmt.Errorf("fetching user %d: %w", id, err)
}

// Bad
if err := db.QueryRow(query, id).Scan(&user); err != nil {
    return err // Lost context
}
```

### Error Handling Patterns

1. **Handle errors immediately**:

```golang
// Good
result, err := someFunction()
if err != nil {
    return fmt.Errorf("failed to execute someFunction: %w", err)
}
// Use result

// Bad
result, err := someFunction()
// Do other things...
if err != nil { // Too late
    return err
}
```

1. **Don't panic in libraries**:

```golang
// Good
func ProcessData(data []byte) error {
    if len(data) == 0 {
        return errors.New("empty data provided")
    }
    // Process data
    return nil
}

// Bad
func ProcessData(data []byte) {
    if len(data) == 0 {
        panic("empty data provided")
    }
    // Process data
}
```

1. **Use %v for logging errors, not %w or %s**:

```golang
// Good
result, err := someFunction()
if err != nil {
    klog.Errorf("failed to execute someFunction: %v", err)
}

// Bad
result, err := someFunction()
if err != nil {
    klog.Errorf("failed to execute someFunction: %w", err)
}
```

### Sentinel Errors

Use sentinel errors for expected error conditions:

```golang
var (
    ErrNotFound = errors.New("resource not found")
    ErrInvalid  = errors.New("invalid input")
)
```

### Error Groups

Use error groups for concurrent operations:

```golang
g := new(errgroup.Group)
for _, item := range items {
    item := item
    g.Go(func() error {
        return processItem(item)
    })
}
if err := g.Wait(); err != nil {
    return fmt.Errorf("processing items: %w", err)
}
```

## Logging Practices

kube-router uses `klog` from the Kubernetes project for logging.

### Basic Logging

```golang
import (
    "k8s.io/klog/v2"
)

func main() {
    klog.Info("Application started")
    klog.Infof("User created: %v", userID)
    klog.V(1).Infof("Found %d routes for interface %s, deleting them...", len(routes), iface.Attrs().Name)
}
```

### Logging Best Practices

- Add the logger at the top of the file or as a package/global variable
- Do not use global context for sensitive or user-specific data
- Avoid logging sensitive information (passwords, tokens, keys)
- Use appropriate log levels:
  - `klog.Info()`: General informational messages
  - `klog.V(1).Info()`: Verbose/debug information
  - `klog.Warning()`: Warning messages
  - `klog.Error()`: Error messages
  - `klog.Fatal()`: Fatal errors (use sparingly)

## Testing

### Test Structure

1. **Use table-driven tests**:

```golang
func TestCalculate(t *testing.T) {
    tests := []struct {
        name     string
        input    int
        want     int
        wantErr  bool
    }{
        {
            name:    "positive number",
            input:   5,
            want:    10,
            wantErr: false,
        },
        {
            name:    "negative number",
            input:   -5,
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := Calculate(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("Calculate() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !tt.wantErr && got != tt.want {
                t.Errorf("Calculate() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

1. **Use subtests** for better organization:

```golang
func TestService(t *testing.T) {
    t.Run("Create", func(t *testing.T) {
        // Test creation
    })

    t.Run("Update", func(t *testing.T) {
        // Test update
    })

    t.Run("Delete", func(t *testing.T) {
        // Test deletion
    })
}
```

### Test Helpers

Create test utilities with proper helper marking:

```golang
func setupTestDB(t *testing.T) (*sql.DB, func()) {
    t.Helper() // Mark as helper function
    db, err := sql.Open("postgres", "test-connection-string")
    if err != nil {
        t.Fatalf("setting up test db: %v", err)
    }

    return db, func() {
        db.Close()
    }
}

// Usage
func TestDatabase(t *testing.T) {
    db, cleanup := setupTestDB(t)
    defer cleanup()
    // Run tests
}
```

### Mocking

1. **Use interfaces** for testability:

```golang
type UserRepository interface {
    GetUser(id int) (*User, error)
}

// Mock implementation
type mockUserRepo struct {
    users map[int]*User
}

func (m *mockUserRepo) GetUser(id int) (*User, error) {
    user, ok := m.users[id]
    if !ok {
        return nil, ErrNotFound
    }
    return user, nil
}
```

1. **Small mocks (< 200 lines)**: Use testify mock library

```golang
import "github.com/stretchr/testify/mock"
```

See `pkg/utils/node_test.go` for examples.

1. **Large mocks (> 200 lines)**: Use moq to generate mock files

```golang
//go:generate moq -out linux_networking_moq.go . LinuxNetworking
type LinuxNetworking interface {
    ipvsCalls
    netlinkCalls
}
```

### Assertions

Use the Testify library for assertions:

```golang
import "github.com/stretchr/testify/assert"

if testcase.err != nil {
    assert.EqualError(t, err, testcase.err.Error())
}
```

### Fail Fast Pattern

Use `t.Fatalf()` for conditions that would stop a test from executing:

```golang
t.Run(testcase.name, func(t *testing.T) {
    clientset := fake.NewSimpleClientset()
    _, err := clientset.CoreV1().Nodes().Create(context.Background(), testcase.existingNode, metav1.CreateOptions{})
    if err != nil {
        t.Fatalf("failed to create existing nodes for test: %v", err)
    }
})
```

### Test Fixtures

Use test fixtures for large amounts of test data (>100 lines):

```golang
// testdata/users.json
// Place test data in testdata directory
```

See `testdata/ipset_test_1/` for examples.

### Parallel Tests

Use parallel tests when possible:

```golang
func TestParallel(t *testing.T) {
    tests := []struct{
        name string
        // test cases
    }{
        // test cases here
    }

    for _, tt := range tests {
        tt := tt // Capture range variable
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel() // Mark test as parallel
            // Test implementation
        })
    }
}
```

### Test Coverage

1. Run tests with coverage:

```bash
go test -cover ./...
```

1. Generate coverage report:

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

1. Test race conditions:

```bash
go test -race ./...
```

1. Target 70% test coverage for new code with emphasis on:
   - Business logic cases
   - Corner cases
   - Boundary conditions
   - Poorly defined input handling

### Integration Tests

Use build tags for integration tests:

```golang
// +build integration

package integration

func TestIntegration(t *testing.T) {
    // Integration test implementation
}
```

## Refactoring Guidelines

When refactoring code, ensure the following:

### Function Size

- Try to ensure functions are a maximum of 50 lines
- Prefer function sizes of approximately 30 lines or less
- Don't create functions for code that is less than 5 lines long
- Ensure that all functions created encapsulate related logic while obeying max lengths
- If you can't follow these guidelines, ask for guidance rather than assuming

### Code Quality

- For any hard-coded variables encountered during a refactor, consider whether they should be added as constants
- Prioritize keeping code as DRY (Don't Repeat Yourself) as possible and minimize repetition
- If you find elements of code that are reused in the current file, refactor those as well to use the refactored functions

### Constants

Extract magic numbers and repeated strings:

```golang
// Good
const (
    MaxRetries = 3
    DefaultTimeout = 30 * time.Second
)

// Bad
if retries > 3 { // Magic number
    // ...
}
```

## Code Review Process

When conducting code reviews (when explicitly asked), address the following sections:

### 1. Summary

Review the code changes in the indicated range and summarize in four sentences or less the general purpose of the code.

### 2. Obvious Problems

Identify any obvious problems:

- Anything that would stop it from running or accomplishing its intent
- Obvious violations of programming design or functionality

Format as a bulleted list with sub-bullets for recommended remediation.

### 3. Code Style Analysis

Compare the changed code with surrounding code and other committed code in the repository. Provide a brief assessment of
how well the code fits with the structure of the existing code.

**Provide a score (1-10)**: 1 = not matching at all, 10 = matching very well.

### 4. Potential Code Duplication

Audit the rest of the codebase for any code duplication introduced by the changes. Focus on utility functions that might
not have been used.

### 5. Refactoring Potential

Identify obvious wins that would:

- Greatly improve readability
- Be significantly more conformant with generally accepted standards
- Greatly improve performance/memory structure

Don't be pedantic; focus on obvious improvements.

### 6. Test Coverage

Identify any obvious tests that are missing. New code should seek 70% test coverage, with emphasis on:

- Business logic cases
- Corner cases
- Boundary conditions
- Poorly defined input handling

**Provide a test coverage score (1-10)**: 1 = no unit tests, 10 = 100% test coverage.

### 7. Security Implications

List any obvious security problems related to the indicated code. Format as a bulleted list with sub-bullets for
recommended remediation.

### 8. Documentation Opportunities

Review existing documentation in `/docs` and check if:

- Code changes require documentation updates that weren't made
- Any documentation has spelling/grammar issues or readability problems

Format as a bulleted list with sub-bullets for recommended remediation.

### 9. Upstream Reviews

If a URL is provided (likely a related issue or PR):

- Fetch the content remotely and analyze it
- If it's a PR with comments/feedback, check if they were resolved

Format as a bulleted list with sub-bullets for recommended remediation.

### 10. Code Quality Score

Provide a code quality score (1-10): 1 = lowest quality, 10 = highest quality.

### 11. Compare with Previous Reviews

Check if a previous review exists in `.reviews/<branch_name>/`. If it exists, compare the current review to it in terms
of:

- Fixed issues
- Remaining issues
- New issues found

### Review Output Location

Save all review output to:
`.reviews/<branch_name>/<branch_name>-<integer_increment>.md`

Where:

- `<branch_name>` is the name of the current git branch
- `<integer_increment>` is an integer to ensure unique filenames

## Development Workflow

### Git Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature_x`
3. Make changes and commit with descriptive messages
4. Keep branch up-to-date with upstream:

```bash
git checkout master
git fetch upstream
git rebase upstream/master
git checkout feature_x
git rebase master
```

1. Push to your fork: `git push origin feature_x`
1. Create a pull request

### Commit Messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/). Every commit message must follow
this format:

```text
<type>(<scope>): <description>
```

Where `<type>` is one of:

- **feat**: A new feature or enhancement
- **fix**: A bug fix
- **doc**: Documentation-only changes
- **test**: Adding or updating tests
- **build**: Changes to the build system or dependencies (e.g. `build(deps)`)
- **chore**: Maintenance tasks that don't modify src or test files
- **fact** (refactor): Code restructuring without behavior changes

The `<scope>` is optional but encouraged. It should identify the component or file affected (e.g. `gobgp`,
`aws.go`, `Makefile`). Use the following abbreviations for the main controllers:

- **NSC** -- Network Services Controller (`pkg/controllers/proxy/`)
- **NRC** -- Network Routes Controller (`pkg/controllers/routing/`)
- **NPC** -- Network Policy Controller (`pkg/controllers/netpol/`)

Additional guidelines:

- Keep the description concise and lowercase
- Explain the "why" rather than the "what"
- Keep commits focused on a single logical change

Examples from this repository:

```text
feat(gobgp): add kube_router_bgp_peer_info metric
fix(aws.go): load region before attempting to assume a role
test(NSC): add comprehensive TCPMSS unit tests
build(deps): bump golang.org/x/net from 0.49.0 to 0.51.0
doc(metrics.md): replace controller_bgp_peers -> bgp_peer_info
```

### Code Quality Tools

Run the following before submitting:

```bash
# Linting
golangci-lint run

# Static analysis
staticcheck ./...

# Error checking
errcheck ./...

# Tests
go test ./...

# Race detection
go test -race ./...
```

## Planning Guidelines

When asked to create plans for complex features or changes, follow this structured approach to ensure clarity and
thoroughness.

### Plan Location

Create a new directory inside `<git_root>/.plans`. The name of the directory should be 3 words or less that briefly
summarizes the task. It should be camel case and not contain any spaces.

**Example:**

- `.plans/IpsetRefactor/`
- `.plans/BgpPeerConfig/`
- `.plans/MetricsController/`

### Plan Layout

The primary artifact is a `PLAN.md` file that contains markdown documenting the plan. This is a living document that
should be continuously updated during execution. It should contain the following sections with each top level list item
being a heading:

#### Original Prompt

This should be the original prompt or request verbatim.

#### Summary

A paragraph summary of the approach that will be taken.

#### Detail

A markdown list of what will be done in order. Later during implementation, check off items as they are completed and
keep the list updated.

**Example:**

```markdown
## Detail

- [x] Analyze existing ipset implementation
- [x] Identify refactoring opportunities
- [ ] Create new ipset helper functions
- [ ] Update network policy controller to use new helpers
- [ ] Add unit tests for new functionality
- [ ] Update integration tests
```

#### Problems Encountered

This section is filled out during implementation to describe any particular problems encountered while trying to execute
the plan as provided in the details section.

**Example:**

```markdown
## Problems Encountered

- **Netlink compatibility**: Found that some ipset operations don't work consistently across kernel versions.
  Implemented fallback logic to handle this.
- **Test fixtures**: Existing test fixtures didn't cover edge cases. Created new fixtures in testdata/ipset_test_2/
```

#### Files Changed

List the files that are expected to need changes. Update this list as the plan evolves.

**Example:**

```markdown
## Files Changed

- pkg/controllers/netpol/ipset.go
- pkg/utils/ipset.go
- pkg/controllers/netpol/network_policy_controller.go
- pkg/controllers/netpol/ipset_test.go
```

#### Tests Changed

In general, tests should be additive to ensure compatibility is maintained. However, if existing test changes are
unavoidable, detail what will be changed and why.

**Example:**

```markdown
## Tests Changed

- pkg/controllers/netpol/ipset_test.go
  - Updated TestIpsetCreate to use new helper functions
  - Added new test cases for error handling
- No breaking changes to existing tests
```

### Plan Formatting

All plans must abide by the markdown formatting standards described in the [Markdown Formatting](#markdown-formatting)
section. Lines should be no more than 120 characters long.

### Plan Clarification

If any questions arise when creating the plan, ask for clarification rather than making assumptions unless the
assumptions are small and clearly reasonable.

### Plan Updates

As implementation progresses:

1. Check off completed items in the Detail section
1. Add any new tasks discovered during implementation
1. Document problems in the Problems Encountered section
1. Update Files Changed and Tests Changed as needed
1. Keep the plan synchronized with actual work

### When to Create Plans

Create plans for:

- Complex multi-file refactorings
- New feature implementations
- Major architectural changes
- Changes that affect multiple controllers or subsystems
- Work that will take multiple sessions to complete

Do not create plans for:

- Simple bug fixes
- Single-file changes
- Documentation-only updates
- Trivial refactorings

## Markdown Formatting

kube-router uses markdownlint to enforce consistent markdown formatting across all documentation. All markdown files must
pass markdownlint checks before being committed.

### Running Markdownlint

Use the Makefile target to check markdown files:

```bash
make markdownlint
```

This will lint both the README and all files in the `/docs` directory.

### Markdownlint Configuration

The project's markdownlint rules are defined in `.markdownlint.yaml`:

- **MD046**: Code blocks must use fenced style (triple backticks) instead of indented style
- **MD013**: Line length limited to 120 characters (200 for code blocks)
- **MD045**: Images must have alt text (disabled in this project)

### Formatting Rules

#### Line Length (MD013)

- Keep lines under 120 characters
- Code blocks can extend to 200 characters
- Break long sentences and paragraphs naturally at punctuation

**Good:**

```markdown
This is a reasonably long sentence that explains a complex concept but stays within the 120 character limit by
breaking at a natural point.
```

**Bad:**

```markdown
This is an extremely long sentence that goes on and on without any breaks and exceeds the maximum line length of 120 characters which will cause markdownlint to fail.
```

#### Code Blocks (MD046)

Always use fenced code blocks with language identifiers:

**Good:**

````markdown
```bash
make test
```

```golang
func main() {
    fmt.Println("Hello")
}
```
````

**Bad:**

```markdown
    make test

    func main() {
        fmt.Println("Hello")
    }
```

#### Headings

1. **Use ATX-style headings** (with #):

```markdown
# Heading 1
## Heading 2
### Heading 3
```

1. **One H1 per document** - Only use a single `#` heading at the top of the file

1. **No skipping levels** - Don't jump from `##` to `####`

1. **Space after hash** - Always include a space: `## Heading` not `##Heading`

#### Lists

1. **Consistent markers** - Use `-` for unordered lists throughout:

**Good:**

```markdown
- Item 1
- Item 2
  - Nested item
  - Another nested item
- Item 3
```

**Bad:**

```markdown
* Item 1
- Item 2
+ Item 3
```

1. **Proper indentation** - Use 2 spaces for nested lists:

```markdown
- Top level
  - Nested level
    - Double nested
```

1. **Ordered lists** - Use `1.` for all items (auto-numbering):

```markdown
1. First item
1. Second item
1. Third item
```

#### Links

1. **No bare URLs** - Always use link syntax:

**Good:**

```markdown
See the [User Guide](/docs/user-guide.md) for details.
Visit [GitHub](https://github.com/cloudnativelabs/kube-router).
```

**Bad:**

```markdown
See /docs/user-guide.md for details.
Visit https://github.com/cloudnativelabs/kube-router.
```

1. **Reference-style links** - Use for repeated or long URLs:

```markdown
Check out [kube-router and [Kubernetes][k8s].

[kr]: https://github.com/cloudnativelabs/kube-router
[k8s]: https://kubernetes.io
```

#### Emphasis

1. **Bold** - Use `**double asterisks**`:

```markdown
**Important**: This is critical information.
```

1. **Italic** - Use `*single asterisks*`:

```markdown
This is *emphasized* text.
```

1. **Code** - Use backticks for inline code:

```markdown
The `kubectl` command is used to interact with Kubernetes.
Use the `--help` flag for more information.
```

#### Tables

Ensure tables are properly formatted:

```markdown
| Header 1 | Header 2 | Header 3 |
|----------|----------|----------|
| Cell 1   | Cell 2   | Cell 3   |
| Cell 4   | Cell 5   | Cell 6   |
```

#### Blank Lines

1. **Around headings** - One blank line before and after:

```markdown
Some text here.

## New Section

More text here.
```

1. **Around code blocks** - One blank line before and after:

```markdown
Some explanation here.

` ``bash
command here
` ``

More explanation here.
```

1. **Around lists** - One blank line before and after:

```markdown
Paragraph text.

- List item 1
- List item 2

More paragraph text.
```

#### File Structure

1. **Start with H1** - Every markdown file should start with a level 1 heading
1. **No trailing spaces** - Remove spaces at the end of lines
1. **End with newline** - Files should end with a single newline character
1. **No multiple blank lines** - Use only single blank lines

### Common Markdownlint Errors

#### MD009: Trailing Spaces

**Problem:** Lines ending with spaces

**Fix:** Remove trailing whitespace from all lines

#### MD012: Multiple Blank Lines

**Problem:** More than one consecutive blank line

**Fix:** Replace multiple blank lines with a single blank line

#### MD022: Headings Should Be Surrounded by Blank Lines

**Problem:** No blank line before/after heading

**Fix:** Add blank lines around all headings

#### MD025: Multiple H1 Headings

**Problem:** More than one `#` heading in the document

**Fix:** Use only one H1 at the document start; use `##` for sections

#### MD031: Fenced Code Blocks Should Be Surrounded by Blank Lines

**Problem:** No blank line before/after code block

**Fix:** Add blank lines around all code blocks

#### MD040: Fenced Code Blocks Should Have a Language Specified

**Problem:** Code block without language identifier

**Fix:** Add language after opening backticks:

````markdown
```bash
command here
```
````

### Markdown Best Practices

1. **Always run markdownlint before committing** - Use `make markdownlint`
2. **Use language identifiers on all code blocks** - Helps with syntax highlighting
3. **Keep lines under 120 characters** - Improves readability in all editors
4. **Use fenced code blocks** - Never use indented code blocks
5. **Consistent list markers** - Always use `-` for unordered lists
6. **One blank line between sections** - Don't use multiple blank lines
7. **Proper heading hierarchy** - Don't skip heading levels
8. **No trailing whitespace** - Configure your editor to remove it automatically

### Editor Integration

Configure your editor to show/remove:

- Line length guides at 120 characters
- Trailing whitespace
- End-of-file newlines

Popular editors with markdownlint support:

- **VS Code**: Install the "markdownlint" extension
- **Vim**: Use ALE or vim-markdown
- **Emacs**: Use markdown-mode with flycheck

## Kubernetes-Specific Considerations

### Working with Kubernetes Objects

1. **Use typed clients** when possible:

```golang
clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
```

1. **Handle API errors properly**:

```golang
node, err := clientset.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
if err != nil {
    if errors.IsNotFound(err) {
        return fmt.Errorf("node %s not found: %w", nodeName, err)
    }
    return fmt.Errorf("failed to get node %s: %w", nodeName, err)
}
```

1. **Use informers** for watching resources:

```golang
// Prefer informers over direct watches
informerFactory.Core().V1().Nodes().Informer().AddEventHandler(...)
```

### Network Programming

1. **Use netlink library** for Linux networking:

```golang
import "github.com/vishvananda/netlink"

link, err := netlink.LinkByName("eth0")
if err != nil {
    return fmt.Errorf("failed to get link: %w", err)
}
```

1. **Handle iptables carefully**:

```golang
import "github.com/coreos/go-iptables/iptables"

ipt, err := iptables.New()
if err != nil {
    return fmt.Errorf("failed to initialize iptables: %w", err)
}
```

1. **Use ipsets efficiently**:

```golang
// Batch operations when possible
// Clean up sets when no longer needed
```

### Performance Considerations

1. Minimize API calls - use informers and caching
2. Batch netlink operations when possible
3. Use ipsets for large rule sets instead of individual iptables rules
4. Profile code for performance bottlenecks in hot paths
5. Be mindful of goroutine leaks in long-running controllers

### Resource Cleanup

Always clean up resources properly:

```golang
func (c *Controller) Run(stopCh <-chan struct{}) {
    defer c.cleanup()
    
    // Controller logic
    
    <-stopCh
}

func (c *Controller) cleanup() {
    // Clean up iptables rules
    // Clean up ipsets
    // Clean up netlink resources
}
```

## Additional Best Practices

### Context Usage

Always propagate context for cancellation and timeouts:

```golang
func (s *Service) ProcessItem(ctx context.Context, item Item) error {
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
        // Process item
    }
}
```

### Concurrency

1. Use sync primitives appropriately
2. Avoid goroutine leaks
3. Handle context cancellation
4. Use errgroup for managing multiple goroutines

### Dependencies

- Keep dependencies up to date
- Be mindful of Kubernetes version compatibility
- Test with multiple Kubernetes versions when making API changes

### Documentation

- Document exported functions and types
- Keep documentation up to date with code changes
- Use godoc conventions
- Update `/docs` for user-facing changes

## References

- [User Guide](/docs/user-guide.md)
- [Developer Guide](/docs/developing.md)
- [Architecture](/docs/architecture.md)
- [How it Works](/docs/how-it-works.md)
- [Contributing Guidelines](/CONTRIBUTING.md)

## Support

- Slack: [#kube-router on Kubernetes Slack](https://kubernetes.slack.com/messages/C8DCQGTSB/)
- Issues: [GitHub Issues](https://github.com/cloudnativelabs/kube-router/issues)
