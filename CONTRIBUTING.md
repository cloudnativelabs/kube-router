# Contributing to kube-router

## Summary

This document covers how to contribute to the kube-router project. kube-router uses GitHub pull requests to
manage contributions (documentation, bug fixes, features, manifests, etc.).

Please read the [User Guide](/docs/user-guide.md) and [Developer's Guide](/docs/developing.md) for
functionality and internals of kube-router.

## Getting Help

If you have a question about kube-router or have a problem using it, please start with the
[#kube-router](https://kubernetes.slack.com/messages/C8DCQGTSB/) channel on Kubernetes Slack.
If that doesn't answer your question, or if you think you found a bug, please
[file an issue](https://github.com/cloudnativelabs/kube-router/issues).

## Contributing Changes

### Fork and Clone

```bash
git clone https://github.com/YOUR_ACCOUNT/kube-router.git
cd kube-router
git remote add upstream https://github.com/cloudnativelabs/kube-router
git checkout master
git fetch upstream
git rebase upstream/master
```

### Create a Feature Branch

```bash
git checkout -b feature_x
```

Make your changes, then ensure they pass formatting, linting, and tests before committing:

```bash
make clean
make gofmt-fix
make
```

This project uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). Please adopt
this convention for all commit messages. Use the following scope abbreviations for controller changes:

- **NSC** -- Network Services Controller (`pkg/controllers/proxy/`)
- **NRC** -- Network Routes Controller (`pkg/controllers/routing/`)
- **NPC** -- Network Policy Controller (`pkg/controllers/netpol/`)

Commit with a descriptive message that explains the *why*, not just the *what*:

```bash
git add .
git commit -m "fix(NSC): handle nil endpoint slices during sync"
```

### Stay Up-to-Date

Before pushing, rebase on the latest upstream:

```bash
git checkout master
git fetch upstream
git rebase upstream/master
git checkout feature_x
git rebase master
```

### Submit a Pull Request

Push your branch and open a pull request:

```bash
git push origin feature_x
```

Then open a pull request from your fork on GitHub against the `master` branch.
