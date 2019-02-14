
# Contributing to Kube-router

## Summary

This document covers how to contribute to the kube-router project. Kube-router uses github PRs to manage contributions (could be anything from documentation, bug fixes, manifests etc.).

Please read [users guide](./docs/user-guide.md) and [developers guide](/docs/developing.md) for the functionality and internals of kube-router.

## Filing issues

If you have a question about Kube-router or have a problem using it, please start with contacting us on [community forum](https://kubernetes.slack.com/messages/C8DCQGTSB/) for quick help. If that doesn't answer your questions, or if you think you found a bug, please [file an issue](https://github.com/cloudnativelabs/kube-router/issues).

## Contributing Changes

### Fork the code

Navigate to:
[https://github.com/cloudnativelabs/kube-router](https://github.com/cloudnativelabs/kube-router)
and fork the repository.

Follow these steps to setup a local repository for working on Kube-router:

``` bash
$ git clone https://github.com/YOUR_ACCOUNT/kube-router.git
$ cd kube-router
$ git remote add upstream https://github.com/cloudnativelabs/kube-router
$ git checkout master
$ git fetch upstream
$ git rebase upstream/master
```

### Creating A Feature Branch

Create a new branch to make changes on and that branch.

``` bash
$ git checkout -b feature_x
   (make your changes)
$ git status
$ git add .
$ git commit -a -m "descriptive commit message for your changes"
```
get update from upstream

``` bash
$ git checkout master
$ git fetch upstream
$ git rebase upstream/master
$ git checkout feature_x
$ git rebase master
```

Now your `feature_x` branch is up-to-date with all the code in `upstream/master`, so push to your fork

### Performing A Pull Request

``` bash
$ git push origin master
$ git push origin feature_x
```

Now that the `feature_x` branch has been pushed to your GitHub repository, you can initiate the pull request.
