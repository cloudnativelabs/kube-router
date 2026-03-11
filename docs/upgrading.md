# Upgrading kube-router

## Breaking Changes

We follow semantic versioning and try to the best of our abilities to maintain a
stable interface between patch versions. For example, `v0.1.1` -> `v0.1.2`
should be a perfectly safe upgrade path, without data service interruption.
However, major (`vX.0.0`) and minor (`v0.Y.0`) version upgrades may contain
breaking changes, which will be detailed here and in the release notes.

First check if you are upgrading across one of the
[breaking change versions](#breaking-change-version-history). If so, read the
relevant section(s) first before proceeding with the general guidelines below.

## Supported Versions

kube-router generally only supports the current major.minor release. Bug fixes
and security patches are applied to the latest release, and users are encouraged
to stay up to date. In exceptional cases, we may backport critical fixes to the
previous minor release on request. If you need a backport, please open an issue
describing the bug and why upgrading to the latest release is not feasible.

## General Guidelines

### Image Pull Policy

Here we will assume that you have the following in your kube-router DaemonSet:

```yaml
imagePullPolicy: Always
```

If that's not the case, you will need to manually pull the desired image version
on each of your nodes with a command like: `docker pull
cloudnativelabs/kube-router:VERSION`

### Without Rolling Updates

This is the default situation with our DaemonSet manifests. We will soon be
switching these manifests to use Rolling Updates though.

The following example(s) show an upgrade from `v0.0.15` to `v0.0.16`.

First we will modify the kube-router DaemonSet resource's image field:

```sh
kubectl -n kube-system set image ds/kube-router kube-router=cloudnativelabs/kube-router:v0.0.16
```

This does not actually trigger any version changes yet. It is recommended that
you upgrade only one node and perform any tests you see fit to ensure nothing
goes wrong.

For example, we'll test upgrading kube-router on worker-01:

```sh
TEST_NODE="worker-01"
TEST_POD="$(kubectl -n kube-system get pods -o wide|grep -E "^kube-router.*${TEST_NODE}"|awk '{ print $1 }')"

kubectl -n kube-system delete pod "${TEST_POD}"
```

You can watch to make sure the new kube-router pod comes up and stays running
with:

```sh
kubectl -n kube-system get pods -o wide -w
```

Check the logs with:

```sh
TEST_NODE="worker-01"
TEST_POD="$(kubectl -n kube-system get pods -o wide|grep -E "^kube-router.*${TEST_NODE}"|awk '{ print $1 }')"

kubectl -n kube-system logs "${TEST_POD}"
```

If it all looks good, go ahead and upgrade kube-router on all nodes:

```sh
kubectl -n kube-system delete pods -l k8s-app=kube-router
```

### With Rolling Updates

After updating a DaemonSet template, old DaemonSet pods will be killed, and new DaemonSet pods will be created
automatically, in a controlled fashion

If your global BGP peers supports graceful restarts and has it enabled,
[rolling updates](https://kubernetes.io/docs/tasks/manage-daemon/update-daemon-set/) can be used to upgrade your
kube-router DaemonSet without network downtime.

To enable graceful BGP restart kube-router must be started with `--bgp-graceful-restart`

To enable rolling updates on your kube-router DaemonSet modify it and add a updateStrategy

```yaml
updateStrategy:
  type: RollingUpdate
  rollingUpdate:
    maxUnavailable: 1
```

maxUnavailable controls the maximum number of pods to simultaneously upgrade

Starting from the top of the DaemonSet, it should look like this after you are done editing

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  labels:
    k8s-app: kube-router
    tier: node
  name: kube-router
  namespace: kube-system
spec:
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
...
```

## Breaking Change Version History

Breaking changes for major and minor releases (v1.0+) are documented in the
[GitHub release notes](https://github.com/cloudnativelabs/kube-router/releases) for each version. Please review the
release notes for any versions you are upgrading across.
