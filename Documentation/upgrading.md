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
```
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
After updating a DaemonSet template, old DaemonSet pods will be killed, and new DaemonSet pods will be created automatically, in a controlled fashion

If your global BGP peers supports gracefull restarts and has it enabled, [rolling updates](https://kubernetes.io/docs/tasks/manage-daemon/update-daemon-set/) can be used to upgrade your kube-router DaemonSet without network downtime
To enable gracefull BGP restart kube-router must be started with `--bgp-graceful-restart`

To enable rolling updates on your kube-router DaemonSet modify it and add a updateStrategy

      updateStrategy:
        type: RollingUpdate
        rollingUpdate:
          maxUnavailable: 1

maxUnavailable controls the maximum number of pods to simultaneously upgrade

Starting from the top of the DaemonSet, it should look like this after you are done editing

    apiVersion: extensions/v1beta1
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

## Breaking Change Version History

This section covers version specific upgrade instructions.

### v0.0.X alpha versions

While kube-router is in its alpha stage changes can be expected to be rapid.
Therefor we cannot guarantee that a new alpha release will not break previous
expected behavior.

### v0.0.17 (aka v0.1.0-rc1)

This version brings changes to hairpin and BGP peering CLI/annotation
configuration flags/keys.

CLI flag changes:
- OLD: `--peer-router` -> NEW: `--peer-router-ips`
- OLD: `--peer-asn` -> NEW: `--peer-router-asns`

CLI flag additions:
- NEW: `--peer-router-passwords`

Annotation key changes:
- OLD: `kube-router.io/hairpin-mode=` -> NEW:
  `kube-router.io/service.hairpin=`
- OLD: `net.kuberouter.nodeasn=` -> NEW: `kube-router.io/node.asn=`
- OLD: `net.kuberouter.node.bgppeer.address=` -> NEW: `kube-router.io/peer.ips`
- OLD: `net.kuberouter.node.bgppeer.asn` -> NEW: `kube-router.io/peer.asns`

Annotation key additions:
- NEW: `kube-router.io/peer.passwords`

#### v0.0.17 Upgrade Procedure

For CLI flag changes, all that is required is to change the flag names you use
above to their new names at the same time that you change the image version.
```
kubectl -n kube-system edit ds kube-router
```

For Annotations, the recommended approach is to copy all the values of
your current annotations into new annotations with the updated keys.

You can get a quick look at all your service and node annotations with these
commands:
```sh
kubectl describe services --all-namespaces |grep -E '^(Name:|Annotations:)'
kubectl describe nodes |grep -E '^(Name:|Annotations:)'
```

For example if you have a service annotation to enable Hairpin mode like:
```
Name:              hairpin-service
Annotations:       kube-router.io/hairpin-mode=
```

You will then want to make a new annotation with the new key:
```sh
kubectl annotate service hairpin-service "kube-router.io/service.hairpin="
```

Once all new annotations are created, proceed with the
[General Guidelines](#general-guidelines). After the upgrades tested and
complete, you can delete the old annotations.
```sh
kubectl annotate service hairpin-service "kube-router.io/hairpin-mode-"
```
