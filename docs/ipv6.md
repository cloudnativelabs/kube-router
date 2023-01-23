# IPv6 / DualStack Support in kube-router

This document describes the current status, the plan ahead and general thoughts about IPv6 / Dual-Stack support in
kube-router.

Dual-Stack (e.g. IPv4 and IPv6) has been supported in Kubernetes since version `v1.21`:
[IPv4/IPv6 dual-stack documentation](https://kubernetes.io/docs/concepts/services-networking/dual-stack/)

kube-router's current approach is to implement dual-stack functionality function-by-function:

 * CNI `--enable-cni`
 * Proxy `--run-service-proxy`
 * Router `--run-router`
 * Network policies `--run-firewall`


## Current status (January 22, 2023)

Support for dual-stack in kube-router is under active development and is currently the main focus of development for the
kube-router maintainers. Currently, we are targeting a v2.0.0 release of kube-router which will see all controllers
updated for dual-stack compatibility.

We are currently running this work off of the
[prep-v2.0 branch](https://github.com/cloudnativelabs/kube-router/tree/prep-v2.0) and, as of the time of this writing,
have released a [release candidate]() with this some dual-stack functionality built into it.

Functions that currently support dual-stack on the v2.0.0 release line:

* CNI
* Router / BGP (`--run-router`)
* Network Policies (`--run-firewall`)

## How Can You Help?

The work to make dual-stack support workable in kube-router has involved a lot of work and several large contributions
to the code base. If you have access to a development or staging environment where you would be willing to run the
latest v2.0.0 release candidate and give us feedback, it would be much appreciated!

While the most helpful feedback will come from users that are able to run kube-router in dual-stack mode, there have
been enough changes, that even users that are only able to run kube-router in a single-stack mode will be able to give
valuable feedback concerning any bugs or regressions.

If any users that find bugs have Golang experience, please consider helping us squash some of our dual-stack related
bugs by filing PRs against the project.

All PRs related to the new v2.0.0-based functionality will be given priority in terms of review as we work to get this
released and out into the wild so that we can work on other features and issues.

## Roadmap

The next big item to add to make kube-router fully dual-stack functional will be the **Proxy (`--run-service-proxy`)**
functionality. At this point, kube-router is not able to proxy traffic for IPv6 service VIPs at all until we get this
functionality added.

After that, we'd like to give kube-router some time to run in the wild for a bit so that we can be sure that there
aren't any large bugs or regressions before we tag an official v2.0.0 release.

## Important Notes / Known Limitations / Etc.

This represents a major release for kube-router and as such, user's should approach deploying this into an established
kube-router environment carefully. While there aren't any huge bugs that the maintainers are aware of at this time,
there are several small breaks in backwards compatibility. We'll try to detail these below as best we can.

### How To Enable Dual-Stack Functionality

In order to enable dual-stack functionality please ensure the following:

* kube-router option `--enable-ipv4=true` is set (this is the default)
* kube-router option `--enable-ipv6=true` is set
* Your Kubernetes node has both IPv4 and IPv6 addresses on its physical interfaces
* Your Kubernetes node has both IPv4 and IPv6 addresses in its node spec:

```shell
$ kubectl describe node foo
...
Addresses:
  InternalIP:  10.95.0.202
  InternalIP:  2001:1f18:3d5:ed00:d61a:454f:b886:7000
  Hostname:    foo
...
```

* Add additional `--service-cluster-ip-range` and `--service-external-ip-range` kube-router parameters for your IPv6
  addresses. Note, as mentioned before `Proxy` functionality still isn't working, but this is important for a future
  where `Proxy` functionality has been enabled.
* If you use `--enable-cni`, `kube-controller-manager` has been started with both IPv4 and IPv6 cluster CIDRs (e.g.
  `--cluster-cidr=10.242.0.0/16,2001:db8:42:1000::/56`)
* `kube-controller-manager` & `kube-apiserver` have been started with both IPv4 and IPv6 service cluster IP ranges (e.g.
  `--service-cluster-ip-range=10.96.0.0/16,2001:db8:42:1::/112`)

### Tunnel Name Changes (Potentially Breaking Change)

In order to facilitate both IPv4 and IPv6 tunnels, we had to change the hashing format for our current tunnel names. As
such, if you do a kube-router upgrade in place (i.e. without reboot), it is very likely that kube-router will not clean
up old tunnels.

This will only impact users that were utilizing the overlay feature of kube-router to some extent. Such as if you were
running kube-router with `--enable-overlay` or `--overlay-type=full` or `--overlay-type=subnet` (it should be noted that
these options default to on currently).

If you are upgrading kube-router from a pre v2.0.0 release to a v2.0.0 release, we recommend that you coordinate
your upgrade of kube-router with a rolling reboot of your Kubernetes fleet to clean up any tunnels that were left from
previous versions of kube-router.

### kube-router.io/node.bgp.customimportreject Can Only Contain IPs of a Single Family

Due to implementation restrictions with GoBGP, the annotation `kube-router.io/node.bgp.customimportreject`, which allows
user's to add rules for rejecting specific routes sent to GoBGP, can only accept a single IP family (e.g. IPv4 or IPv6).

Attempting to add IPs of two different families will result in a GoBGP error when it attempts to import BGP policy from
kube-router.

### kube-router.io/pod-cidr Deprecation

Now that kube-router has dual-stack capability, it doesn't make sense to have an annotation that can only represent
a single pod CIDR any longer. As such, with this release we are announcing the deprecation of the
`kube-router.io/pod-cidr` annotation in favor of the new `kube-router.io/pod-cidrs` annotation.

The new `kube-router.io/pod-cidrs` annotation is a comma-separated list of CIDRs and can hold either IPv4 or IPv6 CIDRs
in string form.

It should be noted, that until `kube-router.io/pod-cidr` is fully removed, at some point in the future, it will still
be preferred over the `kube-router.io/pod-cidrs` annotation in order to preserve as much backwards compatibility as
possible. Until `kube-router.io/pod-cidr` has been fully retired, user's the use the old annotation will get a warning
in their kube-router logs saying that they should change to the new annotation.

The recommended action here, is that upon upgrade, you convert nodes from using the `kube-router.io/pod-cidr` to the new
`kube-router.io/pod-cidrs` annotation. Since kube-router currently only updates node annotations at start and not as
they are updated, this is a safe change to make before updating kube-router.

If neither annotation is specified, kube-router will use the `PodCIDRs` field of the Kubernetes node spec which is
populated by the `kube-controller-manager` as part of it's `--allocate-node-cidrs` functionality. This should be a sane
default for most users of kube-router.

### CNI Now Accepts Multiple Pod Ranges

Now that kube-router supports dual-stack, it now also supports multiple ranges in the CNI file. While kube-router will
still add your pod CIDRs to your CNI configuration via node configuration like `kube-router.io/pod-cidr`,
`kube-router.io/pod-cidrs`, or `.node.Spec.PodCIDRs`, you can also customize your own CNI to add additional ranges or
plugins.

A CNI configuration with multiple ranges will typically look something like the following:

```json
{
  "cniVersion": "0.3.0",
  "name": "mynet",
  "plugins": [
    {
      "bridge": "kube-bridge",
      "ipam": {
        "ranges": [
          [
            {
              "subnet": "10.242.0.0/24"
            }
          ],
          [
            {
              "subnet": "2001:db8:42:1000::/64"
            }
          ]
        ],
        "type": "host-local"
      },
      "isDefaultGateway": true,
      "mtu": 9001,
      "name": "kubernetes",
      "type": "bridge"
    }
  ]
}
```

All kube-router's handling of the CNI file attempts to minimize disruption to any user made edits to the file.
