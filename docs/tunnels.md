# Tunnels in kube-router

There are several situations in which kube-router will use tunnels in order to perform certain forms of overlay /
underlay routing within the cluster. To accomplish this, kube-router makes use of
[IPIP](https://en.wikipedia.org/wiki/IP_in_IP) overlay tunnels that are built into the Linux kernel and instrumented
with iproute2.

## Scenarios for Tunnelling

By default, kube-router enables the option `--enable-overlay` which will perform overlay networking based upon the
`--overlay-type` setting (by default set to `subnet`). So out of the box, kube-router will create a tunnel for
pod-to-pod traffic any time it comes across a kube-router enabled node that is not within the subnet of it's primary
interface.

Additionally, if `--overlay-type` is set to `full` kube-router will create an tunnel for all pod-to-pod traffic and
attempt to transit any pod traffic in the cluster via an IPIP overlay network between nodes.

Finally, kube-router also uses tunnels for DSR ([Direct Server Return](dsr.md)). In this case, the inbound traffic is
encapsulated in an IPIP packet by IPVS after it reaches the node and before it is set to the pod for processing. This
allows the return IP address of the sender to be preserved at the pod level so that it can be sent directly back to the
requestor (rather than being routed in a synchronous fashion).

## Encapsulation Types

* IPIP (IP in IP) - This is the default method of encapsulation that kube-router uses
* FoU (Foo over UDP) - This is an optional type of IPIP encapsulation that kube-router uses if the user enables it

### FoU Details

Specifically, kube-router uses GUE
([Generic UDP Encapsulation](https://developers.redhat.com/blog/2019/05/17/an-introduction-to-linux-virtual-interfaces-tunnels#gue))
in order to support both IPv4 and IPv6 FoU tunnels. This option can be enabled via the kube-router parameter
`--overlay-encap=fou`. Optionally, the user can also specify a desired port for this traffic via the
`--overlay-encap-port` parameter (by default set to `5555`).

## IPIP with Azure

Unfortunately, Azure doesn't allow IPIP encapsulation on their network. So users that want to use an overlay network
will need to enable `fou` support in order to deploy kube-router in an Azure environment.

## Changing Between Tunnel Types in a Live Cluster

While it is possible to change a running cluster between `ipip` and `fou` type tunnels, administrators should beware
that during the rollout it will cause pod-to-pod traffic to be dropped between nodes. Since, in almost all rollout
scenarios, kube-router would be rolled out gracefully one pod or host to the next, during this rollout there will be
mismatches between the encapsulation support between the two nodes as invariably one node will have an upgraded
kube-router and another node may have a previous deployment.

When this happens, they will have conflicting encapsulation setup on their tunnels and traffic will not be able to be
sent between the two nodes until they are using a consistent encapsulation protocal between them.

Once all nodes have upgraded with the destination configuration, pod-to-pod traffic patterns should return to normal.
