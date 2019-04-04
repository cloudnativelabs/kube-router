# Ipv6 support in kube-router

This document describes the current status, the plan ahead and general
thoughts about ipv6 support in `kube-router`.

Ipv6-only is supported (in alpha) in `Kubernetes` from version 1.9 and
support for ipv4/ipv6 dual stack is on the way
([KEP](https://github.com/leblancd/community/blob/dual-stack-kep/keps/sig-network/0013-20180612-ipv4-ipv6-dual-stack.md)). It
is desirable for `kube-router` to keep up with that development.

The idea is to implement ipv6-only function-by-function;

 * CNI `--enable-cni`
 * Proxy `--run-service-proxy`
 * Router `--run-router`
 * Network policies `--run-firewall`

It is important to always keep dual-stack in mind. The code must not
be altered to handle ipv6 instead of ipv4 but must be able to handle
both at the same time in the near future.

To use ipv6 is usually not so hard in golang. The same code is used,
only the addresses differ. This is also true for `iptables` and
`ipvsadm`. This makes support for ipv6 a bit easier to implement.

## Testing

Test and development has so far used
https://github.com/Nordix/xcluster/tree/master/ovl/kube-router-ipv6
which is an easy way to get a ipv6-only Kubernetes cluster.

To setup an ipv6-only Kubernetes cluster is usually no simple task,
see for instance https://github.com/leblancd/kube-v6

No automatic tests exist yet for ipv6.


## Current status (Thu Oct 11 2018)

Support for ipv6 in the the CNI function in `kube-router` is under
development. The local BGP routers peers with ipv6;

```
# gobgp neighbor
Peer                AS  Up/Down State       |#Received  Accepted
1000::1:c0a8:101 64512 00:00:37 Establ      |        0         0
1000::1:c0a8:102 64512 00:00:37 Establ      |        0         0
1000::1:c0a8:103 64512 00:00:40 Establ      |        0         0
```

The CNI configuration is also updated with ipv6 addresses;

```
# jq . < /etc/cni/net.d/10-kuberouter.conf  | cat
{
  "bridge": "kube-bridge",
  "ipam": {
    "subnet": "1000::2:b00:100/120",
    "type": "host-local"
  },
  "isDefaultGateway": true,
  "isGateway": true,
  "name": "ekvm",
  "type": "bridge"
}
```

This means that pod's gets assigned ipv6 addresses.

The announcement of the pod CIDRs does not work yet. So pods on other
nodes than the own cannot be reached.

To get this working the routes must be inserted in the RIB for
`gobgp`. Checking the ipv4 rib gives an error;

```
# gobgp -a ipv4 global rib
invalid nexthop address: <nil>
```

While the ipv6 rib is empty;

```
# gobgp -a ipv6 global rib
Network not in table
```

A guess is that `kube-router` tries to insert ipv6 addresses in the
ipv4 rib.

When the bgp announcement of ipv6 cidr for pods work the support for
ipv6 in the `kube-router` CNI is done (I hope).


## Roadmap

There is no time-plan. Help is welcome.

After the CNI the next function in line may be the service
proxy. `ipvs` has full support for ipv6. The dual-stack KEP states
that to get dual stack support for a service two services must be
specified, one for ipv4 and another for ipv6. The implementation
should get the protocol from a global setting for ipv6-only and later
from some attribute in the service object.

Since the same `gobgp` is used for the CNI and the router functions is
may be fairly simple to implement ipv6 support.

Ipv6 support for the firewall function is not investigated. Ipv6 support
for `ipset` is implemented already for the CNI.




