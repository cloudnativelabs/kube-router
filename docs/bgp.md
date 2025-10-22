# Configuring BGP Peers

When kube-router is used to provide pod-to-pod networking, BGP is used to exchange routes across the nodes. Kube-router
provides flexible networking models to support different deployments (public vs private cloud, routable vs non-routable
pod IPs, service IPs, etc.).

## Peering Within The Cluster

### Full Node-To-Node Mesh

This is the default mode. All nodes in the clusters form iBGP peering relationships with rest of the nodes forming a
full node-to-node mesh. Each node advertise the pod CIDR allocated to the nodes with its peers (the rest of the nodes in
the cluster). There is no configuration required in this mode. All the nodes in the cluster are associated with the
private ASN 64512 implicitly (which can be configured with `--cluster-asn` flag) and users are transparent to use of
iBGP. This mode is suitable in public cloud environments or small cluster deployments.

### Node-To-Node Peering Without Full Mesh

This model is used to support more than a single AS per cluster to allow for an AS per rack or an AS per node. Nodes in
the cluster do not form full node-to-node meshes. Users have to explicitly select this mode by specifying
`--nodes-full-mesh=false` when launching kube-router. In this mode kube-router expects each node will be configured with
an ASN number from the node's API object annotations. Kube-router will use the node's `kube-router.io/node.asn`
annotation value as the ASN number for the node.

Users can annotate node objects with the following command:

```sh
kubectl annotate node <kube-node> "kube-router.io/node.asn=64512"
```

Only nodes within same ASN form full mesh. Two nodes with different ASNs never get peered.

### Route-Reflector setup Without Full Mesh

This model supports the common scheme of using a Route Reflector Server node to concentrate peering from client peers.
This has the big advantage of not needing full mesh, and will scale better. In this mode kube-router expects each node
is configured either in Route Reflector server mode or in Route Reflector client mode. This is done with node
`kube-router.io/rr.server=ClusterID`, `kube-router.io/rr.client=ClusterId` respectively. In this mode each route
reflector client will only peer with route reflector servers. Each route reflector server will only peer with other
route reflector servers and with route reflector clients enabling reflection.

Users can annotate node objects with the following command for Route Reflector server mode:

```sh
kubectl annotate node <kube-node> "kube-router.io/rr.server=42"
```

and for Route Reflector client mode:

```sh
kubectl annotate node <kube-node> "kube-router.io/rr.client=42"
```

Only nodes with the same ClusterID in client and server mode will peer together.

When joining new nodes to the cluster, remember to annotate them with `kube-router.io/rr.client=42`, and then restart
kube-router on the new nodes and the route reflector server nodes to let them successfully read the annotations and peer
with each other.

## Peering Outside The Cluster

### Global External BGP Peers

An optional global BGP peer can be configured by specifying the parameters: `--peer-router-asns` and
`--peer-router-ips`. When configured each node in the cluster forms a peer relationship with specified global peer.
Pod CIDR and Cluster IPs get advertised to the global BGP peer. For redundancy, you can also configure more than one
peer router by specifying a slice of BGP peers.

For example:

```sh
--peer-router-ips="192.168.1.99,192.168.1.100"
--peer-router-asns=65000,65000
```

### Node Specific External BGP Peers

Each node can be configured with one or more node specific BGP peers using the `kube-router.io/peers` node annotation.
Previously, these settings were configured using individual `kube-router.io/peer.*` annotations.
While these individual annotations are still supported, they're now deprecated and
will be removed in a future release.

#### Using Consolidated Annotation

The `kube-router.io/peers` annotation accepts peer configurations in YAML format with the following fields:

- `remoteip` (required): The IP address of the peer
- `remoteasn` (required): The ASN of the peer
- `localip` (optional): Local IP address to use for this peer connection
- `password` (optional): Base64 encoded password for BGP authentication
- `port` (optional): BGP port (defaults to 179 if not specified)

```shell
kubectl annotate node <kube-node> \
kube-router.io/peers="$(cat <<'EOF'
- remoteip: 192.168.1.99
  remoteasn: 65000
  password: U2VjdXJlUGFzc3dvcmQK,
- remoteip: 192.168.1.100
  remoteasn: 65000'
  password: U2VjdXJlUGFzc3dvcmQK,
EOF
)"
```

#### Using Individual Annotations (Deprecated)

> **NOTE:** The individual peer annotations listed below are deprecated in favor of the consolidated `kube-router.io/peers`
> annotation. They are maintained for backward compatibility but will be removed in a future release.

Node-specific BGP peer configs can also be set via individual node API object annotations:

- `kube-router.io/peer.ips`
- `kube-router.io/peer.asns`
- `kube-router.io/peer.passwords`
- `kube-router.io/peer.localips`

For example, users can annotate node object with below commands:

```shell
kubectl annotate node <kube-node> "kube-router.io/peer.ips=192.168.1.99,192.168.1.100"
kubectl annotate node <kube-node> "kube-router.io/peer.asns=65000,65000"
```

### AS Path Prepending

For traffic shaping purposes, you may want to prepend the AS path announced to peers. This can be accomplished on a
per-node basis with annotations:

- `kube-router.io/path-prepend.as`
- `kube-router.io/path-prepend.repeat-n`

If you wanted to prepend all routes from a particular node with the AS 65000 five times, you would run the following
commands:

```shell
kubectl annotate node <kube-node> "kube-router.io/path-prepend.as=65000"
kubectl annotate node <kube-node> "kube-router.io/path-prepend.repeat-n=5"
```

### BGP Peer Local IP configuration

In some setups it might be desirable to set a local IP address used for connecting external BGP peers.

When using the `kube-router.io/peers` annotation, specify the `localip` field for each peer as shown in the
[Node Specific External BGP Peers](#node-specific-external-bgp-peers) section above.

When using individual annotations, you can specify the local IP address using `kube-router.io/peer.localips`:

```shell
kubectl annotate node <kube-node> "kube-router.io/peer.localips=10.1.1.1,10.1.1.2"
```

If set, this must be a list with a local IP address for each peer, or left empty to use nodeIP.

### BGP Peer Password Authentication

If you need to use a password for peering with BGP peer routers, you can configure it using the `kube-router.io/peers`
annotation, the `--peer-router-passwords` command-line option, the deprecated `kube-router.io/peer.passwords` node
annotation, or the `--peer-router-passwords-file` command-line option.

#### Base64 Encoding Passwords

To ensure passwords are easily parsed, but not easily read by human eyes, kube-router requires that they are encoded as
base64.

On a Linux or MacOS system you can encode your passwords on the command line:

```shell
$ printf "SecurePassword" | base64
U2VjdXJlUGFzc3dvcmQ=
```

#### Password Configuration Examples

**Using the consolidated annotation (recommended):**

When using the `kube-router.io/peers` annotation, specify the `password` field with a base64 encoded password for each
peer that requires authentication. See the [Node Specific External BGP Peers](#node-specific-external-bgp-peers) section for an example.

**Using CLI flags:**

In this example the first router (192.168.1.99) uses a password, while the second (192.168.1.100) does not:

```sh
--peer-router-ips="192.168.1.99,192.168.1.100"
--peer-router-asns="65000,65000"
--peer-router-passwords="U2VjdXJlUGFzc3dvcmQK,"
```

Note the comma indicating the end of the first password.

**Using individual annotations (deprecated):**

Here's the same example but configured with individual node annotations:

```shell
kubectl annotate node <kube-node> "kube-router.io/peer.ips=192.168.1.99,192.168.1.100"
kubectl annotate node <kube-node> "kube-router.io/peer.asns=65000,65000"
kubectl annotate node <kube-node> "kube-router.io/peer.passwords=U2VjdXJlUGFzc3dvcmQK,"
```

**Using a password file:**

Finally, to include peer passwords as a file you would run kube-router with the following option:

```shell
--peer-router-ips="192.168.1.99,192.168.1.100"
--peer-router-asns="65000,65000"
--peer-router-passwords-file="/etc/kube-router/bgp-passwords.conf"
```

The password file closely follows the syntax of the command-line and node annotation options.
Here, the first peer IP (192.168.1.99) would be configured with a password, while the second would not:

```sh
U2VjdXJlUGFzc3dvcmQK,
```

Note, complex parsing is not done on this file, please do not include any content other than the passwords on a single
line in this file.

### BGP Communities

Global peers support the addition of BGP communities via node annotations. Node annotations can be formulated either as:

- a single 32-bit integer
- two 16-bit integers separated by a colon (`:`)
- common BGP community names (e.g. `no-export`, `internet`, `no-peer`, etc.)
  (see: [WellKnownCommunityNameMap](https://github.com/osrg/gobgp/blob/cbdb752b10847163d9f942853b67cf173b6aa151/pkg/packet/bgp/bgp.go#L9444))

In the following example we add the `NO_EXPORT` BGP community to two of our nodes via annotation using all three forms
of the annotation:

```shell
kubectl annotate node <kube-node> "kube-router.io/node.bgp.communities=4294967041"
kubectl annotate node <kube-node> "kube-router.io/node.bgp.communities=65535:65281"
kubectl annotate node <kube-node> "kube-router.io/node.bgp.communities=no-export"
```

### Custom BGP Import Policy Reject

kube-router, by default, accepts all routes advertised by its neighbors.

If the bgp session with one neighbor dies, GoBGP deletes all routes received by it.

If one of the received routes is needed for this node to function properly (eg: custom static route), it could stop
working.

In the following example we add custom prefixes that'll be set via a custom import policy reject rule annotation,
protecting the node from losing required routes:

```shell
kubectl annotate node <kube-node> "kube-router.io/node.bgp.customimportreject=10.0.0.0/16, 192.168.1.0/24"
```

## BGP listen address list

By default, the GoBGP server binds on the node IP address. However, in some cases nodes with multiple IP addresses
desire to bind GoBGP to multiple local addresses. Local IP addresses on which GoGBP should listen on a node can be
configured with annotation `kube-router.io/bgp-local-addresses`.

Here is sample example to make GoBGP server to listen on multiple IP address:

```shell
kubectl annotate node ip-172-20-46-87.us-west-2.compute.internal "kube-router.io/bgp-local-addresses=172.20.56.25,192.168.1.99"
```

## Overriding the next hop

By default, kube-router populates the GoBGP RIB with node IP as next hop for the advertised pod CIDRs and service VIPs.
While this works for most cases, overriding the next hop for the advertised routes is necessary when node has multiple
interfaces over which external peers are reached. Next hops need to be defined as the interface over which external
peer can be reached. Setting `--override-nexthop` to true leverages the BGP next-hop-self functionality implemented in
GoBGP. The next hop will automatically be selected appropriately when advertising routes, irrespective of the next hop
in the RIB.

## Overriding the next hop and enable IPIP/tunnel

A common scenario exists where each node in the cluster is connected to two upstream routers that are in two different
subnets. For example, one router is connected to a public network subnet and the other router is connected to a private
network subnet. Additionally, nodes may be split across different subnets (e.g. different racks) each of which has their
own routers.

In this scenario, `--override-nexthop` can be used to correctly peer with each upstream router, ensuring that the BGP
next-hop attribute is correctly set to the node's IP address that faces the upstream router. The `--enable-overlay`
option can be set to allow overlay/underlay tunneling across the different subnets to achieve an interconnected pod
network.

This configuration would have the following effects:

- [Peering Outside the Cluster](https://github.com/cloudnativelabs/kube-router/blob/master/docs/bgp.md#peering-outside-the-cluster)
  via one of themany means that kube-router makes available
- Overriding Next Hop
- Enabling overlays in either full mode or with nodes in different subnets

The warning here is that when using `--override-nexthop` in the above scenario, it may cause kube-router to advertise an
IP address other than the node IP which is what kube-router connects the tunnel to when the `--enable-overlay` option is
given. If this happens it may cause some network flows to become un-routable.

Specifically, people need to take care when combining `--override-nexthop` and `--enable-overlay` and make sure that
they understand their network, the flows they desire, how the kube-router logic works, and the possible side effects
that are created from their configuration. Please refer to [this PR](https://github.com/cloudnativelabs/kube-router/pull/1025)
for the risk and impact discussion.
