# Configuring BGP Peers

When kube-router is used to provide pod-to-pod networking, BGP is used to exchange routes across the nodes. Kube-router
provides flexible networking models to support different deployments (public vs private cloud, routable vs non-routable
pod IP's, service ip's etc).

## Peering Within The Cluster
### Full Node-To-Node Mesh

This is the default mode. All nodes in the clusters form iBGP peering
relationship with rest of the nodes forming full node-to-node mesh. Each node
advertise the pod CIDR allocated to the nodes with peers (rest of the nodes in
the cluster).  There is no configuration required in this mode. All the nodes in
the cluster are associated with private ASN 64512 implicitly (which can be
configured with `--cluster-asn` flag). Users are transparent to use of iBGP.
This mode is suitable in public cloud environments or small cluster deployments.

### Node-To-Node Peering Without Full Mesh

This model support more than a single AS per cluster to allow AS per rack or AS
per node models. Nodes in the cluster does not form full node-to-node mesh.
Users has to explicitly select this mode by specifying `--nodes-full-mesh=false`
when launching kube-router. In this mode kube-router expects each node is
configured with an ASN number from the node's API object annonations. Kube-router
will use the node's `kube-router.io/node.asn` annotation value as the ASN
number for the node.

Users can annotate node objects with the following command:

```
kubectl annotate node <kube-node> "kube-router.io/node.asn=64512"
```

Only nodes with in same ASN form full mesh. Two nodes with different ASNs never
get peered.

### Route-Reflector setup  Without Full Mesh

This model support the common scheme of using Route Reflector Server node to concentrate
peering from Client Peer. This has the big advantage of not needing full mesh, and
scale better. In this mode kube-router expects each node is configured either in
Route Reflector server mode or in Route Reflector client mode. This is done
with node `kube-router.io/rr.server=ClusterID`, `kube-router.io/rr.client=ClusterId`
respectively. In this mode each Route Reflector Client will only peer with Route
Reflector Servers. Each Route Reflector Server will peer other Route Reflector
Server and with Route Reflector Clients enabling reflection.

Users can annotate node objects with the following command:

```
kubectl annotate node <kube-node> "kube-router.io/rr.server=42"
```

for Route Reflector server mode, and

```
kubectl annotate node <kube-node> "kube-router.io/rr.client=42"
```

for Route Reflector client mode.

Only nodes with the same ClusterID in client and server mode will peer together.

When joining new nodes to the cluster, remember to annotate them with `kube-router.io/rr.client=42`, and then restart kube-router on the new nodes and the route reflector server nodes to let them successfully read the annotations and peer with each other.

## Peering Outside The Cluster
### Global External BGP Peers

An optional global BGP peer can be configured by specifying `--peer-router-asns`
and `--peer-router-ips` parameters. When configured each node in the cluster
forms a peer relationship with specified global peer. Pod CIDR and Cluster IP's
get advertised to the global BGP peer. For redundancy you can also configure
more than one peer router by specifying a slice of BGP peers.

For example:
```
--peer-router-ips="192.168.1.99,192.168.1.100"
--peer-router-asns=65000,65000
```

### Node Specific External BGP Peers

Alternatively, each node can be configured with one or more node specific BGP
peers. Information regarding node specific BGP peer is read from node API object
annotations:
- `kube-router.io/peer.ips`
- `kube-router.io/peer.asns`


For e.g users can annotate node object with below commands
```
kubectl annotate node <kube-node> "kube-router.io/peer.ips=192.168.1.99,192.168.1.100"
kubectl annotate node <kube-node> "kube-router.io/peer.asns=65000,65000"
```

### AS Path Prepending

For traffic shaping purposes, you may want to prepend the AS path announced to peers.
This can be accomplished on a per-node basis with annotations:
- `kube-router.io/path-prepend.as`
- `kube-router.io/path-prepend.repeat-n`

If you wanted to prepend all routes from a particular node with the AS 65000 five times,
you would run the following commands:
```
kubectl annotate node <kube-node> "kube-router.io/path-prepend.as=65000"
kubectl annotate node <kube-node> "kube-router.io/path-prepend.repeat-n=5"
```

### BGP Peer Password Authentication

The examples above have assumed there is no password authentication with BGP
peer routers. If you need to use a password for peering, you can use the
`--peer-router-passwords` command-line option, the `kube-router.io/peer.passwords` node
annotation, or the `--peer-router-passwords-file` command-line option.

#### Base64 Encoding Passwords

To ensure passwords are easily parsed, but not easily read by human eyes,
kube-router requires that they are encoded as base64.

On a Linux or MacOS system you can encode your passwords on the command line:
```
$ printf "SecurePassword" | base64
U2VjdXJlUGFzc3dvcmQ=
```

#### Password Configuration Examples

In this CLI flag example the first router (192.168.1.99) uses a password, while
the second (192.168.1.100) does not.
```
--peer-router-ips="192.168.1.99,192.168.1.100"
--peer-router-asns="65000,65000"
--peer-router-passwords="U2VjdXJlUGFzc3dvcmQK,"
```

Note the comma indicating the end of the first password.

Now here's the same example but configured as node annotations:
```
kubectl annotate node <kube-node> "kube-router.io/peer.ips=192.168.1.99,192.168.1.100"
kubectl annotate node <kube-node> "kube-router.io/peer.asns=65000,65000"
kubectl annotate node <kube-node> "kube-router.io/peer.passwords=U2VjdXJlUGFzc3dvcmQK,"
```

Finally, to include peer passwords as a file you would run kube-router with the following option:
```
--peer-router-ips="192.168.1.99,192.168.1.100"
--peer-router-asns="65000,65000"
--peer-router-passwords-file='/etc/kube-router/bgp-passwords.conf'
```

The password file, closely follows the syntax of the command-line and node annotation options.
Here, the first peer IP (192.168.1.99) would be configured with a password, while the second would not.
```
U2VjdXJlUGFzc3dvcmQK,
```

Note, complex parsing is not done on this file, please do not include any content other than the passwords on a single line in this file.

## BGP listen address list 

By default, GoBGP server binds on the node IP address. However in case of nodes with multiple IP address it is desirable to bind GoBGP to multiple local adresses. Local IP address on which GoGBP should listen on an node can be configured with annotation `kube-router.io/bgp-local-addresses`.

Here is sample example to make GoBGP server to listen on multiple IP address
```
kubectl annotate node ip-172-20-46-87.us-west-2.compute.internal "kube-router.io/bgp-local-addresses=172.20.56.25,192.168.1.99"
```

## Overriding the next hop

By default kube-router populates GoBGP RIB with node IP as next hop for the advertised pod CIDR's and service VIP. While this works for most cases, overriding the next hop for the advertised rotues is necessary when node has multiple interfaces over which external peers are reached. Next hop need to be as per the interface local IP over which external peer can be reached. `--override-nexthop` let you override the next hop for the advertised route. Setting `--override-nexthop` to true leverages BGP next-hop-self functionality implemented in GoBGP. Next hop will automatically selected appropriately when advertising routes irrespective of the next hop in the RIB. 

## Overriding the next hop and enable IPIP/tuennel

A common scenario exists where each node in the cluster is connected to two upstream routers that are in two different subnets. For example, one router is connected to a public network subnet and the other router is connected to a private network subnet. Additionally, nodes may be split across different subnets (e.g. different racks) each of which has their own routers.

In this scenario, `--override-nexthop` can be used to correctly peer with each upstream router, ensuring that the BGP next-hop attribute is correctly set to the node's IP address that faces the upstream router. The `--enable-overlay` option can be set to allow overlay/underlay tunneling across the different subnets to achieve an interconnected pod network.
 This configuration would have the following effects:

* Peering Outside the Cluster (https://github.com/cloudnativelabs/kube-router/blob/master/docs/bgp.md#peering-outside-the-cluster) via one of the many means that kube-router makes that option available
* Overriding Next Hop
* Enabling overlays in either full mode or with nodes in different subnets

The warning here is that when using `--override-nexthop` in the above scenario, it may cause kube-router to advertise an IP address other than the node IP which is what kube-router connects the tunnel to when the `--enable-overlay` option is given. If this happens it may cause some network flows to become un-routable.

Specifically, people need to take care when combining `--override-nexthop` and `--enable-overlay` and make sure that they understand their network, the flows they desire, how the kube-router logic works, and the possible side-effects that are created from their configuration. Please refer to this PR for the risk and impact discussion https://github.com/cloudnativelabs/kube-router/pull/1025.