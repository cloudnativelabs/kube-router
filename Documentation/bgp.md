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
In this mode all the nodes are expected to be L2 adjacent.

### Node-To-Node Peering Without Full Mesh

This model support more than a single AS per cluster to allow AS per rack or AS
per node models. Nodes in the cluster does not form full node-to-node mesh.
Users has to explicitly select this mode by specifying `--nodes-full-mesh=false`
when launching kube-router. In this mode kube-router expects each node is
configured with an ASN number from the node's API object annoations. Kube-router
will use the node's `io.kube-router.net.node.asn` annotation value as the ASN
number for the node.

Users can annotate node objects with the following command:

```
kubectl annotate node <kube-node> "io.kube-router.net.node.asn=64512"
```

Only nodes with in same ASN form full mesh. Two nodes with different ASNs never
get peered.

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
--peer-router-asns="65000,65000"
```

### Node Specific External BGP Peers

Alternativley, each node can be configured with one or more node specific BGP
peers. Information regarding node specific BGP peer is read from node API object
annotations:
- `io.kube-router.net.peer.ips`
- `io.kube-router.net.peer.asns`


For e.g users can annotate node object with below commands
```
kubectl annotate node <kube-node> "io.kube-router.net.peer.ips=192.168.1.98,192.168.1.99"
kubectl annotate node <kube-node> "io.kube-router.net.peer.asns=64513"
```

### BGP Peer Password Authentication

The examples above have assumed there is no password authentication with BGP
peer routers. If you need to use a password for peering, you can use the
`--peer-router-passwords` CLI flag or the `io.kube-router.net.peer.passwords` node
annotation.

#### Base64 Encoding Passwords

To ensure passwords are easily parsed, but not easily read by human eyes,
kube-router requires that they are encoded as base64.

On a Linux or MacOS system you can encode your passwords on the command line:
```
$ echo "SecurePassword" | base64
U2VjdXJlUGFzc3dvcmQK
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
kubectl annotate node <kube-node> "io.kube-router.net.peer.ips=192.168.1.99,192.168.1.100"
kubectl annotate node <kube-node> "io.kube-router.net.peer.asns=65000,65000"
kubectl annotate node <kube-node> "io.kube-router.net.peer.passwords=U2VjdXJlUGFzc3dvcmQK,"
```
