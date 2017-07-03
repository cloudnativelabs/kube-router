## Configuring BGP Peers

When kube-router is used to provide pod-to-pod networking, BGP is used to exchange routes across the nodes. Kube-router
provides flexible networking models to support different deployment (public vs private cloud, routable vs non-routable 
pod IP's, service ip's etc) 

### Full node-to-node mesh

This is the default mode. All nodes in the clusters form iBGP peering relationship with rest of the nodes forming full 
node-to-node mesh. Each node advertise the pod CIDR allocated to the nodes with peers (rest of the nodes in the cluster). 
There is no configuration required in this mode. All the nodes in the cluster are associated with private ASN 64512 
implicitly (which can be configured with `--cluster-asn` flag). Users are transparent to use of iBGP. This mode is
suitable in public cloud environments or small cluster deployments. In this mode all the nodes are expected to be L2 adjacent.

### Node specific BGP peers

This model support more than a single AS per cluster to allow AS per rack or AS per node models. Nodes in the cluster
does not form full node-to-node mesh. Users has to explicitly select this mode by specifying `--nodes-full-mesh=false` 
when launching kube-router. In this mode kube-router expects each node is configured with ASN number to be used for the 
node from the nodes API object annoations. Kube-router will use the configured value for the key `net.kuberouter.nodeasn`
in the node object as the ASN number for the node.

Users can annotate node object with below command

```
kubectl annotate node <kube-node> "net.kuberouter.nodeasn=64512”"
```

Only nodes with in same ASN form full mesh. Two nodes with different configured ASN never gets peered.

### Global BGP Peer

An optional global BGP peer can be configured by specifying `--peer-asn` and `--peer-router` parameters. When configured
each node in the cluster forms a peer relationship with specified global peer. Pod cidr, cluster IP's get advertised to
the global BGP peer. For redundancy you can also configure more than one peer router by specifying comma seperated list
of BGP peers for `--peer-router` flag, like `--peer-router=192.168.1.99,192.168.1.100`

### Node specific BGP peer

Alternativley, each node can be configured with one or mode node specific BGP peer. Information regarding node specific BGP peer is
read from node API object annotations `net.kuberouter.node.bgppeer.address` and `net.kuberouter.node.bgppeer.asn`.


For e.g users can annotate node object with below commands
```
kubectl annotate node <kube-node> “net.kuberouter.node.bgppeer.address=192.168.1.98,192.168.1.99”
kubectl annotate node <kube-node> "net.kuberouter.node.bgppeer.asn=64513”"
```
