kube-router
==========

[![Build Status](https://travis-ci.org/cloudnativelabs/kube-router.svg?branch=master)](https://travis-ci.org/cloudnativelabs/kube-router)
[![Gitter chat](http://badges.gitter.im/kube-router/Lobby.svg)](https://gitter.im/kube-router/Lobby)

Kube-router is a distributed load balancer, firewall and router for Kubernetes
clusters. It gives your cluster a unified control plane for features
that would typically be provided by two or three separate software projects.

## Project status

Project is in alpha stage. We are working towards beta release [milestone](https://github.com/cloudnativelabs/kube-router/milestone/2) and are activley incorporating users feedback.

## Primary Features

*kube-router does it all.*

With all features enabled, kube-router is a lean yet powerful alternative to
several software components used in typical Kubernetes clusters. All this from a
single DaemonSet manifest. It doesn't get any easier.

### Alternative to kube-proxy

kube-router uses the Linux kernel's IPVS features to implement its K8s Services
Proxy. This feature has been requested for some time in kube-proxy, but you can
have it right now with kube-router.

Read more about the advantages of IPVS for container load balancing:
- https://cloudnativelabs.github.io/post/2017-05-10-kube-network-service-proxy/
- https://blog.codeship.com/kernel-load-balancing-for-docker-containers-using-ipvs/

### Pod Networking Plugin

kube-router handles Pod networking efficiently with direct routing thanks to the
BGP protocol and the GoBGP library. It uses the native Kubernetes API to
maintain distributed pod networking state. That means no dependency on a
separate datastore to maintain in your cluster.

kube-router's elegant design also means there is no dependency on another CNI
plugin. The official "bridge" plugin provided by the CNI project is all you
need -- and chances are you already have it in your CNI binary directory!

Read more about the advantages and potential provided by BGP Kubernetes:
- https://cloudnativelabs.github.io/post/2017-05-22-kube-pod-networking/

### Network Policy Controller

Enabling Kubernetes Network Policies is easy with kube-router -- just add a flag
to kube-router. It uses ipsets with iptables to ensure your firewall rules have
as little performance impact on your cluster as possible.

## Additional Features

There's more to kube-router than the features mentioned above.  We're just
getting started with kube-router and the enormous potential IPVS and BGP provide
to Kubernetes clusters, however, here's some more fun things that are ready for
you to try out today.

### Advanced BGP Capabilities

If you have other networking devices or SDN systems that talk BGP, kube-router
will fit in perfectly. From a simple full node-to-node mesh to per-node peering
configurations, most routing needs can be attained. The configuration is
Kubernetes native (annotations) just like the rest of kube-router, so use the
tools you already know! Since kube-router uses GoBGP, you have access to a
modern BGP API platform as well right out of the box.

For more details please refer to the [BGP documentation](Documentation/bgp.md).

### Small Footprint

Although it does the work of several of its peers in one binary, kube-router
does it all with a relatively tiny codebase, partly because IPVS is already
there on your Kuberneres nodes waiting to help you do amazing things.
kube-router brings that and GoBGP's modern BGP interface to you in an elegant
package designed from the ground up for Kubernetes.

### It Is Fast

The combination of BGP for inter-node Pod networking and IPVS for load balanced
proxy Services is a perfect recipe for high-performance clusters at scale. BGP
ensures that the data path is dynamic and efficient, and IPVS provides in-kernel
load balancing that has been thouroughly tested and optimized.

## Getting Started

Use below guides to get started.

- [Architecture](./Documentation/README.md#architecture)
- [Users Guide](./Documentation/README.md#user-guide)
- [Developers Guide](./Documentation/developing.md)

## Contributing

We encourage all kinds of contributions, be they documentation, code, fixing
typos, tests — anything at all. Please read the [contribution guide](./CONTRIBUTING.md).

## Support & Feedback

If you experience any problems please reach us on our gitter
[community forum](https://gitter.im/kube-router/Lobby)
for quick help. Feel free to leave feedback or raise questions at any time by
opening an issue [here](https://github.com/cloudnativelabs/kube-router/issues).

## See it in action

<a href="https://asciinema.org/a/118056" target="_blank"><img src="https://asciinema.org/a/118056.png" /></a>


## Theory of Operation

Kube-router can be run as a agent or a pod (through daemonset) on each node and
leverages standard Linux technologies **iptables, ipvs/lvs, ipset, iproute2**

### service proxy and load balancing

Refer to
https://cloudnativelabs.github.io/post/2017-05-10-kube-network-service-proxy/
for the design details and demo

Kube-router uses IPVS/LVS technology built in Linux to provide L4 load
balancing. Each of the kubernetes service of **ClusterIP** and **NodePort** type
is configured as IPVS virtual service. Each service endpoint is configured as
real server to the virtual service.  Standard **ipvsadm** tool can be used to
verify the configuration and monitor the active connections.

Below is example set of services on kubernetes

![Kube services](./Documentation/img/svc.jpg)

and the endpoints for the services

![Kube services](./Documentation/img/ep.jpg)

and how they got mapped to the ipvs by kube-router

![IPVS configuration](./Documentation/img/ipvs1.jpg)

Kube-router watches kubernetes API server to get updates on the services,
endpoints and automatically syncs the ipvs configuration to reflect desired
state of services. Kube-router uses IPVS masquerading mode and uses round robin
scheduling currently. Source pod IP is preserved so that appropriate network
policies can be applied.

### pod ingress firewall

refer to https://cloudnativelabs.github.io/post/2017-05-1-kube-network-policies/
for the detailed design details

Kube-router provides implementation of network policies semantics through the
use of iptables, ipset and conntrack.  All the pods in a namespace with
'DefaultDeny' ingress isolation policy has ingress blocked. Only traffic that
matches whitelist rules specified in the network policies are permitted to reach
pod. Following set of iptables rules and chains in the 'filter' table are used
to achieve the network policies semantics.

Each pod running on the node, which needs ingress blocked by default is matched
in FORWARD and OUTPUT chains of fliter table and send to pod specific firewall
chain. Below rules are added to match various cases

- traffic getting switched between the pods on the same node through bridge
- traffic getting routed between the pods on different nodes
- traffic originating from a pod and going through the service proxy and getting routed to pod on same node

![FORWARD/OUTPUT chain](./Documentation/img/forward.png)

Each pod specific firewall chain has default rule to block the traffic. Rules
are added to jump traffic to the network policy specific policy chains. Rules
cover only policies that apply to the destination pod ip. A rule is added to
accept the the established traffic to permit the return traffic.

![Pod firewall chain](./Documentation/img/podfw.png)

Each policy chain has rules expressed through source and destination ipsets. Set
of pods matching ingress rule in network policy spec forms a source pod ip
ipset. set of pods matching pod selector (for destination pods) in the network
policy forms destination pod ip ipset.

![Policy chain](./Documentation/img/policyfw.png)

Finally ipsets are created that are used in forming the rules in the network
policy specific chain

![ipset](./Documentation/img/ipset.jpg)

Kube-router at runtime watches Kubernetes API server for changes in the
namespace, network policy and pods and dynamically updates iptables and ipset
configuration to reflect desired state of ingress firewall for the the pods.

### Pod networking

Please see the
[blog](https://cloudnativelabs.github.io/post/2017-05-22-kube-pod-networking/)
for design details.

Kube-router is expected to run on each node. Subnet of the node is learnt by
kube-router from the CNI configuration file on the node or through the
node.PodCidr. Each kube-router instance on the node acts a BGP router and
advertise the pod CIDR assigned to the node. Each node peers with rest of the
nodes in the cluster forming full mesh. Learned routes about the pod CIDR from
the other nodes (BGP peers) are injected into local node routing table. On the
data path, inter node pod-to-pod communication is done by routing stack on the
node.

## TODO
- ~~convert Kube-router to docker image and run it as daemonset~~
- heathcheck pods
- explore integration of an ingress controller so Kube-router will be one complete solution for both east-west and north-south traffic
- ~~get pod CIDR from node.PodCidr when kube-controller-manager is run with `--allocate-node-cidrs=true` option~~
- explore the possibility of using IPVS direct routing mode
- Explore the possibilities of making Kube-router on the node a Prometheus endpoint
- ~~session persistence~~

## Acknowledgement

Kube-router build upon following libraries:

- Iptables: https://github.com/coreos/go-iptables
- GoBGP: https://github.com/osrg/gobgp
- Netlink: https://github.com/vishvananda/netlink
- Ipset: https://github.com/janeczku/go-ipset
- IPVS: https://github.com/mqliang/libipvs

