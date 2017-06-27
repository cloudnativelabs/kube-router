kube-router
==========

[![Build Status](https://travis-ci.org/cloudnativelabs/kube-router.png?branch=master)](https://travis-ci.org/cloudnativelabs/kube-router)
[![Gitter chat](http://badges.gitter.im/kube-router/Lobby.png)](https://gitter.im/kube-router/Lobby)

Kube-router is a distributed load balancer, firewall and router for Kubernetes. Kube-router can be configured to provide on each cluster node:

- a IPVS/LVS based service proxy on each node for *ClusterIP* and *NodePort* service types, providing service discovery and load balancing
- an ingress firewall for the pods running on the node as per the defined Kubernetes network policies using iptables and ipset
- a BGP router to advertise and learn the routes to the pod IP's for cross-node pod-to-pod connectivity

## Why Kube-router
We have Kube-proxy which provides service proxy and load balancer. We have several addons or solutions like Flannel, Calico, Weave etc to provide cross node pod-to-pod networking. Simillarly there are solutions like Calico that enforce network policies. Then why do we need Kube-router for a similar job? Here is the motivation:

- It is challenging to deploy, monitor and troubleshoot multiple solutions at runtime. These independent solution need to work well together. Kube-router aims to provide operational simplicity by combining all the networking functionality that can be provided at the node in to one cohesive solution. Run Kube-router as daemonset, by just running one command ``kubectl create -f kube-router-daemonset.yaml`` you have solution for pod-to-pod networking, service proxy and firewall on each node.

- Kube-router is motivated to provide optimized solution for performance. Kube-router uses IPVS for service proxy as compared to iptables by Kube-proxy. Kube-router uses solutions like ipsets to optimize iptables rules matching while providing ingress firewall for the pods. For inter-node pod-to-pod communication, routing rules added by kube-router ensures data path is efficient (one hop for pod-to-pod connectivity) with out overhead of overlays.

- Kube-router builds on standard Linux technologies, so you can verify the configuration and troubleshoot with standard Linux networking tools (ipvsadm, ip route, iptables, ipset, traceroute, tcpdump etc).

## See it in action

<a href="https://asciinema.org/a/118056" target="_blank"><img src="https://asciinema.org/a/118056.png" /></a>

## Project status

Project is in alpha stage. We are working towards beta release [milestone](https://github.com/cloudnativelabs/kube-router/milestone/2) and are activley incorporating users feedback.

## Support & Feedback

If you experience any problems please reach us on gitter [community forum](https://gitter.im/kube-router/Lobby) for quick help. Feel free to leave feedback or raise questions at any time by opening an issue [here](https://github.com/cloudnativelabs/kube-router/issues).

## Getting Started

Use below guides to get started.

- [Architecture](./Documentation/README.md#architecture)
- [Users Guide](./Documentation/README.md#user-guide)
- [Developers Guide](./Documentation/README.md#develope-guide)

## Contribution

We encourage all kinds of contributions, be they documentation, code, fixing typos, tests — anything at all. Please
read the [contribution guide](./CONTRIBUTING.md).

## Theory of Operation

Kube-router can be run as a agent or a pod (through daemonset) on each node and leverages standard Linux technologies **iptables, ipvs/lvs, ipset, iproute2** 

### service proxy and load balancing 

refer to https://cloudnativelabs.github.io/post/2017-05-10-kube-network-service-proxy/ for the design details and demo

Kube-router uses IPVS/LVS technology built in Linux to provide L4 load balancing. Each of the kubernetes service of **ClusterIP** and **NodePort** type is configured as IPVS virtual service. Each service endpoint is configured as real server to the virtual service.
Standard **ipvsadm** tool can be used to verify the configuration and monitor the active connections. 

Below is example set of services on kubernetes

![Kube services](./Documentation/img/svc.jpg)

and the endpoints for the services

![Kube services](./Documentation/img/ep.jpg)

and how they got mapped to the ipvs by kube-router

![IPVS configuration](./Documentation/img/ipvs1.jpg)

Kube-router watches kubernetes API server to get updates on the services, endpoints and automatically syncs the ipvs
configuration to reflect desired state of services. Kube-router uses IPVS masquerading mode and uses round robin scheduling
currently. Source pod IP is preserved so that appropriate network policies can be applied.

### pod ingress firewall 

refer to https://cloudnativelabs.github.io/post/2017-05-1-kube-network-policies/ for the detailed design details

Kube-router provides implementation of network policies semantics through the use of iptables, ipset and conntrack.
All the pods in a namespace with 'DefaultDeny' ingress isolation policy has ingress blocked. Only traffic that matches
whitelist rules specified in the network policies are permitted to reach pod. Following set of iptables rules and 
chains in the 'filter' table are used to achieve the network policies semantics.

Each pod running on the node, which needs ingress blocked by default is matched in FORWARD and OUTPUT chains of fliter table 
and send to pod specific firewall chain. Below rules are added to match various cases

- traffic getting switched between the pods on the same node through bridge
- traffic getting routed between the pods on different nodes
- traffic originating from a pod and going through the service proxy and getting routed to pod on same node

![FORWARD/OUTPUT chain](./Documentation/img/forward.png)

Each pod specific firewall chain has default rule to block the traffic. Rules are added to jump traffic to the network policy 
specific policy chains. Rules cover only policies that apply to the destination pod ip. A rule is added to accept the
the established traffic to permit the return traffic.

![Pod firewall chain](./Documentation/img/podfw.png)

Each policy chain has rules expressed through source and destination ipsets. Set of pods matching ingress rule in network policy spec
forms a source pod ip ipset. set of pods matching pod selector (for destination pods) in the network policy forms
destination pod ip ipset.

![Policy chain](./Documentation/img/policyfw.png)

Finally ipsets are created that are used in forming the rules in the network policy specific chain

![ipset](./Documentation/img/ipset.jpg)

Kube-router at runtime watches Kubernetes API server for changes in the namespace, network policy and pods and
dynamically updates iptables and ipset configuration to reflect desired state of ingress firewall for the the pods.

### Pod networking

Please see the [blog](https://cloudnativelabs.github.io/post/2017-05-22-kube-pod-networking/) for design details.

Kube-router is expected to run on each node. Subnet of the node is learnt by kube-router from the CNI configuration file on the node or through the node.PodCidr. Each kube-router
instance on the node acts a BGP router and advertise the pod CIDR assigned to the node. Each node peers with rest of the 
nodes in the cluster forming full mesh. Learned routes about the pod CIDR from the other nodes (BGP peers) are injected into
local node routing table. On the data path, inter node pod-to-pod communication is done by routing stack on the node.


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

