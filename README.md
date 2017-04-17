kube-router
==========
Kube-router is a distributed load balancer, firewall and router for Kubernetes. 

Kube-router can be configured to provide on each node:

- a ingress firewall for the pods running on the node as per the defined network policies
- a service proxy on each node for 'ClusterIP' and 'NodePort' service types, providing service discovery and load
  balancing
- a router to advertise the routes to the pod IP's to the peer nodes in the cluster

Kube-router is motivated to provide:

- all in one cohesive solution that is simple to deploy and operate
- optimized for performance and scale
- easy to verify configuration and troubleshoot with standard linux networking tools

## Theory of Operation

Kube-router runs as agent on each node and leverages standard Linux technologies **iptables, ipvs/lvs, ipset, iproute2** 

### service proxy and load balancing 

Kube-router uses IPVS/LVS technology built in Linux to provide L4 load balancing. Each of the kubernetes service of **ClusterIP** and **NodePort**
type is configured as IPVS virtual service. Each service endpoint is configured as real server to the virtual service.
Standard **ipvsadm** tool can be used to verify the configuration and monitor the status. 

Below is example set of services on kubernetes

![Kube services](./Documentation/img/svc.jpg)

and the endpoints for the services

![Kube services](./Documentation/img/ep.jpg)

and how they got mapped to the ipvs by kube-router

![IPVS configuration](./Documentation/img/ipvs1.jpg)

Kube-router watches kubernetes API server to get updates on the services, endpoints and automatically syncs the ipvs
configuration to reflect desired state of services. Kube-router uses IPVS masquerading mode and uses round robin scheduling
currently. Source pod IP is preserved so thap appropriate network policies can be applied.

### pod ingress firewall 

Kube-router provides implementation of network policies semantics through the use of iptables, ipset and conntrack.
All the pods in a namespace with 'DefaultDeny' ingress isolation policy has ingress blocked. Only traffic that matches
whitelist rules specified in the network policies are permitted to reach pod. Following set of iptables rules and 
chians in the 'filter' table are used to achive the network policies semantics.

Each pod running on the node, which needs ingress blocked by default is mathced in FORWARD and OUTPUT chains of fliter table 
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

Kube-router is expected to run on each node. It is expected that a subnet lease out a preconfigured address space is
allocated to the node. Subnet of the node is learnt by kube-router from the CNI configuration file on the node. Each kube-router
instance on the node acts a BGP router and advertise the subnet assigned to the node. Each node peers with rest of the 
nodes in the cluster forming full mesh. Learned routes about the subnet from the other nodes (BGP peers) are injected into
local node routing table.

On the data path, inter node pod-to-pod communication is done by routing stack on the node. 

## Documenation

### Building

**Go version 1.7 or above is required to build kube-router**

All the dependencies are vendored already, so just run  *make* or *go build -o kube-router kube-router.go* to build
   
### Configuration
```
  --cleanup-config                  If true cleanup iptables rules, ipvs, ipset configuration and exit.
  --cni-conf-file string            Full path to CNI configuration file.
  --config-sync-period duration     How often configuration from the apiserver is refreshed. Must be greater than 0. (default 1m0s)
  --iptables-sync-period duration   The maximum interval of how often iptables rules are refreshed (e.g. '5s', '1m'). Must be greater than 0. (default 1m0s)
  --ipvs-sync-period duration       The maximum interval of how often ipvs config is refreshed (e.g. '5s', '1m', '2h22m'). Must be greater than 0. (default 1m0s)
  --kubeconfig string               Path to kubeconfig file with authorization information (the master location is set by the master flag).
  --master string                   The address of the Kubernetes API server (overrides any value in kubeconfig)
  --routes-sync-period duration     The maximum interval of how often routes are adrvertised and learned (e.g. '5s', '1m', '2h22m'). Must be greater than 0. (default 1m0s)
  --run-firewall                    If false, kube-router wont setup iptables to provide ingress firewall for pods. true by default. 
  --run-router                      If true each node advertise routes the rest of the nodes and learn the routes for the pods. false by default
  --run-service-proxy               If false, kube-router wont setup IPVS for services proxy. true by default.
```

### Running

Kube-router need to access kubernetes API server to get information on pods, services, endpoitns, network policies etc.
The very minimum infomation it requires is the details on where to access the kuberntes API server. This information can
be passed as

```
kube-router --master=http://192.168.1.99:8080/
```
or 
``` 
kube-router --kubeconfig=<path to kubeconfig file>
```

In this minimal configuration mode, kube-router provides service proxy and ingress firewall on the node on which it is running. You
can use the flags *--run-firewall*, *--run-router*, *--run-service-proxy* to selectivley run the required services.

For e.g if you just want kube-router to provide ingress firewall for the pods then you can start kube-router as 
```
kube-router --master=http://192.168.1.99:8080/ --run-service-proxy=false --run-router=false
```

You can clean up all the configurations done (to ipvs, iptables, ip routes) by kube-router on the node by running
```
 kube-router --cleanup-config
```

#### trying kube-router as alternative to kube-proxy

If you have a kube-proxy in use, and want to try kube-router just for service proxy you can do
```
kube-proxy --cleanup-iptables
```
followed by
```
kube-router --master=http://192.168.1.99:8080/ --run-firewall=false --run-router=false
```
and if you want to move back to kube-proxy then 
```
 kube-router --cleanup-config
```
and run kube-proxy with what ever configuration you have

##### pod networking
kube-router does not (at this point) do subnet managment for the node. It assumes the information is provided in the CNI conf file.

Any CNI plug-in which just does IPAM and hooking up the pods to the bridge can be used. For e.g. CNI plugin *bridge*
with below conf can be used to work with kube-router

```
{
  "name": "mynet",
  "type": "bridge",
  "bridge": "kube-bridge",
  "isDefaultGateway": true,
  "ipam": {
    "type": "host-local",
    "subnet": "10.1.3.0/24"
  }
}
```
In this case kube-router will advertise the availailibity of subnet "10.1.3.0/24" through the node ip to the peers.

Assuming CNI conf file is located at */etc/cni/net.d/mynet.conf* kube-router can be started as

```
kube-router --master=http://192.168.1.99:8080/ --run-router=true --cni-conf-file=/etc/cni/net.d/mynet.conf
```

