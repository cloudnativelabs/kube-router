# See Kube-router in action

## Network Services Controller

Network services controller is responsible for reading the services and endpoints information from Kubernetes API server and configure IPVS on each cluster node accordingly.

Please our read blog for design details and pros and cons compared to iptables based Kube-proxy
https://cloudnativelabs.github.io/post/2017-05-10-kube-network-service-proxy/

Demo of Kube-router's IPVS based Kubernetes network service proxy

[![asciicast](https://asciinema.org/a/120312.png)](https://asciinema.org/a/120312)

Features:
- round robin load balancing
- client IP based session persistence
- source IP is preserved if service controller is used in conjuction with network routes controller (kube-router with --run-router flag)
- option to explicitly masquerade (SNAT) with --masquerade-all flag

## Network Policy Controller

Network policy controller is responsible for reading the namespace, network policy and pods information from Kubernetes API server and configure iptables accordingly to provide ingress filter to the pods.

Kube-router supports the networking.k8s.io/NetworkPolicy API or network policy V1/GA
[semantics](https://github.com/kubernetes/kubernetes/pull/39164#issue-197243974) and also network policy beta semantics.

Please read blog for design details of Network Policy controller
https://cloudnativelabs.github.io/post/2017-05-1-kube-network-policies/

Demo of Kube-router's iptables based implementaton of network policies

[![asciicast](https://asciinema.org/a/120735.png)](https://asciinema.org/a/120735)

## Network Routes Controller

Network routes controller is responsible for reading pod CIDR allocated by controller manager to the node, and advertises the routes to the rest of the nodes in the cluster (BGP peers). Use of BGP is transperent to user for basic pod-to-pod networking.

[![asciicast](https://asciinema.org/a/120885.png)](https://asciinema.org/a/120885)

However BGP can be leveraged to other use cases like advertising the cluster ip, routable pod ip etc. Only in such use-cases understanding of BGP and configuration is required. Please see below demo how kube-router advertises cluster IP and pod cidrs to external BGP router
[![asciicast](https://asciinema.org/a/121635.png)](https://asciinema.org/a/121635)