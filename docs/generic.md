# Kube-router on generic clusters

This guide is for running kube-router as the [CNI](https://github.com/containernetworking) network provider for on premise and/or bare metal clusters outside of a cloud provider's environment. It assumes the initial cluster is bootstrapped and a networking provider needs configuration.

All pod networking [CIDRs](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) are allocated by kube-controller-manager. Kube-router provides service/pod networking, a network policy firewall, and a high performance [IPVS/LVS](http://www.linuxvirtualserver.org/software/ipvs.html) based service proxy. The network policy firewall and service proxy are both optional but recommended.

### Configuring the Kubelet

If you choose to run kube-router as daemonset, then both kube-apiserver and kubelet must be run with `--allow-privileged=true` option

Ensure each [Kubelet](https://kubernetes.io/docs/reference/generated/kubelet/) is configured with the following options:

    --network-plugin=cni
    --cni-conf-dir=/etc/cni/net.d

If running Kubelet containerised, make sure `/etc/cni/net.d` is mapped to the host's `/etc/cni/net.d`

If a previous CNI provider (e.g. weave-net, calico, or flannel) was used, remove old configurations from `/etc/cni/net.d` on each kubelet.

_**Note: Switching CNI providers on a running cluster requires re-creating all pods to pick up new pod IPs**_

### Configuring kube-controller-manager

If you choose to use kube-router for pod-to-pod network connectivity then [kube-controller-manager](https://kubernetes.io/docs/reference/generated/kube-controller-manager/) need to be configured to allocate pod CIDRs by passing `--allocate-node-cidrs=true` flag and providing a `cluster-cidr` (i.e. by passing --cluster-cidr=10.32.0.0/12 for e.g.)

For example:

    --allocate-node-cidrs=true
    --cluster-cidr=10.32.0.0/12
    --service-cluster-ip-range=10.50.0.0/22

## Running kube-router with everything

This runs kube-router with pod/service networking, the network policy firewall, and service proxy to replace kube-proxy. The example command uses `10.32.0.0/12` as the pod CIDR address range and `https://cluster01.int.domain.com:6443` as the [apiserver](https://kubernetes.io/docs/reference/generated/kube-apiserver/) address. Please change these to suit your cluster.

    CLUSTERCIDR=10.32.0.0/12 \
    APISERVER=https://cluster01.int.domain.com:6443 \
    sh -c 'curl https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/generic-kuberouter-all-features.yaml -o - | \
    sed -e "s;%APISERVER%;$APISERVER;g" -e "s;%CLUSTERCIDR%;$CLUSTERCIDR;g"' | \
    kubectl apply -f -

### Removing a previous kube-proxy

If [kube-proxy](https://kubernetes.io/docs/reference/generated/kube-proxy/) was never deployed to the cluster, this can likely be skipped.

Remove any previously running kube-proxy and all iptables rules it created. Start by deleting the kube-proxy daemonset:

    kubectl -n kube-system delete ds kube-proxy

Any iptables rules kube-proxy left around will also need to be cleaned up. This command might differ based on how kube-proxy was setup or configured:

    docker run --privileged --net=host gcr.io/google_containers/kube-proxy-amd64:v1.7.3 kube-proxy --cleanup-iptables

## Running kube-router without the service proxy

This runs kube-router with pod/service networking and the network policy firewall. The Services proxy is disabled.

    kubectl apply -f https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/generic-kuberouter.yaml

In this mode kube-router relies on for example [kube-proxy](https://kubernetes.io/docs/reference/generated/kube-proxy/) to provide service networking.

When service proxy is disabled kube-router will use [in-cluster configuration](https://github.com/kubernetes/client-go/tree/master/examples/in-cluster-client-configuration) to access APIserver through cluster-ip. Service networking must therefore be setup before deploying kube-router.

## Debugging

kube-router supports setting log level via the command line -v or --v, To get maximal debug output from kube-router please start with `--v=3`