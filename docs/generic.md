# Kube-router on generic clusters

This guide is for running kube-router as the [CNI](https://github.com/containernetworking) network provider for on
premise and/or bare metal clusters outside of a cloud provider's environment. It assumes the initial cluster is
bootstrapped and a networking provider needs configuration.

All pod networking [CIDRs](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) are allocated by
kube-controller-manager. Kube-router provides service/pod networking, a network policy firewall, and a high performance
[IPVS/LVS](http://www.linuxvirtualserver.org/software/ipvs.html) based service proxy. The network policy firewall and
service proxy are both optional but recommended.

## Configuring the Worker Nodes

If you choose to run kube-router as daemonset, then both kube-apiserver and kubelet must be run with
`--allow-privileged=true` option (see our
[example daemonsets for more information](https://github.com/cloudnativelabs/kube-router/tree/master/daemonset))

Ensure your [Container Runtime](https://kubernetes.io/docs/setup/production-environment/container-runtimes/) is
configured to point its CNI configuration directory to `/etc/cni/net.d`.

This is the default location for both `containerd` and `cri-o`, but can be set specifically if needed:

### containerd CRI Configuration

Here is what the default containerd CNI plugin configuration looks like as of the writing of this document. The default
containerd configuration can be retrieved using:

```sh
containerd config default
```

```toml
[plugins]
    [plugins."io.containerd.grpc.v1.cri".cni]
      bin_dir = "/opt/cni/bin"
      conf_dir = "/etc/cni/net.d"
      conf_template = ""
      ip_pref = ""
      max_conf_num = 1
```

### cri-o CRI Configuration

cri-o CRI configuration can be referenced via their
[documentation](https://github.com/cri-o/cri-o/blob/main/docs/crio.conf.5.md#crionetwork-table)

If a previous CNI provider (e.g. weave-net, calico, or flannel) was used, remove old configurations from
`/etc/cni/net.d` on each kubelet.

### Note: Switching CNI providers on a running cluster requires re-creating all pods to pick up new pod IPs**

## Configuring kube-controller-manager

If you choose to use kube-router for pod-to-pod network connectivity then
[kube-controller-manager](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)
needs to be configured to allocate pod CIDRs by passing the `--allocate-node-cidrs=true` flag and providing a
`cluster-cidr` (e.g. by passing `--cluster-cidr=10.32.0.0/12`)

For example:

```sh
--allocate-node-cidrs=true
--cluster-cidr=10.32.0.0/12
--service-cluster-ip-range=10.50.0.0/22
```

## Running kube-router with Everything

This runs kube-router with pod/service networking, the network policy firewall, and service proxy to replace kube-proxy.
The example command uses `10.32.0.0/12` as the pod CIDR address range and `https://cluster01.int.domain.com:6443` as the
[apiserver](https://kubernetes.io/docs/reference/generated/kube-apiserver/) address. Please change these to suit your
cluster.

```sh
CLUSTERCIDR=10.32.0.0/12 \
APISERVER=https://cluster01.int.domain.com:6443 \
sh -c 'curl -s https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/generic-kuberouter-all-features.yaml | \
sed -e "s;%APISERVER%;$APISERVER;g" -e "s;%CLUSTERCIDR%;$CLUSTERCIDR;g"' | \
kubectl apply -f -
```

### Removing a Previous kube-proxy

If [kube-proxy](https://kubernetes.io/docs/reference/generated/kube-proxy/) was ever deployed to the cluster, then you
need to remove it when running kube-router in this capacity or they will conflict with each other.

Remove any previously running kube-proxy and all iptables rules it created. Start by deleting the kube-proxy daemonset:

```sh
kubectl -n kube-system delete ds kube-proxy
```

Any iptables rules kube-proxy left around will also need to be cleaned up. This command might differ based on how
kube-proxy was setup or configured:

To cleanup kube-proxy we can do this with docker, containerd, or cri-o:

#### docker

```sh
docker run --privileged -v /lib/modules:/lib/modules --net=host registry.k8s.io/kube-proxy-amd64:v1.28.2 kube-proxy --cleanup
```

#### containerd

```sh
ctr images pull k8s.gcr.io/kube-proxy-amd64:v1.28.2
ctr run --rm --privileged --net-host --mount type=bind,src=/lib/modules,dst=/lib/modules,options=rbind:ro \
    registry.k8s.io/kube-proxy-amd64:v1.28.2 kube-proxy-cleanup kube-proxy --cleanup
```

#### cri-o

```sh
crictl pull registry.k8s.io/kube-proxy-amd64:v1.28.2
crictl run --rm --privileged --net-host --mount type=bind,src=/lib/modules,dst=/lib/modules,options=rbind:ro
    registry.k8s.io/kube-proxy-amd64:v1.28.2 kube-proxy-cleanup kube-proxy --cleanup
```

## Running kube-router without the service proxy

This runs kube-router with pod/service networking and the network policy firewall. The Service proxy is disabled.

```sh
kubectl apply -f https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/generic-kuberouter.yaml
```

In this mode kube-router relies on [kube-proxy](https://kubernetes.io/docs/reference/generated/kube-proxy/) (or some
other network service provider) to provide service networking.

When service proxy is disabled kube-router will use
[in-cluster configuration](https://github.com/kubernetes/client-go/tree/master/examples/in-cluster-client-configuration)
to access APIserver through cluster-ip. Service networking must therefore be setup before deploying kube-router.

## Debugging

kube-router supports setting log level via the command line -v or --v, To get maximal debug output from kube-router
please start with `--v=3`
