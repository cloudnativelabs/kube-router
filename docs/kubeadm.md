# Deploying kube-router with kubeadm

Please follow the [steps](https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/) to install Kubernetes
cluster with Kubeadm, however must specify `--pod-network-cidr` when you run `kubeadm init`.

kube-router relies on kube-controller-manager to allocate pod CIDR for the nodes.

kube-router provides pod networking, network policy and high perfoming IPVS/LVS based service proxy. Depending on your
choice to use kube-router for service proxy you have two options.

## kube-router Providing Pod Networking and Network Policy

For the step #3 **Installing a Pod network add-on** install a kube-router pod network and network policy add-on with the
following command:

```sh
KUBECONFIG=/etc/kubernetes/admin.conf kubectl apply -f https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/kubeadm-kuberouter.yaml
```

## kube-router Providing Service Proxy, Firewall and Pod Networking

For the step #3 **Installing a Pod network add-on** install a kube-router pod network and network policy add-on with the
following command:

```sh
KUBECONFIG=/etc/kubernetes/admin.conf kubectl apply -f https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/kubeadm-kuberouter-all-features.yaml
```

Now since kube-router provides service proxy as well. Run below commands to remove kube-proxy and cleanup any iptables
configuration it may have done.

```sh
KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n kube-system delete ds kube-proxy
```

To cleanup kube-proxy we can do this with docker, containerd, or cri-o:

### docker

```sh
docker run --privileged -v /lib/modules:/lib/modules --net=host registry.k8s.io/kube-proxy-amd64:v1.28.2 kube-proxy --cleanup
```

### containerd

```sh
ctr images pull registry.k8s.io/kube-proxy-amd64:v1.28.2
ctr run --rm --privileged --net-host --mount type=bind,src=/lib/modules,dst=/lib/modules,options=rbind:ro \
    registry.k8s.io/kube-proxy-amd64:v1.28.2 kube-proxy-cleanup kube-proxy --cleanup
```

### cri-o

```sh
crictl pull registry.k8s.io/kube-proxy-amd64:v1.28.2
crictl run --rm --privileged --net-host --mount type=bind,src=/lib/modules,dst=/lib/modules,options=rbind:ro
    registry.k8s.io/kube-proxy-amd64:v1.28.2 kube-proxy-cleanup kube-proxy --cleanup
```
