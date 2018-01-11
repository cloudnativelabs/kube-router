# Deploying kube-router on generic cluster

Kube-router relies on kube-controller-manager to allocate pod CIDR for the nodes.

Kube-router provides pod networking, network policy and high perfoming IPVS/LVS based service proxy. Depending on you choose to use kube-router for service proxy you have two options.

## Prerequisites

### Kubelet

kube-router assumes each Kubelet is using `/etc/cni/net.d` as cni conf dir & network plugin `cni`
Startup options:

- --cni-conf-dir=/etc/cni/net.d
- --network-plugin=cni

### Kube controller-manager

The following options needs to be set on the controller-manager:

```text
--cluster-cidr=${POD_NETWORK} # for example 10.32.0.0/12
--service-cluster-ip-range=${SERVICE_IP_RANGE} # for example 10.50.0.0/22
```

## kube-router providing pod networking and network policy

```sh
CLUSTERCIDR=10.32.0.0/12 \
APISERVER=https://cluster01.int.domain.com:6443 \
sh -c 'curl https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/generic-kuberouter.yaml -o - | \
sed -e "s;%APISERVER%;$APISERVER;g" -e "s;%CLUSTERCIDR%;$CLUSTERCIDR;g"' | \
kubectl apply -f -
```

## kube-router providing service proxy, firewall and pod networking

```sh
CLUSTERCIDR=10.32.0.0/12 \
APISERVER=https://cluster01.int.domain.com:6443 \
sh -c 'curl https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/generic-kuberouter-all-features.yaml -o - | \
sed -e "s;%APISERVER%;$APISERVER;g" -e "s;%CLUSTERCIDR%;$CLUSTERCIDR;g"' | \
kubectl apply -f -
```

Now since kube-router provides service proxy as well. Run below commands to remove kube-proxy and cleanup any iptables configuration it may have done.
Depending on if or how you installed kube-proxy these instructions will differ and have to be ran on every node where kube-proxy has run.

```sh
kubectl -n kube-system delete ds kube-proxy
docker run --privileged --net=host gcr.io/google_containers/kube-proxy-amd64:v1.7.3 kube-proxy --cleanup-iptables
```