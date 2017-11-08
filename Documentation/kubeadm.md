# Deploying kube-router with kubeadm

Please follow the [steps](https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/) to install Kubernetes cluster with Kubeadm.

Kube-router relies on kube-controll-manager to allocate pod CIDR for the nodes. So you must use `kubeadm init` with `--pod-network-cidr` flag. On the controller node after `kubeadm init` is complete:

Kube-router provides pod networking, network policy and high perfoming IPVS/LVS based service proxy. Depending on you choose to use kube-router for service proxy you have two options.

## kube-router providing pod networking and network policy

For the step #3 **Installing a pod network** install a kube-router pod network and network policy add-on with the following command:

```sh
KUBECONFIG=/etc/kubernetes/admin.conf kubectl apply -f https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/kubeadm-kuberouter.yaml
```

## kube-router providing service proxy, firewall and pod networking.

For the step #3 **Installing a pod network** install a kube-router pod network and network policy add-on with the following command:

```sh
KUBECONFIG=/etc/kubernetes/admin.conf kubectl apply -f https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/kubeadm-kuberouter-all-features.yaml
```

Now since kube-router provides service proxy as well. Run below commands to remove kube-proxy and cleanup any iptables configuration it may have done.

```sh
KUBECONFIG=/etc/kubernetes/admin.conf kubectl -n kube-system delete ds kube-proxy
docker run --privileged --net=host gcr.io/google_containers/kube-proxy-amd64:v1.7.3 kube-proxy --cleanup-iptables
```


