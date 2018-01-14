# Kube-router on generic clusters

This guide is for running kube-router as the [CNI](https://github.com/containernetworking) network provider for on premise and/or bare metal clusters outside of a cloud provider's environment. It assumes the initial cluster is bootstrapped and a networking provider needs configuration.

All pod networking CIDRs are allocated by kube-controller-manager. Kube-router provides service/pod networking, a network policy firewall, and a high performance IPVS/LVS based service proxy. The network policy firewall and service proxy are both optional but recommended.


### Configuring the Kubelet

Ensure each kubelet is configured with the following options:

    --network-plugin=cni
    --cni-conf-dir=/etc/cni/net.d

If a previous CNI provider (e.g. weave-net, calico, or flannel) was used, remove old configurations from `/etc/cni/net.d` on each kubelet.

**Note: Switching CNI providers on a running cluster requires re-creating all pods to pick up new pod IPs**


### Configuring kube-controller-manager

The following options are mandatory for kube-controller-manager:

    --cluster-cidr=${POD_NETWORK} # for example 10.32.0.0/12
    --service-cluster-ip-range=${SERVICE_IP_RANGE} # for example 10.50.0.0/22


## Running kube-router with everything

This runs kube-router with pod/service networking, the network policy firewall, and service proxy to replace kube-proxy. The example command uses `10.32.0.0/12` as the pod CIDR address range and `https://cluster01.int.domain.com:6443` as the apiserver address. Please change these to suit your cluster.

    CLUSTERCIDR=10.32.0.0/12 \
    APISERVER=https://cluster01.int.domain.com:6443 \
    sh -c 'curl https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/generic-kuberouter-all-features.yaml -o - | \
    sed -e "s;%APISERVER%;$APISERVER;g" -e "s;%CLUSTERCIDR%;$CLUSTERCIDR;g"' | \
    kubectl apply -f -

### Removing a previous kube-proxy

If kube-proxy was never deployed to the cluster, this can likely be skipped.

Remove any previously running kube-proxy and all iptables rules it created. Start by deleting the kube-proxy daemonset:

    kubectl -n kube-system delete ds kube-proxy

Any iptables rules kube-proxy left around will also need to be cleaned up. This command might differ based on how kube-proxy was setup or configured:

    docker run --privileged --net=host gcr.io/google_containers/kube-proxy-amd64:v1.7.3 kube-proxy --cleanup-iptables


## Running kube-router without the service proxy

This runs kube-router with pod/service networking and the network policy firewall. The service proxy is disabled. Don't forget to update the cluster CIDR and apiserver addresses to match your cluster.

    kubectl apply -f https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/generic-kuberouter.yaml

When service proxy is disabled kube-router will use in-cluster configuration to access APIserver through the cluster-ip.