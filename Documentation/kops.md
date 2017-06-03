# Kops Integration

The following instructions and examples demonstrate how to create a new [Kops](https://github.com/kubernetes/kops/) provisioned Kubernetes cluster using kube-router. Kube-router will provide an IPVS based service proxy (replacing kube-proxy), a network policy enforcer and also provides pod-to-pod networking.


We are working to get the Kube-router support in Kops thorugh [#2606](https://github.com/kubernetes/kops/issues/2606). Till we get the support in upstream kops, you can use patched kops. Following instruction will walk through setting up cluster with patche kops


## Instructions

- Please download the [Linux](https://s3.amazonaws.com/nodeupbkt/kops/1.6.0/linux/amd64/kops) or [Mac](https://s3.amazonaws.com/nodeupbkt/kops/1.6.0/darwin/amd64/kops) version of KOPS.

- Please run `kops create cluster --help` to see the support for kube-router in `--networking` flag. You should see as below

```
--networking string                    Networking mode to use.  kubenet (default), classic, external, kopeio-vxlan (or kopeio), weave, flannel, calico, canal, kube-router. (default "kubenet")
```

- Please export KOPS_BASE_URL as environment variable `export KOPS_BASE_URL=https://nodeupbkt.s3.amazonaws.com/kops/1.6.0/` this will make kops to use patche protokube and nodeup with support for Kube-router

- Now you can deploy cluster with `--networking` flag set to `kube-router`. For e.g as shown below, all kops functionality remains same, so you configure rest of the param as you need.

```
kops create cluster \
    --node-count 2 \
    --zones us-west-2a \
    --master-zones us-west-2a \
    --dns-zone aws.cloudnativelabs.net \
    --node-size t2.medium \
    --master-size t2.medium \
    --networking kube-router  \
    mycluster.aws.cloudnativelabs.net
```

- Now provision cluster

```
kops update cluster mycluster.aws.cloudnativelabs.net --yes
```

- It would take couple of minutes to provision cluster. Once cluster is provisioned please veriy kube-router running on each node `kubectl get pods --all-namespaces`

- At this point your cluster control plane is setup. One last is step is needed for pod connectivity. Since kube-router used host based routing, AWS instances will send and recieve traffic from IP in the pod CIDR range. AWS by default drops packets destined to instance and from instances with IP not in subnet range. So we will need to perform disable source and desintation check on each instance by running below command

```
aws ec2 modify-instance-attribute --instance-id <instance id> --no-source-dest-check
```

At this point your cluster is ready to deploy pods, services, network policies etc. Please report if you face any issue.



