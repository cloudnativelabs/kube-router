# Deploying kube-router with kubeadm

Please follow the [steps](https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/) to install Kubernetes cluster with Kubeadm.


For the step #3 **Installing a pod network** install a kube-router pod network and network policy add-on with the following command:

```
kubectl apply -f https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/kubeadm-kuberouter.yaml
```
