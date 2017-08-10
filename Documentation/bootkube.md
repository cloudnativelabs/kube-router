# Bootkube Integration

The following instructions and examples demonstrate how to create a new
[Bootkube](https://github.com/kubernetes-incubator/bootkube) provisioned
Kubernetes cluster using kube-router in place of kube-proxy and flannel.

## Asset Creation

Follow the
[documentation](https://github.com/kubernetes-incubator/bootkube#guides) for
your environment and setup arguments for `bootkube render`.

For example:
```
bootkube render --asset-dir=${PWD}/assets --api-servers=https://kube-api-dev.zbrbdl:443 --api-server-alt-names=DNS=kube-api-dev.zbrbdl --etcd-servers="http://127.0.0.1:2379"
Writing asset: /home/bzub/assets/manifests/kube-scheduler.yaml
Writing asset: /home/bzub/assets/manifests/kube-scheduler-disruption.yaml
Writing asset: /home/bzub/assets/manifests/kube-controller-manager-disruption.yaml
Writing asset: /home/bzub/assets/manifests/kube-dns-deployment.yaml
Writing asset: /home/bzub/assets/manifests/pod-checkpointer.yaml
Writing asset: /home/bzub/assets/manifests/kube-flannel.yaml
Writing asset: /home/bzub/assets/manifests/kube-system-rbac-role-binding.yaml
Writing asset: /home/bzub/assets/manifests/kube-controller-manager.yaml
Writing asset: /home/bzub/assets/manifests/kube-apiserver.yaml
Writing asset: /home/bzub/assets/manifests/kube-proxy.yaml
Writing asset: /home/bzub/assets/manifests/kube-flannel-cfg.yaml
Writing asset: /home/bzub/assets/manifests/kube-dns-svc.yaml
Writing asset: /home/bzub/assets/bootstrap-manifests/bootstrap-apiserver.yaml
Writing asset: /home/bzub/assets/bootstrap-manifests/bootstrap-controller-manager.yaml
Writing asset: /home/bzub/assets/bootstrap-manifests/bootstrap-scheduler.yaml
Writing asset: /home/bzub/assets/tls/ca.key
Writing asset: /home/bzub/assets/tls/ca.crt
Writing asset: /home/bzub/assets/tls/apiserver.key
Writing asset: /home/bzub/assets/tls/apiserver.crt
Writing asset: /home/bzub/assets/tls/service-account.key
Writing asset: /home/bzub/assets/tls/service-account.pub
Writing asset: /home/bzub/assets/tls/kubelet.key
Writing asset: /home/bzub/assets/tls/kubelet.crt
Writing asset: /home/bzub/assets/auth/kubeconfig
Writing asset: /home/bzub/assets/manifests/kube-apiserver-secret.yaml
Writing asset: /home/bzub/assets/manifests/kube-controller-manager-secret.yaml
```

## Kube-router Installation

Next move/delete the manifests for kube-proxy and flannel from
`assets/manifests` and replace them with the
[kube-router.yaml](/contrib/bootkube/kube-router.yaml) and
[kube-router-cfg.yaml](/contrib/bootkube/kube-router-cfg.yaml) files provided in
this repo.
```
rm assets/manifests/kube-flannel{,-cfg}.yaml assets/manifests/kube-proxy.yaml
curl -L https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/contrib/bootkube/kube-router-cfg.yaml -o assets/manifests/kube-router-cfg.yaml
curl -L https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/contrib/bootkube/kube-router.yaml -o assets/manifests/kube-router.yaml
```

## Cluster Startup

Finally, proceed by following the Bootkube documentation, which generally
involves starting Kubelet and running `bootkube start` referring to your assets
directory on a new Kubernetes node.

After starting multiple master nodes, our example cluster looks like this:
```
$ kubectl -n kube-system get pods,services
NAME                                          READY     STATUS    RESTARTS   AGE       IP          NODE
po/kube-apiserver-gztjp                       1/1       Running   0          15h       10.10.3.2   node2-dev.zbrbdl
po/kube-apiserver-h55t7                       1/1       Running   0          15h       10.10.3.3   node3-dev.zbrbdl
po/kube-apiserver-qn5xm                       1/1       Running   2          15h       10.10.3.1   node1-dev.zbrbdl
po/kube-controller-manager-3052101514-kp121   1/1       Running   1          15h       10.2.0.5    node1-dev.zbrbdl
po/kube-controller-manager-3052101514-n4q9p   1/1       Running   2          15h       10.2.0.6    node1-dev.zbrbdl
po/kube-dns-2431531914-pr9lg                  3/3       Running   0          15h       10.2.0.3    node1-dev.zbrbdl
po/kube-router-ckdj1                          1/1       Running   15         15h       10.10.3.3   node3-dev.zbrbdl
po/kube-router-dcgbr                          1/1       Running   15         15h       10.10.3.1   node1-dev.zbrbdl
po/kube-router-n0vcn                          1/1       Running   15         15h       10.10.3.2   node2-dev.zbrbdl
po/kube-scheduler-2172662190-g4q3w            1/1       Running   4          15h       10.2.0.2    node1-dev.zbrbdl
po/kube-scheduler-2172662190-hcq3t            1/1       Running   2          15h       10.2.0.4    node1-dev.zbrbdl
po/pod-checkpointer-jlfsv                     1/1       Running   0          15h       10.10.3.1   node1-dev.zbrbdl
po/pod-checkpointer-jlfsv-node1-dev.zbrbdl    1/1       Running   0          15h       10.10.3.1   node1-dev.zbrbdl
po/pod-checkpointer-lhckt                     1/1       Running   0          15h       10.10.3.3   node3-dev.zbrbdl
po/pod-checkpointer-lhckt-node3-dev.zbrbdl    1/1       Running   0          15h       10.10.3.3   node3-dev.zbrbdl
po/pod-checkpointer-tsbkh                     1/1       Running   0          15h       10.10.3.2   node2-dev.zbrbdl
po/pod-checkpointer-tsbkh-node2-dev.zbrbdl    1/1       Running   0          15h       10.10.3.2   node2-dev.zbrbdl

NAME                CLUSTER-IP   EXTERNAL-IP   PORT(S)         AGE       SELECTOR
svc/kube-dns        10.3.0.10    <none>        53/UDP,53/TCP   15h       k8s-app=kube-dns
```
