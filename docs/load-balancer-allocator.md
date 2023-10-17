# Load Balancer allocator

## What does it do

The load balancer allocator controller looks for services with the type LoadBalancer and tries to allocate addresses for
it if needed. The controller doesn't enable any announcement of the addresses by default, so
`--advertise-loadbalancer-ip` should be set to true and BGP peers configured.

## Load balancer classes

By default the controller allocates addresses for all LoadBalancer services with the where `loadBalancerClass` is empty
or set to one of "default" or "kube-router". If `--loadbalancer-default-class` is set to false, the controller will only
handle services with the class set to "kube-router".

## RBAC permissions

The controller needs some extra permissions to get, create and update leases for leader election and to update services
with allocated addresses.

Example permissions:

```yaml
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: kube-router
  namespace: kube-system
rules:
  - apiGroups:
      - "coordination.k8s.io"
    resources:
      - leases
    verbs:
      - get
      - create
      - update
  - apiGroups:
      - ""
    resources:
      - services/status
    verbs:
      - update
```

## Environment variables

The controller uses the environment variable `POD_NAME` as the identify for the lease used for leader election.
Using the kubernetes downward api to set `POD_NAME` to the pod name the lease identify will match the current leader.

```yaml
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  labels:
    k8s-app: kube-router
    tier: node
  name: kube-router
  namespace: kube-system
spec:
  ...
  template:
    metadata:
      ....
    spec:
        ...
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
...
```

The environment variable `POD_NAMESPACE` can also be specified to set the namespace used for the lease.
By default the namespace is looked up from within the pod using `/var/run/secrets/kubernetes.io/serviceaccount/namespace`.

## Running outside kubernetes

When running the controller outside a pod, both `POD_NAME` and `POD_NAMESPACE` must set for the controller to work.
`POD_NAME` should be unique per instance, so using for example the hostname of the machine might be a good idea.
`POD_NAMESPACE` must be the same across all instances running in the same cluster.

## Notes

It's not possible to specify the addresses for the load balancer services. A externalIP service can be used instead.
