# Direct Server Return

## More Information

For a more detailed explanation on how to use Direct Server Return (DSR) to build a highly scalable and available
ingress for Kubernetes see the following
[blog post](https://cloudnativelabs.github.io/post/2017-11-01-kube-high-available-ingress/)

## What is DSR?

When enabled, DSR allows the service endpoint to respond directly to the client request, bypassing the service proxy.
When DSR is enabled kube-router will use LVS's tunneling mode to achieve this (more on how later).

## Quick Start

You can enable DSR functionality on a per service basis.

Requirements:

* ClusterIP type service has an externalIP set on it or is a LoadBalancer type service
* kube-router has been started with `--service-external-ip-range` configured at least once. This option can be
  specified multiple times for multiple ranges. The external IPs or LoadBalancer IPs must be included in these ranges.
* kube-router must be run in service proxy mode with `--run-service-proxy` (this option is defaulted to `true` if left
  unspecified)
* If you are advertising the service outside the cluster `--advertise-external-ip` must be set
* If kube-router is deployed as a Kubernetes pod:
  * `hostIPC: true` must be set for the pod
  * `hostPID: true` must be set for the pod
  * The container runtime socket must be mounted into the kube-router pod via a `hostPath` volume mount.
* A pod network that allows for IPIP encapsulated traffic. The most notable exception to this is that Azure does not
  transit IPIP encapsulated packets on their network. In this scenario, the end-user may be able to get around this
  issue by enabling FoU (`--overlay-encap=fou`) and full overlay networking (`--overlay-type=full`) options in
  kube-router. This hasn't been well tested, but it should allow the DSR encapsulated traffic to route correctly.

To enable DSR you need to annotate service with the `kube-router.io/service.dsr=tunnel` annotation:

```sh
kubectl annotate service my-service "kube-router.io/service.dsr=tunnel"
```

## Things To Lookout For

* In the current implementation, **DSR will only be available to the external IPs or LoadBalancer IPs**
* **The current implementation does not support port remapping.** So you need to use same port and target port for the
  service.
* In order for DSR to work correctly, an `ipip` tunnel to the pod is used. This reduces the
  [MTU](https://en.wikipedia.org/wiki/Maximum_transmission_unit) for the packet by 20 bytes. Because of the way DSR
  works it is not possible for clients to use [PMTU](https://en.wikipedia.org/wiki/Path_MTU_Discovery) to discover this
  MTU reduction. In TCP based services, we mitigate this by using iptables to set the
  [TCP MSS](https://en.wikipedia.org/wiki/Maximum_segment_size) value to 20 bytes less than kube-router's primary
  interface MTU size. However, it is not possible to do this for UDP streams. Therefore, UDP streams that continuously
  use large packets may see a performance impact due to packet fragmentation. Additionally, if clients set the `DF`
  (Do Not Fragment) bit, services may see packet loss on UDP services.

## Kubernetes Pod Examples

As mentioned previously, if kube-router is run as a Kubernetes deployment, there are a couple of things needed on the
deployment. Below is an example of what is necessary to get going (this is NOT a full deployment, it is just meant to
highlight the elements needed for DSR):

```sh
apiVersion: apps/v1
kind: DaemonSet
metadata:
  labels:
    k8s-app: kube-router
    tier: node
  name: kube-router
  namespace: kube-system
spec:
  selector:
    matchLabels:
      k8s-app: kube-router
      tier: node
  template:
    metadata:
      labels:
        k8s-app: kube-router
        tier: node
    spec:
      hostNetwork: true
      hostIPC: true
      hostPID: true
      volumes:
      - name: run
        hostPath:
          path: /var/run/docker.sock
      ...
      containers:
      - name: kube-router
        image: docker.io/cloudnativelabs/kube-router:latest
        ...
        volumeMounts:
        - name: run
          mountPath: /var/run/docker.sock
          readOnly: true
...
```

For an example manifest please look at the
[kube-router all features manifest](../daemonset/kubeadm-kuberouter-all-features-dsr.yaml) with DSR requirements for
Docker enabled.

### DSR with containerd or cri-o

As of kube-router-1.2.X and later, kube-router's DSR mode now works with non-docker container runtimes. Officially only
containerd has been tested, but this solution should work with cri-o as well.

Most of what was said above also applies for non-docker container runtimes, however, there are some adjustments that
you'll need to make:

* You'll need to let kube-router know what container runtime socket to use via the `--runtime-endpoint` CLI parameter
* If running kube-router as a Kubernetes deployment you'll need to make sure that you expose the correct socket via
  `hostPath` volume mount

Here is an example kube-router daemonset manifest with just the changes needed to enable DSR with containerd (this is
not a full manifest, it is just meant to highlight differences):

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kube-router
spec:
  template:
    spec:
    ...
      volumes:
      - name: containerd-sock
        hostPath:
          path: /run/containerd/containerd.sock
      ...
      containers:
      - name: kube-router
        args:
        - --runtime-endpoint=unix:///run/containerd/containerd.sock
        ...
        volumeMounts:
        - name: containerd-sock
          mountPath: /run/containerd/containerd.sock
          readOnly: true
...
```

## More Details About DSR

In order to facilitate troubleshooting it is worth while to explain how kube-router accomplishes DSR functionality.

1. kube-router adds iptables rules to the `mangle` table which marks incoming packets destined for DSR based services
   with a unique FW mark. This mark is then used in later stages to identify the packet and route it correctly.
   Additionally, for TCP streams, there are rules that enable
   [TCP MSS](https://en.wikipedia.org/wiki/Maximum_segment_size) since the packets will change MTU when traversing an
   ipip tunnel later on.
2. kube-router adds the marks to an `ip rule` (see: [ip-rule(8)](https://man7.org/linux/man-pages/man8/ip-rule.8.html)).
   This ip rule then forces the incoming DSR service packets to use a specific routing table.
3. kube-router adds a new `ip route` table (at the time of this writing the table number is `78`) which forces the
   packet to route to the host even though there are no interfaces on the host that carry the DSR IP address
4. kube-router adds an IPVS server configured for the custom FW mark. When packets arrive on the localhost interface
   because of the above `ip rule` and `ip route`, IPVS will intercept them based on their unique FW mark.
5. When pods selected by the DSR service become ready, kube-router adds endpoints configured for tunnel mode to the
   above IPVS server. Each endpoint is configured in tunnel mode (as opposed to masquerade mode), which then
   encapsulates the incoming packet in an ipip packet. It is at this point that the pod's destination IP is placed on
   the ipip packet header so that a packet can be routed to the pod via the kube-bridge on either this host or the
   destination host.
6. kube-router then finds the targeted pod and enters it's local network namespace. Once inside the pod's linux network
   namespace, it sets up two new interfaces called `kube-dummy-if` and `ipip`. `kube-dummy-if` is configured with the
   externalIP address of the service.
7. When the ipip packet arrives inside the pod, the original source packet with the externalIP is then extracted from
   the ipip packet via the `ipip` interface and is accepted to the listening application via the `kube-dummy-if`
   interface.
8. When the application sends its response back to the client, it responds to the client's public IP address (since
   that is what it saw on the request's IP header) and the packet is returned directly to the client (as opposed to
  traversing the Kubernetes internal network and potentially making multiple intermediate hops)
