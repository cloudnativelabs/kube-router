![logo](https://cdn.rawgit.com/cloudnativelabs/kube-router/64f7700e/Documentation/img/logo-full.svg)

[![Build Status](https://travis-ci.org/cloudnativelabs/kube-router.svg?branch=master)](https://travis-ci.org/cloudnativelabs/kube-router)
[![Slack](https://img.shields.io/badge/slack-join%20chat%20%E2%86%92-e01563.svg)](https://kubernetes.slack.com/messages/C8DCQGTSB/)
[![Docker Pulls kube-router](https://img.shields.io/docker/pulls/cloudnativelabs/kube-router.svg?label=docker+pulls)](https://hub.docker.com/r/cloudnativelabs/kube-router/)
[![](https://images.microbadger.com/badges/image/cloudnativelabs/kube-router.svg)](https://microbadger.com/images/cloudnativelabs/kube-router "Get your own image badge on microbadger.com")
[![](https://img.shields.io/github/release/cloudnativelabs/kube-router/all.svg?style=flat-square)](https://github.com/cloudnativelabs/kube-router/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Kube-router is a turnkey solution for Kubernetes networking with aim to provide operational simplicity and high performance.

## Primary Features

*kube-router does it all.*

With all features enabled, kube-router is a lean yet powerful alternative to
several network components used in typical Kubernetes clusters. All this from a
single DaemonSet/Binary. It doesn't get any easier.

### IPVS/LVS based service proxy | `--run-service-proxy`

kube-router uses the Linux kernel's LVS/IPVS features to implement its K8s Services
Proxy. Kube-router fully leverages power off LVS/IPVS to provide rich set of [scheduling options](/docs#load-balancing-scheduling-algorithms) and unique features like DSR (Direct Server Return), L3 load balancing with ECMP for deployments where high throughput, minimal latency and high-availability are crucial.

Read more about the advantages of IPVS for container load balancing:
- [Kubernetes network services proxy with IPVS/LVS](https://cloudnativelabs.github.io/post/2017-05-10-kube-network-service-proxy/)
- [Highly-available and scalable ingress for baremetal Kubernetes clusters](https://cloudnativelabs.github.io/post/2017-11-01-kube-high-available-ingress/)

### Pod Networking | `--run-router`

kube-router handles Pod networking efficiently with direct routing thanks to the
BGP protocol and the GoBGP Go library. It uses the native Kubernetes API to
maintain distributed pod networking state. That means no dependency on a
separate datastore to maintain in your cluster.

kube-router's elegant design also means there is no dependency on another CNI
plugin. The
[official "bridge" plugin](https://github.com/containernetworking/plugins/tree/master/plugins/main/bridge)
provided by the CNI project is all you need -- and chances are you already have
it in your CNI binary directory!

Read more about the advantages and potential of BGP with Kubernetes:
- [Kubernetes pod networking and beyond with BGP](https://cloudnativelabs.github.io/post/2017-05-22-kube-pod-networking)

### Network Policy Controller | `--run-firewall`

Enabling Kubernetes [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
is easy with kube-router -- just add a flag to kube-router. It uses ipsets with
iptables to ensure your firewall rules have as little performance impact on your
cluster as possible.

Kube-router supports the networking.k8s.io/NetworkPolicy API or network policy V1/GA
[semantics](https://github.com/kubernetes/kubernetes/pull/39164#issue-197243974) and also network policy beta semantics.

Read more about kube-router's approach to Kubernetes Network Policies:
- [Enforcing Kubernetes network policies with iptables](https://cloudnativelabs.github.io/post/2017-05-1-kube-network-policies/)

### Advanced BGP Capabilities

If you have other networking devices or SDN systems that talk BGP, kube-router
will fit in perfectly. From a simple full node-to-node mesh to per-node peering
configurations, most routing needs can be attained. The configuration is
Kubernetes native (annotations) just like the rest of kube-router, so use the
tools you already know! Since kube-router uses GoBGP, you have access to a
modern BGP API platform as well right out of the box. Kube-router also provides
a way to expose services outside the cluster by advertising ClusterIP and externalIPs to
configured BGP peers. Kube-routes also support MD5 password based authentication and
uses strict export policies so you can be assured routes are advertised to underlay
only as you intended.

For more details please refer to the [BGP documentation](docs/bgp.md).

### Standard Linux Networking

A key design tenet of Kube-router is to use standard Linux networking stack and toolset. There is no overlays or 
SDN pixie dust, but just plain good old networking. You can use standard Linux networking tools like iptables, ipvsadm, ipset,
iproute, traceroute, tcpdump etc. to troubleshoot or observe data path. When kube-router is ran as a daemonset, image also ships with these [tools](./docs/pod-toolbox.md#pod-toolbox) automatically configured for your cluster.

### Small Footprint

Although it does the work of several of its peers in one binary, kube-router
does it all with a relatively [tiny codebase](https://github.com/cloudnativelabs/kube-router/tree/master/pkg/controllers), partly because IPVS is already
there on your Kuberneres nodes waiting to help you do amazing things.
kube-router brings that and GoBGP's modern BGP interface to you in an elegant
package designed from the ground up for Kubernetes.

### High Performance

A primary motivation for kube-router is performance. The combination of BGP for
inter-node Pod networking and IPVS for load balanced proxy Services is a perfect
recipe for high-performance cluster networking at scale. BGP ensures that the
data path is dynamic and efficient, and IPVS provides in-kernel load balancing
that has been thoroughly tested and optimized.

## Getting Started

- [How it Works](./docs/how-it-works.md)
- [Architecture](./docs/architecture.md)
- [See Kube-router in action](./docs/see-it-in-action.md)
- [User Guide](./docs/user-guide.md)
- [Developer Guide](./docs/developing.md)

## Project status

Kube-router is being used in several production clusters by diverse set of users ranging from financial firms, gaming companies to universities. For almost a year we have listened to users and incorporated feedback. The core functionality is stable. We are working toward GA release.

## Contributing

We encourage all kinds of contributions, be they documentation, code, fixing
typos, tests — anything at all. Please read the [contribution guide](./CONTRIBUTING.md).

## Support & Feedback

If you experience any problems please reach us on kube-router [slack channel](https://kubernetes.slack.com/messages/C8DCQGTSB/)
for quick help. Feel free to leave feedback or raise questions by opening an issue [here](https://github.com/cloudnativelabs/kube-router/issues).

## Acknowledgement

Kube-router build upon following libraries:

- Iptables: https://github.com/coreos/go-iptables
- GoBGP: https://github.com/osrg/gobgp
- Netlink: https://github.com/vishvananda/netlink
- Ipset: https://github.com/janeczku/go-ipset
- IPVS: https://github.com/docker/libnetwork/

## Sponsorships

E2E Tests sponsored by [DigitalOcean](https://www.digitalocean.com/about/)

<p align="left">
  <img src="docs/img/do_logo_blue.png"> </image>
</p>

Testing and development by [ShopGun](https://shopgun.com/about)

<p align="left">
  <img height="90" src="docs/img/shopgun_logo.png"> </image>
</p>
