# nftables Support

## Background

Linux has two major packet filtering frameworks: **iptables** and **nftables**.

**iptables** is the traditional framework, in use since the late 1990s. It manages rules across separate tables
(`filter`, `nat`, `mangle`, etc.) and requires one syscall per rule for updates. Under the hood, it uses netfilter
hooks in the kernel.

**nftables** is the modern replacement, introduced in Linux 3.13. It consolidates all rule management into a single
interface, supports atomic batch updates (all rule changes commit together or not at all), and offers improved
performance for complex rule sets due to better kernel integration and support for set-based matching.

kube-router's network policy controller has historically used iptables combined with ipsets to enforce Kubernetes
`NetworkPolicy` objects. The `--use-nftables-for-netpol` flag enables an alternative implementation backed by
nftables named sets and chains instead.

## Experimental Status

> **Warning:** nftables support in kube-router is **experimental**. It has not been broadly tested across diverse
> cluster configurations, workloads, or Kubernetes versions. There are no performance benchmarks comparing it against
> the iptables implementation. Performance on large clusters may not be acceptable — treat this flag as
> unsuitable for production use until further validation is completed.

Bugs and feedback are welcome via [GitHub Issues](https://github.com/cloudnativelabs/kube-router/issues).

## Scope

The `--use-nftables-for-netpol` flag **only affects the Network Policy Controller (NPC)**. All other kube-router
controllers (service proxy, routing) continue to use their existing implementations regardless of this flag.

## Requirements

- `nft` >= 1.0.1
- Kernel with nftables support enabled (Linux >= 3.13; most modern distributions satisfy this)

## Usage

Pass the flag when starting kube-router:

```bash
kube-router --run-network-policy-controller --run-firewall --use-nftables-for-netpol
```

Or in a DaemonSet manifest:

```yaml
args:
  - --run-network-policy-controller
  - --use-nftables-for-netpol
```

When enabled, the NPC creates two nftables tables (`kube-router-filter-ipv4` and `kube-router-filter-ipv6`) and
manages chains and named sets within them to enforce `NetworkPolicy` rules. The iptables chains and ipsets
previously created by the NPC are not used.

## Known Limitations

- No performance benchmarks on large clusters
- Not validated across all Kubernetes versions or CNI combinations
- Should not be used alongside any other tool that manages the `kube-router-filter-*` nftables tables
