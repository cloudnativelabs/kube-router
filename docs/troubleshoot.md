# Troubleshooting kube-router

This guide covers the most common issues encountered when running kube-router, based on patterns observed across
hundreds of real-world deployments. Each section describes symptoms, diagnostic commands, root causes, and
solutions.

## General Diagnostic Tools

Before diving into specific problems, familiarize yourself with these essential diagnostic commands. Most can be run
from within the kube-router pod using the [pod toolbox](pod-toolbox.md) or by exec-ing into the kube-router container.

### Log Verbosity

Increase kube-router log verbosity for detailed debugging output:

```text
-v=0  Default logging (errors, warnings, key info)
-v=1  Additional informational messages
-v=2  Detailed sync operations and ipset/iptables restore output
-v=3  Full debug output including per-rule details
```

Set the verbosity flag in the kube-router DaemonSet or command-line arguments.

### IPVS and Service Proxy

```sh
# List all IPVS services and their backends
ipvsadm -ln

# Show IPVS connection table (active connections)
ipvsadm -lnc

# Show IPVS service statistics
ipvsadm -ln --stats
```

### ipset

```sh
# List all ipsets and their members
ipset list

# List a specific ipset
ipset list kube-router-svip-prt

# Check if the local IP set is populated (critical for node connectivity)
ipset list kube-router-local-ips
```

### iptables

```sh
# Dump all iptables rules across all tables
iptables-save

# List rules in a specific chain with packet counters
iptables -nvL KUBE-ROUTER-SERVICES
iptables -t nat -nvL KUBE-ROUTER-HAIRPIN

# Check which iptables backend is in use (legacy vs nft)
iptables --version
ls -l /sbin/iptables
```

### BGP and Routing

```sh
# Check BGP neighbor status
gobgp neighbor

# View the BGP RIB (Routing Information Base)
gobgp global rib

# Check a specific route
gobgp global rib 10.244.1.0/24

# View BGP policies
gobgp global policy

# Check kernel routing table
ip route
ip route show table 77

# List tunnel interfaces
ip link show type ipip
```

### Network and Interfaces

```sh
# Check service VIPs on the dummy interface
ip addr show kube-dummy-if

# Check local route table for service VIPs
ip route list table local

# Check all routing tables for service VIPs
ip route list table all

# View kube-bridge configuration
ip addr show kube-bridge
```

### Observing Dropped Traffic

Traffic rejected by network policy enforcement is logged via iptables NFLOG under group 100. See the
[observability documentation](observability.md) for details.

```sh
tcpdump -i nflog:100 -n
```

### Health Endpoint

kube-router exposes a health check at `/healthz` on port 20244 by default. See the
[health documentation](health.md) for details.

```sh
curl http://localhost:20244/healthz
```

## Prerequisites and Common Setup Issues

### Required Kernel Modules

kube-router requires several kernel modules. If these are missing, you will see cryptic errors like
`iptables: No chain/target/match by that name`
([#775](https://github.com/cloudnativelabs/kube-router/issues/775)).

Required modules include:

- `xt_set` (CONFIG_NETFILTER_XT_SET) -- required for ipset-based iptables rules
- `ip_vs` -- required for IPVS service proxy
- `ip_vs_rr`, `ip_vs_wrr`, `ip_vs_sh` -- IPVS scheduling algorithms
- `ip_set` -- ipset support
- `br_netfilter` -- bridge netfilter support

Verify a module is available:

```sh
# Check kernel config
zgrep XT_SET /boot/config-$(uname -r)
# or
zgrep XT_SET /proc/config.gz

# Check if loaded
lsmod | grep xt_set

# Attempt to load
modprobe xt_set
```

If `CONFIG_NETFILTER_XT_SET` shows `is not set`, you need a different kernel. Some minimal cloud kernels
(e.g., Ubuntu's `linux-kvm` flavor) omit these modules. Switch to the `linux-generic` or `linux-aws` kernel
package.

### iptables Backend: legacy vs nft

Modern Linux distributions (Debian Buster+, Fedora 30+, Ubuntu 20.04+) default to the `iptables-nft` backend.
kube-router auto-detects the correct backend, but mismatches can occur if the detection fails or the
container's iptables version differs significantly from the host's
([#1069](https://github.com/cloudnativelabs/kube-router/issues/1069)).

**Symptoms:** kube-router rules appear in `iptables-legacy -L` but are missing from `iptables -L` (which
uses nft). Pod networking is broken.

**Diagnosis:**

```sh
# On the host
iptables --version        # Should show (nf_tables) or (legacy)
ls -l /sbin/iptables      # Check symlink target

# Inside kube-router pod
iptables --version        # Compare with host
```

**Solution:** Ensure the kube-router container's iptables version matches the host. See the
[iptables version compatibility](#iptables-version-compatibility) section below.

### iptables Version Compatibility

The iptables nf_tables binary format is **not forwards or backwards compatible** between different minor
versions of the userspace tools. If the kube-router container bundles iptables 1.8.7 but the host runs
1.8.8, rules written by one may be silently corrupted when read by the other
([#1415](https://github.com/cloudnativelabs/kube-router/issues/1415),
[#1588](https://github.com/cloudnativelabs/kube-router/issues/1588)).

**Symptoms:** Network connectivity lost after host OS upgrade. Critical iptables rules lose match conditions
(e.g., a `-m mark --mark 0x8000/0x8000 -j DROP` rule becomes just `-j DROP`, dropping all traffic).

**Diagnosis:**

```sh
# Compare versions
iptables --version                                          # on host
kubectl exec -n kube-system <pod> -- iptables --version     # in container

# Check for corrupted rules
iptables -L KUBE-FIREWALL -v  # look for missing match conditions
```

**Solution:** Upgrade kube-router to a version whose bundled iptables matches the host, or build a custom
container image with matching iptables. Distributions like k0s solve this by bundling statically-compiled
iptables binaries.

### Cleaning Up kube-proxy

If you previously ran kube-proxy and are switching to kube-router's service proxy, leftover kube-proxy
iptables rules will conflict with IPVS. This is one of the most common causes of "No route to host" errors
for service IPs ([#425](https://github.com/cloudnativelabs/kube-router/issues/425)).

**Cleanup steps:**

```sh
# Option 1: Run kube-proxy cleanup
kube-proxy --cleanup

# Option 2: Manual cleanup
iptables -t nat --flush
iptables -t mangle --flush

# Delete kube-proxy DaemonSet
kubectl -n kube-system delete ds kube-proxy
```

See the [kubeadm guide](kubeadm.md) for complete instructions.

### Required Flags

Several kube-router flags have defaults that may not match your cluster. Omitting these causes subtle
failures:

- **`--service-cluster-ip-range`**: Defaults to `10.96.0.0/12`. If your cluster uses a different service
  CIDR, egress network policies will block traffic to services
  ([#1617](https://github.com/cloudnativelabs/kube-router/issues/1617)). Specify your actual CIDR:

  ```text
  --service-cluster-ip-range=172.16.0.0/16
  ```

- **`--service-node-port-range`**: Defaults to `30000-32767`. Must match your cluster's configuration.

## Service Proxy (IPVS) Issues

### Services Showing "No Destination Available"

**Symptoms:** Kernel logs show `IPVS: rr: TCP x.x.x.x:port - no destination available`. Connections to
service IPs fail.

**Diagnosis:**

```sh
# Check if the service has backends
ipvsadm -ln | grep -A5 <service-ip>

# Verify endpoints exist
kubectl get endpoints <service-name>
kubectl describe svc <service-name>
```

**Root Cause:** The IPVS service exists but has no backend endpoints. This is normal when no pods are running
for the service, or when `externalTrafficPolicy: Local` is set and no pods run on the current node
([#415](https://github.com/cloudnativelabs/kube-router/issues/415)).

**Solution:** Ensure pods backing the service are running and ready. If using
`externalTrafficPolicy: Local`, verify pods exist on the node in question.

### "No Route to Host" for Service IPs

**Symptoms:** `curl` or connections to ClusterIP/ExternalIP addresses fail with "No route to host".

**Diagnosis:**

```sh
# Check if service VIPs are assigned to the dummy interface (for non-DSR services)
ip addr show kube-dummy-if

# Check local route table
ip route list table local | grep <service-ip>

# Check for leftover kube-proxy rules
iptables-save | grep KUBE-SEP
```

**Root Cause:** Service VIPs are not assigned to `kube-dummy-if`, or leftover kube-proxy NAT rules are
intercepting traffic before it reaches IPVS
([#425](https://github.com/cloudnativelabs/kube-router/issues/425)).

**Solution:** Clean up kube-proxy rules (see [Cleaning Up kube-proxy](#cleaning-up-kube-proxy)). If
`kube-dummy-if` is missing VIPs, check kube-router logs for service proxy controller errors.

### NodePort Not Accessible from Outside the Node

**Symptoms:** NodePort services work when accessed from the node itself (`curl localhost:<nodeport>`) but
fail from external clients.

**Diagnosis:**

```sh
# Check iptables FORWARD chain
iptables -nvL FORWARD

# Look for Docker isolation rules
iptables -nvL DOCKER-ISOLATION-STAGE-1 2>/dev/null
```

**Root Cause:** Docker's default iptables rules set the FORWARD chain to DROP and add isolation rules that
block traffic forwarded by IPVS
([#757](https://github.com/cloudnativelabs/kube-router/issues/757)).

**Solution:** Disable Docker's iptables management by adding `"iptables": false` to
`/etc/docker/daemon.json` and restarting Docker. Alternatively, if using containerd directly, this is not
an issue.

### High CPU Usage with Many Services

**Symptoms:** kube-router consumes high CPU during IPVS sync cycles, especially in clusters with 2000+
services.

**Diagnosis:**

```sh
# Enable pprof for CPU profiling
# Add --enable-pprof to kube-router args, then:
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30
```

**Root Cause:** Older versions used individual `exec()` calls for each ipset add and ip route operation,
spawning thousands of processes per sync cycle
([#962](https://github.com/cloudnativelabs/kube-router/issues/962)).

**Solution:** Upgrade to a version containing the batch ipset restore optimization (PR #964). Modern
versions of kube-router use batched `ipset restore` operations and native netlink calls, reducing sync time
from ~6.5 seconds to ~0.6 seconds for 2000+ services.

If this symptom is still happening in newer versions of kube-router, please open an issue with the reproduction scenario
and results of the pprof.

### Hairpin NAT Not Working

**Symptoms:** A pod cannot reach its own service via the ClusterIP.

**Diagnosis:**

```sh
# Check if hairpin mode is enabled on bridge ports
grep . /sys/devices/virtual/net/*/brport/hairpin_mode

# Check hairpin NAT rules
iptables -t nat -nvL KUBE-ROUTER-HAIRPIN
```

**Root Cause:** Hairpin mode requires both the `--hairpin-mode=true` CLI flag and proper CNI configuration.
Additionally, hairpin NAT rules may not regenerate after pod restarts
([#637](https://github.com/cloudnativelabs/kube-router/issues/637),
[#1196](https://github.com/cloudnativelabs/kube-router/issues/1196)).

**Solution:** Enable hairpin mode with `--hairpin-mode=true`. If rules are missing after a pod restart,
upgrade to a version containing the fix (PR #1200). As a workaround, flush NAT rules and restart
kube-router:

```sh
iptables -t nat -F KUBE-ROUTER-HAIRPIN
# Then restart the kube-router pod
```

## BGP and Routing Issues

### Routes Not Being Advertised

**Symptoms:** `gobgp global rib` shows routes, but external peers report receiving zero prefixes
(`PfxRcd = 0`).

**Diagnosis:**

```sh
# Check BGP session state
gobgp neighbor

# Check if routes are in the RIB
gobgp global rib

# On the external router (e.g., FRR)
show ip bgp summary
show bgp detail  # look for routes marked as Stale
```

**Root Cause:** Most commonly caused by a GoBGP graceful restart bug. When kube-router negotiates graceful
restart with a peer but the peer has a different GR configuration, routes remain in "Stale" state
indefinitely
([#1389](https://github.com/cloudnativelabs/kube-router/issues/1389),
[#1486](https://github.com/cloudnativelabs/kube-router/issues/1486)).

**Solution:**

- Enable `--bgp-graceful-restart` on kube-router **and** configure graceful restart on the external peer
  to match
- Or disable `--bgp-graceful-restart` entirely if peer compatibility cannot be guaranteed
- After changing settings, restart the external BGP router to clear stale GR state

### Routes Lost After Network Interface Bounce

**Symptoms:** After a network interface goes down and comes back up (e.g., DHCP renewal,
`systemctl restart systemd-networkd`), pod-to-pod connectivity across nodes is broken. Routes are missing
from `ip route`.

**Diagnosis:**

```sh
# Verify routes are missing
ip route | grep 10.244

# Check if GoBGP still has them
gobgp global rib

# Compare neighbor count vs route count
gobgp neighbor | grep Establ | wc -l
ip route | grep <pod-cidr-prefix> | wc -l
```

**Root Cause:** The Linux kernel flushes all routes on an interface when it goes down. GoBGP's RIB still
has the routes but does not detect that the kernel lost them, so it does not re-inject them until the next
periodic sync
([#509](https://github.com/cloudnativelabs/kube-router/issues/509)).

**Solution:** Upgrade to a version with separated kernel route synchronization (PR #1151), which
re-populates routes within 15 seconds. As a workaround, restart the kube-router pod or reduce
`--routes-sync-period`.

Also check for **systemd-networkd interference**: by default, systemd-networkd removes all "foreign" routes
on restart. Add to `/etc/systemd/networkd.conf`
([#1815](https://github.com/cloudnativelabs/kube-router/issues/1815)):

```ini
[Network]
ManageForeignRoutingPolicyRules=no
ManageForeignRoutes=no
```

### Mismatched Local Address with External Peers

**Symptoms:** BGP sessions with external peers remain in `Active` state and never establish. Logs show
`Mismatched local address`.

**Diagnosis:**

```sh
# Check peer state
gobgp neighbor <peer-ip>

# Look for the mismatch in logs
# "Mismatched local address Addr=X.X.X.X Configured addr=Y.Y.Y.Y"
```

**Root Cause:** On multi-homed nodes, kube-router may use the wrong local address for external BGP peers.
The node's primary IP may not be the correct source for reaching an external peer on a different subnet
([#1371](https://github.com/cloudnativelabs/kube-router/issues/1371)).

**Solution:** Use the `kube-router.io/peer.localips` node annotation to explicitly set the local address
for external peers. Configure peers via annotations rather than `--peer-router-ips` CLI flags for more
control.

### Slow BGP Convergence on Startup

**Symptoms:** New nodes take ~5 minutes to establish BGP routes with other nodes.

**Diagnosis:**

```sh
# Check node addresses
kubectl get node <name> -o jsonpath='{.status.addresses}'

# Look for log messages about missing node IP
# "failed to get node object: host IP unknown"
```

**Root Cause:** With `--cloud-provider=external` on Kubernetes 1.29+, kubelet no longer populates
`status.addresses` immediately. kube-router skips adding nodes as BGP peers when their address is unknown
and only retries at the next periodic sync
([#1668](https://github.com/cloudnativelabs/kube-router/issues/1668)).

**Solution:** Pass `--node-ip=<IP>` to kubelet to restore immediate address population. For kubeadm, set
`node-ip` in `kubeletExtraArgs`.

### Scaling Issues with Large Clusters

**Symptoms:** Upstream switches run out of TCAM/routing table space. Network devices show hundreds of
thousands of routes.

**Root Cause:** Default iBGP full mesh creates N*(N-1)/2 peerings, and `--advertise-cluster-ip` adds a /32
route for every service
([#923](https://github.com/cloudnativelabs/kube-router/issues/923)).

**Solution:**

- Set `--enable-ibgp=false` and peer only with upstream routers via `--peer-router-ips`
- Use route reflectors instead of full mesh
- Disable `--advertise-cluster-ip` globally and use per-service annotation
  `kube-router.io/service.advertise.clusterip` for services that need external advertisement
- Consider advertising aggregate subnet routes instead of individual /32s

### PMTU / Path MTU Discovery Failures

**Symptoms:** Large TCP transfers hang or time out. Small requests work but large responses fail,
particularly in environments with reduced MTU (VPNs, GRE tunnels, IPIP overlays).

**Diagnosis:**

```sh
# Check for ICMP "need to frag" messages being dropped
tcpdump -i any icmp

# Verify ICMP destination-unreachable is allowed in the service and policy chains
iptables -nvL KUBE-ROUTER-SERVICES | grep icmp
iptables -nvL | grep "destination-unreachable"
```

**Root Cause:** Older versions of kube-router only allowed ICMP type 8 (echo request), blocking ICMP
type 3 ("Destination Unreachable") which includes code 4 ("Fragmentation Needed"), essential for PMTU
discovery ([#685](https://github.com/cloudnativelabs/kube-router/issues/685)).

**Current Status:** Modern versions of kube-router allow `destination-unreachable` (which covers PMTU),
`echo-request`, and `time-exceeded` ICMP types in both the service proxy and network policy chains via
`CommonICMPRules()` in `pkg/utils/iptables.go`. IPv6 additionally allows neighbor discovery packets.

If you are still experiencing PMTU issues on a current version, verify that the ICMP rules are present
in the relevant iptables chains. If they are missing, check kube-router logs for iptables sync errors.

## Network Policy Issues

### Egress Policy Blocking Service Access

**Symptoms:** Pods with egress network policies can reach other pods by IP but cannot access services via
ClusterIP.

**Diagnosis:**

```sh
# Test pod-to-pod (by IP) -- works
kubectl exec <pod> -- nc -zv <target-pod-ip> <port>

# Test pod-to-service (by ClusterIP) -- fails
kubectl exec <pod> -- nc -zv <cluster-ip> <port>

# Check kube-router arguments
kubectl get ds -n kube-system kube-router -o yaml | grep service-cluster-ip-range
```

**Root Cause:** kube-router does not know the cluster IP range and cannot properly allow egress to service
IPs. This happens when `--service-cluster-ip-range` is not set or does not match the actual cluster CIDR
([#1617](https://github.com/cloudnativelabs/kube-router/issues/1617)).

**Solution:** Add `--service-cluster-ip-range=<your-cidr>` to the kube-router arguments.

### Pods Have Network Access Before Policy is Applied

**Symptoms:** A pod can briefly communicate with destinations that should be blocked by its NetworkPolicy.
CronJobs or short-lived pods may complete before policies take effect.

**Root Cause:** Network policies are applied asynchronously after pod creation. There is a race window
where the pod can send/receive traffic before iptables rules are synced. Connections established during
this window persist because `ESTABLISHED,RELATED` flows are always allowed
([#873](https://github.com/cloudnativelabs/kube-router/issues/873)).

**Solution:** This is an architectural limitation. Modern versions sync policies within a few seconds. For
critical workloads, add an `initContainer` that waits for network readiness before starting the main
container.

### ipBlock Not Matching Real Client IP

**Symptoms:** NetworkPolicy `ipBlock` rules do not match external client IPs. Traffic appears to come from
cluster node IPs instead.

**Diagnosis:**

```sh
# Observe traffic source IPs
tcpdump -i nflog:100 -nnnn

# Check service traffic policy
kubectl get svc <name> -o yaml | grep -i trafficpolicy
```

**Root Cause:** Without `externalTrafficPolicy: Local`, IPVS proxies traffic across nodes, rewriting the
source IP to the forwarding node's address
([#1199](https://github.com/cloudnativelabs/kube-router/issues/1199)).

**Solution:** Set `externalTrafficPolicy: Local` on the service. This ensures traffic is only delivered to
nodes running the service pod, preserving the original client IP for network policy matching. Note: this
means only nodes with pods advertise the VIP.

## Overlay and Tunnel Issues

### Cross-Subnet Connectivity Failures

**Symptoms:** Pods on nodes in the same subnet can communicate, but pods on nodes in different subnets
cannot.

**Diagnosis:**

```sh
# Check if overlay is enabled
kubectl get ds -n kube-system kube-router -o yaml | grep enable-overlay

# Check if tunnel interfaces exist
ip link show type ipip

# Check if routes use the tunnel
ip route | grep tun-
```

**Root Cause:** When `--enable-overlay=true` (the default), kube-router creates IPIP tunnels for
cross-subnet communication. If tunnels are not created, or if firewall rules block IP protocol 4 (IPIP
encapsulation), cross-subnet traffic fails
([#647](https://github.com/cloudnativelabs/kube-router/issues/647)).

**Solution:** Verify that:

- `--enable-overlay=true` is set
- IP protocol 4 is allowed through any host firewalls (e.g., `firewalld`, security groups)
- Tunnel interfaces exist for remote-subnet nodes
- For `--overlay-type=full`, tunnels are created for all nodes regardless of subnet

### MTU Issues with Tunnels

**Symptoms:** Large packets fail silently when crossing tunnel interfaces. TCP connections hang on large
transfers.

**Root Cause:** IPIP encapsulation adds 20 bytes of overhead (40 bytes for IPv6). If the tunnel interface
MTU is not reduced accordingly, packets exceed the physical MTU and are dropped
([#630](https://github.com/cloudnativelabs/kube-router/issues/630),
[#1033](https://github.com/cloudnativelabs/kube-router/issues/1033)).

**Solution:** Enable `--auto-mtu=true` (the default) to let kube-router automatically calculate the
correct MTU for kube-bridge and pod interfaces, accounting for IPIP overhead.

## DSR (Direct Server Return) Issues

### DSR with containerd / CRI-O

**Symptoms:** DSR mode fails with errors about Docker socket not being available, or "container ID should
not be empty."

**Root Cause:** Older kube-router versions required Docker for DSR container setup. DSR needs to configure
loopback addresses inside pod network namespaces, which originally used Docker API calls
([#843](https://github.com/cloudnativelabs/kube-router/issues/843)).

**Solution:** Upgrade to a version with CRI support (PR #1027) and set `--runtime-endpoint` to your
container runtime socket:

```text
--runtime-endpoint=unix:///run/containerd/containerd.sock
```

### Large Packet Failures with DSR

**Symptoms:** DSR services fail for large TCP transfers. Packets with the DF (Don't Fragment) flag set are
dropped when they exceed 1480 bytes.

**Root Cause:** IPIP encapsulation in DSR mode adds 20 bytes of overhead. Without TCP MSS clamping,
packets near the 1500-byte MTU are encapsulated to >1500 bytes and dropped
([#630](https://github.com/cloudnativelabs/kube-router/issues/630)).

**Solution:** Upgrade to a version with TCPMSS clamping for DSR (PR #1063). Verify the mangle table has
MSS clamping rules:

```sh
iptables -t mangle -nvL | grep TCPMSS
```

**NOTE:** There is no solution for this for UDP traffic unfortunately. The best that can be done in the UDP scenario is
to manually attempt to control packet sizes via the client.

### Policy Routing Setup Failures

**Symptoms:** DSR traffic is not returned directly to the client. Logs show errors about missing
`/etc/iproute2/rt_tables`.

**Root Cause:** The custom routing table file is missing or unwritable in the container
([#1616](https://github.com/cloudnativelabs/kube-router/issues/1616)).

**Solution:** Ensure `/etc/iproute2/rt_tables` (or system equivalent) is mounted into the kube-router container. The
DaemonSet manifests in the `daemonset/` directory include the correct volume mounts.

## System Integration Issues

### systemd-networkd Purging Routes

**Symptoms:** Pod connectivity breaks after a system update or `systemd-networkd` restart. Routes managed
by kube-router disappear.

**Root Cause:** systemd-networkd's `ManageForeignRoutingPolicyRules` option (default: `yes`) removes all
routes not managed by networkd on restart
([#1815](https://github.com/cloudnativelabs/kube-router/issues/1815)).

**Solution:** Disable foreign route management in `/etc/systemd/networkd.conf`:

```ini
[Network]
ManageForeignRoutingPolicyRules=no
ManageForeignRoutes=no
```

Then restart systemd-networkd: `systemctl restart systemd-networkd`

### Docker iptables Rules Conflicting

**Symptoms:** Pod traffic works on the node but is blocked when forwarded to/from external clients. The
FORWARD chain has a DROP policy from Docker.

**Root Cause:** Docker adds its own iptables rules including a default DROP policy on the FORWARD chain
and DOCKER-ISOLATION rules that interfere with IPVS forwarding
([#757](https://github.com/cloudnativelabs/kube-router/issues/757)).

**Solution:** Set `"iptables": false` in `/etc/docker/daemon.json` and restart Docker. If using containerd
as your runtime (recommended), this is not an issue.

### CrashLoopBackOff and Liveness Probe Failures

**Symptoms:** kube-router pods are in CrashLoopBackOff, but logs show normal operation with no errors.
`kubectl describe pod` shows `Liveness probe failed: connection refused`.

**Diagnosis:**

```sh
# Check from the host
curl http://localhost:20244/healthz

# Check pod events
kubectl describe pod -n kube-system <kube-router-pod>

# Check if kubelet can reach the health port
kubectl get events -n kube-system | grep kube-router
```

**Root Cause:** The liveness probe uses the node IP (not localhost), and intermittent connectivity issues
prevent kubelet from reaching the health endpoint. This is often caused by missing
`--service-cluster-ip-range` or host firewall rules
([#1670](https://github.com/cloudnativelabs/kube-router/issues/1670)).

**Solution:**

- Set `--service-cluster-ip-range` to match your actual cluster CIDR
- Increase probe tolerances: `initialDelaySeconds: 120`, `failureThreshold: 6`
- Check host-level firewalls that might block traffic to the health port

### API Server Connectivity Loss

**Symptoms:** kube-router crashes with panic traces when the Kubernetes API server restarts or is
temporarily unavailable.

**Root Cause:** In older versions, kube-router's event handlers did not handle the
`cache.DeletedFinalStateUnknown` wrapper type that Kubernetes informers deliver when the API server was
unavailable during object deletion. This caused runtime panics on type assertions
([#712](https://github.com/cloudnativelabs/kube-router/issues/712)).

**Solution:** Upgrade to v1.0.0-rc1 or later (PRs #864, #856, #813). Use `--bgp-graceful-restart` to
preserve BGP routes during restarts. Ensure the API server is deployed in a highly available
configuration.

## IPv6 and Dual-Stack Issues

### Common Dual-Stack Pitfalls

When running kube-router with dual-stack networking, keep the following in mind:

- **Enable both protocols**: Set `--enable-ipv4=true --enable-ipv6=true`
- **Service CIDR**: Specify both CIDRs with `--service-cluster-ip-range` (can be specified multiple times)
- **PreferDualStack**: Changing a service to `PreferDualStack` after initial creation may not trigger route
  advertisements immediately
  ([#1442](https://github.com/cloudnativelabs/kube-router/issues/1442))
- **Egress and NDP**: IPv6 egress network policies can block NDP (Neighbor Discovery Protocol) NA/NS
  packets, breaking IPv6 connectivity entirely
  ([#1895](https://github.com/cloudnativelabs/kube-router/issues/1895))

### IPv6 Route Advertisement Issues

**Symptoms:** IPv6 ClusterIPs or ExternalIPs are not advertised to BGP peers.

**Diagnosis:**

```sh
# Check IPv6 routes in BGP RIB
gobgp global rib -a ipv6

# Verify IPv6 is enabled
kubectl get ds -n kube-system kube-router -o yaml | grep enable-ipv6
```

**Solution:** Ensure `--enable-ipv6=true` is set. For `--advertise-cluster-ip`, verify that IPv6 service
addresses are present in the service spec. If using BGP graceful restart, ensure both IPv4 and IPv6
AFI-SAFI families are properly negotiated with external peers.

## Getting Further Help

If the troubleshooting steps above do not resolve your issue:

1. **Search existing issues**: Many problems have been discussed in detail at
   [GitHub Issues](https://github.com/cloudnativelabs/kube-router/issues)
1. **Collect diagnostics**: Before reporting, gather output from the commands in the
   [General Diagnostic Tools](#general-diagnostic-tools) section at `-v=2` or higher log verbosity
1. **Join the community**: Ask questions in
   [#kube-router on Kubernetes Slack](https://kubernetes.slack.com/messages/C8DCQGTSB/)
1. **File an issue**: Include your kube-router version, Kubernetes version, Linux kernel version, iptables
   version, and the diagnostic output collected above
