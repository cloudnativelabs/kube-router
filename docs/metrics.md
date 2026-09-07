# Metrics

## Scraping kube-router metrics with Prometheus

The scope of this document is to describe how to setup the
[annotations](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/) needed for
[Prometheus](https://prometheus.io/) to use
[Kubernetes SD](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#<kubernetes_sd_config>) to
discover & scrape kube-router [pods](https://kubernetes.io/docs/concepts/workloads/pods/pod/).

For help with installing Prometheus please see their [docs](https://prometheus.io/docs/introduction/overview/)

Metrics options:

```sh
--metrics-path        string               Path to serve Prometheus metrics on ( default: /metrics )
--metrics-port        uint16 <0-65535>     Prometheus metrics port to use ( default: 0, disabled )
```

To enable kube-router metrics, start kube-router with `--metrics-port` and provide a port over 0

Metrics is generally exported at the same rate as the sync period for each service. Service metrics are exported real-time.

The default values unless otherwise specified are

* iptables-sync-period - `5 min`
* routes-sync-period - `5 min`

By enabling
[Kubernetes SD](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#<kubernetes_sd_config>) in
your Prometheus configuration & adding the required annotations, Prometheus can automatically discover & scrape
kube-router metrics.

## Monitoring sync correctness

Because kube-router's /healthz endpoint deliberately does not comment on sync correctness, kube-router emits two metrics
to help operators better understand how syncs are progressing within their cluster:

* `kube_router_controller_sync_last_success` - `NO_DEFAULT_SET` - Unix timestamp of the last fully successful sync,
  labelled by `controller`.
* `kube_router_controller_sync_failures_total` - `NO_DEFAULT_SET` - Running count of sync attempts that did not
  complete, labelled by `controller`.

The `controller` label carries the same component names the health controller uses: `NetworkPolicyController`,
`NetworkRoutesController`, `NetworkServicesController`, and `RouteSyncController`. The load balancer allocator
heartbeats on the same unconditional contract, but it allocates per service off a queue rather than in one sync pass,
so it has no single per-iteration outcome to report and does not appear under these two metrics.

Both series are created the first time a controller reports any result, successful or not. That matters, because a
controller that has failed every sync since startup still needs to be visible: its
`kube_router_controller_sync_last_success` sits at `0` rather than being absent, so a staleness alert matches it
instead of silently evaluating against an empty vector.

You'll want an alert on a controller that is alive but not making progress, which is the case `/healthz` no longer
catches for you. Something like the following:

```yaml
# Alerts on staleness: a controller that is alive but has not completed a sync in 15m. The 900s threshold assumes
# the default 5 minute sync periods (roughly three missed syncs), so adjust it if you've changed
# --iptables-sync-period, --routes-sync-period, --ipvs-sync-period, or --injected-routes-sync-period.
# RouteSyncController syncs every 60s by default, so you may want a tighter threshold for that label. A controller
# that has never succeeded sits at 0 and fires as soon as the for window elapses, which is the intent.
- alert: KubeRouterSyncFailing
  expr: time() - kube_router_controller_sync_last_success > 900
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "kube-router {{ $labels.controller }} on {{ $labels.instance }} has not completed a sync in 15m"
    description: >
      The control loop is still running (kube-router would be reporting unhealthy otherwise), but its last
      several sync attempts have failed. Check the pod logs for more details.

# Alerts on the rate of failures rather than staleness. Note that this also fires on a controller that is flapping
# between success and failure, not just one that is stuck, so it is noisier than the alert above.
- alert: KubeRouterSyncFailureRate
  expr: increase(kube_router_controller_sync_failures_total[15m]) > 2
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "kube-router {{ $labels.controller }} on {{ $labels.instance }} has failed multiple syncs in 15m"
    description: >
      The control loop has recorded several failed sync attempts in the last 15 minutes, though it may still be
      succeeding in between them. Check the pod logs for more details.
```

The thresholds above are tuned for the default sync periods, so be sure to revisit them if you've changed any of the
sync period flags. Because a controller that has never succeeded reports a `0` timestamp, `KubeRouterSyncFailing`
pages for it sooner than for one that merely went stale, which is what you want - it has never programmed anything.

## Available metrics

If metrics is enabled only services that are running have their metrics exposed

The following metrics are exposed by kube-router prefixed by `kube_router_`

### Always enabled

* build_info
  Expose version and other build information (labels: goversion, version)
* controller_sync_last_success
  Unix timestamp of the last fully successful sync, by controller (labels: controller)
* controller_sync_failures_total
  Total count of sync attempts that did not complete successfully, by controller (labels: controller)

The `controller` label on the two sync metrics carries the same component names the health controller uses:
`NetworkPolicyController`, `NetworkRoutesController`, `NetworkServicesController`, and `RouteSyncController`. These
two are the only signal that a control loop is running but failing to apply its changes, because `/healthz` reports
liveness only and deliberately stays healthy through a failing sync. Both series appear the first time a controller
reports any result, so a controller that has never once succeeded shows `controller_sync_last_success` at `0` rather
than not showing up at all. See [Health checking](/docs/health.md) for why, and for an example alert expression.

### --run-router=true

* bgp_peer_info
  BGP peer information: address, state, and type (internal for iBGP and external for eBGP)
  (labels: address, type, asn, state)
* controller_bgp_advertisements_received
  Total number of BGP advertisements received since kube-router started
* controller_bgp_advertisements_sent
  Total number of BGP advertisements sent since kube-router started (labels: type)
* controller_bgp_internal_peers_sync_time
  Time it took for the BGP internal peer sync loop to complete
* controller_routes_sync_time
  Time it took for controller to sync routes
* host_routes_sync_time
  Time it took for the host routes controller to sync to the system
* host_routes_synced
  Count of host routes currently synced to the system
* host_routes_added
  Total count of host routes added to the system
* host_routes_removed
  Total count of host routes removed from the system

### --run-firewall=true

* controller_iptables_sync_time
  Time it took for the iptables sync loop to complete
* controller_iptables_v4_save_time
  Time it took controller to save IPv4 rules
* controller_iptables_v6_save_time
  Time it took for controller to save IPv6 rules
* controller_iptables_v4_restore_time
  Time it took for controller to restore IPv4 rules
* controller_iptables_v6_restore_time
  Time it took for controller to restore IPv6 rules
* controller_policy_chains_sync_time
  Time it took for controller to sync policy chains
* controller_policy_ipset_v4_restore_time
  Time it took for controller to restore IPv4 ipsets
* controller_policy_ipset_v6_restore_time
  Time it took for controller to restore IPv6 ipsets
* controller_policy_chains
  Active policy chains (gauge)
* controller_policy_ipsets
  Active policy ipsets (gauge)

### --run-service-proxy=true

* controller_ipvs_services_sync_time
  Time it took for the ipvs sync loop to complete
* controller_ipvs_services
  The number of ipvs services in the instance
* controller_ipvs_metrics_export_time
  The time it took to run the metrics export for IPVS services
* service_total_connections
  Total connections made to the service since creation
* service_packets_in
  Total incoming packets
* service_packets_out
  Total outgoing packets
* service_bytes_in
  Total incoming bytes
* service_bytes_out
  Total outgoing bytes
* service_pps_in
  Incoming packets per second
* service_pps_out
  Outgoing packets per second
* service_cps
  Service connections per second
* service_bps_in
  Incoming bytes per second
* service_bps_out
  Outgoing bytes per second

To get a grouped list of CPS for each service a Prometheus query could look like this e.g:
`sum(kube_router_service_cps) by (svc_namespace, service_name)`

## Grafana Dashboard

This repo contains an example
[Grafana dashboard](https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/dashboard/kube-router.json)
utilizing all the above exposed metrics from kube-router.
![dashboard](https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/dashboard/dashboard.png)
