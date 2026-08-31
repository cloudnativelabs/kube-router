# Health checking kube-router

kube-router has basic health checking in the form of heartbeats sent from each controller to the health controller
at the start and at the end of every iteration of that controller's main loop.

The health port is by default 20244 but can be changed with the startup option.
The health path is `/healthz`

```sh
--health-port=<port number>
```

If port is set to 0 (zero) no HTTP endpoint will be made available but the health controller will still run and print
out any missed heartbeats to STDERR of kube-router

If a controller does not send a heartbeat within its sync period, plus the startup lead time learned from its first
heartbeat, plus a 1.5 second grace window, the component will be flagged as unhealthy.

If any of the running components is failing the whole kube-router state will be marked as failed in the /healthz
endpoint

For example, if kube-router is started with

```sh
--run-router=true
--run-firewall=true
--run-service-proxy=true
--run-loadbalancer=true
```

If the route controller, policy controller or service controller exits its main loop and does not publish a heartbeat
the `/healthz` endpoint will return a error 500 signaling that kube-router is not healthy.

## What A Heartbeat Does And Does Not Assert

This is worth being explicit about, because the two shipped daemonsets wire `/healthz` as a **livenessProbe** with
`periodSeconds: 3` and `failureThreshold: 3`. Roughly nine seconds of unhealthy and the kubelet kills the container,
so what a heartbeat means decides when kube-router gets restarted.

A heartbeat asserts that **a control loop is turning**. It does not assert that an iteration accomplished anything.
Every controller sends one heartbeat when an iteration starts and another when that iteration's work returns,
unconditionally, whether it succeeded or failed.

That is a deliberate choice. `/healthz` answers the one question a livenessProbe can act on: is this goroutine wedged?
A restart fixes a wedged loop. A restart does not fix a network policy that references something the kernel keeps
rejecting, a route that cannot be installed, or a BGP peer that will not come up. Gating the heartbeat on sync success
turns those into a `CrashLoopBackOff`, which takes kube-router off the node entirely and leaves the underlying problem
exactly where it was. A running kube-router with a stale-but-working rule set is strictly better than a restarting one.

The start-of-iteration beat exists because the health deadline is the sync period plus a small grace window measured
at startup. Beating only at iteration end would mean each sync could only run as long as the *first* sync did before
`/healthz` flipped unhealthy, and the first sync happens against a freshly started process, which is the cheapest sync
kube-router will ever run. With the start beat, every sync gets the full sync period as its budget. A genuinely wedged
sync never sends its end beat, so a wedged goroutine is still detected within one sync period plus grace of the moment
it stuck.

The tradeoff is that a sync which completes but takes far longer than usual (while staying under the sync period) will
not show up on `/healthz` at all. That's intentional: slowness while making progress is not a liveness problem, and it
is visible instead through the sync-time histograms (for example `controller_iptables_sync_time`) and the sync metrics
described below.

So `/healthz` returning `OK` means the process is alive and its loops are turning. It does **not** mean the node's
networking is correctly programmed.

## Monitoring Sync Correctness

Because health deliberately does not cover it, whether syncs are actually succeeding is reported through two metrics
(see [Metrics](/docs/metrics.md) for the full list):

- `kube_router_controller_sync_last_success` - `NO_DEFAULT_SET` - Unix timestamp of the last fully successful sync,
  labelled by `controller`.
- `kube_router_controller_sync_failures_total` - `NO_DEFAULT_SET` - Running count of sync attempts that did not
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
- alert: KubeRouterSyncFailing
  expr: time() - kube_router_controller_sync_last_success > 900
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "kube-router {{ $labels.controller }} on {{ $labels.instance }} has not completed a sync in 15m"
    description: >
      The control loop is still running (kube-router would be reporting unhealthy otherwise), but its last
      several sync attempts have failed. Check the pod logs for the abort reason; a restart will not help.
```

The 900 second threshold assumes the default 5 minute sync periods of the three main controllers, so it fires after
roughly three consecutive missed syncs for those. `RouteSyncController` syncs every 60 seconds by default, so the same
threshold represents around 15 missed route syncs; tighten it (or split out a separate alert for that label) if you
want faster detection there. Adjust the threshold if you've changed `--iptables-sync-period`, `--routes-sync-period`,
`--ipvs-sync-period`, or `--injected-routes-sync-period`.
Note that a controller which has never succeeded is stuck at `0` and therefore trips the threshold as soon as the
`for` window elapses, which is the intent - it has never programmed anything, so it deserves to page sooner than one
that merely went stale.

If you'd rather alert on the rate of failures than on staleness,
`increase(kube_router_controller_sync_failures_total[15m])`
works as well, though it will also fire on a controller that is flapping between success and failure rather than one
that is stuck.
