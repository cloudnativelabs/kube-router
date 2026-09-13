# Health checking kube-router

kube-router has basic health checking in the form of heartbeats sent from each controller to the health controller
at the start and at the end of every iteration of that controller's main loop. This happens unconditionally, whether
the controller's logic succeeded or failed.

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

## What a heartbeat does and does not assert

A heartbeat asserts that **a control loop is turning**. It does **not** mean the node's networking is correctly
programmed.

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

## Monitoring sync correctness

Because health deliberately does not cover sync correctness, this is reported through metrics see:
[Metrics](/docs/metrics.md) for more details.
