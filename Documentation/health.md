# Health checking kube-router

kube-router currently has basic health checking in form of heartbeats sent from each controller to the healthcontroller each time the main loop completes successfully.

The health port is by default 20244 but can be changed with the startup option.
The health path is `/healthz`

    --health-port=<port number>

If port is set to 0 (zero) no HTTP endpoint will be made availible but the health controller will still run and print out any missed heartbeats to STDERR of kube-router

If a controller does not send a heartbeat within controllersynctime + 5 seconds the component will be flagged as unhealthy.

If any of the running components is failing the whole kube-router state will be marked as failed in the /healthz endpoint

E.g

kube-router is started with

    --run-router=true
    --run-firewall=true
    --run-service-proxy=true

If the route controller, policy controller or service controller exits it's main loop and does not publish a heartbeat the /healthz endpoint will return a error 500 signaling that kube-router is not healthy.