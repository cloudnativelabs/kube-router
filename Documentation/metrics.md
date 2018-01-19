# Metrics

## Scraping kube-router metrics with Prometheus

The scope of this document is to describe how to setup the [annotations](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/) needed for [Prometheus](https://prometheus.io/) to use [Kubernetes SD](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#<kubernetes_sd_config>) to discover & scape kube-router [pods](https://kubernetes.io/docs/concepts/workloads/pods/pod/).
For help with installing Prometheus please see their [docs](https://prometheus.io/docs/introduction/overview/)

By default kube-router will export Prometheus metrics on port `8080` under the path `/metrics`.
If running kube-router as [daemonset](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) this port might collide with other applications running on the host network and must be changed.

kube-router 0.1.0-rc2 and upwards supports the following runtime configuration for controlling where to expose the metrics.
If you are using a older version, metrics path & port is locked to `/metrics` & `8080`.

      --metrics-port int                    Prometheus metrics port to use ( default 8080 )
      --metrics-path string                 Path to serve Prometheus metrics on ( default /metrics )

By enabling [Kubernetes SD](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#<kubernetes_sd_config>) in Prometheus configuration & adding required annotations it can automaticly discover & scrape kube-router metrics.

## Supported annotations

The following annotations can be set on pods/services to enable automatic SD & scraping

* `prometheus.io/scrape`: Only scrape services that have a value of `true`
* `prometheus.io/path`: If the metrics path is not `/metrics` override this.
* `prometheus.io/port`: If the metrics are exposed on a different port to the

They are to be set under `spec.template.metadata`

For example:

    spec:
      template:
        metadata:
          labels:
            k8s-app: kube-router
          annotations:
            prometheus.io/scrape: "true"
            prometheus.io/port: "8080"

## Avail metrics

The following metrics is exposed by kube-router prefixed by `kube_router_`

* service_total_connections
  Total connections made to the service since creation
* service_packets_in
  Total n/o packets received by service
* service_packets_out
  Total n/o packets sent by service
* service_bytes_in
  Total bytes received by the service
* service_bytes_out
  Total bytes sent by the service
* service_pps_in
  Incoming packets per second
* service_pps_out
  Outgoing packets per second
* service_cps
  Connections per second
* service_bps_in
  Incoming bytes per second
* service_bps_out
  Outgoing bytes per second

To get a grouped list of CPS for each service a Prometheus query could look like this e.g: 
`sum(kube_router_service_cps) by (namespace, service_name)`

## Grafana Dashboard

This repo contains a example [Grafana dashboard](https://grafana.com/) utilizing all the above exposed metrics from kube-router.
[kube-router.json](https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/dashboard/kube-router.json)
[dashboard.png](https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/dashboard/dashboard.png)
