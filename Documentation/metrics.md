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

By enabling Kubernetes SD in Prometheus configuration & adding required annotations it can automaticly discover & scrape kube-router metrics.

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