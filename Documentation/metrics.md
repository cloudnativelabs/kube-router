# Scraping kube-router metrics with Prometheus

The scope of this document is to describe how to setup the annotations needed for Prometheus to use Kubernetes SD to discover & scape kube-router pods.
For help with installing Prometheus please see their [docs](https://prometheus.io/docs/introduction/overview/)

By default kube-router will export Prometheus metrics on port `8080` under the path `/metrics`.

If running kube-router as daemonset this port might collide with other services running on the host network and must be changed.

kube-router supports the following runtime configuration for controlling where to expose the metrics

      --metrics-port int                    Prometheus metrics port to use ( default 8080 )
      --metrics-path string                 Path to serve Prometheus metrics on ( default /metrics )

By enabling [Kubernetes SD](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#<kubernetes_sd_config>) in Prometheus it will automaticly discover & scrape pods with the correct annotations under `spec.template.metadata'

Supported annotations are:

* `prometheus.io/scrape`: Only scrape services that have a value of `true`
* `prometheus.io/path`: If the metrics path is not `/metrics` override this.
* `prometheus.io/port`: If the metrics are exposed on a different port to the

E.g

    annotations:
      prometheus.io/scrape: "true"
      prometheus.io/port: "8080"
