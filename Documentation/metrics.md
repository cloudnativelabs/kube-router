# Scraping kube-router metrics with Prometheus

By default kube-router will export Prometheus metrics on port `8080` under the path `/metrics`.

If running kube-router with hostNetworking this port might collide with other services running on the host network and must be changed.

kube-router supports the following runtime configuration for controlling where to expose the metrics

      --metrics-port int                    Prometheus metrics port to use ( default 8080 )
      --metrics-path string                 Path to serve Prometheus metrics on ( default /metrics )

By enabling [Kubernetes SD](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#<kubernetes_sd_config>) in Prometheus you can have it automaticly scrape the endpoints and discover the running pods by adding the following annotations to `spec.template.metadata'

    annotations:
      prometheus.io/scrape: "true"
      prometheus.io/port: "8080"
