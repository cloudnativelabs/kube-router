# CHANGELOG

## v0.2.0-beta.1 - April 11th 2018
* Add service/endpoints handlers so BGP routes are added/removed as soon as service/endpoints updates occur (@andrewsykim)
* Networkpolicies should account for pods that are not given a pod IP yet (@xanonid)
* Refactor to use shared informers (@andrewsykim)
* Fix bug where default ASN is used for iBGP peering when cluster ASN is set (@andrewsykim)
* Support advertising `service.Status.LoadBalancer.Ingress` IPs with flag `--advertise-loadbalancer-ip` (@jjo)
* Add delay for AWS EC2 operations and only make API calls if kube-router has the necessary IAM roles (@murali-reddy)
* Add unit tests `Test_addExportPolicies` (@andrewsykim)
* Allow advertise pod CIDR to be set using a node annotation `kube-router.io/pod-cidr`, this will override the pod CIDR specified in node.Spec.PodCIDR(@andrewsykim)
* Withdraw VIP routes if `service.Spec.ExternalTrafficPolicy=Local` and a node does not contain healthy endpoints for a service (@TvL2386)
