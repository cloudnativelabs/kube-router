# Introduction

Welcome to the introduction guide to Kube-router! This guide is the best place to start with Kube-router. We cover what Kube-router is, what problems it can solve, how it compares to existing software, and how you can get started using it. If you are familiar with the basics of Kube-router, head over to the next sections that provide a more detailed reference of available features.

## What is Kube-router

If you are not familiar with Kubernetes networking model it is recommended to familiarize with Kubernetes [networking model](https://kubernetes.io/docs/concepts/cluster-administration/networking/#kubernetes-model). So essentially Kubernetes expects:

- all containers can communicate with all other containers without NAT
- all nodes can communicate with all containers (and vice-versa) without NAT
- the IP that a container sees itself as is the same IP that others see it as

Kubernetes only prescribes the requirements for the networking model but does not provide any default implementation. For a functional Kubernetes cluster one has to deploy what is called as CNI or pod networking solution that provides above functionality.

Any non-trivial containerized application will end up running multiple pods running different services. [Service](https://kubernetes.io/docs/concepts/services-networking/service/) abstraction in Kubernetes is an essential building block that helps in service discovery and load balancing. A layer-4 service proxy must be deployed to Kubernetes cluster that provides the load-balancing for the services exposed by the pods.

Once you have pod-to-pod networking established and have a service proxy that provides load-balancing, you need a way to secure your pods. Kubernetes [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) provides a specfication on how to secure pods. You need to deploy a solution that implements network policy specification and provides security to your pods.

Kube-router is a turnkey solution for Kubernetes networking that provides all the above essential functionality in one single elegant package.

## Why Kube-router

Network is hard. You have multiple Kubernetes networking solutions that provide pod networking or network policy etc. But when you deploy indiviudal solution for each functionality you end up with lot of moving parts making it difficult to operate and troubleshoot.

Kube-router is a lean yet powerful all-in-one alternative to several network components used in typical Kubernetes clusters. All this from a single DaemonSet/Binary. It doesn't get any easier. 

Kube-router also uses best of the solution for maximum performance. Kube-router uses IPVS/LVS for service proxy and provides direct routing between the nodes.

Kube-router also provides very unique and advanced functionalities like DSR (Direct Server Return), ECMP based network load balancing etc
