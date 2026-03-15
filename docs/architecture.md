# Architecture

kube-router is built around the concept of watchers and controllers. Watchers use the Kubernetes watch API to get
notification on events related to create, update, delete of Kubernetes objects. Each watcher gets notification related
to a particular API object. On receiving an event from API server, watcher broadcasts events. Controller registers to
get event updates from the watchers and act upon the events.

kube-router consists of 4 core controllers and multiple watchers as depicted in the diagram below.

![Arch](./img/kube-router-arch.drawio.svg)

Each of the [controller](https://github.com/cloudnativelabs/kube-router/tree/master/pkg/controllers) follows below
structure:

```go
func Run() {
    for {
        Sync() // control loop that runs forever and performs sync at periodic interval
    }
}

func OnUpdate() {
    Sync() // on receiving update of a watched API object (namespace, node, pod, network policy etc)
}

Sync() {
    //re-concile any state changes
}

Cleanup() {
    // cleanup any changes (to iptables, ipvs, network etc) done to the system
}
```
