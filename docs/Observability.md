# Observability

## Observing dropped traffic due to network policy enforcements

Traffic that gets rejected due to network policy enforcements gets logged by kube-route using iptables NFLOG target under the group 100. Simplest way to observe the dropped packets by kube-router is by running tcpdump on `nflog:100` interface for e.g. `tcpdump -i nflog:100 -n`. You can also configure ulogd to monitor dropped packets in desired output format. Please see https://kb.gtkc.net/iptables-with-ulogd-quick-howto/ for an example configuration to setup a stack to log packets.
