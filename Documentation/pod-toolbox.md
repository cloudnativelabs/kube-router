# Pod Toolbox

When kube-router is ran as a Pod within your Kubernetes cluster, it also ships
with a number of tools automatically configured for your cluster.  These can be
used to troubleshoot issues and learn more about how cluster networking is
performed.

## Logging In

Here's a quick way to get going on a random node in your cluster:
```
KR_POD=$(basename $(kubectl -n kube-system get pods -l k8s-app=kube-router --output name|head -n1))
kubectl -n kube-system exec -it ${KR_POD} bash
```

Use `kubectl -n kube-system get pods -l k8s-app=kube-router -o wide` to see what
nodes are running which pods. This will help if you want to investigate a
particular node.

## Tools And Usage

Once logged in you will see some help on using the tools in the container.

For example:
```console
Welcome to kube-router on "node1.zbrbdl"!

For debugging, the following tools are available:
- ipvsadm | Gather info about Virtual Services and Real Servers via IPVS.
          | Examples:
          |   ## Show all options
          |   ipvsadm --help
          |   ## List Services and Endpoints handled by IPVS
          |   ipvsadm -ln
          |   ## Show traffic rate information
          |   ipvsadm -ln --rate
          |   ## Show cumulative traffic
          |   ipvsadm -ln --stats

- gobgp   | Get BGP related information from your nodes.
          |
          | Tab-completion is ready to use, just type "gobgp <TAB>"
          | to see the subcommands available.
          |
          | By default gobgp will query the Node this Pod is running
          | on, i.e. "node1.zbrbdl". To query a different node use
          | "gobgp --host node02.mydomain" as an example.
          |
          | For more examples see: https://github.com/osrg/gobgp/blob/master/docs/sources/cli-command-syntax.md

Here's a quick look at what's happening on this Node
--- BGP Server Configuration ---
AS:        64512
Router-ID: 10.10.3.2
Listening Port: 179, Addresses: 0.0.0.0, ::

--- BGP Neighbors ---
Peer    AS     Up/Down State       |#Received  Accepted
 64512 2d 01:05:07 Establ      |        1         1

--- BGP Route Info ---
   Network              Next Hop             AS_PATH                  Age        Attrs
*> 10.2.0.0/24          10.10.3.3            4000 400000 300000 40001 2d 01:05:20 [{Origin: i} {LocalPref: 100}]
*> 10.2.1.0/24          10.10.3.2            4000 400000 300000 40001 00:00:36   [{Origin: i}]

--- IPVS Services ---
IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  10.3.0.1:443 rr persistent 10800 mask 0.0.0.0
  -> 10.10.3.2:443                Masq    1      0          0
TCP  10.3.0.10:53 rr
  -> 10.2.0.2:53                  Masq    1      0          0
TCP  10.3.0.15:2379 rr
  -> 10.10.3.3:2379               Masq    1      45         0
TCP  10.3.0.155:2379 rr
  -> 10.10.3.3:2379               Masq    1      0          0
UDP  10.3.0.10:53 rr
  -> 10.2.0.2:53                  Masq    1      0          0
```
