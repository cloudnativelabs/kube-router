
<font size="5">**Method of reducing BGP neighbors between each kubernetes node in AS**</font>
<br>
<br>
<br>



<font size="4">**The number growth of BGP neighbors before optimization**</font><br>

When "--enable-ibgp=true" is set by default by kube-router, all kubernetes nodes establish BGP neighborhood relationships with each other. Suppose there are eight k8s-nodes in our network. Their topological relationships are as follows:

![avatar](../docs/img/large-networks02.jpg)

We can login to each kubernetes node to see the local neighborhood.
<br>
View on k8s-node-1:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[k8s-node-1 ~]# gobgp neighbor<br>
Peer             AS  Up/Down State       |#Received  Accepted<br>
192.168.110.12  64558 17:17:28 Establ      |        0         0<br>
192.168.120.13  64558 17:17:28 Establ      |        0         0<br>
192.168.120.14  64558 17:17:28 Establ      |        0         0<br>
192.168.130.15  64558 17:17:28 Establ      |        0         0<br>
192.168.130.16  64558 17:17:28 Establ      |        0         0<br>
192.168.140.17  64558 17:17:28 Establ      |        0         0<br>
192.168.140.18  64558 17:17:28 Establ      |        0         0<br>
[k8s-node-1 ~]#
</font></td></tr></table>

View on k8s-node-2:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[k8s-node-2 ~]# gobgp neighbor<br>
Peer             AS  Up/Down State       |#Received  Accepted<br>
192.168.110.11  64558 17:17:28 Establ      |        0         0<br>
192.168.120.13  64558 17:17:28 Establ      |        0         0<br>
192.168.120.14  64558 17:17:28 Establ      |        0         0<br>
192.168.130.15  64558 17:17:28 Establ      |        0         0<br>
192.168.130.16  64558 17:17:28 Establ      |        0         0<br>
192.168.140.17  64558 17:17:28 Establ      |        0         0<br>
192.168.140.18  64558 17:17:28 Establ      |        0         0<br>
[k8s-node-2 ~]#
</font></td></tr></table>

View on k8s-node-3:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[k8s-node-3 ~]# gobgp neighbor<br>
Peer             AS  Up/Down State       |#Received  Accepted<br>
192.168.110.11  64558 17:17:28 Establ      |        0         0<br>
192.168.110.12  64558 17:17:28 Establ      |        0         0<br>
192.168.120.14  64558 17:17:28 Establ      |        0         0<br>
192.168.130.15  64558 17:17:28 Establ      |        0         0<br>
192.168.130.16  64558 17:17:28 Establ      |        0         0<br>
192.168.140.17  64558 17:17:28 Establ      |        0         0<br>
192.168.140.18  64558 17:17:28 Establ      |        0         0<br>
[k8s-node-3 ~]#
</font></td></tr></table>

View on k8s-node-4:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[k8s-node-4 ~]# gobgp neighbor<br>
Peer             AS  Up/Down State       |#Received  Accepted<br>
192.168.110.11  64558 17:17:28 Establ      |        0         0<br>
192.168.110.12  64558 17:17:28 Establ      |        0         0<br>
192.168.120.13  64558 17:17:28 Establ      |        0         0<br>
192.168.130.15  64558 17:17:28 Establ      |        0         0<br>
192.168.130.16  64558 17:17:28 Establ      |        0         0<br>
192.168.140.17  64558 17:17:28 Establ      |        0         0<br>
192.168.140.18  64558 17:17:28 Establ      |        0         0<br>
[k8s-node-4 ~]#
</font></td></tr></table>

View on k8s-node-5:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[k8s-node-5 ~]# gobgp neighbor<br>
Peer             AS  Up/Down State       |#Received  Accepted<br>
192.168.110.11  64558 17:17:28 Establ      |        0         0<br>
192.168.110.12  64558 17:17:28 Establ      |        0         0<br>
192.168.120.13  64558 17:17:28 Establ      |        0         0<br>
192.168.120.14  64558 17:17:28 Establ      |        0         0<br>
192.168.130.16  64558 17:17:28 Establ      |        0         0<br>
192.168.140.17  64558 17:17:28 Establ      |        0         0<br>
192.168.140.18  64558 17:17:28 Establ      |        0         0<br>
[k8s-node-5 ~]#
</font></td></tr></table>

View on k8s-node-6:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[k8s-node-6 ~]# gobgp neighbor<br>
Peer             AS  Up/Down State       |#Received  Accepted<br>
192.168.110.11  64558 17:17:28 Establ      |        0         0<br>
192.168.110.12  64558 17:17:28 Establ      |        0         0<br>
192.168.120.13  64558 17:17:28 Establ      |        0         0<br>
192.168.120.14  64558 17:17:28 Establ      |        0         0<br>
192.168.130.15  64558 17:17:28 Establ      |        0         0<br>
192.168.140.17  64558 17:17:28 Establ      |        0         0<br>
192.168.140.18  64558 17:17:28 Establ      |        0         0<br>
[k8s-node-6 ~]#
</font></td></tr></table>

View on k8s-node-7:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[k8s-node-7 ~]# gobgp neighbor<br>
Peer             AS  Up/Down State       |#Received  Accepted<br>
192.168.110.11  64558 17:17:28 Establ      |        0         0<br>
192.168.110.12  64558 17:17:28 Establ      |        0         0<br>
192.168.120.13  64558 17:17:28 Establ      |        0         0<br>
192.168.120.14  64558 17:17:28 Establ      |        0         0<br>
192.168.130.15  64558 17:17:28 Establ      |        0         0<br>
192.168.130.16  64558 17:17:28 Establ      |        0         0<br>
192.168.140.18  64558 17:17:28 Establ      |        0         0<br>
[k8s-node-7 ~]#
</font></td></tr></table>

View on k8s-node-8:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[k8s-node-8 ~]# gobgp neighbor<br>
Peer             AS  Up/Down State       |#Received  Accepted<br>
192.168.110.11  64558 17:17:28 Establ      |        0         0<br>
192.168.110.12  64558 17:17:28 Establ      |        0         0<br>
192.168.120.13  64558 17:17:28 Establ      |        0         0<br>
192.168.120.14  64558 17:17:28 Establ      |        0         0<br>
192.168.130.15  64558 17:17:28 Establ      |        0         0<br>
192.168.130.16  64558 17:17:28 Establ      |        0         0<br>
192.168.140.17  64558 17:17:28 Establ      |        0         0<br>
 [k8s-node-8 ~]#
 </font></td></tr></table>

We present the neighborhood relationships between all kubernetes nodes in red dotted lines as follows:

![avatar](../docs/img/large-networks03.jpg)

You will find that the number of BGP peers per kubernetes node is n-1 (n is the total number of all nodes in the k8s cluster). If we had 2000 node servers in our k8s cluster, there would be 1999 BGP peers on each node. With the increasing number of kubernetes nodes in k8s cluster, the number of BGP peers per k8s-node will also increase, which is undoubtedly not a small overhead for node servers. With the increase of cluster size, the pressure of node server will increase.
<br>



<br>
<br>
<font size="4">**How to optimize the BGP neighborhood of kubernetes node?**</font><br>

To solve this problem, you need to turn on the BGP function of the router device on the node server. Moreover, hardware router devices have special chips to handle BGP routing forwarding, and its performance is better. At the same time, you need to set the parameter "--enable-ibgp=false" of kube-router. 
<br>
<br>
For example：
<br>
You can see the white font parameters in the configuration example below.
<table><tr><td bgcolor=#000000><font color=#F0E68C>
      - name: kube-router<br>
        image: cloudnativelabs/kube-router:0.3.2<br>
        imagePullPolicy: IfNotPresent<br>
        args:<br>
        - --run-router=true<br>
        - --run-firewall=true<br>
        - --run-service-proxy=true<br>
        - --enable-overlay=false<br>
        - --advertise-pod-cidr=true<br>
        - --advertise-cluster-ip=true<br>
        - --bgp-graceful-restart=true</font><br><font color=#ffffff>
        - --enable-ibgp=false        </font><br><font color=#F0E68C>
        - --nodes-full-mesh=true<br>
        - --cluster-asn=64558<br>
        - --peer-router-ips=192.168.110.1<br>
        - --peer-router-asns=64558<br>
        ......<br>
</font></td></tr></table>
       
When you set this parameter, all kubernetes nodes will not establish BGP neighborhood relationships with each other. Each kubernetes node establishes a BGP peer only between the router it is connected to.
<br>
We can log in to each kubernetes node and router to see the local neighborhood.
<br>
View on router1:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
<router1>dis bgp peer<br>
 BGP local router ID        : 192.168.110.1<br>
 Local AS number            : 64558<br>
 Total number of peers      : 2        <br>        
 Peers in established state : 2<br>

  Peer            V          AS  MsgRcvd  MsgSent  OutQ  Up/Down       State  PrefRcv<br>
  192.168.110.11  4       64558     2203     2524     0 17:57:52 Established        1<br>
  192.168.110.12  4       64558     2203     2524     0 17:57:57 Established        1<br>
<router1>
</font></td></tr></table>

View on router2:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
<router2>dis bgp peer<br>
 BGP local router ID        : 192.168.120.1<br>
 Local AS number            : 64558<br>
 Total number of peers      : 2        <br>        
 Peers in established state : 2<br>

  Peer            V          AS  MsgRcvd  MsgSent  OutQ  Up/Down       State  PrefRcv<br>
  192.168.120.13  4       64558     2203     2524     0 17:57:52 Established        1<br>
  192.168.120.14  4       64558     2203     2524     0 17:57:57 Established        1<br>
<router2>
</font></td></tr></table>

View on router3:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
<router3>dis bgp peer<br>
 BGP local router ID        : 192.168.130.1<br>
 Local AS number            : 64558<br>
 Total number of peers      : 2            <br>    
 Peers in established state : 2<br>

  Peer            V          AS  MsgRcvd  MsgSent  OutQ  Up/Down       State  PrefRcv<br>
  192.168.130.15  4       64558     2203     2524     0 17:57:52 Established        1<br>
  192.168.130.16  4       64558     2203     2524     0 17:57:57 Established        1<br>
<router3>
</font></td></tr></table>

View on router4:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
<router4>dis bgp peer<br>
 BGP local router ID        : 192.168.140.1<br>
 Local AS number            : 64558<br>
 Total number of peers      : 2                <br>
 Peers in established state : 2<br>

  Peer            V          AS  MsgRcvd  MsgSent  OutQ  Up/Down       State  PrefRcv<br>
  192.168.140.17  4       64558     2203     2524     0 17:57:52 Established        1<br>
  192.168.140.18  4       64558     2203     2524     0 17:57:57 Established        1<br>
<router1>
</font></td></tr></table>


View on k8s-node-1:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[k8s-node-1 ~]# gobgp neighbor<br>
Peer             AS  Up/Down State       |#Received  Accepted<br>
192.168.110.1  64558 17:17:28 Establ      |        0         0<br>
[k8s-node-1 ~]#
</font></td></tr></table>

View on k8s-node-2:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[k8s-node-2 ~]# gobgp neighbor<br>
Peer             AS  Up/Down State       |#Received  Accepted<br>
192.168.110.1  64558 17:17:28 Establ      |        0         0<br>
[k8s-node-2 ~]#
</font></td></tr></table>

View on k8s-node-3:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[k8s-node-3 ~]# gobgp neighbor<br>
Peer             AS  Up/Down State       |#Received  Accepted<br>
192.168.120.1  64558 17:17:28 Establ      |        0         0<br>
[k8s-node-3~]#
</font></td></tr></table>

View on k8s-node-4:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[k8s-node-4 ~]# gobgp neighbor<br>
Peer             AS  Up/Down State       |#Received  Accepted<br>
192.168.120.1  64558 17:17:28 Establ      |        0         0<br>
[k8s-node-4 ~]#
</font></td></tr></table>

View on k8s-node-5:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[k8s-node-5 ~]# gobgp neighbor<br>
Peer             AS  Up/Down State       |#Received  Accepted<br>
192.168.130.1  64558 17:17:28 Establ      |        0         0<br>
[k8s-node-5 ~]#
</font></td></tr></table>

View on k8s-node-6:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[k8s-node-6 ~]# gobgp neighbor<br>
Peer             AS  Up/Down State       |#Received  Accepted<br>
192.168.130.1  64558 17:17:28 Establ      |        0         0<br>
[k8s-node-6 ~]#
</font></td></tr></table>

View on k8s-node-7:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[k8s-node-7 ~]# gobgp neighbor<br>
Peer             AS  Up/Down State       |#Received  Accepted<br>
192.168.140.1  64558 17:17:28 Establ      |        0         0<br>
[k8s-node-7 ~]#
</font></td></tr></table>

View on k8s-node-8:
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[k8s-node-8 ~]# gobgp neighbor<br>
Peer             AS  Up/Down State       |#Received  Accepted<br>
192.168.140.1  64558 17:17:28 Establ      |        0         0<br>
[k8s-node-8 ~]#
</font></td></tr></table>


We present the neighborhood relationships between all kubernetes nodes in red dotted lines as follows:

![avatar](../docs/img/large-networks04.jpg)

You will find that no matter how many kubernetes nodes you have in your k8s cluster, there is only one BGP neighbor on each kubernetes node. Each router has only BGP neighbors to the downlink kubernetes node and a small number of BGP neighbors to the downlink. In the actual production environment, due to the number of interfaces of router devices, the number of kubernetes nodes that can be connected to each router is very limited, generally less than 100.
<br>
By setting the parameter "--enable-ibgp=false", we achieve the effect of BGP neighbor control on each kubernetes node in the same AS. This reduces the pressure on the kubernetes node server.
<br>
<br>


