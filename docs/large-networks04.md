<font size="5">**How to optimize the neighborhood relationship and reduce the number of routes through kube-router in order to support the BGP network of large kubernetes cluster?**</font>
<br>
<br>
<br>



<font size="4">**1 Contrast before and after enabling ECMP function of network equipment**</font>
<br>
<br>
<font size="3">**1.1 Network traffic flow before ECMP is enabled**</font><br>
Before optimization, network traffic will choose a path to reach its destination.
<br>
The network topology is as follows:
![avatar](../docs/img/large-networks08.jpg)


<font size="3">**1.2 Network traffic sharing after ECMP enabled**</font><br>
After optimization, network traffic will be balanced to all network devices and nodes.
<br>
The network topology is as follows:
![avatar](../docs/img/large-networks09.jpg)

<br>

<font size="4">**2 How to enable BGP ECMP for network devices?**</font><br>

Taking the router equipment of the mainstream network manufacturer as an example, this paper briefly introduces how the router equipment can turn on the equivalent routing load balancing of BGP ECMP.

<font size="3">**2.1 Cisco Network Equipment Configuration BGP ECMP**</font><br>
可以使用下面的命令来开启EBGP ECMP：
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[config-Router] config terminal<br>
[config-Router] bgp 64558<br>
[config-Router] maximum-paths 32<br>
</font></td></tr></table>

可以使用下面的命令来开启IBGP ECMP：
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[config-Router] config terminal<br>
[config-Router] bgp 64558<br>
[config-Router] maximum-paths ibgp 32<br>
</font></td></tr></table>

<font size="3">**2.2 Huawei Network Equipment Configuration BGP ECMP**</font><br>
可以使用下面的命令来开启EBGP ECMP：
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[Router] system view<br>
[Router] bgp 64558<br>
[Router-bgp] ipv4-family unicast<br>
[Router-bgp-af-ipv4] maximum load-balancing ebgp 32<br>
</font></td></tr></table>

可以使用下面的命令来开启IBGP ECMP：
<table><tr><td bgcolor=#000000><font color=#F0E68C>
[Router] system view<br>
[Router] bgp 64558<br>
[Router-bgp] ipv4-family unicast<br>
[Router-bgp-af-ipv4] maximum load-balancing ibgp 32<br>
</font></td></tr></table>
<br>
<br>
