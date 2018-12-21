## End-To-End Testing Framework

This framework uses [Ginkgo](https://onsi.github.io/ginkgo/#getting-ginkgo) -- a BDD-style Go testing framework built to help you efficiently write expressive and comprehensive tests.

Assumming a cluster already exists, the framework allows you to run tests against it. 
- NOTE: As of Jan 10th, 2019, a cluster must first be setup beforehand; that is, we don't yet support automatic provisioning of a cluster, though we hope to have this feature in very shortly. :) 

## Tests

Tests are catogrized as follows. Additional categories may be added as desired.

- Router: focus on pod-to-pod connectivity
- Services: focus on kube-router's services functionality
- Policy: focus on network policy enforcement
- Runtime: tests that focus just on specific kube-router functionality and are not tied to kubernetes

## Running Tests

The following command will run all tests: 


        $ ginkgo -- --kuberouter.SSHConfig='cd <path-to-Vagrantfile> && vagrant ssh-config' --kuberouter.testScope="ipv6-cluster"


### Running Specific tests

To run a subset of the tests, you can use ginkgo's [focus spec](https://onsi.github.io/ginkgo/#focused-specs). Here are some examples:

        $ ginkgo --focus="Router*" -- --kuberouter.SSHConfig='cd /home/awander/go/src/github.com/Arvinderpal/k8-ipv6 && vagrant ssh-config' --kuberouter.testScope="ipv6-cluster"

        $ ginkgo --focus="Service-Proxy*" -- --kuberouter.SSHConfig='cd /home/awander/go/src/github.com/Arvinderpal/k8-ipv6 && vagrant ssh-config' --kuberouter.testScope="ipv6-cluster"  

## Configuration Options
```
--kuberouter.provisioner: specify a provisioner (e.g. vagrant)
--kuberouter.provision:  provision a cluster before running the tests
--kuberouter.skipLogs: skip gathering logs if a test fails
--kuberouter.SSHConfig: specify a custom command to fetch SSH configuration (eg: 'vagrant ssh-config')
--kuberouter.showCommands: output which commands are ran to stdout
```
## Logs/Results

For each test, we log:
1. List commands that were issued (cmds.log) 
2. Output of kube-router instances on the 2 nodes during the the time the specific test was running (kuberouter-test-k8s(1/2).s) 
3. Output of each command (test-out.log). 
4. If the test fails, we also save the entire kube-router log file (kube-router-complete-k8s1.s). 
These files can be found in the directory `test_results` under the test name. For example,

```
~/go/src/github.com/cloudnativelabs/kube-router/test/test_results/Service-Proxy_Basic_Connectivity_to_Nodeport_Service_with_many_replicas $ ll
total 12140
drwxrwxr-x 2 awander awander     4096 Jan 10 12:34 ./
drwxrwxr-x 4 awander awander     4096 Jan 10 12:29 ../
-rw-rw-r-- 1 awander awander     5417 Jan 10 12:34 cmds.log
-rw-rw-r-- 1 awander awander   199945 Jan 10 12:29 kuberouter-test.log-k8s1.s
-rw-rw-r-- 1 awander awander    16566 Jan 10 12:34 test-output.log
```

Here is an example cmds.log file:
```
curl -g -6 http://[::1]:20244/healthz
gobgp neighbor
kubectl apply -f  /home/vagrant/go/src/github.com/cloudnativelabs/kube-router/test/manifests/busybox-1.yaml
kubectl -n default get pods -l app=busybox-2 -o json
sudo journalctl -au kube-router --since '60 seconds ago'
kubectl delete -f  /home/vagrant/go/src/github.com/cloudnativelabs/kube-router/test/manifests/busybox-2.yaml --grace-period=0 --force
```

And here is a snippet of he kuberouter-test.log-k8s1.s file:
```
-- Logs begin at Tue 2018-08-28 17:10:09 UTC, end at Tue 2019-01-15 23:47:44 UTC. --
Jan 15 23:46:46 k8s1 kube-router[4871]: I0115 23:46:46.615714    4871 network_routes_controller.go:252] Syncing ipsets
Jan 15 23:46:46 k8s1 kube-router[4871]: I0115 23:46:46.661630    4871 network_routes_controller.go:265] Performing periodic sync of service VIP routes
Jan 15 23:46:46 k8s1 kube-router[4871]: I0115 23:46:46.661699    4871 ecmp_vip.go:24] Advertising route: '172.20.0.10/32 via 192.168.33.8' to peers
Jan 15 23:46:46 k8s1 kube-router[4871]: I0115 23:46:46.661717    4871 network_routes_controller.go:269] Performing periodic sync of pod CIDR routes
```


## Acknowledgement

This framework is based on the e2e testing framework of the [cilium project](https://github.com/cilium/cilium/tree/master/test). Many thanks to them for their excellent work!
