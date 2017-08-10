# Testing kube-router

Our end-user testing goals are to:
- Support easily running kube-router in any Kubernetes environment, new or
  existing.
- Provide tools to quickly collect information about a cluster to help with
  troubleshooting kube-router issues.

Our developer testing goals are to:
- Provide tools to quickly build and test kube-router code and container images
- Provide well-documented code testing protocols to ensure consistent code
  quality for all contributions.
- Support quickly testing code changes by spinning up test clusters in local
  VMs, cloud environments, and via CI systems in pull requests.
- Support running official Kubernetes e2e tests as well as custom e2e tests for
  kube-router's exclusive features.

## End Users

We currently support running kube-router on local VMs via Vagrant. Follow the
instructions in [Starting A Local VM Cluster](#starting-a-local-vm-cluster)
to get started.

## Developers

### Option 1: Local VM Cluster

#### Starting A Local VM Cluster

Running your code changes or simply trying out kube-router as-is in a real
Kubernetes cluster is easy. Just make sure you have Virtualbox, VMware Fusion,
or VMware Workstation installed and run:
```
make vagrant-up-single-node
```

Alternatively if you have 6GB RAM for the VMs, you can run a multi-node cluster
that consists of a dedicated etcd node, a controller node, and a worker node:
```
make vagrant-up-multi-node
```

You will see lots of output as the VMs are provisioned, and the first run may
take some time as VM and container images are downloaded. After the cluster is
up you will recieve instructions for using kubectl and gaining ssh access:
```
  SUCCESS! The local cluster is ready.

  ### kubectl usage ###
  # Quickstart - Use this kubeconfig for individual commands
  KUBECONFIG=/tmp/kr-vagrant-shortcut/cluster/auth/kubeconfig kubectl get pods --all-namespaces -o wide
  #
  ## OR ##
  #
  # Use this kubeconfig for the current terminal session
  KUBECONFIG=/tmp/kr-vagrant-shortcut/cluster/auth/kubeconfig
  export KUBECONFIG
  kubectl get pods --all-namespaces -o wide
  #
  ## OR ##
  #
  # Backup and replace your default kubeconfig
  # Note: This will continue to work on recreated local clusters
  mv ~/.kube/config ~/.kube/config-backup
  ln -s /tmp/kr-vagrant-shortcut/cluster/auth/kubeconfig ~/.kube/config

  ### SSH ###
  # Get node names
  make vagrant status
  # SSH into a the controller node (c1)
  make vagrant ssh c1
```

#### Managing Your Local VM Cluster

You can use [Vagrant](https://www.vagrantup.com/docs/cli/) commands against the
running cluster with `make vagrant COMMANDS`.

For example, `make vagrant status` outputs:
```
Current machine states:

e1                        not created (virtualbox)
c1                        not created (virtualbox)
w1                        not created (virtualbox)

This environment represents multiple VMs. The VMs are all listed
above with their current state. For more information about a specific
VM, run `vagrant status NAME`.
```

With this information you can ssh into any of the VMs listed:
```
make vagrant ssh c1
```

#### Upgrading kube-router In Your Local VM Cluster

If you make code changes or checkout a different branch/tag, you can easily
build, install, and run these changes in your previously started local VM
cluster.

`make vagrant-image-update`

Unlike `make vagrant-up-*` targets, this does not destroy and recreate the VMs,
and instead does the updates live. This will save time if you aren't concerned
about having a pristine OS/Kubernetes environment to test against.
