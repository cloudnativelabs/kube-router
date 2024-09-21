# How to Use

Here lies the RPM spec and its build directories needed for building an rpm.

This repository directory contains the RPM spec for kube-router.
kube-router.spec uses Go 1.22, which is not available in RHEL9, and because of that, we download and use upstream Go binaries.

Here we also have a `build.sh` script to lint or build the package.
The `build.sh` script can lint and build the package either natively on an RHEL9 host or using Docker.

## How to Use build.sh

There are four options:
  - `lint`
  - `lint_in_docker`
  - `build`
  - `build_in_docker`

For linting or building natively on RHEL9, you need to specify one of the two options as `${1}` and the path to a spec file as `${2}`.

`./build.sh lint SPECS/kube-router.spec`

`./build.sh build SPECS/kube-router.spec`

There is a way to do that inside a Docker container if you cannot build natively on RHEL9.

`./build.sh lint_in_docker SPECS/kube-router.spec`

`./build.sh build_in_docker SPECS/kube-router.spec`

The resulting RPM file will be found in the RPMS directory.

## Configuring kube-router Installed from RPM Package

When you install kube-router from an RPM package, it sets up a systemd unit that reads its arguments from the /etc/default/kube-router file.

Note: The service provided by the systemd unit does not start automatically. To enable and start the service, use the following commands:

`systemctl enable kube-router`

`systemctl start kube-router`

To adjust the arguments that kube-router runs with, \
  modify the ARGS variable in the /etc/default/kube-router file.

For example, to add the --advertise-cluster-ip argument, update the file as follows:

`ARGS="--advertise-cluster-ip"`

After making changes to the ARGS variable, restart the systemd service to apply the new configuration:

`systemctl restart kube-router`

Tip: Use configuration management tools like Ansible or Puppet to manage this configuration file efficiently.
