module github.com/cloudnativelabs/kube-router

require (
	github.com/Microsoft/go-winio v0.4.14 // indirect
	github.com/aws/aws-sdk-go v1.38.30
	github.com/containerd/containerd v1.4.4 // indirect
	github.com/containernetworking/cni v0.8.1
	github.com/containernetworking/plugins v0.9.1
	github.com/coreos/go-iptables v0.6.0
	github.com/dgryski/go-farm v0.0.0-20180109070241-2de33835d102 // indirect
	github.com/docker/distribution v0.0.0-20170524205824-1e2f10eb6574 // indirect
	github.com/docker/docker v20.10.6+incompatible
	github.com/docker/go-connections v0.3.0 // indirect
	github.com/docker/go-units v0.3.3 // indirect
	github.com/golang/protobuf v1.4.3
	github.com/hashicorp/hcl v0.0.0-20180404174102-ef8a98b0bbce // indirect
	github.com/k-sone/critbitgo v1.4.0 // indirect
	github.com/magiconair/properties v1.7.6 // indirect
	github.com/moby/ipvs v1.0.1
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/onsi/ginkgo v1.16.1
	github.com/onsi/gomega v1.11.0
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/osrg/gobgp v0.0.0-20210503121111-d1a8400dc698
	github.com/pelletier/go-toml v1.1.0 // indirect
	github.com/prometheus/client_golang v1.10.0
	github.com/spf13/cast v1.2.0 // indirect
	github.com/spf13/jwalterweatherman v0.0.0-20180109140146-7c0cea34c8ec // indirect
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/vishvananda/netlink v1.1.1-0.20201029203352-d40f9887b852
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f
	golang.org/x/net v0.0.0-20210503060351-7fd8e65b6420
	google.golang.org/grpc v1.38.0
	k8s.io/api v0.21.1
	k8s.io/apimachinery v0.21.1
	k8s.io/client-go v0.21.1
	k8s.io/cri-api v0.21.0
	k8s.io/klog/v2 v2.8.0
)

go 1.13
