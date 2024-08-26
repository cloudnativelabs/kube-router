%define debug_package %{nil}
%define golang_version 1.22.6

Name: kube-router
Version: 2.2.1
Release: 1%{?dist}
Summary: a turnkey solution for Kubernetes networking
License: ASL 2.0
URL: https://www.kube-router.io
Source0: https://github.com/cloudnativelabs/kube-router/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz
# rhel9 and derivatives latest golang version is 1.21
Source1: https://go.dev/dl/go%{golang_version}.linux-amd64.tar.gz
%{?systemd_requires}
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot

%description
Kube-router is a turnkey solution for Kubernetes networking with aim to provide operational simplicity and high performance.

%prep
%setup -q -b 0 -n kube-router-%{version}
%setup -q -T -D -a 1

%build
export CGO_ENABLED=0
./go/bin/go build \
  -ldflags "-X github.com/cloudnativelabs/kube-router/v2/pkg/version.Version=%{version}" \
  -o kube-router cmd/kube-router/kube-router.go

%install
%{__rm} -rf %{buildroot}
%{__install} -d %{buildroot}%{_bindir}
%{__install} -d %{buildroot}%{_unitdir}
%{__install} -d %{buildroot}%{_sysconfdir}/default
%{__install} -d %{buildroot}%{_sysconfdir}/kube-router
%{__install} -m 755 kube-router %{buildroot}%{_bindir}/kube-router
cat <<EOF > %{buildroot}%{_unitdir}/kube-router.service
[Unit]
Description=a turnkey solution for Kubernetes networking
Documentation=%{url}

[Service]
Restart=always
User=root
Group=root
EnvironmentFile=%{_sysconfdir}/default/kube-router
ExecStart=%{_bindir}/kube-router \$ARGS
LimitNOFILE=65536
Slice=kubernetes.slice

[Install]
WantedBy=multi-user.target
EOF

cat <<EOF > %{buildroot}%{_sysconfdir}/default/kube-router
ARGS=""
EOF

%post
%systemd_post kube-router.service

%preun
%systemd_preun kube-router.service

%postun
%systemd_postun kube-router.service

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_sysconfdir}/kube-router
%{_bindir}/kube-router
%{_unitdir}/kube-router.service
%config(noreplace) %{_sysconfdir}/default/kube-router
