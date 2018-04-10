#!/bin/bash

function get_kops {
  echo "==> fetching the latest kops codebase"
  go get -u k8s.io/kops
}

function install_kubectl {
  if ! kubectl version --client=true > /dev/null; then	
    echo "==> installing kubectl"
    curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
    chmod +x ./kubectl
    sudo mv ./kubectl /usr/local/bin/kubectl
  fi
}

function create_template {
  local version=$1

  cat > $GOPATH/src/k8s.io/kops/upup/models/cloudup/resources/addons/networking.kuberouter/k8s-1.6.yaml.template <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-router-cfg
  namespace: kube-system
  labels:
    tier: node
    k8s-app: kube-router
data:
  cni-conf.json: |
    {
      "name":"kubernetes",
      "type":"bridge",
      "bridge":"kube-bridge",
      "isDefaultGateway":true,
      "ipam": {
        "type":"host-local"
      }
    }
---
apiVersion: extensions/v1beta1
kind: DaemonSet
metadata:
  labels:
    k8s-app: kube-router
    tier: node
  name: kube-router
  namespace: kube-system
spec:
  template:
    metadata:
      labels:
        k8s-app: kube-router
        tier: node
      annotations:
        scheduler.alpha.kubernetes.io/critical-pod: ''
    spec:
      containers:
      - name: kube-router
        image: $KUBE_ROUTER_DOCKER_IMAGE
        args:
        - --run-router=true
        - --run-firewall=true
        - --run-service-proxy=true
        - --advertise-cluster-ip=true
        - --advertise-external-ip=true
        - --kubeconfig=/var/lib/kube-router/kubeconfig
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        resources:
          requests:
            cpu: 100m
            memory: 250Mi
        securityContext:
          privileged: true
        volumeMounts:
        - name: lib-modules
          mountPath: /lib/modules
          readOnly: true
        - name: cni-conf-dir
          mountPath: /etc/cni/net.d
        - name: kubeconfig
          mountPath: /var/lib/kube-router/kubeconfig
          readOnly: true
      initContainers:
      - name: install-cni
        image: busybox
        command:
        - /bin/sh
        - -c
        - set -e -x;
          if [ ! -f /etc/cni/net.d/10-kuberouter.conf ]; then
            TMP=/etc/cni/net.d/.tmp-kuberouter-cfg;
            cp /etc/kube-router/cni-conf.json \${TMP};
            mv \${TMP} /etc/cni/net.d/10-kuberouter.conf;
          fi
        volumeMounts:
        - name: cni-conf-dir
          mountPath: /etc/cni/net.d
        - name: kube-router-cfg
          mountPath: /etc/kube-router
      hostNetwork: true
      serviceAccountName: kube-router
      tolerations:
      - key: CriticalAddonsOnly
        operator: Exists
      - effect: NoSchedule
        key: node-role.kubernetes.io/master
        operator: Exists
      volumes:
      - hostPath:
          path: /lib/modules
        name: lib-modules
      - hostPath:
          path: /etc/cni/net.d
        name: cni-conf-dir
      - name: kubeconfig
        hostPath:
          path: /var/lib/kube-router/kubeconfig
      - name: kube-router-cfg
        configMap:
          name: kube-router-cfg
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kube-router
  namespace: kube-system
---
# Kube-router roles
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: kube-router
  namespace: kube-system
rules:
  - apiGroups: [""]
    resources:
      - namespaces
      - pods
      - services
      - nodes
      - endpoints
    verbs:
      - get
      - list
      - watch
  - apiGroups: ["networking.k8s.io"]
    resources:
      - networkpolicies
    verbs:
      - get
      - list
      - watch
  - apiGroups: ["extensions"]
    resources:
      - networkpolicies
    verbs:
      - get
      - list
      - watch
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: kube-router
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kube-router
subjects:
- kind: ServiceAccount
  name: kube-router
  namespace: kube-system
- kind: User
  name: system:kube-router
EOF
}
