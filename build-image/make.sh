NAME=kube-router-build
docker run --rm --name=$NAME -w /go/src/github.com/cloudnativelabs/kube-router -v $GOPATH:/go golang:1.8.3 "make" "$@"
