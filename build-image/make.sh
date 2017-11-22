NAME=kube-router-build
docker build -t kube-router-build:latest .
docker rm -f $NAME
docker run --name=$NAME -v $GOPATH:/data/go kube-router-build:latest "$@"
