#all: push
all:  
	go build  -o kube-router kube-router.go

clean:
	rm -f kube-router

run:
	./kube-router --kubeconfig=~/kubeconfig
