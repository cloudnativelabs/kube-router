all: dockerimg

dockerimg: build
	sudo docker build -t "cloudnativelabs/kube-router" .

build:
	go build --ldflags '-extldflags "-static"' -o kube-router kube-router.go

clean:
	rm -f kube-router

run:
	./kube-router --kubeconfig=/var/lib/kube-router/kubeconfig
