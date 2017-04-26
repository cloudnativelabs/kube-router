FROM alpine
RUN apk add --no-cache iptables ipset
COPY kube-router /

ENTRYPOINT ["/kube-router"]
