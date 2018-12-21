package helpers

import (
	"fmt"
	"net"
)

func Curl(remoteIP string, port int) string {
	ip := net.ParseIP(remoteIP)
	if ip.To4() == nil {
		return fmt.Sprintf("curl http://[%s]:%v", remoteIP, port)
	} else {
		return fmt.Sprintf("curl http://%s:%v", remoteIP, port)
	}
}
