package main

import (
	"fmt"
	"net"
	"syscall"

	"github.com/mqliang/libipvs"
)

func main() {
	h, err := libipvs.New()
	if err != nil {
		panic(err)
	}
	if err := h.Flush(); err != nil {
		panic(err)
	}

	info, err := h.GetInfo()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%#v\n", info)

	svcs, err := h.ListServices()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%#v\n", svcs)

	svc := libipvs.Service{
		Address:       net.ParseIP("172.192.168.1"),
		AddressFamily: syscall.AF_INET,
		Protocol:      libipvs.Protocol(syscall.IPPROTO_TCP),
		Port:          80,
		SchedName:     libipvs.RoundRobin,
	}

	if err := h.NewService(&svc); err != nil {
		panic(err)
	}

	svcs, err = h.ListServices()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%#v\n", svcs)

	dst := libipvs.Destination{
		Address:       net.ParseIP("172.192.100.1"),
		AddressFamily: syscall.AF_INET,
		Port:          80,
	}

	if err := h.NewDestination(&svc, &dst); err != nil {
		panic(err)
	}

	dsts, err := h.ListDestinations(&svc)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%#v\n", dsts)
}
