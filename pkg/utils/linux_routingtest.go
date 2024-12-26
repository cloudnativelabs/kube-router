package utils

import (
	"fmt"
	"net"

	"github.com/stretchr/testify/mock"
	"github.com/vishvananda/netlink"
)

type FakeLocalLinkQuerier struct {
	links []netlink.Link
	addrs []*net.IPNet
}

func NewFakeLocalLinkQuerier(addrStrings []string, mtus []int) *FakeLocalLinkQuerier {
	links := make([]netlink.Link, len(addrStrings))
	for idx := range addrStrings {
		mtu := 1
		if idx < len(mtus) {
			mtu = mtus[idx]
		}
		linkAttrs := netlink.LinkAttrs{
			Index: idx,
			MTU:   mtu,
		}
		linkDevice := netlink.Device{LinkAttrs: linkAttrs}
		links[idx] = &linkDevice
	}
	addrs := make([]*net.IPNet, len(addrStrings))
	for idx, addr := range addrStrings {
		ip := net.ParseIP(addr)
		var netMask net.IPMask
		if ip.To4() != nil {
			//nolint:mnd // Hardcoded value is used for testing purposes
			netMask = net.CIDRMask(24, 32)
		} else {
			//nolint:mnd // Hardcoded value is used for testing purposes
			netMask = net.CIDRMask(64, 128)
		}
		ipNet := &net.IPNet{
			IP:   ip,
			Mask: netMask,
		}
		addrs[idx] = ipNet
	}
	return &FakeLocalLinkQuerier{
		links: links,
		addrs: addrs,
	}
}

func (f *FakeLocalLinkQuerier) LinkList() ([]netlink.Link, error) {
	return f.links, nil
}

func (f *FakeLocalLinkQuerier) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	addrs := make([]netlink.Addr, 1)
	addrs[0] = netlink.Addr{IPNet: f.addrs[link.Attrs().Index]}
	if link.Attrs().MTU == 0 {
		return nil, fmt.Errorf("MTU was set to 0 to simulate an error")
	}
	return addrs, nil
}

type MockLocalLinkQuerier struct {
	mock.Mock
}

func (m *MockLocalLinkQuerier) LinkList() ([]netlink.Link, error) {
	args := m.Called()
	return args.Get(0).([]netlink.Link), args.Error(1)
}

func (m *MockLocalLinkQuerier) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	args := m.Called(link, family)
	return args.Get(0).([]netlink.Addr), args.Error(1)
}
