package utils

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
)

type Listener interface {
	OnUpdate(instance interface{})
}

type ListenerFunc func(instance interface{})

func (f ListenerFunc) OnUpdate(instance interface{}) {
	f(instance)
}

// Broadcaster holds the details of registered listeners
type Broadcaster struct {
	listenerLock sync.RWMutex
	listeners    []Listener
}

// Add lets to register a listener
func (b *Broadcaster) Add(listener Listener) {
	b.listenerLock.Lock()
	defer b.listenerLock.Unlock()
	b.listeners = append(b.listeners, listener)
}

// Notify notifies an update to registered listeners
func (b *Broadcaster) Notify(instance interface{}) {
	b.listenerLock.RLock()
	listeners := b.listeners
	b.listenerLock.RUnlock()
	for _, listener := range listeners {
		go listener.OnUpdate(instance)
	}
}

// CloseCloserDisregardError it is a common need throughout kube-router's code base to need close a closer in defer
// statements, this allows an action like that to pass a linter as well as describe its intention well
func CloseCloserDisregardError(handler io.Closer) {
	_ = handler.Close()
}

// ContainsIPv4Address checks a given string array to see if it contains a valid IPv4 address within it
func ContainsIPv4Address(addrs []string) bool {
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			return true
		}
	}
	return false
}

// ContainsIPv6Address checks a given string array to see if it contains a valid IPv6 address within it
func ContainsIPv6Address(addrs []string) bool {
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			continue
		}
		if ip.To16() != nil {
			return true
		}
	}
	return false
}

// SliceContainsString checks to see if needle is contained within haystack, returns true if found, otherwise
// returns false
func SliceContainsString(needle string, haystack []string) bool {
	for _, hay := range haystack {
		if needle == hay {
			return true
		}
	}
	return false
}

// TCPAddressBindable checks to see if an IP/port is bindable by attempting to open a listener then closing it
// returns nil if successful
func TCPAddressBindable(addr string, port uint16) error {
	endpoint := addr + ":" + strconv.Itoa(int(port))
	ln, err := net.Listen("tcp", endpoint)
	if err != nil {
		return fmt.Errorf("unable to open %s: %w", endpoint, err)
	}
	return ln.Close()
}
