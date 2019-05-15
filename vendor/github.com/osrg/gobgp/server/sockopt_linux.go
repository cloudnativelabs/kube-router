// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// +build linux

package server

import (
	"fmt"
	unix "golang.org/x/sys/unix"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	TCP_MD5SIG       = 14 // TCP MD5 Signature (RFC2385)
	IPV6_MINHOPCOUNT = 73 // Generalized TTL Security Mechanism (RFC5082)
)

type tcpmd5sig struct {
	ss_family uint16
	ss        [126]byte
	// padding the struct
	_      uint16
	keylen uint16
	// padding the struct
	_   uint32
	key [80]byte
}

func buildTcpMD5Sig(address string, key string) (tcpmd5sig, error) {
	t := tcpmd5sig{}
	addr := net.ParseIP(address)
	if addr.To4() != nil {
		t.ss_family = unix.AF_INET
		copy(t.ss[2:], addr.To4())
	} else {
		t.ss_family = unix.AF_INET6
		copy(t.ss[6:], addr.To16())
	}

	t.keylen = uint16(len(key))
	copy(t.key[0:], []byte(key))

	return t, nil
}

func setsockoptTcpMD5Sig(fd int, address string, key string) error {
	t, err := buildTcpMD5Sig(address, key)
	if err != nil {
		return err
	}
	b := *(*[unsafe.Sizeof(t)]byte)(unsafe.Pointer(&t))
	return os.NewSyscallError("setsockopt", unix.SetsockoptString(fd, unix.IPPROTO_TCP, TCP_MD5SIG, string(b[:])))
}

func SetTcpMD5SigSockopt(l *net.TCPListener, address string, key string) error {
	fi, _, err := extractFileAndFamilyFromTCPListener(l)
	if err != nil {
		return err
	}
	defer fi.Close()

	return setsockoptTcpMD5Sig(int(fi.Fd()), address, key)
}

func setsockoptIpTtl(fd int, family int, value int) error {
	level := unix.IPPROTO_IP
	name := unix.IP_TTL
	if family == unix.AF_INET6 {
		level = unix.IPPROTO_IPV6
		name = unix.IPV6_UNICAST_HOPS
	}
	return os.NewSyscallError("setsockopt", unix.SetsockoptInt(fd, level, name, value))
}

func SetListenTcpTTLSockopt(l *net.TCPListener, ttl int) error {
	fi, family, err := extractFileAndFamilyFromTCPListener(l)
	if err != nil {
		return err
	}
	defer fi.Close()

	return setsockoptIpTtl(int(fi.Fd()), family, ttl)
}

func SetTcpTTLSockopt(conn *net.TCPConn, ttl int) error {
	fi, family, err := extractFileAndFamilyFromTCPConn(conn)
	if err != nil {
		return err
	}
	defer fi.Close()

	return setsockoptIpTtl(int(fi.Fd()), family, ttl)
}

func setsockoptIpMinTtl(fd int, family int, value int) error {
	level := unix.IPPROTO_IP
	name := unix.IP_MINTTL
	if family == unix.AF_INET6 {
		level = unix.IPPROTO_IPV6
		name = IPV6_MINHOPCOUNT
	}
	return os.NewSyscallError("setsockopt", unix.SetsockoptInt(fd, level, name, value))
}

func SetTcpMinTTLSockopt(conn *net.TCPConn, ttl int) error {
	fi, family, err := extractFileAndFamilyFromTCPConn(conn)
	if err != nil {
		return err
	}
	defer fi.Close()

	return setsockoptIpMinTtl(int(fi.Fd()), family, ttl)
}

type TCPDialer struct {
	net.Dialer

	// MD5 authentication password.
	AuthPassword string

	// The TTL value to set outgoing connection.
	Ttl uint8

	// The minimum TTL value for incoming packets.
	TtlMin uint8
}

func (d *TCPDialer) DialTCP(addr string, port int) (*net.TCPConn, error) {
	var family int
	var ra, la unix.Sockaddr

	raddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(addr, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, fmt.Errorf("invalid remote address: %s", err)
	}
	laddr, err := net.ResolveTCPAddr("tcp", d.LocalAddr.String())
	if err != nil {
		return nil, fmt.Errorf("invalid local address: %s", err)
	}
	if raddr.IP.To4() != nil {
		family = unix.AF_INET
		rsockaddr := &unix.SockaddrInet4{Port: port}
		copy(rsockaddr.Addr[:], raddr.IP.To4())
		ra = rsockaddr
		lsockaddr := &unix.SockaddrInet4{}
		copy(lsockaddr.Addr[:], laddr.IP.To4())
		la = lsockaddr
	} else {
		family = unix.AF_INET6
		rsockaddr := &unix.SockaddrInet6{Port: port}
		copy(rsockaddr.Addr[:], raddr.IP.To16())
		ra = rsockaddr
		var zone uint32
		if laddr.Zone != "" {
			if intf, err := net.InterfaceByName(laddr.Zone); err != nil {
				return nil, err
			} else {
				zone = uint32(intf.Index)
			}
		}
		lsockaddr := &unix.SockaddrInet6{ZoneId: zone}
		copy(lsockaddr.Addr[:], laddr.IP.To16())
		la = lsockaddr
	}

	sockType := unix.SOCK_STREAM | unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK
	proto := 0
	fd, err := unix.Socket(family, sockType, proto)
	if err != nil {
		return nil, err
	}
	fi := os.NewFile(uintptr(fd), "")
	defer fi.Close()
	// A new socket was created so we must close it before this
	// function returns either on failure or success. On success,
	// net.FileConn() in newTCPConn() increases the refcount of
	// the socket so this fi.Close() doesn't destroy the socket.
	// The caller must call Close() with the file later.
	// Note that the above os.NewFile() doesn't play with the
	// refcount.

	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1); err != nil {
		return nil, os.NewSyscallError("setsockopt", err)
	}

	if err = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1); err != nil {
		return nil, os.NewSyscallError("setsockopt", err)
	}

	if d.AuthPassword != "" {
		if err = setsockoptTcpMD5Sig(fd, addr, d.AuthPassword); err != nil {
			return nil, err
		}
	}

	if d.Ttl != 0 {
		if err = setsockoptIpTtl(fd, family, int(d.Ttl)); err != nil {
			return nil, err
		}
	}

	if d.TtlMin != 0 {
		if err = setsockoptIpMinTtl(fd, family, int(d.Ttl)); err != nil {
			return nil, err
		}
	}

	if err = unix.Bind(fd, la); err != nil {
		return nil, os.NewSyscallError("bind", err)
	}

	newTCPConn := func(fi *os.File) (*net.TCPConn, error) {
		if conn, err := net.FileConn(fi); err != nil {
			return nil, err
		} else {
			return conn.(*net.TCPConn), err
		}
	}

	err = unix.Connect(fd, ra)
	switch err {
	case unix.EINPROGRESS, unix.EALREADY, unix.EINTR:
		// do timeout handling
	case nil, unix.EISCONN:
		return newTCPConn(fi)
	default:
		return nil, os.NewSyscallError("connect", err)
	}

	epfd, e := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if e != nil {
		return nil, e
	}
	defer unix.Close(epfd)

	var event unix.EpollEvent
	events := make([]unix.EpollEvent, 1)

	event.Events = unix.EPOLLIN | unix.EPOLLOUT | unix.EPOLLPRI
	event.Fd = int32(fd)
	if e = unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fd, &event); e != nil {
		return nil, e
	}

	for {
		nevents, e := unix.EpollWait(epfd, events, int(d.Timeout/1000000) /*msec*/)
		if e != nil {
			return nil, e
		}
		if nevents == 0 {
			return nil, fmt.Errorf("timeout")
		} else if nevents == 1 && events[0].Fd == int32(fd) {
			nerr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			if err != nil {
				return nil, os.NewSyscallError("getsockopt", err)
			}
			switch err := syscall.Errno(nerr); err {
			case unix.EINPROGRESS, unix.EALREADY, unix.EINTR:
			case syscall.Errno(0), unix.EISCONN:
				return newTCPConn(fi)
			default:
				return nil, os.NewSyscallError("getsockopt", err)
			}
		} else {
			return nil, fmt.Errorf("unexpected epoll behavior")
		}
	}
}
