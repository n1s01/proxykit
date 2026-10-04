//go:build windows

package proxykit

import (
	"math/bits"
	"net"
	"syscall"
)

const bindSupported = true

// IP_UNICAST_IF and IPV6_UNICAST_IF share the option number.
const unicastIF = 31

func physicalName(name string) bool { return !virtualName(name) }

func bindSocket(fd uintptr, ipv6 bool, iface *net.Interface) error {
	if ipv6 {
		return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, unicastIF, iface.Index)
	}
	// IPv4 expects the interface index in network byte order.
	index := bits.ReverseBytes32(uint32(iface.Index))
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, unicastIF, int(int32(index)))
}
