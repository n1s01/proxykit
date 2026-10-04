//go:build darwin

package proxykit

import (
	"net"
	"strings"
	"syscall"
)

const bindSupported = true

// physicalName accepts en*: Wi-Fi and Ethernet. VPN tunnels are utun*.
func physicalName(name string) bool { return strings.HasPrefix(name, "en") }

func bindSocket(fd uintptr, ipv6 bool, iface *net.Interface) error {
	if ipv6 {
		return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, iface.Index)
	}
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, iface.Index)
}
