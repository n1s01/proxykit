//go:build darwin

// Platform backend for macOS. GOOS=ios compiles through the darwin tag but is
// not a supported target.
// Contract: platformBackend in platform.go.

package proxykit

import (
	"net"
	"runtime"
	"strings"
	"syscall"
)

var backend platformBackend = darwinBackend{}

type darwinBackend struct{}

func (darwinBackend) info() Platform {
	return Platform{
		OS:           runtime.GOOS, // darwin or ios
		Bypass:       true,
		SocketOption: "IP_BOUND_IF / IPV6_BOUND_IF",
		RouteTable:   "sysctl NET_RT_DUMP",
		Notes: []string{
			"physical interfaces are en*; VPN tunnels are utun*",
		},
	}
}

func (darwinBackend) bind(fd uintptr, ipv6 bool, iface *net.Interface) error {
	if ipv6 {
		return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, iface.Index)
	}
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, iface.Index)
}

// physicalName accepts en*: Wi-Fi, Ethernet and USB/Thunderbolt adapters.
func (darwinBackend) physicalName(name string) bool { return strings.HasPrefix(name, "en") }

// defaultRoutes reads IPv4 default routes from the kernel. A VPN installs its
// own unscoped default via utun and leaves the physical one scoped
// (RTF_IFSCOPE); utun is filtered out later, so both orders end up on the
// physical adapter that really owns a gateway.
func (darwinBackend) defaultRoutes() []int {
	// syscall.RouteRIB & co. are deprecated for x/net/route; see .golangci.yml.
	rib, err := syscall.RouteRIB(syscall.NET_RT_DUMP, 0)
	if err != nil {
		return nil
	}
	msgs, err := syscall.ParseRoutingMessage(rib)
	if err != nil {
		return nil
	}
	var unscoped, scoped []int
	for _, msg := range msgs {
		rm, ok := msg.(*syscall.RouteMessage)
		if !ok || rm.Header.Flags&syscall.RTF_UP == 0 || rm.Header.Flags&syscall.RTF_GATEWAY == 0 {
			continue
		}
		addrs, err := syscall.ParseRoutingSockaddr(rm)
		if err != nil || len(addrs) == 0 {
			continue
		}
		dst, ok := addrs[0].(*syscall.SockaddrInet4)
		if !ok || dst.Addr != [4]byte{} {
			continue
		}
		if rm.Header.Flags&syscall.RTF_IFSCOPE != 0 {
			scoped = append(scoped, int(rm.Header.Index))
		} else {
			unscoped = append(unscoped, int(rm.Header.Index))
		}
	}
	return append(unscoped, scoped...)
}
