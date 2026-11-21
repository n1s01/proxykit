package proxykit

// Platform layer: the ONLY place where operating systems differ.
//
// Every OS-specific line of proxykit lives in exactly one platform_<os>.go
// file, selected by its build tag. Each of them declares
//
//	var backend platformBackend = <os>Backend{}
//
// so a missing method is a compile error on that OS, not a runtime surprise.
// `make cross` builds every target listed below; run it after touching any
// platform file. Portable code (bypass.go) calls backend.* and never checks
// runtime.GOOS — the linter rejects runtime.GOOS outside platform files.
//
//	file                      GOOS                     bypass  socket option            route table
//	platform_darwin.go        darwin (ios compiles)    yes     IP_BOUND_IF/IPV6_BOUND_IF sysctl NET_RT_DUMP
//	platform_linux.go         linux (android compiles) yes     SO_BINDTODEVICE          /proc/net/route
//	platform_windows.go       windows                  yes     IP_UNICAST_IF            GetIpForwardTable
//	platform_unsupported.go   everything else          no      -                        -
//
// Targets are desktop Windows, macOS and Linux. ios and android build through
// the darwin/linux tags but are not supported: cellular interfaces (pdp_ip*,
// rmnet*) have no MAC or broadcast and are never picked.
//
// On an unsupported OS the default route (bypass) cannot be built, so
// NewDialer fails with ErrBypassUnsupported until the caller explicitly sets
// DialOptions.Advanced.DisableBypass. There is no silent downgrade.

import (
	"net"
	"strings"
)

// platformBackend is the contract every platform_<os>.go implements.
type platformBackend interface {
	// info describes the implementation for CurrentPlatform.
	info() Platform
	// bind pins an unconnected socket to iface. It runs inside
	// syscall.RawConn.Control before connect(2).
	bind(fd uintptr, ipv6 bool, iface *net.Interface) error
	// physicalName reports whether an interface name may belong to Wi-Fi or
	// Ethernet. It is a coarse filter; MAC and broadcast checks follow.
	physicalName(name string) bool
	// defaultRoutes lists indexes of interfaces owning an IPv4 default route,
	// most preferred first. Nil means the routing table is unavailable and the
	// first candidate in system order wins.
	defaultRoutes() []int
}

// Platform describes how this build implements VPN bypass. It is fixed at
// compile time by build tags; see platform_<os>.go.
type Platform struct {
	// OS is runtime.GOOS of this build.
	OS string `json:"os"`
	// Bypass reports whether interface binding is implemented. When false,
	// every Dialer needs DialOptions.Advanced.DisableBypass.
	Bypass bool `json:"bypass"`
	// SocketOption names the mechanism that pins a socket to an interface.
	SocketOption string `json:"socket_option,omitempty"`
	// RouteTable names the source used to rank candidate interfaces by their
	// default route. Empty means candidates keep system order.
	RouteTable string `json:"route_table,omitempty"`
	// Notes lists OS-specific caveats worth showing to an operator.
	Notes []string `json:"notes,omitempty"`
}

// CurrentPlatform reports the bypass implementation compiled into this binary.
func CurrentPlatform() Platform {
	p := backend.info()
	p.Notes = append([]string(nil), p.Notes...)
	return p
}

// BypassSupported is shorthand for CurrentPlatform().Bypass.
func BypassSupported() bool { return backend.info().Bypass }

// virtualName matches tunnel, bridge and hypervisor adapters by name. Linux
// and Windows have no naming scheme for physical adapters, so their
// physicalName is the negation of this list.
func virtualName(name string) bool {
	name = strings.ToLower(name)
	for _, mark := range virtualNameMarks {
		if strings.Contains(name, mark) {
			return true
		}
	}
	return false
}

var virtualNameMarks = []string{
	"tun", "tap", "wg", "ppp", "warp", "vpn", "wireguard", "tailscale", "zerotier", "zt",
	"xray", "v2ray", "sing-box", "clash", "mihomo", "hiddify", "nekoray", "outline",
	"nordlynx", "ipsec", "docker", "veth", "br-", "virbr", "vmnet", "vmware", "virtual",
	"vethernet", "hyper-v", "loopback", "bluetooth",
}
