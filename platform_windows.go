//go:build windows

// Platform backend for Windows. Contract: platformBackend in platform.go.

package proxykit

import (
	"math/bits"
	"net"
	"sort"
	"syscall"
	"unsafe"
)

var backend platformBackend = windowsBackend{}

type windowsBackend struct{}

func (windowsBackend) info() Platform {
	return Platform{
		OS:           "windows",
		Bypass:       true,
		SocketOption: "IP_UNICAST_IF / IPV6_UNICAST_IF",
		RouteTable:   "GetIpForwardTable",
		Notes: []string{
			"adapter names are free-form; tunnels are recognized by missing MAC/broadcast and by name",
			"hypervisor host-only adapters look physical; the default-route ranking skips them",
		},
	}
}

// unicastIF is the value of both IP_UNICAST_IF and IPV6_UNICAST_IF.
const unicastIF = 31

func (windowsBackend) bind(fd uintptr, ipv6 bool, iface *net.Interface) error {
	if ipv6 {
		return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, unicastIF, iface.Index)
	}
	// IPv4 expects the interface index in network byte order.
	index := bits.ReverseBytes32(uint32(iface.Index))
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, unicastIF, int(int32(index)))
}

func (windowsBackend) physicalName(name string) bool { return !virtualName(name) }

var procGetIPForwardTable = syscall.NewLazyDLL("iphlpapi.dll").NewProc("GetIpForwardTable")

// ipForwardRow mirrors MIB_IPFORWARDROW.
type ipForwardRow struct {
	Dest, Mask, Policy, NextHop, IfIndex, Type, Proto, Age, NextHopAS uint32
	// Metric1 already includes the interface metric.
	Metric1, Metric2, Metric3, Metric4, Metric5 uint32
}

// defaultRoutes lists interfaces owning an IPv4 default route, best metric
// first. A VPN adds its own routes but leaves the physical default in place.
func (windowsBackend) defaultRoutes() []int {
	if procGetIPForwardTable.Find() != nil {
		return nil
	}
	// The table is a DWORD row count followed by the rows.
	var buf []uint32
	var size uint32
	for attempt := 0; ; attempt++ {
		var table unsafe.Pointer
		if len(buf) > 0 {
			table = unsafe.Pointer(&buf[0])
		}
		code, _, _ := procGetIPForwardTable.Call(uintptr(table), uintptr(unsafe.Pointer(&size)), 0)
		if code == 0 && len(buf) > 0 {
			break
		}
		// The table may grow between the sizing call and the next one.
		if syscall.Errno(code) != syscall.ERROR_INSUFFICIENT_BUFFER || size == 0 || attempt == 3 {
			return nil
		}
		buf = make([]uint32, (size+3)/4)
	}
	const rowWords = int(unsafe.Sizeof(ipForwardRow{}) / 4)
	count := int(buf[0])
	if count == 0 || count > (len(buf)-1)/rowWords {
		return nil
	}
	rows := unsafe.Slice((*ipForwardRow)(unsafe.Pointer(&buf[1])), count)
	var routes []ipForwardRow
	for _, row := range rows {
		if row.Dest == 0 && row.Mask == 0 {
			routes = append(routes, row)
		}
	}
	sort.SliceStable(routes, func(i, j int) bool { return routes[i].Metric1 < routes[j].Metric1 })
	indexes := make([]int, 0, len(routes))
	for _, row := range routes {
		indexes = append(indexes, int(row.IfIndex))
	}
	return indexes
}
