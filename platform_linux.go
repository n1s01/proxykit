//go:build linux

// Platform backend for desktop Linux. GOOS=android compiles through the linux
// tag but is not a supported target.
// Contract: platformBackend in platform.go.

package proxykit

import (
	"bufio"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

var backend platformBackend = linuxBackend{}

type linuxBackend struct{}

func (linuxBackend) info() Platform {
	return Platform{
		OS:           runtime.GOOS, // linux or android
		Bypass:       true,
		SocketOption: "SO_BINDTODEVICE",
		RouteTable:   "/proc/net/route",
		Notes: []string{
			"SO_BINDTODEVICE needs Linux 5.7+ or CAP_NET_RAW; older kernels fail with EPERM",
			"/proc/net/route shows the main table only; policy-routed VPNs leave it intact",
		},
	}
}

func (linuxBackend) bind(fd uintptr, _ bool, iface *net.Interface) error {
	return syscall.BindToDevice(int(fd), iface.Name)
}

func (linuxBackend) physicalName(name string) bool { return !virtualName(name) }

func (linuxBackend) defaultRoutes() []int {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil
	}
	defer f.Close()
	// One interface dump for the whole table: InterfaceByName dumps every
	// interface over netlink on each call.
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	indexes := make(map[string]int, len(ifaces))
	for _, iface := range ifaces {
		indexes[iface.Name] = iface.Index
	}
	return parseProcNetRoute(f, func(name string) (int, bool) {
		index, ok := indexes[name]
		return index, ok
	})
}

// parseProcNetRoute extracts IPv4 default routes from /proc/net/route, lowest
// metric first. Columns: Iface Destination Gateway Flags RefCnt Use Metric
// Mask ...; addresses are hex in host byte order, so zero is zero either way.
func parseProcNetRoute(r io.Reader, index func(string) (int, bool)) []int {
	const rtfUp = 0x1
	type route struct{ index, metric int }
	var routes []route
	sc := bufio.NewScanner(r)
	for first := true; sc.Scan(); first = false {
		f := strings.Fields(sc.Text())
		if first || len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&rtfUp == 0 {
			continue
		}
		metric, err := strconv.Atoi(f[6])
		if err != nil {
			continue
		}
		if i, ok := index(f[0]); ok {
			routes = append(routes, route{i, metric})
		}
	}
	sort.SliceStable(routes, func(i, j int) bool { return routes[i].metric < routes[j].metric })
	out := make([]int, 0, len(routes))
	for _, r := range routes {
		out = append(out, r.index)
	}
	return out
}
