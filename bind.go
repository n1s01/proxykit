package proxykit

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// BypassOptions routes connections to the proxy through a physical network
// interface, skipping VPN/WARP tunnels (TUN). There is deliberately no fallback
// through the tunnel: without a physical interface the dial fails with
// ErrNoInterface. Loopback proxies are never bound.
type BypassOptions struct {
	// Interface pins a network interface by name. Empty selects the first
	// running Wi-Fi/Ethernet interface with a routable IPv4 address.
	Interface string
	// DNS lists ip:port resolvers queried over the same interface, round-robin.
	// Under a VPN the system resolver may return tunnel-only (fake-ip) addresses.
	// Nil uses 1.1.1.1, 8.8.8.8 and 77.88.8.8.
	DNS []string
}

// BypassSupported reports whether interface binding exists for this platform.
// Where it does not, NewDialer rejects DialOptions.Bypass with ErrBypassUnsupported.
func BypassSupported() bool { return bindSupported }

var defaultBypassDNS = []string{"1.1.1.1:53", "8.8.8.8:53", "77.88.8.8:53"}

type bypass struct {
	iface string
	dns   []string
	next  atomic.Uint32
}

// BypassDialContext returns the bound dialer behind DialOptions.Bypass for
// connections that are not proxy tunnels, such as diagnostics.
func BypassDialContext(opts BypassOptions) (DialContextFunc, error) { return newBypassForward(opts) }

// newBypassForward validates options and returns the bound forward dialer.
func newBypassForward(opts BypassOptions) (DialContextFunc, error) {
	if !bindSupported {
		return nil, ErrBypassUnsupported
	}
	dns := append([]string(nil), opts.DNS...)
	if len(dns) == 0 {
		dns = defaultBypassDNS
	}
	for _, server := range dns {
		host, port, err := net.SplitHostPort(server)
		if err != nil || net.ParseIP(host) == nil {
			return nil, invalid("bypass DNS requires ip:port")
		}
		if _, err = parsePort(port); err != nil {
			return nil, err
		}
	}
	b := &bypass{iface: opts.Interface, dns: dns}
	d := &net.Dialer{
		KeepAlive: 30 * time.Second,
		Control:   b.control,
		Resolver:  &net.Resolver{PreferGo: true, Dial: b.dialDNS},
	}
	return d.DialContext, nil
}

func (b *bypass) dialDNS(ctx context.Context, network, _ string) (net.Conn, error) {
	server := b.dns[int(b.next.Add(1))%len(b.dns)]
	d := &net.Dialer{Timeout: 5 * time.Second, Control: b.control}
	return d.DialContext(ctx, network, server)
}

func (b *bypass) control(network, address string, c syscall.RawConn) error {
	if host, _, err := net.SplitHostPort(address); err == nil {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	iface, err := b.pick()
	if err != nil {
		return err
	}
	var opErr error
	if err = c.Control(func(fd uintptr) {
		opErr = bindSocket(fd, strings.HasSuffix(network, "6"), iface)
	}); err != nil {
		return err
	}
	return opErr
}

// pick is evaluated per connection: interfaces come and go with Wi-Fi and VPN.
func (b *bypass) pick() (*net.Interface, error) {
	if b.iface != "" {
		iface, err := net.InterfaceByName(b.iface)
		if err != nil || iface.Flags&net.FlagUp == 0 {
			return nil, ErrNoInterface
		}
		return iface, nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifaces {
		iface := &ifaces[i]
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagRunning == 0 ||
			iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 || !physicalName(iface.Name) {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLinkLocalUnicast() {
				return iface, nil
			}
		}
	}
	return nil, ErrNoInterface
}

// virtualName matches tunnel, bridge and hypervisor adapters by name. It backs
// physicalName on systems without a naming scheme for physical interfaces.
func virtualName(name string) bool {
	name = strings.ToLower(name)
	for _, mark := range []string{
		"tun", "tap", "wg", "ppp", "warp", "vpn", "wireguard", "tailscale", "zerotier", "zt",
		"nordlynx", "ipsec", "docker", "veth", "br-", "virbr", "vmnet", "vmware", "virtual",
		"vethernet", "hyper-v", "loopback", "bluetooth",
	} {
		if strings.Contains(name, mark) {
			return true
		}
	}
	return false
}
