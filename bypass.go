package proxykit

// VPN bypass: the DEFAULT route for every connection to a proxy.
//
// The socket to the proxy is pinned to a physical interface (Wi-Fi/Ethernet),
// so a VPN/WARP/TUN client on the same machine does not carry proxy traffic.
// Names are resolved over that same interface, because a VPN resolver may
// answer with tunnel-only fake-ip addresses. There is no fallback through the
// tunnel: without a physical interface the dial fails with ErrNoInterface.
//
// This file is portable. Everything OS-specific goes through `backend`
// (platform.go, platform_<os>.go). Route selection lives in route.go.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// BypassOptions tunes the default bypass route. The zero value is the
// recommended setting: pick the interface automatically and use public DNS.
// To turn bypass off, use DialOptions.Advanced.DisableBypass instead.
type BypassOptions struct {
	// Interface pins a network interface by name ("en0", "eth0", "Wi-Fi").
	// Empty selects a running interface with a MAC address, broadcast and a
	// routable IPv4 address whose name does not look like a tunnel; among
	// those, the one owning the best default route wins (see Platform).
	Interface string
	// DNS lists ip:port resolvers queried over the same interface,
	// round-robin. Nil uses 1.1.1.1, 8.8.8.8 and 77.88.8.8. When plain DNS
	// gets no answer, the same servers are asked over TLS on port 853.
	DNS []string
}

func (o BypassOptions) isZero() bool { return o.Interface == "" && len(o.DNS) == 0 }

var defaultBypassDNS = []string{"1.1.1.1:53", "8.8.8.8:53", "77.88.8.8:53"}

// BypassDialContext returns the bound dialer behind the default route, for
// connections that are not proxy tunnels (diagnostics, IP checks).
func BypassDialContext(opts BypassOptions) (DialContextFunc, error) {
	b, err := newBypass(opts)
	if err != nil {
		return nil, err
	}
	return b.dial, nil
}

type bypass struct {
	iface string
	dns   []string
	next  atomic.Uint32
	// dot remembers that plain DNS was blocked and DNS over TLS answered.
	dot           atomic.Bool
	plain, secure *net.Resolver
}

func newBypass(opts BypassOptions) (*bypass, error) {
	if !BypassSupported() {
		return nil, fmt.Errorf("%w (GOOS=%s); set DialOptions.Advanced.DisableBypass to use the system route",
			ErrBypassUnsupported, CurrentPlatform().OS)
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
	b.plain = &net.Resolver{PreferGo: true, Dial: b.dialDNS}
	b.secure = &net.Resolver{PreferGo: true, Dial: b.dialDoT}
	return b, nil
}

func (b *bypass) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{KeepAlive: 30 * time.Second, Control: b.control}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) != nil {
		return d.DialContext(ctx, network, addr)
	}
	if isLocalhost(host) {
		// Public DNS does not know localhost; loopback is never bound anyway.
		return (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(ctx, network, addr)
	}
	ips, err := b.lookup(ctx, network, host)
	if err != nil {
		return nil, err
	}
	return dialFirst(ctx, d, network, ips, port)
}

func isLocalhost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// dialFirst connects to whichever address answers first. A new attempt starts
// every 250ms or as soon as one fails, so an address that silently drops
// packets costs a fraction of a second instead of the whole deadline.
func dialFirst(ctx context.Context, d *net.Dialer, network string, ips []net.IP, port string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, len(ips))
	next := time.NewTimer(0)
	defer next.Stop()
	err := invalid("host has no addresses")
	for started, pending := 0, 0; started < len(ips) || pending > 0; {
		select {
		case <-next.C:
			if started == len(ips) {
				continue
			}
			go func(addr string) {
				c, e := d.DialContext(ctx, network, addr)
				results <- result{c, e}
			}(net.JoinHostPort(ips[started].String(), port))
			started++
			pending++
			next.Reset(250 * time.Millisecond)
		case r := <-results:
			pending--
			if r.err != nil {
				err = r.err
				next.Reset(0)
				continue
			}
			go drainConns(results, pending, func(r result) net.Conn { return r.conn })
			return r.conn, nil
		}
	}
	return nil, err
}

// drainConns closes connections that lost a race after the winner returned.
func drainConns[T any](results <-chan T, pending int, conn func(T) net.Conn) {
	for ; pending > 0; pending-- {
		if c := conn(<-results); c != nil {
			_ = c.Close()
		}
	}
}

// lookup resolves over the physical interface. VPN clients in strict-route
// mode drop plain DNS outside the tunnel, so DNS over TLS is the second try;
// whichever worked last goes first next time.
func (b *bypass) lookup(ctx context.Context, network, host string) ([]net.IP, error) {
	family := "ip4"
	if strings.HasSuffix(network, "6") {
		family = "ip6"
	}
	resolvers := []*net.Resolver{b.plain, b.secure}
	if b.dot.Load() {
		resolvers[0], resolvers[1] = b.secure, b.plain
	}
	var err error
	for i, resolver := range resolvers {
		attempt, cancel := ctx, context.CancelFunc(func() {})
		if i == 0 {
			// Blocked DNS is silent; leave time for the other transport.
			attempt, cancel = context.WithTimeout(ctx, 2*time.Second)
		}
		var ips []net.IP
		ips, err = resolver.LookupIP(attempt, family, host)
		cancel()
		if err == nil {
			b.dot.Store(resolver == b.secure)
			return ips, nil
		}
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			break
		}
	}
	return nil, err
}

func (b *bypass) dialDNS(ctx context.Context, network, _ string) (net.Conn, error) {
	server := b.dns[int(b.next.Add(1))%len(b.dns)]
	d := &net.Dialer{Timeout: 5 * time.Second, Control: b.control}
	return d.DialContext(ctx, network, server)
}

// dialDoT opens DNS over TLS on port 853. The resolver frames queries for a
// stream connection exactly as DoT requires. Every server is tried at once and
// the first handshake wins: networks commonly drop DoT to one provider, and
// waiting out its timeout would spend the whole dial deadline.
func (b *bypass) dialDoT(ctx context.Context, _, _ string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, len(b.dns))
	for _, server := range b.dns {
		go func(server string) {
			host, _, _ := net.SplitHostPort(server)
			d := &net.Dialer{Timeout: 5 * time.Second, Control: b.control}
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "853"))
			if err != nil {
				results <- result{nil, err}
				return
			}
			tc := tls.Client(c, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
			if err = tc.HandshakeContext(ctx); err != nil {
				_ = c.Close()
				results <- result{nil, err}
				return
			}
			results <- result{tc, nil}
		}(server)
	}
	var err error
	for pending := len(b.dns); pending > 0; pending-- {
		r := <-results
		if r.err != nil {
			err = r.err
			continue
		}
		go drainConns(results, pending-1, func(r result) net.Conn { return r.conn })
		return r.conn, nil
	}
	return nil, err
}

// control runs before connect(2) on every socket the bypass opens.
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
		opErr = backend.bind(fd, strings.HasSuffix(network, "6"), iface)
	}); err != nil {
		return err
	}
	if opErr != nil {
		return fmt.Errorf("bind socket to %q: %w", iface.Name, opErr)
	}
	return nil
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
	var candidates []*net.Interface
	for i := range ifaces {
		if iface := &ifaces[i]; physicalCandidate(iface) {
			candidates = append(candidates, iface)
		}
	}
	if len(candidates) == 0 {
		return nil, ErrNoInterface
	}
	return preferRouted(candidates, backend.defaultRoutes()), nil
}

func physicalCandidate(iface *net.Interface) bool {
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagRunning == 0 ||
		iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 || !backend.physicalName(iface.Name) {
		return false
	}
	// TUN adapters (Wintun, utun) are layer 3: no MAC and no broadcast. This
	// catches tunnels whatever the VPN client chose to call them.
	if len(iface.HardwareAddr) == 0 || iface.Flags&net.FlagBroadcast == 0 {
		return false
	}
	addrs, _ := iface.Addrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

// preferRouted returns the candidate that owns the best default route; routed
// lists interface indexes, best first. Host-only and internal adapters of
// hypervisors look physical but lead nowhere, and binding to one fails with
// "network unreachable". Without a routed candidate the first one is kept.
func preferRouted(candidates []*net.Interface, routed []int) *net.Interface {
	for _, index := range routed {
		for _, iface := range candidates {
			if iface.Index == index {
				return iface
			}
		}
	}
	return candidates[0]
}
