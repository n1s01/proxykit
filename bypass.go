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
	"sync"
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
	// routable IPv4 or IPv6 address whose name does not look like a tunnel; among
	// those, the one owning the best default route wins (see Platform).
	Interface string
	// DNS lists ip:port resolvers queried over the same interface, all at
	// once. Nil uses 1.1.1.1, 8.8.8.8 and 77.88.8.8. When plain DNS gets no
	// answer, the same servers are asked over TLS on port 853. Answers are
	// cached for a minute per Dialer (shared within CheckAll, Detect and New).
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

// Caching: one bypass serves every Dialer of an operation (see sharedRoute in
// dial.go), so a batch check resolves each proxy host and inspects the network
// interfaces once instead of per socket.
const (
	// dnsCacheTTL keeps resolved proxy addresses. The Go resolver hides record
	// TTLs; a minute is short enough for rotating DNS and long enough for a batch.
	dnsCacheTTL = time.Minute
	// dnsCacheMax bounds the cache; expired entries are pruned past it.
	dnsCacheMax = 4096
	// plainDNSBudget bounds the first transport: blocked DNS is silent.
	plainDNSBudget = 2 * time.Second
	// resolveTimeout bounds one shared resolution independently of any caller.
	resolveTimeout = 8 * time.Second
	// pickTTL reuses the chosen interface: listing interfaces and the routing
	// table costs several system calls (GetAdaptersAddresses on Windows) and
	// runs before every connect, DNS sockets included.
	pickTTL = 2 * time.Second
)

type bypass struct {
	iface string
	dns   []string
	// plain holds one resolver per server, queried in parallel.
	plain  []*net.Resolver
	secure *net.Resolver
	// dot remembers that plain DNS was blocked and DNS over TLS answered.
	dot atomic.Bool

	pickMu   sync.Mutex
	picked   *net.Interface
	pickedAt time.Time

	dnsMu    sync.Mutex
	cache    map[string]dnsEntry
	inflight map[string]*dnsCall
}

type dnsEntry struct {
	ips     []net.IP
	expires time.Time
}

type dnsCall struct {
	done chan struct{}
	ips  []net.IP
	err  error
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
	b := &bypass{iface: opts.Interface, dns: dns, cache: map[string]dnsEntry{}, inflight: map[string]*dnsCall{}}
	for _, server := range dns {
		b.plain = append(b.plain, &net.Resolver{PreferGo: true, Dial: b.dialDNS(server)})
	}
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

// lookup resolves host over the physical interface, from the cache when
// possible. Concurrent lookups of one name share a single resolution, which
// runs on its own deadline so one caller's cancellation does not fail others.
// "tcp" asks for both families, IPv4 first; tcp4/tcp6 ask for one.
func (b *bypass) lookup(ctx context.Context, network, host string) ([]net.IP, error) {
	family := "ip"
	switch {
	case strings.HasSuffix(network, "4"):
		family = "ip4"
	case strings.HasSuffix(network, "6"):
		family = "ip6"
	}
	key := family + "|" + strings.ToLower(strings.TrimSuffix(host, "."))
	b.dnsMu.Lock()
	if e, ok := b.cache[key]; ok && time.Now().Before(e.expires) {
		b.dnsMu.Unlock()
		return e.ips, nil
	}
	call, ok := b.inflight[key]
	if !ok {
		call = &dnsCall{done: make(chan struct{})}
		b.inflight[key] = call
		go b.resolveShared(context.WithoutCancel(ctx), key, family, host, call)
	}
	b.dnsMu.Unlock()
	select {
	case <-call.done:
		return call.ips, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (b *bypass) resolveShared(ctx context.Context, key, family, host string, call *dnsCall) {
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	call.ips, call.err = b.resolve(ctx, family, host)
	b.dnsMu.Lock()
	delete(b.inflight, key)
	if call.err == nil {
		now := time.Now()
		if len(b.cache) >= dnsCacheMax {
			for k, e := range b.cache {
				if !now.Before(e.expires) {
					delete(b.cache, k)
				}
			}
			if len(b.cache) >= dnsCacheMax {
				clear(b.cache)
			}
		}
		b.cache[key] = dnsEntry{ips: call.ips, expires: now.Add(dnsCacheTTL)}
	}
	b.dnsMu.Unlock()
	close(call.done)
}

// resolve asks plain DNS (every server at once) and DNS over TLS. VPN clients
// in strict-route mode drop plain DNS outside the tunnel, so DoT is the second
// try; whichever worked last goes first next time. The name is queried as
// rooted, so search domains a VPN pushed into the system config never apply.
func (b *bypass) resolve(ctx context.Context, family, host string) ([]net.IP, error) {
	name := host
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	type step struct {
		secure bool
		lookup func(context.Context) ([]net.IP, error)
	}
	plain := step{false, func(ctx context.Context) ([]net.IP, error) {
		// Blocked DNS is silent; leave time for the other transport.
		ctx, cancel := context.WithTimeout(ctx, plainDNSBudget)
		defer cancel()
		return raceLookup(ctx, b.plain, family, name)
	}}
	secure := step{true, func(ctx context.Context) ([]net.IP, error) { return b.secure.LookupIP(ctx, family, name) }}
	steps := [2]step{plain, secure}
	if b.dot.Load() {
		steps = [2]step{secure, plain}
	}
	var err error
	for _, s := range steps {
		var ips []net.IP
		if ips, err = s.lookup(ctx); err == nil {
			b.dot.Store(s.secure)
			return ipv4First(ips), nil
		}
		if notFound(err) {
			break
		}
	}
	return nil, err
}

// raceLookup asks every resolver at once and returns the first answer, so one
// blocked public resolver does not cost the whole plain-DNS budget.
func raceLookup(ctx context.Context, resolvers []*net.Resolver, family, name string) ([]net.IP, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		ips []net.IP
		err error
	}
	results := make(chan result, len(resolvers))
	for _, r := range resolvers {
		go func(r *net.Resolver) {
			ips, err := r.LookupIP(ctx, family, name)
			results <- result{ips, err}
		}(r)
	}
	err := invalid("no DNS servers")
	for range resolvers {
		r := <-results
		if r.err == nil {
			return r.ips, nil
		}
		err = r.err
		if notFound(err) {
			break
		}
	}
	return nil, err
}

func notFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// ipv4First keeps resolver order within each family and tries IPv4 first:
// the physical network almost always has it, IPv6 is not guaranteed.
func ipv4First(ips []net.IP) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip.To4() != nil {
			out = append(out, ip)
		}
	}
	for _, ip := range ips {
		if ip.To4() == nil {
			out = append(out, ip)
		}
	}
	return out
}

func (b *bypass) dialDNS(server string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := &net.Dialer{Timeout: 5 * time.Second, Control: b.control}
		return d.DialContext(ctx, network, server)
	}
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

// pick is re-evaluated at most every pickTTL: interfaces come and go with
// Wi-Fi and VPN, but listing them before every connect is expensive.
func (b *bypass) pick() (*net.Interface, error) {
	b.pickMu.Lock()
	defer b.pickMu.Unlock()
	if b.picked != nil && time.Since(b.pickedAt) < pickTTL {
		return b.picked, nil
	}
	iface, err := b.choose()
	if err != nil {
		b.picked = nil
		return nil, err
	}
	b.picked, b.pickedAt = iface, time.Now()
	return iface, nil
}

func (b *bypass) choose() (*net.Interface, error) {
	if b.iface != "" {
		iface, err := net.InterfaceByName(b.iface)
		if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagRunning == 0 {
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
		// Link-local addresses (169.254/16, fe80::/10) do not reach a gateway.
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.IsGlobalUnicast() {
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
