package proxykit

import (
	"context"
	"crypto/tls"
	"errors"
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
	// running interface with a MAC address and a routable IPv4 address whose
	// name does not look like a tunnel or a virtual switch.
	Interface string
	// DNS lists ip:port resolvers queried over the same interface, round-robin.
	// Under a VPN the system resolver may return tunnel-only (fake-ip) addresses.
	// Nil uses 1.1.1.1, 8.8.8.8 and 77.88.8.8. When plain DNS gets no answer,
	// the same servers are asked over TLS on port 853.
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
	// dot remembers that plain DNS was blocked and DNS over TLS answered.
	dot           atomic.Bool
	plain, secure *net.Resolver
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
	b.plain = &net.Resolver{PreferGo: true, Dial: b.dialDNS}
	b.secure = &net.Resolver{PreferGo: true, Dial: b.dialDoT}
	return b.dial, nil
}

func (b *bypass) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{KeepAlive: 30 * time.Second, Control: b.control}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) != nil {
		return d.DialContext(ctx, network, addr)
	}
	ips, err := b.lookup(ctx, network, host)
	if err != nil {
		return nil, err
	}
	return dialFirst(ctx, d, network, ips, port)
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
	err := error(invalid("host has no addresses"))
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
			go func(pending int) {
				for ; pending > 0; pending-- {
					if late := <-results; late.conn != nil {
						_ = late.conn.Close()
					}
				}
			}(pending)
			return r.conn, nil
		}
	}
	return nil, err
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
		go func(pending int) {
			for ; pending > 0; pending-- {
				if late := <-results; late.conn != nil {
					_ = late.conn.Close()
				}
			}
		}(pending - 1)
		return r.conn, nil
	}
	return nil, err
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
		// TUN adapters (Wintun, utun) are layer 3: no MAC and no broadcast. This
		// catches tunnels whatever the VPN client chose to call them.
		if len(iface.HardwareAddr) == 0 || iface.Flags&net.FlagBroadcast == 0 {
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
		"xray", "v2ray", "sing-box", "clash", "mihomo", "hiddify", "nekoray", "outline",
		"nordlynx", "ipsec", "docker", "veth", "br-", "virbr", "vmnet", "vmware", "virtual",
		"vethernet", "hyper-v", "loopback", "bluetooth",
	} {
		if strings.Contains(name, mark) {
			return true
		}
	}
	return false
}
