package proxykit

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

// Dialer opens TCP tunnels through one proxy. It is safe for concurrent use,
// owns no open resources (no Close) and copies its configuration at
// construction. Build it with New or NewDialer; the zero value cannot dial.
type Dialer struct {
	spec      Spec
	timeout   time.Duration
	route     Route
	forward   DialContextFunc
	tlsConfig *tls.Config
	connector connector
}

// Spec returns a copy of the resolved endpoint, including credentials.
func (d *Dialer) Spec() Spec { return d.spec }

// Route reports how this Dialer reaches its proxy: RouteBypass unless
// DialOptions.Advanced overrode it.
func (d *Dialer) Route() Route { return d.route }

// NewDialer validates and snapshots a resolved proxy configuration. The
// protocol must be concrete (not Auto). With zero DialOptions the connection
// to the proxy uses VPN bypass; see route.go.
func NewDialer(s Spec, opts DialOptions) (*Dialer, error) {
	return newDialer(s, opts, func() (DialContextFunc, Route, error) { return buildRoute(opts) })
}

// newDialer validates s and opts before asking for the route, so a bad spec is
// reported ahead of route problems whichever way the route is obtained.
func newDialer(s Spec, opts DialOptions, route func() (DialContextFunc, Route, error)) (*Dialer, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	handshake, err := connectorFor(s)
	if err != nil {
		return nil, err
	}
	if opts.Timeout < 0 {
		return nil, invalid("negative dial timeout")
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	forward, kind, err := route()
	if err != nil {
		return nil, err
	}
	var cfg *tls.Config
	if opts.TLSConfig != nil {
		cfg = opts.TLSConfig.Clone()
	} else {
		// Resumption saves a round trip on every tunnel after the first one
		// through an HTTPS proxy.
		cfg = &tls.Config{MinVersion: tls.VersionTLS12, ClientSessionCache: tls.NewLRUClientSessionCache(64)}
	}
	if cfg.ServerName == "" {
		cfg.ServerName = s.Host
	}
	// Our CONNECT exchange uses HTTP/1.1, even when a supplied config offers h2.
	cfg.NextProtos = []string{"http/1.1"}
	return &Dialer{
		spec:      s,
		timeout:   timeout,
		route:     kind,
		forward:   forward,
		tlsConfig: cfg,
		connector: handshake,
	}, nil
}

// sharedRoute builds the route of one operation once (lazily, on the first
// Dialer) and hands it to every Dialer of that operation. With the default
// bypass this shares the DNS cache, the DoT preference and the interface
// choice across all proxies of a CheckAll or all candidates of a Detect. It is
// scoped to the operation, never global.
type sharedRoute struct {
	opts    DialOptions
	once    sync.Once
	forward DialContextFunc
	kind    Route
	err     error
}

func newSharedRoute(opts DialOptions) *sharedRoute { return &sharedRoute{opts: opts} }

func (r *sharedRoute) get() (DialContextFunc, Route, error) {
	r.once.Do(func() { r.forward, r.kind, r.err = buildRoute(r.opts) })
	return r.forward, r.kind, r.err
}

func (r *sharedRoute) dialer(s Spec) (*Dialer, error) { return newDialer(s, r.opts, r.get) }

func (r *sharedRoute) factory() dialerFactory {
	return func(s Spec) (ContextDialer, error) {
		d, err := r.dialer(s)
		if err != nil {
			return nil, err // never a typed nil inside the interface
		}
		return d, nil
	}
}

// DialContext completes authentication and CONNECT before returning a tunnel.
// Both proxy and target use TCP; UDP/BIND and direct fallback are unsupported.
// tcp4/tcp6 constrain the connection to the proxy, not proxy-side target DNS.
func (d *Dialer) DialContext(parent context.Context, network, target string) (net.Conn, error) {
	if d == nil || d.forward == nil {
		return nil, invalid("uninitialized dialer")
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, invalid("only TCP networks are supported")
	}
	host, port, e := parseTarget(target)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(parent, d.timeout)
	defer cancel()
	if e = ctx.Err(); e != nil {
		return nil, &OpError{Stage: StageDial, Protocol: d.spec.Protocol, Err: e}
	}
	c, e := d.forward(ctx, network, d.spec.Address())
	if e != nil {
		if c != nil {
			_ = c.Close()
		}
		if ctx.Err() != nil {
			e = ctx.Err()
		}
		return nil, &OpError{Stage: StageDial, Protocol: d.spec.Protocol, Err: e}
	}
	if c == nil {
		return nil, &OpError{Stage: StageDial, Protocol: d.spec.Protocol, Err: invalid("forward dialer returned nil connection")}
	}
	// Closing the socket interrupts all handshake reads/writes, including custom
	// transports whose deadlines alone do not implement context cancellation.
	raw := c
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = raw.Close()
		close(done)
	})
	stopWatch := func() {
		if stop != nil {
			f := stop
			stop = nil
			if !f() {
				<-done
			}
		}
	}
	defer stopWatch()
	fail := func(stage Stage, code int, err error) (net.Conn, error) {
		_ = c.Close()
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return nil, &OpError{Stage: stage, Protocol: d.spec.Protocol, StatusCode: code, Err: err}
	}
	deadline, _ := ctx.Deadline()
	if e = c.SetDeadline(deadline); e != nil {
		return fail(StageDial, 0, e)
	}
	if d.spec.Protocol == HTTPS {
		// A tls.Config is safe to share once it is no longer modified.
		tc := tls.Client(c, d.tlsConfig)
		c = tc
		if e = tc.HandshakeContext(ctx); e != nil {
			return fail(StageProxyTLS, 0, e)
		}
	}
	var stage Stage
	var code int
	c, stage, code, e = d.connector.Connect(c, targetInfo{address: target, host: host, port: port})
	if e != nil {
		return fail(stage, code, e)
	}
	stopWatch()
	if e = ctx.Err(); e != nil {
		return fail(StageConnect, 0, e)
	}
	if e = c.SetDeadline(time.Time{}); e != nil {
		return fail(StageConnect, 0, e)
	}
	return c, nil
}

// connector owns only the wire handshake. Dialer owns socket setup, TLS,
// cancellation and cleanup, so new protocols do not duplicate that lifecycle.
type connector interface {
	Connect(net.Conn, targetInfo) (net.Conn, Stage, int, error)
}

type targetInfo struct {
	address string
	host    string
	port    int
}

// connectorFor is the single transport dispatch point for supported protocols.
func connectorFor(spec Spec) (connector, error) {
	switch spec.Protocol {
	case HTTP, HTTPS:
		return httpConnector{spec: spec}, nil
	case SOCKS5:
		return socksConnector{spec: spec}, nil
	case Auto:
		return nil, ErrUnresolved
	default:
		return nil, ErrProtocol
	}
}
