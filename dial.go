package proxykit

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// Dialer is safe for concurrent use. Its configuration is copied at construction.
// Construct it with New or NewDialer; its zero value cannot open a tunnel.
type Dialer struct {
	spec      Spec
	timeout   time.Duration
	forward   DialContextFunc
	tlsConfig *tls.Config
	connector connector
}

// Spec returns a copy of the resolved endpoint, including credentials.
func (d *Dialer) Spec() Spec { return d.spec }

// NewDialer validates and snapshots a resolved proxy configuration.
func NewDialer(s Spec, opts DialOptions) (*Dialer, error) {
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
	forward := opts.Forward
	if opts.Bypass != nil {
		if forward != nil {
			return nil, invalid("Forward and Bypass are mutually exclusive")
		}
		if forward, err = newBypassForward(*opts.Bypass); err != nil {
			return nil, err
		}
	}
	if forward == nil {
		forward = (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.TLSConfig != nil {
		cfg = opts.TLSConfig.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = s.Host
	}
	// Our CONNECT exchange uses HTTP/1.1, even when a supplied config offers h2.
	cfg.NextProtos = []string{"http/1.1"}
	return &Dialer{
		spec:      s,
		timeout:   timeout,
		forward:   forward,
		tlsConfig: cfg,
		connector: handshake,
	}, nil
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
		tc := tls.Client(c, d.tlsConfig.Clone())
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

// DialContextFunc establishes a TCP connection and must honor cancellation.
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// DialOptions controls proxy connection setup and proxy-side TLS.
type DialOptions struct {
	// Timeout bounds the entire connection setup, including authentication.
	// Zero uses 10 seconds. Returned tunnels have no library-imposed deadline.
	Timeout time.Duration
	// Forward opens only the connection to the proxy. It must honor cancellation.
	// Inject interface binding, DNS policy, tracing or test transports here.
	Forward DialContextFunc
	// Bypass sends the connection to the proxy through a physical interface,
	// around VPN/WARP tunnels. It replaces Forward; setting both is an error.
	Bypass *BypassOptions
	// TLSConfig configures TLS to HTTPS proxies, not TLS to the target.
	// It is cloned. Normal certificate verification is enabled by default.
	TLSConfig *tls.Config
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
