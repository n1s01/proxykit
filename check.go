package proxykit

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

// CheckOptions selects a target and the depth of a reachability check.
type CheckOptions struct {
	// Exactly one of Target and URL is required. Target checks a TCP tunnel;
	// URL performs an HTTP GET, including target TLS for an https URL.
	Target string
	URL    string
	// TLSConfig adds a target TLS handshake to Target checks. ServerName defaults
	// to the target hostname. For URL checks, this config controls target TLS.
	TLSConfig *tls.Config
	// Timeout bounds the entire check; zero uses 10 seconds.
	Timeout time.Duration
	// StatusCodes defaults to 200..299. Redirects are deliberately not followed.
	StatusCodes []int
}

// CheckResult reports tunnel setup and total operation durations separately.
// Duration fields encode as nanoseconds in JSON, following time.Duration.
type CheckResult struct {
	Proxy         Spec          `json:"proxy"`
	Target        string        `json:"target"`
	StartedAt     time.Time     `json:"started_at"`
	TunnelLatency time.Duration `json:"tunnel_latency"`
	Duration      time.Duration `json:"duration"`
	StatusCode    int           `json:"status_code,omitempty"`
	OK            bool          `json:"ok"`
}

func checkTarget(opts CheckOptions) (string, *url.URL, error) {
	if (opts.Target == "") == (opts.URL == "") {
		return "", nil, invalid("provide exactly one of Target and URL")
	}
	if opts.Target != "" {
		_, _, e := parseTarget(opts.Target)
		return opts.Target, nil, e
	}
	u, e := url.Parse(opts.URL)
	if e != nil {
		return "", nil, invalid("check URL syntax")
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.User != nil || u.Fragment != "" {
		return "", nil, invalid("check URL requires http(s), no credentials or fragment")
	}
	if e = validateHost(u.Hostname()); e != nil {
		return "", nil, e
	}
	p := u.Port()
	if p == "" {
		p = "80"
		if u.Scheme == "https" {
			p = "443"
		}
	}
	if _, e = parsePort(p); e != nil {
		return "", nil, e
	}
	return net.JoinHostPort(u.Hostname(), p), u, nil
}

// Check tests a resolved proxy using the default connection settings.
// For custom routing or proxy TLS, construct a Dialer and use its Check method.
func Check(ctx context.Context, spec Spec, opts CheckOptions) (CheckResult, error) {
	d, err := NewDialer(spec, DialOptions{})
	if err != nil {
		return CheckResult{Proxy: spec}, err
	}
	return d.Check(ctx, opts)
}

// Check uses the same proxy configuration and network route as DialContext.
func (d *Dialer) Check(ctx context.Context, opts CheckOptions) (CheckResult, error) {
	if d == nil {
		return CheckResult{}, invalid("nil check dialer")
	}
	return check(ctx, d.spec, d, opts)
}

// check tests reachability of the supplied target through a resolved proxy.
// A failed target check is not proof that the proxy itself is dead. The returned
// OpError distinguishes proxy connection/authentication from target TLS/HTTP.
// CheckResult.Proxy contains credentials when marshaled as JSON.
func check(parent context.Context, s Spec, d ContextDialer, opts CheckOptions) (result CheckResult, err error) {
	startedCheck := time.Now()
	result.Proxy = s
	result.StartedAt = startedCheck.UTC()
	defer func() {
		result.Duration = time.Since(startedCheck)
		result.OK = err == nil
	}()
	target, u, e := checkTarget(opts)
	if e != nil {
		return result, e
	}
	result.Target = target
	if err := s.Validate(); err != nil {
		return result, err
	}
	if s.Protocol == Auto {
		return result, ErrUnresolved
	}
	if d == nil {
		return result, invalid("nil check dialer")
	}
	if opts.Timeout < 0 {
		return result, invalid("negative check timeout")
	}
	for _, code := range opts.StatusCodes {
		if code < 100 || code > 599 {
			return result, invalid("HTTP status code")
		}
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	started := time.Now()
	c, e := d.DialContext(ctx, "tcp", target)
	result.TunnelLatency = time.Since(started)
	if e != nil {
		if c != nil {
			_ = c.Close()
		}
		return result, e
	}
	if c == nil {
		return result, invalid("check dialer returned nil connection")
	}
	defer func() { _ = c.Close() }()
	if u == nil {
		if opts.TLSConfig == nil {
			return result, nil
		}
		cfg := opts.TLSConfig.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName, _, _ = net.SplitHostPort(target)
		}
		tc := tls.Client(c, cfg)
		e = tc.HandshakeContext(ctx)
		if e != nil {
			if ctx.Err() != nil {
				e = ctx.Err()
			}
			return result, &OpError{Stage: StageTargetTLS, Protocol: s.Protocol, Err: e}
		}
		return result, nil
	}
	// Use net/http's framing, header limits and TLS behavior, but consume the
	// already-created tunnel exactly once. HTTP retries cannot dial a direct route.
	var used atomic.Bool
	tr := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if used.Swap(true) {
				return nil, invalid("check tunnel already consumed")
			}
			return c, nil
		},
		DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10,
	}
	if opts.TLSConfig != nil {
		tr.TLSClientConfig = opts.TLSConfig.Clone()
	}
	if u.Scheme == "https" {
		tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, e := tr.DialContext(ctx, network, addr)
			if e != nil {
				return nil, e
			}
			cfg := &tls.Config{MinVersion: tls.VersionTLS12}
			if opts.TLSConfig != nil {
				cfg = opts.TLSConfig.Clone()
			}
			if cfg.ServerName == "" {
				cfg.ServerName = u.Hostname()
			}
			cfg.NextProtos = []string{"http/1.1"}
			tc := tls.Client(conn, cfg)
			if e = tc.HandshakeContext(ctx); e != nil {
				_ = tc.Close()
				return nil, &OpError{Stage: StageTargetTLS, Protocol: s.Protocol, Err: e}
			}
			return tc, nil
		}
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return result, invalid("check request")
	}
	resp, e := client.Do(req)
	if e != nil {
		var op *OpError
		if errors.As(e, &op) {
			if ctx.Err() != nil {
				op.Err = ctx.Err()
			}
			return result, op
		}
		if ctx.Err() != nil {
			e = ctx.Err()
		}
		// net/url errors may contain query strings; OpError.Error never prints them.
		return result, &OpError{Stage: StageHTTP, Protocol: s.Protocol, Err: e}
	}
	defer resp.Body.Close()
	result.StatusCode = resp.StatusCode
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	if len(opts.StatusCodes) > 0 {
		ok = false
		for _, code := range opts.StatusCodes {
			if code == resp.StatusCode {
				ok = true
				break
			}
		}
	}
	if !ok {
		return result, &OpError{Stage: StageHTTP, Protocol: s.Protocol, StatusCode: resp.StatusCode, Err: ErrStatus}
	}
	// Health means successful response headers, not a speed test or full download.
	return result, nil
}
