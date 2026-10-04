package proxykit

import (
	"context"
	"net"
	"time"
)

// DetectOptions controls bounded protocol discovery against an explicit target.
type DetectOptions struct {
	// Target must reflect the application's intended use, e.g. Telegram DC IP:port.
	Target string
	// Candidates defaults to SOCKS5, HTTP, HTTPS, tried concurrently. On a proxy
	// serving several protocols, the first successful tunnel wins; pin explicitly
	// if protocol preference matters. At most three sockets are opened.
	Candidates []Protocol
	Timeout    time.Duration
	// DialOptions controls connections to the proxy during discovery.
	DialOptions DialOptions
}

// Attempt is the completed observation for one candidate protocol.
type Attempt struct {
	Protocol Protocol
	Duration time.Duration
	Err      error
}

// Detection contains a resolved endpoint and all attempted protocols in input order.
type Detection struct {
	Proxy    Spec
	Attempts []Attempt
}

// DetectionError preserves every candidate's failure; errors.Is/As traverses all.
// Failure means no usable protocol/credentials/target combination was found.
type DetectionError struct{ Attempts []Attempt }

func (e *DetectionError) Error() string { return "proxykit: no candidate established a proxy tunnel" }
func (e *DetectionError) Unwrap() []error {
	var errs []error
	for _, a := range e.Attempts {
		if a.Err != nil {
			errs = append(errs, a.Err)
		}
	}
	return errs
}

// Detect requires Auto and authenticates plus opens the target tunnel. A SOCKS
// greeting or any HTTP status line alone is never reported as success. All
// attempts and sockets are cleaned up before return, including losing attempts.
func Detect(ctx context.Context, spec Spec, opts DetectOptions) (Detection, error) {
	return detect(ctx, spec, opts, newDialerFactory(opts.DialOptions))
}

// Resolve parses input and discovers only missing protocols. An explicit
// protocol is returned without opening a connection.
func Resolve(ctx context.Context, input string, parseOpts ParseOptions, detectOpts DetectOptions) (Spec, error) {
	spec, err := ParseWithOptions(input, parseOpts)
	if err != nil {
		return Spec{}, err
	}
	if spec.Protocol != Auto {
		return spec, nil
	}
	result, err := Detect(ctx, spec, detectOpts)
	return result.Proxy, err
}

func detect(parent context.Context, s Spec, opts DetectOptions, factory dialerFactory) (Detection, error) {
	out := Detection{}
	if factory == nil {
		return out, invalid("nil detection factory")
	}
	if e := s.Validate(); e != nil {
		return out, e
	}
	if s.Protocol != Auto {
		return out, invalid("Detect requires Auto; explicit protocols are never overridden")
	}
	if _, _, e := parseTarget(opts.Target); e != nil {
		return out, e
	}
	if opts.Timeout < 0 {
		return out, invalid("negative detection timeout")
	}
	candidates := append([]Protocol(nil), opts.Candidates...)
	if len(candidates) == 0 {
		candidates = []Protocol{SOCKS5, HTTP, HTTPS}
	}
	if len(candidates) > 3 {
		return out, invalid("too many detection candidates")
	}
	seen := map[Protocol]bool{}
	for _, p := range candidates {
		if p != HTTP && p != HTTPS && p != SOCKS5 || seen[p] {
			return out, invalid("invalid or duplicate detection candidate")
		}
		seen[p] = true
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	type outcome struct {
		index   int
		attempt Attempt
		spec    Spec
	}
	ch := make(chan outcome, len(candidates))
	for i, p := range candidates {
		go func(i int, p Protocol) {
			ps := s
			ps.Protocol = p
			started := time.Now()
			d, e := factory(ps)
			if e == nil && d == nil {
				e = invalid("detection factory returned nil dialer")
			}
			if e == nil {
				var c net.Conn
				c, e = d.DialContext(ctx, "tcp", opts.Target)
				if e == nil && c == nil {
					e = invalid("detection dialer returned nil connection")
				}
				if c != nil {
					_ = c.Close()
				}
			}
			ch <- outcome{i, Attempt{p, time.Since(started), e}, ps}
		}(i, p)
	}
	out.Attempts = make([]Attempt, len(candidates))
	winner := false
	for range candidates {
		v := <-ch
		out.Attempts[v.index] = v.attempt
		if v.attempt.Err == nil && !winner {
			out.Proxy = v.spec
			winner = true
			cancel()
		}
	}
	if e := parent.Err(); e != nil {
		return out, e
	}
	if winner {
		return out, nil
	}
	return out, &DetectionError{out.Attempts}
}

// dialerFactory is an implementation detail for bounded discovery and checks.
type dialerFactory func(Spec) (ContextDialer, error)

func newDialerFactory(opts DialOptions) dialerFactory {
	return func(spec Spec) (ContextDialer, error) {
		return NewDialer(spec, opts)
	}
}
