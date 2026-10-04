package proxykit

import "context"

// Options configures parsing, proxy connection setup and optional discovery.
type Options struct {
	Parse ParseOptions
	Dial  DialOptions
	// Target is required only when the input has no explicit protocol.
	Target string
	// Candidates selects discovery protocols; nil tries SOCKS5, HTTP and HTTPS.
	Candidates []Protocol
}

// New parses input and returns a ready dialer. Explicit protocols require no
// network I/O. Auto discovery uses the same routing and TLS settings as traffic.
// The returned Dialer owns no open resources and needs no Close.
func New(ctx context.Context, input string, opts Options) (*Dialer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	spec, err := ParseWithOptions(input, opts.Parse)
	if err != nil {
		return nil, err
	}
	if spec.Protocol == Auto {
		result, err := Detect(ctx, spec, DetectOptions{
			Target: opts.Target, Candidates: opts.Candidates,
			Timeout: opts.Dial.Timeout, DialOptions: opts.Dial,
		})
		if err != nil {
			return nil, err
		}
		spec = result.Proxy
	}
	return NewDialer(spec, opts.Dial)
}
