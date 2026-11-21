package proxykit

// Route selection: how the TCP socket reaches the PROXY (not the target).
//
//	DialOptions{}                                   -> RouteBypass (default)
//	DialOptions{Bypass: BypassOptions{...}}         -> RouteBypass, tuned
//	DialOptions{Advanced: {DisableBypass: true}}    -> RouteSystem (OS routing table, i.e. through a VPN)
//	DialOptions{Advanced: {Forward: f}}             -> RouteCustom (f owns the whole route)
//
// Conflicting combinations are rejected with ErrInvalid rather than one
// silently winning. On a platform without bypass (see platform.go) the default
// fails with ErrBypassUnsupported; the caller opts out explicitly.

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// DialContextFunc establishes a TCP connection and must honor cancellation.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// DialOptions controls the connection to the proxy and proxy-side TLS. The
// zero value is the recommended configuration: 10s setup timeout, VPN bypass
// on, standard certificate verification.
type DialOptions struct {
	// Timeout bounds the entire connection setup, including authentication.
	// Zero uses 10 seconds. Returned tunnels have no library-imposed deadline.
	Timeout time.Duration
	// TLSConfig configures TLS to HTTPS proxies, not TLS to the target.
	// It is cloned. Normal certificate verification is enabled by default.
	TLSConfig *tls.Config
	// Bypass tunes the default VPN bypass route. The zero value is right for
	// almost everyone. It cannot switch bypass off; see Advanced.
	Bypass BypassOptions
	// Advanced holds route overrides that turn the default bypass off.
	Advanced AdvancedDialOptions
}

// AdvancedDialOptions overrides the default route to the proxy. Each field
// switches VPN bypass off; use them only when traffic to the proxy must
// follow the OS routing table or a custom transport.
type AdvancedDialOptions struct {
	// DisableBypass sends the connection to the proxy through the OS routing
	// table, which includes any active VPN/TUN. Required on platforms where
	// CurrentPlatform().Bypass is false.
	DisableBypass bool
	// Forward replaces the built-in route entirely: it opens only the
	// connection to the proxy and must honor cancellation. Inject custom DNS,
	// tracing or test transports here. Bypass settings cannot be combined
	// with it.
	Forward DialContextFunc
}

// Route names how a Dialer reaches its proxy.
type Route string

const (
	// RouteBypass pins the socket to a physical interface, around VPN tunnels.
	RouteBypass Route = "bypass"
	// RouteSystem follows the OS routing table (Advanced.DisableBypass).
	RouteSystem Route = "system"
	// RouteCustom uses Advanced.Forward.
	RouteCustom Route = "custom"
)

// buildRoute is the single place that turns DialOptions into a forward dialer.
func buildRoute(opts DialOptions) (DialContextFunc, Route, error) {
	adv := opts.Advanced
	switch {
	case adv.Forward != nil:
		if !opts.Bypass.isZero() {
			return nil, "", invalid("Bypass settings cannot be combined with Advanced.Forward")
		}
		return adv.Forward, RouteCustom, nil
	case adv.DisableBypass:
		if !opts.Bypass.isZero() {
			return nil, "", invalid("Bypass settings cannot be combined with Advanced.DisableBypass")
		}
		return (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext, RouteSystem, nil
	default:
		b, err := newBypass(opts.Bypass)
		if err != nil {
			return nil, "", err
		}
		return b.dial, RouteBypass, nil
	}
}
