package proxykit

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// Sentinel errors. Match them with errors.Is; most arrive wrapped in *OpError.
var (
	ErrInvalid    = errors.New("invalid proxy configuration")
	ErrAmbiguous  = errors.New("ambiguous proxy format; specify a layout or use a URL")
	ErrProtocol   = errors.New("unsupported or unexpected proxy protocol")
	ErrUnresolved = errors.New("proxy protocol must be resolved before dialing")
	ErrAuth       = errors.New("proxy authentication failed")
	ErrRejected   = errors.New("proxy rejected the target")
	ErrStatus     = errors.New("unexpected target HTTP status")
	// ErrNoInterface means the default VPN bypass found no usable physical
	// interface. The dial fails instead of going through the tunnel.
	ErrNoInterface = errors.New("no active physical network interface")
	// ErrBypassUnsupported means this OS has no interface binding (see
	// CurrentPlatform). NewDialer returns it for the default route; set
	// DialOptions.Advanced.DisableBypass to use the system route instead.
	ErrBypassUnsupported = errors.New("VPN bypass is not supported on this platform")
)

// Stage names the phase of a proxy operation that failed; see OpError.
type Stage string

// Stages in the order a tunnel is built, then the check stages.
const (
	StageDial        Stage = "dial"
	StageProxyTLS    Stage = "proxy_tls"
	StageNegotiation Stage = "negotiation"
	StageAuth        Stage = "auth"
	StageConnect     Stage = "connect"
	StageTargetTLS   Stage = "target_tls"
	StageHTTP        Stage = "http"
	StageGeo         Stage = "geo"
)

// OpError identifies the failing phase. Err remains available via errors.Is/As.
// Error does not include remote text, URLs, credentials or the underlying error
// message. Inspect Unwrap explicitly when more diagnostics are appropriate.
type OpError struct {
	Stage      Stage
	Protocol   Protocol
	StatusCode int // HTTP status or SOCKS5 reply code, depending on Protocol.
	Err        error
}

// Error reports the stage and protocol without remote text or credentials.
func (e *OpError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("proxykit: %s (%s, status %d)", e.Stage, e.Protocol, e.StatusCode)
	}
	return fmt.Sprintf("proxykit: %s (%s) failed", e.Stage, e.Protocol)
}

// Unwrap exposes the underlying cause to errors.Is and errors.As.
func (e *OpError) Unwrap() error { return e.Err }

// IsTimeout also recognizes context deadlines, unlike net.Error alone.
func IsTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
}
