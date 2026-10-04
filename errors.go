package proxykit

import (
	"context"
	"errors"
	"fmt"
	"net"
)

var (
	ErrInvalid    = errors.New("invalid proxy configuration")
	ErrAmbiguous  = errors.New("ambiguous proxy format; specify a layout or use a URL")
	ErrProtocol   = errors.New("unsupported or unexpected proxy protocol")
	ErrUnresolved = errors.New("proxy protocol must be resolved before dialing")
	ErrAuth       = errors.New("proxy authentication failed")
	ErrRejected   = errors.New("proxy rejected the target")
	ErrStatus     = errors.New("unexpected target HTTP status")
	// ErrNoInterface means VPN bypass found no usable physical interface.
	ErrNoInterface = errors.New("no active physical network interface")
	// ErrBypassUnsupported means interface binding is unavailable on this platform.
	ErrBypassUnsupported = errors.New("VPN bypass is not supported on this platform")
)

type Stage string

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

func (e *OpError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("proxykit: %s (%s, status %d)", e.Stage, e.Protocol, e.StatusCode)
	}
	return fmt.Sprintf("proxykit: %s (%s) failed", e.Stage, e.Protocol)
}
func (e *OpError) Unwrap() error { return e.Err }

// IsTimeout also recognizes context deadlines, unlike net.Error alone.
func IsTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
}
