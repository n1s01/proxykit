package proxykit

import (
	"context"
	"net"
	"net/http"
	"time"
)

// Transport creates a fresh transport with no environment proxy lookup.
// All HTTP and HTTPS requests use the same authenticated proxy tunnel logic.
// HTTP proxies must allow CONNECT to the requested port, including port 80.
// TLSClientConfig (target TLS) can be set on the returned transport before use.
func (d *Dialer) Transport() *http.Transport {
	return NewHTTPTransport(d)
}

// ContextDialer is the HTTP adapter's only dependency on a tunnel implementation.
type ContextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// NewHTTPTransport builds a fresh environment-independent HTTP transport.
func NewHTTPTransport(d ContextDialer) *http.Transport {
	return &http.Transport{
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// Dial implements conventional dialer interfaces with the setup timeout.
func (d *Dialer) Dial(network, target string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, target)
}
