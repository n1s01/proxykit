package relay

import (
	"context"
	"net"
)

// Dialer is the relay-owned port for opening an authenticated target tunnel.
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}
