package proxykit

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDialFirstSkipsDeadAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	// Nothing listens on 127.0.0.2 at that port: the attempt is refused.
	ips := []net.IP{net.ParseIP("127.0.0.2"), net.ParseIP("127.0.0.1")}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dialFirst(ctx, &net.Dialer{}, "tcp", ips, port)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.RemoteAddr().String(); got != ln.Addr().String() {
		t.Fatalf("connected to %s", got)
	}
	_ = c.Close()

	ln.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if c, err = dialFirst(ctx, &net.Dialer{}, "tcp", ips, port); err == nil {
		_ = c.Close()
		t.Fatal("expected an error when no address accepts")
	}
	if _, err = dialFirst(ctx, &net.Dialer{}, "tcp", nil, port); err == nil {
		t.Fatal("expected an error without addresses")
	}
}
