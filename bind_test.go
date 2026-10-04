package proxykit_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/n1s01/proxykit"
)

func TestBypassOptions(t *testing.T) {
	s := socksProxy(t, "", "", 0, nil)
	forward := (&net.Dialer{}).DialContext
	if !proxykit.BypassSupported() {
		_, e := proxykit.NewDialer(s, proxykit.DialOptions{Bypass: &proxykit.BypassOptions{}})
		if !errors.Is(e, proxykit.ErrBypassUnsupported) {
			t.Fatalf("unsupported platform: %v", e)
		}
		return
	}
	if _, e := proxykit.NewDialer(s, proxykit.DialOptions{Forward: forward, Bypass: &proxykit.BypassOptions{}}); !errors.Is(e, proxykit.ErrInvalid) {
		t.Fatalf("Forward with Bypass: %v", e)
	}
	for _, dns := range []string{"dns.example:53", "1.1.1.1", "1.1.1.1:0"} {
		if _, e := proxykit.NewDialer(s, proxykit.DialOptions{Bypass: &proxykit.BypassOptions{DNS: []string{dns}}}); !errors.Is(e, proxykit.ErrInvalid) {
			t.Fatalf("DNS %q: %v", dns, e)
		}
	}
	// Loopback proxies are never bound, so a missing interface does not matter.
	d, e := proxykit.NewDialer(s, proxykit.DialOptions{Bypass: &proxykit.BypassOptions{Interface: "proxykit-missing0"}})
	if e != nil {
		t.Fatal(e)
	}
	c, e := d.DialContext(context.Background(), "tcp", echoTarget(t))
	if e != nil {
		t.Fatal(e)
	}
	assertEcho(t, c)
}

func TestBypassNeverFallsBackWithoutInterface(t *testing.T) {
	if !proxykit.BypassSupported() {
		t.Skip("interface binding is unavailable on this platform")
	}
	s := specFor(t, proxykit.SOCKS5, "192.0.2.1:1080")
	d, e := proxykit.NewDialer(s, proxykit.DialOptions{Bypass: &proxykit.BypassOptions{Interface: "proxykit-missing0"}})
	if e != nil {
		t.Fatal(e)
	}
	_, e = d.DialContext(context.Background(), "tcp", "192.0.2.2:443")
	var op *proxykit.OpError
	if !errors.Is(e, proxykit.ErrNoInterface) || !errors.As(e, &op) || op.Stage != proxykit.StageDial {
		t.Fatalf("missing interface: %v", e)
	}
}
