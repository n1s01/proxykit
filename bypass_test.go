package proxykit_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/n1s01/proxykit"
)

func TestDefaultRouteIsBypass(t *testing.T) {
	s := socksProxy(t, "", "", 0, nil)
	d, e := proxykit.NewDialer(s, proxykit.DialOptions{})
	if !proxykit.BypassSupported() {
		if !errors.Is(e, proxykit.ErrBypassUnsupported) {
			t.Fatalf("unsupported platform must refuse the default route explicitly: %v", e)
		}
		return
	}
	if e != nil {
		t.Fatal(e)
	}
	if d.Route() != proxykit.RouteBypass {
		t.Fatalf("default route = %q, want bypass", d.Route())
	}
	// Loopback proxies are never bound, so the tunnel works on any machine.
	c, e := d.DialContext(context.Background(), "tcp", echoTarget(t))
	if e != nil {
		t.Fatal(e)
	}
	assertEcho(t, c)
}

func TestAdvancedRoutes(t *testing.T) {
	s := socksProxy(t, "", "", 0, nil)
	forward := (&net.Dialer{}).DialContext
	for _, tc := range []struct {
		name string
		opts proxykit.DialOptions
		want proxykit.Route
	}{
		{"disable bypass", proxykit.DialOptions{Advanced: proxykit.AdvancedDialOptions{DisableBypass: true}}, proxykit.RouteSystem},
		{"custom forward", proxykit.DialOptions{Advanced: proxykit.AdvancedDialOptions{Forward: forward}}, proxykit.RouteCustom},
		{"forward wins over disable", proxykit.DialOptions{Advanced: proxykit.AdvancedDialOptions{Forward: forward, DisableBypass: true}}, proxykit.RouteCustom},
	} {
		d, e := proxykit.NewDialer(s, tc.opts)
		if e != nil {
			t.Fatalf("%s: %v", tc.name, e)
		}
		if d.Route() != tc.want {
			t.Fatalf("%s: route %q, want %q", tc.name, d.Route(), tc.want)
		}
		c, e := d.DialContext(context.Background(), "tcp", echoTarget(t))
		if e != nil {
			t.Fatalf("%s: %v", tc.name, e)
		}
		assertEcho(t, c)
	}
}

func TestRouteConflictsAreRejected(t *testing.T) {
	s := socksProxy(t, "", "", 0, nil)
	tuned := proxykit.BypassOptions{Interface: "en0"}
	for name, opts := range map[string]proxykit.DialOptions{
		"bypass + forward": {Bypass: tuned, Advanced: proxykit.AdvancedDialOptions{Forward: (&net.Dialer{}).DialContext}},
		"bypass + disable": {Bypass: tuned, Advanced: proxykit.AdvancedDialOptions{DisableBypass: true}},
	} {
		if _, e := proxykit.NewDialer(s, opts); !errors.Is(e, proxykit.ErrInvalid) {
			t.Fatalf("%s: %v", name, e)
		}
	}
}

func TestBypassOptionsValidation(t *testing.T) {
	if !proxykit.BypassSupported() {
		t.Skip("interface binding is unavailable on this platform")
	}
	s := socksProxy(t, "", "", 0, nil)
	for _, dns := range []string{"dns.example:53", "1.1.1.1", "1.1.1.1:0"} {
		if _, e := proxykit.NewDialer(s, proxykit.DialOptions{Bypass: proxykit.BypassOptions{DNS: []string{dns}}}); !errors.Is(e, proxykit.ErrInvalid) {
			t.Fatalf("DNS %q: %v", dns, e)
		}
	}
	// A missing interface does not matter for a loopback proxy.
	d, e := proxykit.NewDialer(s, proxykit.DialOptions{Bypass: proxykit.BypassOptions{Interface: "proxykit-missing0"}})
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
	d, e := proxykit.NewDialer(s, proxykit.DialOptions{Bypass: proxykit.BypassOptions{Interface: "proxykit-missing0"}})
	if e != nil {
		t.Fatal(e)
	}
	_, e = d.DialContext(context.Background(), "tcp", "192.0.2.2:443")
	var op *proxykit.OpError
	if !errors.Is(e, proxykit.ErrNoInterface) || !errors.As(e, &op) || op.Stage != proxykit.StageDial {
		t.Fatalf("missing interface: %v", e)
	}
}

func TestCurrentPlatformIsConsistent(t *testing.T) {
	p := proxykit.CurrentPlatform()
	if p.OS == "" || p.Bypass != proxykit.BypassSupported() {
		t.Fatalf("inconsistent platform: %+v", p)
	}
	if p.Bypass && p.SocketOption == "" {
		t.Fatalf("supported platform must name its socket option: %+v", p)
	}
}
