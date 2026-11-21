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

func TestPreferRouted(t *testing.T) {
	// A VirtualBox host-only adapter is listed before the one that reaches
	// the internet, as on the Windows machine this was reported on.
	hostOnly, ethernet, wifi := &net.Interface{Index: 12}, &net.Interface{Index: 11}, &net.Interface{Index: 7}
	candidates := []*net.Interface{hostOnly, ethernet, wifi}
	for _, tc := range []struct {
		name   string
		routed []int
		want   *net.Interface
	}{
		{"default route wins over order", []int{11}, ethernet},
		{"best metric first", []int{7, 11}, wifi},
		{"tunnel route is skipped", []int{40, 11}, ethernet},
		{"no routed candidate", []int{40}, hostOnly},
		{"routing table unknown", nil, hostOnly},
	} {
		if got := preferRouted(candidates, tc.routed); got != tc.want {
			t.Errorf("%s: picked #%d, want #%d", tc.name, got.Index, tc.want.Index)
		}
	}
}

func TestIsLocalhost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost": true, "LOCALHOST.": true, "app.localhost": true,
		"localhost.example": false, "example.com": false,
	} {
		if isLocalhost(host) != want {
			t.Errorf("isLocalhost(%q) != %v", host, want)
		}
	}
}

func TestVirtualName(t *testing.T) {
	for name, want := range map[string]bool{
		"utun3": true, "wg0": true, "Cloudflare WARP": true, "vEthernet (WSL)": true,
		"tailscale0": true, "docker0": true, "eth0": false, "Wi-Fi": false, "enp3s0": false,
	} {
		if virtualName(name) != want {
			t.Errorf("virtualName(%q) != %v", name, want)
		}
	}
}

func TestIPv4First(t *testing.T) {
	ips := []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::2"), net.ParseIP("192.0.2.2")}
	got := ipv4First(ips)
	want := []string{"192.0.2.1", "192.0.2.2", "2001:db8::1", "2001:db8::2"}
	for i, ip := range got {
		if ip.String() != want[i] {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
}

func newTestBypass() *bypass {
	return &bypass{cache: map[string]dnsEntry{}, inflight: map[string]*dnsCall{}}
}

func TestLookupServesCacheByFamily(t *testing.T) {
	b := newTestBypass()
	cached := []net.IP{net.ParseIP("192.0.2.7")}
	b.cache["ip4|proxy.example"] = dnsEntry{ips: cached, expires: time.Now().Add(time.Minute)}
	ips, err := b.lookup(context.Background(), "tcp4", "Proxy.Example.")
	if err != nil || len(ips) != 1 || !ips[0].Equal(cached[0]) {
		t.Fatalf("cache miss: %v %v", ips, err)
	}
	// Another family is a different entry: it must not be served from ip4.
	// A pending resolution stands in for the network.
	b.inflight["ip|proxy.example"] = &dnsCall{done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = b.lookup(ctx, "tcp", "proxy.example"); err == nil {
		t.Fatal("ip lookup was served from the ip4 entry")
	}
}

func TestLookupSharesInflightResolution(t *testing.T) {
	b := newTestBypass()
	call := &dnsCall{done: make(chan struct{})}
	b.inflight["ip|proxy.example"] = call

	// A caller giving up does not fail the shared resolution.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.lookup(ctx, "tcp", "proxy.example"); err == nil {
		t.Fatal("canceled caller got an answer")
	}

	results := make(chan []net.IP, 2)
	for i := 0; i < 2; i++ {
		go func() {
			ips, _ := b.lookup(context.Background(), "tcp", "proxy.example")
			results <- ips
		}()
	}
	call.ips = []net.IP{net.ParseIP("192.0.2.9")}
	close(call.done)
	for i := 0; i < 2; i++ {
		select {
		case ips := <-results:
			if len(ips) != 1 || !ips[0].Equal(call.ips[0]) {
				t.Fatalf("waiter got %v", ips)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("waiter did not get the shared answer")
		}
	}
}
