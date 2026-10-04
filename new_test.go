package proxykit_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/n1s01/proxykit"
	"github.com/n1s01/proxykit/relay"
)

func TestDialerSharesConfiguredRouteAcrossTrafficAndChecks(t *testing.T) {
	var calls atomic.Int32
	forward := func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls.Add(1)
		if addr != "proxy.test:8080" {
			t.Errorf("route changed to %s", addr)
		}
		client, peer := net.Pipe()
		go func() {
			defer peer.Close()
			rd := bufio.NewReader(peer)
			req, err := http.ReadRequest(rd)
			if err != nil {
				return
			}
			if req.Method != "CONNECT" || req.Host != "target.test:443" {
				t.Error("unexpected proxy request")
			}
			if _, err = io.WriteString(peer, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, rd)
		}()
		return client, nil
	}
	c, err := proxykit.New(context.Background(), "http://proxy.test:8080", proxykit.Options{
		Dial: proxykit.DialOptions{Forward: forward},
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("explicit construction performed network I/O")
	}
	snapshot := c.Spec()
	snapshot.Host = "changed.test"
	if c.Spec().Host != "proxy.test" {
		t.Fatal("caller mutated client endpoint")
	}
	conn, err := c.DialContext(context.Background(), "tcp", "target.test:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	result, err := c.Check(context.Background(), proxykit.CheckOptions{Target: "target.test:443"})
	if err != nil || !result.OK || calls.Load() != 2 {
		t.Fatalf("client check did not use configured route: %v", err)
	}
	tr := c.Transport()
	defer tr.CloseIdleConnections()
	if tr.Proxy != nil {
		t.Fatal("environment proxy lookup enabled")
	}
	relay, err := relay.Start(c, relay.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err = relay.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDialerRejectsUnusableInputAndCanceledConstruction(t *testing.T) {
	if _, err := proxykit.New(context.Background(), "proxy.test:8080", proxykit.Options{}); !errors.Is(err, proxykit.ErrInvalid) {
		t.Fatalf("Auto without detection target: %v", err)
	}
	if _, err := proxykit.New(context.Background(), "unknown://proxy.test:8080", proxykit.Options{}); !errors.Is(err, proxykit.ErrProtocol) {
		t.Fatalf("unknown protocol: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := proxykit.New(ctx, "http://proxy.test:8080", proxykit.Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled construction: %v", err)
	}
}

func TestStructuredAndListInput(t *testing.T) {
	spec, err := proxykit.ParseJSON([]byte(`["socks5","host.test",1080,true,"u","p"]`), proxykit.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	client, err := proxykit.NewDialer(spec, proxykit.DialOptions{})
	if err != nil || client.Spec() != spec {
		t.Fatalf("structured constructor: %v", err)
	}
	specs, failures := proxykit.ParseLines("# comment\nhttp://host.test:80\ninvalid", proxykit.ParseOptions{})
	if len(specs) != 1 || len(failures) != 1 || failures[0].Line != 3 {
		t.Fatal("list API lost input positions")
	}
}

func TestUninitializedDialerReturnsError(t *testing.T) {
	for _, d := range []*proxykit.Dialer{nil, new(proxykit.Dialer)} {
		conn, err := d.DialContext(context.Background(), "tcp", "target.test:443")
		if conn != nil || !errors.Is(err, proxykit.ErrInvalid) {
			t.Fatalf("uninitialized dialer: %v", err)
		}
		result, err := d.Check(context.Background(), proxykit.CheckOptions{Target: "target.test:443"})
		if result.OK || err == nil {
			t.Fatalf("uninitialized check: %v", err)
		}
	}
}
