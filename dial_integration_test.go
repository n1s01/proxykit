package proxykit_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n1s01/proxykit"
)

func TestProtocolsAndTransport(t *testing.T) {
	target := echoTarget(t)
	for _, p := range []proxykit.Protocol{proxykit.HTTP, proxykit.HTTPS, proxykit.SOCKS5} {
		t.Run(string(p), func(t *testing.T) {
			var s proxykit.Spec
			var cfg *tls.Config
			var hits atomic.Int32
			if p == proxykit.SOCKS5 {
				s = socksProxy(t, "u", "p", 0, nil)
			} else {
				s, cfg = connectProxy(t, p == proxykit.HTTPS, "u", "p", &hits)
			}
			d, e := proxykit.NewDialer(s, proxykit.DialOptions{TLSConfig: cfg})
			if e != nil {
				t.Fatal(e)
			}
			c, e := d.DialContext(context.Background(), "tcp", target)
			if e != nil {
				t.Fatal(e)
			}
			assertEcho(t, c)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Proxy-Authorization") != "" {
					t.Error("proxy credential reached origin")
				}
				_, _ = io.WriteString(w, "origin")
			}))
			defer origin.Close()
			tr := d.Transport()
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: time.Second}
			t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
			t.Setenv("NO_PROXY", "*")
			resp, e := client.Get(origin.URL)
			if e != nil {
				t.Fatal(e)
			}
			body, e := io.ReadAll(resp.Body)
			resp.Body.Close()
			if e != nil || string(body) != "origin" {
				t.Fatal("origin response")
			}
			if p != proxykit.SOCKS5 && hits.Load() != 2 {
				t.Fatalf("expected both requests through proxy, got %d", hits.Load())
			}
		})
	}
}

func TestTransportHTTPSAndHTTP2ThroughTLSProxy(t *testing.T) {
	var hits atomic.Int32
	s, proxyTLS := connectProxy(t, true, "u", "p", &hits)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("expected HTTP/2 at origin, got %s", r.Proto)
		}
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials reached TLS origin")
		}
		_, _ = io.WriteString(w, "nested-tls")
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	d, e := proxykit.NewDialer(s, proxykit.DialOptions{TLSConfig: proxyTLS})
	if e != nil {
		t.Fatal(e)
	}
	tr := d.Transport()
	tr.TLSClientConfig = &tls.Config{RootCAs: roots}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Second}
	resp, e := client.Get(origin.URL)
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(resp.Body)
	resp.Body.Close()
	if e != nil || string(b) != "nested-tls" || hits.Load() != 1 {
		t.Fatal("HTTPS target did not use the TLS proxy tunnel")
	}
}

func TestMalformedProxyRepliesAreRejected(t *testing.T) {
	for _, wire := range []string{
		"HTTP/1.1 407 denied\r\n\r\n",
		"HTTP/1.1 403 denied\r\n\r\n",
		"HTTP/1.1 502 denied\r\n\r\n",
		"not an HTTP response\r\n\r\n",
		"HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("x", 70<<10) + "\r\n\r\n",
	} {
		addr := tcpFixture(t, func(c net.Conn) {
			if _, e := http.ReadRequest(bufio.NewReader(c)); e != nil {
				return
			}
			_ = writeAll(c, []byte(wire))
		})
		d, _ := proxykit.NewDialer(specFor(t, proxykit.HTTP, addr), proxykit.DialOptions{})
		if c, e := d.DialContext(context.Background(), "tcp", "target.test:443"); e == nil {
			c.Close()
			t.Fatal("malformed/rejected HTTP reply established a tunnel")
		}
	}
	for _, reply := range [][]byte{{4, 0}, {5, 1}, {5, 255}, {5, 2}} {
		addr := tcpFixture(t, func(c net.Conn) {
			var h [2]byte
			if _, e := io.ReadFull(c, h[:]); e != nil {
				return
			}
			methods := make([]byte, int(h[1]))
			if _, e := io.ReadFull(c, methods); e != nil {
				return
			}
			_ = writeAll(c, reply)
		})
		d, _ := proxykit.NewDialer(specFor(t, proxykit.SOCKS5, addr), proxykit.DialOptions{})
		if c, e := d.DialContext(context.Background(), "tcp", "target.test:443"); e == nil {
			c.Close()
			t.Fatal("unexpected SOCKS method/version accepted")
		}
	}
}

func TestAuthFailuresAndTargetRejection(t *testing.T) {
	target := echoTarget(t)
	for _, p := range []proxykit.Protocol{proxykit.HTTP, proxykit.SOCKS5} {
		t.Run(string(p), func(t *testing.T) {
			var s proxykit.Spec
			var hits atomic.Int32
			if p == proxykit.HTTP {
				s, _ = connectProxy(t, false, "u", "p", &hits)
			} else {
				s = socksProxy(t, "u", "p", 0, nil)
			}
			s.Password = "wrong"
			d, _ := proxykit.NewDialer(s, proxykit.DialOptions{})
			c, e := d.DialContext(context.Background(), "tcp", target)
			if c != nil || !errors.Is(e, proxykit.ErrAuth) {
				t.Fatalf("auth result: %v %v", c, e)
			}
			var op *proxykit.OpError
			if !errors.As(e, &op) || op.Stage != proxykit.StageAuth {
				t.Fatal("auth phase lost")
			}
		})
	}
	s := socksProxy(t, "", "", 5, nil)
	d, _ := proxykit.NewDialer(s, proxykit.DialOptions{})
	_, e := d.DialContext(context.Background(), "tcp", target)
	var op *proxykit.OpError
	if !errors.Is(e, proxykit.ErrRejected) || !errors.As(e, &op) || op.StatusCode != 5 {
		t.Fatalf("target rejection: %v", e)
	}
}

func TestRemoteDNSAndIPv6Encoding(t *testing.T) {
	for _, target := range []string{"remote-dns.invalid:443", "[2001:db8::8]:443"} {
		t.Run(target, func(t *testing.T) {
			targets := make(chan string, 1)
			reject := byte(0)
			if strings.HasPrefix(target, "[") {
				reject = 5
			}
			s := socksProxy(t, "", "", reject, targets)
			d, _ := proxykit.NewDialer(s, proxykit.DialOptions{})
			c, e := d.DialContext(context.Background(), "tcp", target)
			if c != nil {
				assertEcho(t, c)
			} else if !errors.Is(e, proxykit.ErrRejected) {
				t.Fatal(e)
			}
			if got := <-targets; got != target {
				t.Fatalf("target changed to %s", got)
			}
		})
	}
}

func TestCancellationClosesHandshakeSocket(t *testing.T) {
	for _, p := range []proxykit.Protocol{proxykit.HTTP, proxykit.HTTPS, proxykit.SOCKS5} {
		t.Run(string(p), func(t *testing.T) {
			entered := make(chan struct{})
			closed := make(chan struct{})
			addr := tcpFixture(t, func(c net.Conn) {
				var b [1]byte
				if _, e := c.Read(b[:]); e != nil {
					return
				}
				close(entered)
				_, _ = io.Copy(io.Discard, c)
				close(closed)
			})
			d, _ := proxykit.NewDialer(specFor(t, p, addr), proxykit.DialOptions{Timeout: time.Second})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				c, e := d.DialContext(ctx, "tcp", "target.test:443")
				if c != nil {
					c.Close()
				}
				done <- e
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("handshake not started")
			}
			cancel()
			select {
			case e := <-done:
				if !errors.Is(e, context.Canceled) {
					t.Fatalf("cancellation: %v", e)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation stalled")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("socket leaked")
			}
		})
	}
}

func TestSetupTimeoutAndReturnedConnIndependence(t *testing.T) {
	addr := tcpFixture(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	d, _ := proxykit.NewDialer(specFor(t, proxykit.HTTP, addr), proxykit.DialOptions{Timeout: 30 * time.Millisecond})
	started := time.Now()
	_, e := d.DialContext(context.Background(), "tcp", "target.test:443")
	if !proxykit.IsTimeout(e) || time.Since(started) > time.Second {
		t.Fatalf("timeout failed: %v", e)
	}
	var hits atomic.Int32
	s, _ := connectProxy(t, false, "", "", &hits)
	d, _ = proxykit.NewDialer(s, proxykit.DialOptions{Timeout: 50 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	c, e := d.DialContext(ctx, "tcp", echoTarget(t))
	if e != nil {
		t.Fatal(e)
	}
	cancel()
	time.Sleep(65 * time.Millisecond)
	assertEcho(t, c)
}

func TestBufferedCONNECTAndAny2xx(t *testing.T) {
	for _, status := range []int{200, 201, 204} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			addr := tcpFixture(t, func(c net.Conn) {
				br := bufio.NewReader(c)
				if _, e := http.ReadRequest(br); e != nil {
					return
				}
				_ = writeAll(c, []byte(fmt.Sprintf("HTTP/1.1 %d OK\r\nContent-Length: 0\r\n\r\nbuffered", status)))
				_, _ = io.Copy(c, br)
			})
			d, _ := proxykit.NewDialer(specFor(t, proxykit.HTTP, addr), proxykit.DialOptions{})
			c, e := d.DialContext(context.Background(), "tcp", "target.test:443")
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			b := make([]byte, 8)
			if _, e = io.ReadFull(c, b); e != nil || string(b) != "buffered" {
				t.Fatalf("lost buffered tunnel bytes: %q %v", b, e)
			}
			// Tunnel payloads must not inherit the 64 KiB response-header limit.
			payload := strings.Repeat("x", 96<<10)
			done := make(chan error, 1)
			go func() { done <- writeAll(c, []byte(payload)) }()
			got := make([]byte, len(payload))
			_, e = io.ReadFull(c, got)
			if e != nil || string(got) != payload {
				t.Fatal("tunnel was truncated")
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestHTTPSCertificateVerification(t *testing.T) {
	var hits atomic.Int32
	s, cfg := connectProxy(t, true, "", "", &hits)
	d, _ := proxykit.NewDialer(s, proxykit.DialOptions{})
	_, e := d.DialContext(context.Background(), "tcp", echoTarget(t))
	var op *proxykit.OpError
	if !errors.As(e, &op) || op.Stage != proxykit.StageProxyTLS {
		t.Fatalf("expected untrusted proxy certificate, got %v", e)
	}
	d, _ = proxykit.NewDialer(s, proxykit.DialOptions{TLSConfig: cfg})
	cfg.ServerName = "mutated.invalid"
	c, e := d.DialContext(context.Background(), "tcp", echoTarget(t))
	if e != nil {
		t.Fatalf("TLS config not cloned: %v", e)
	}
	assertEcho(t, c)
}

func TestForwardValidationNoDirectFallback(t *testing.T) {
	var calls atomic.Int32
	cause := errors.New("injected failure")
	d, e := proxykit.NewDialer(proxykit.Spec{Protocol: proxykit.HTTP, Host: "proxy.test", Port: 80, Username: "", Password: ""}, proxykit.DialOptions{Forward: func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls.Add(1)
		if addr != "proxy.test:80" {
			t.Error("dialed target directly")
		}
		return nil, cause
	}})
	if e != nil {
		t.Fatal(e)
	}
	for _, target := range []string{"target.test:443\r\nInjected: header", "bad", "target.test:0"} {
		if _, e = d.DialContext(context.Background(), "tcp", target); e == nil {
			t.Fatal("invalid target accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input caused network I/O")
	}
	if _, e = d.DialContext(context.Background(), "udp", "target.test:443"); e == nil {
		t.Fatal("UDP accepted")
	}
	_, e = d.DialContext(context.Background(), "tcp", "target.test:443")
	if !errors.Is(e, cause) || calls.Load() != 1 {
		t.Fatal("forward error lost or retried")
	}
	if _, e = proxykit.NewDialer(proxykit.Spec{Protocol: proxykit.Auto, Host: "host", Port: 80, Username: "", Password: ""}, proxykit.DialOptions{}); !errors.Is(e, proxykit.ErrUnresolved) {
		t.Fatal("Auto silently dialed")
	}
}
