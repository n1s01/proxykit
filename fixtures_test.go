package proxykit_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n1s01/proxykit"
)

// Local fixtures exercise real sockets. Cleanup waits for every accepted handler.
func tcpFixture(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	conns := map[net.Conn]bool{}
	var wg sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			conns[c] = true
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				defer func() { mu.Lock(); delete(conns, c); mu.Unlock() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				handle(c)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-acceptDone
		mu.Lock()
		for c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return ln.Addr().String()
}

func specFor(t *testing.T, p proxykit.Protocol, addr string) proxykit.Spec {
	t.Helper()
	s, e := proxykit.Parse(string(p) + "://" + addr)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func echoTarget(t *testing.T) string { return tcpFixture(t, func(c net.Conn) { _, _ = io.Copy(c, c) }) }
func pipePair(a net.Conn, ar io.Reader, b net.Conn) {
	done := make(chan struct{})
	go func() { _, _ = io.Copy(b, ar); _ = b.Close(); _ = a.Close(); close(done) }()
	_, _ = io.Copy(a, b)
	_ = a.Close()
	_ = b.Close()
	<-done
}

func connectProxy(t *testing.T, secure bool, user, pass string, hits *atomic.Int32) (proxykit.Spec, *tls.Config) {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		want := ""
		if user != "" || pass != "" {
			want = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
		}
		if r.Header.Get("Proxy-Authorization") != want {
			w.WriteHeader(407)
			return
		}
		if r.Method != "CONNECT" {
			w.WriteHeader(405)
			return
		}
		up, e := net.DialTimeout("tcp", r.Host, time.Second)
		if e != nil {
			w.WriteHeader(502)
			return
		}
		defer up.Close()
		c, rw, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer c.Close()
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		pipePair(c, rw, up)
	})
	var server *httptest.Server
	var cfg *tls.Config
	p := proxykit.HTTP
	if secure {
		server = httptest.NewTLSServer(handler)
		roots := x509.NewCertPool()
		roots.AddCert(server.Certificate())
		cfg = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		p = proxykit.HTTPS
	} else {
		server = httptest.NewServer(handler)
	}
	t.Cleanup(server.Close)
	u, _ := url.Parse(server.URL)
	s := specFor(t, p, u.Host)
	s.Username = user
	s.Password = pass
	return s, cfg
}

func socksProxy(t *testing.T, user, pass string, reject byte, targets chan<- string) proxykit.Spec {
	addr := tcpFixture(t, func(c net.Conn) {
		var h [2]byte
		if _, e := io.ReadFull(c, h[:]); e != nil || h[0] != 5 {
			return
		}
		methods := make([]byte, int(h[1]))
		if _, e := io.ReadFull(c, methods); e != nil {
			return
		}
		method := byte(0)
		if user != "" {
			method = 2
		}
		_ = writeAll(c, []byte{5, method})
		if method == 2 {
			if _, e := io.ReadFull(c, h[:]); e != nil || h[0] != 1 {
				return
			}
			u := make([]byte, int(h[1]))
			if _, e := io.ReadFull(c, u); e != nil {
				return
			}
			var n [1]byte
			if _, e := io.ReadFull(c, n[:]); e != nil {
				return
			}
			pw := make([]byte, int(n[0]))
			if _, e := io.ReadFull(c, pw); e != nil {
				return
			}
			if string(u) != user || string(pw) != pass {
				_ = writeAll(c, []byte{1, 1})
				return
			}
			_ = writeAll(c, []byte{1, 0})
		}
		var request [4]byte
		if _, e := io.ReadFull(c, request[:]); e != nil || request[1] != 1 {
			return
		}
		var host string
		switch request[3] {
		case 1:
			ip := make([]byte, 4)
			if _, e := io.ReadFull(c, ip); e != nil {
				return
			}
			host = net.IP(ip).String()
		case 4:
			ip := make([]byte, 16)
			if _, e := io.ReadFull(c, ip); e != nil {
				return
			}
			host = net.IP(ip).String()
		case 3:
			var n [1]byte
			if _, e := io.ReadFull(c, n[:]); e != nil {
				return
			}
			b := make([]byte, int(n[0]))
			if _, e := io.ReadFull(c, b); e != nil {
				return
			}
			host = string(b)
		default:
			return
		}
		if _, e := io.ReadFull(c, h[:]); e != nil {
			return
		}
		target := net.JoinHostPort(host, fmt.Sprint(int(h[0])<<8|int(h[1])))
		if targets != nil {
			targets <- target
		}
		if reject != 0 {
			_ = writeAll(c, []byte{5, reject, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		if host == "remote-dns.invalid" {
			_ = writeAll(c, []byte{5, 0, 0, 3, 1, 'x', 0, 0})
			_, _ = io.Copy(c, c)
			return
		}
		up, e := net.DialTimeout("tcp", target, time.Second)
		if e != nil {
			_ = writeAll(c, []byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		_ = writeAll(c, []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		pipePair(c, c, up)
	})
	s := specFor(t, proxykit.SOCKS5, addr)
	s.Username = user
	s.Password = pass
	return s
}

func assertEcho(t *testing.T, c net.Conn) {
	t.Helper()
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if e := writeAll(c, []byte("tunnel-data")); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 11)
	if _, e := io.ReadFull(c, b); e != nil || string(b) != "tunnel-data" {
		t.Fatalf("tunnel payload: %q %v", b, e)
	}
}
