package proxykit_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n1s01/proxykit"
	"github.com/n1s01/proxykit/relay"
)

func TestRelayForwardsHTTPAndReusesClientConnection(t *testing.T) {
	var hits atomic.Int32
	s, _ := connectProxy(t, false, "u", "p", &hits)
	d, _ := proxykit.NewDialer(s, proxykit.DialOptions{})
	r, e := relay.Start(d, relay.Options{})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	var requests atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		if req.Header.Get("Proxy-Authorization") != "" || req.Header.Get("X-Hop") != "" {
			t.Error("hop header leaked to target")
		}
		w.Header().Set("Connection", "X-Response-Hop")
		w.Header().Set("X-Response-Hop", "hidden")
		_, _ = io.WriteString(w, "relay-response")
	}))
	defer origin.Close()
	u, _ := url.Parse(r.URL())
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Second}
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("GET", origin.URL, nil)
		req.Header.Set("Proxy-Authorization", "client-secret")
		req.Header.Set("Connection", "X-Hop")
		req.Header.Set("X-Hop", "hidden")
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		b, e := io.ReadAll(resp.Body)
		resp.Body.Close()
		if e != nil || string(b) != "relay-response" || resp.Header.Get("X-Response-Hop") != "" {
			t.Fatal("relay response or hop headers")
		}
	}
	if requests.Load() != 2 || hits.Load() == 0 {
		t.Fatal("requests bypassed upstream")
	}
}

func TestRelayCONNECTBufferedPayloadAndClose(t *testing.T) {
	target := echoTarget(t)
	s := socksProxy(t, "u", "p", 0, nil)
	d, _ := proxykit.NewDialer(s, proxykit.DialOptions{})
	r, e := relay.Start(d, relay.Options{})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	c, e := net.Dial("tcp", strings.TrimPrefix(r.URL(), "http://"))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if e = writeAll(c, []byte("CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\nearly")); e != nil {
		t.Fatal(e)
	}
	br := bufio.NewReader(c)
	resp, e := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if e != nil || resp.StatusCode != 200 {
		t.Fatalf("relay CONNECT: %v", e)
	}
	b := make([]byte, 5)
	if _, e = io.ReadFull(br, b); e != nil || string(b) != "early" {
		t.Fatalf("buffered payload lost: %v", e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal("close not idempotent")
	}
	if _, e = br.ReadByte(); e == nil {
		t.Fatal("active tunnel survived relay close")
	}
	if c, e = net.DialTimeout("tcp", strings.TrimPrefix(r.URL(), "http://"), time.Second); e == nil {
		c.Close()
		t.Fatal("listener survived close")
	}
}

func TestRelayCloseCancelsPendingHandshake(t *testing.T) {
	entered := make(chan struct{})
	forward := func(ctx context.Context, network, addr string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	d, _ := proxykit.NewDialer(proxykit.Spec{Protocol: proxykit.HTTP, Host: "proxy.test", Port: 80, Username: "", Password: ""}, proxykit.DialOptions{Forward: forward})
	r, e := relay.Start(d, relay.Options{})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	c, e := net.Dial("tcp", strings.TrimPrefix(r.URL(), "http://"))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = writeAll(c, []byte("CONNECT target.test:443 HTTP/1.1\r\nHost: target.test:443\r\n\r\n"))
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("upstream dial not started")
	}
	done := make(chan error, 1)
	go func() { done <- r.Close() }()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("relay close retained handshake")
	}
}

func TestRelayRejectsUnsupportedRequestAndLimitsHeaders(t *testing.T) {
	var calls atomic.Int32
	d, _ := proxykit.NewDialer(proxykit.Spec{Protocol: proxykit.HTTP, Host: "proxy.test", Port: 80, Username: "", Password: ""}, proxykit.DialOptions{Forward: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("should not dial")
	}})
	r, e := relay.Start(d, relay.Options{HeaderTimeout: 30 * time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	for _, request := range []string{"GET / HTTP/1.1\r\nHost: local\r\n\r\n", "GET http://target.test/ HTTP/1.1\r\nHost: target.test\r\nUpgrade: websocket\r\n\r\n", "CONNECT target.test:0 HTTP/1.1\r\nHost: target.test:0\r\n\r\n"} {
		c, e := net.Dial("tcp", strings.TrimPrefix(r.URL(), "http://"))
		if e != nil {
			t.Fatal(e)
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_ = writeAll(c, []byte(request))
		resp, e := http.ReadResponse(bufio.NewReader(c), nil)
		if e != nil || resp.StatusCode != 400 {
			t.Fatalf("invalid request result: %v", e)
		}
		resp.Body.Close()
		c.Close()
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request dialed upstream")
	}
	c, e := net.Dial("tcp", strings.TrimPrefix(r.URL(), "http://"))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_ = writeAll(c, []byte("GET "))
	// net/http may send 408 before closing; either response or immediate EOF is
	// valid. An open socket reaching the client's deadline is not.
	_, e = io.ReadAll(c)
	var ne net.Error
	if errors.As(e, &ne) && ne.Timeout() {
		t.Fatal("partial headers remained open")
	}
}
