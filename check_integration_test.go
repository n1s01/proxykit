package proxykit_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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

func TestCheckTCPAndTLS(t *testing.T) {
	var hits atomic.Int32
	s, _ := connectProxy(t, false, "u", "p", &hits)
	r, e := proxykit.Check(context.Background(), s, proxykit.CheckOptions{Target: echoTarget(t)})
	if e != nil || !r.OK || r.TunnelLatency <= 0 || r.Duration < r.TunnelLatency {
		t.Fatalf("TCP check: %+v %v", r, e)
	}
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer origin.Close()
	target := strings.TrimPrefix(origin.URL, "https://")
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	r, e = proxykit.Check(context.Background(), s, proxykit.CheckOptions{Target: target, TLSConfig: &tls.Config{RootCAs: roots}})
	if e != nil || !r.OK {
		t.Fatalf("target TLS: %v", e)
	}
	_, e = proxykit.Check(context.Background(), s, proxykit.CheckOptions{Target: target, TLSConfig: &tls.Config{}})
	var op *proxykit.OpError
	if !errors.As(e, &op) || op.Stage != proxykit.StageTargetTLS {
		t.Fatalf("TLS phase: %v", e)
	}
}

func TestCheckHTTPStatusRedirectAndTargetTLS(t *testing.T) {
	var hits atomic.Int32
	s, _ := connectProxy(t, false, "", "", &hits)
	var redirected atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(204)
		case "/redirect":
			http.Redirect(w, r, "/followed", 302)
		case "/followed":
			redirected.Add(1)
		default:
			w.WriteHeader(503)
		}
	}))
	defer origin.Close()
	r, e := proxykit.Check(context.Background(), s, proxykit.CheckOptions{URL: origin.URL + "/ok"})
	if e != nil || !r.OK || r.StatusCode != 204 {
		t.Fatalf("HTTP check: %+v %v", r, e)
	}
	r, e = proxykit.Check(context.Background(), s, proxykit.CheckOptions{URL: origin.URL + "/redirect"})
	if !errors.Is(e, proxykit.ErrStatus) || r.StatusCode != 302 || redirected.Load() != 0 {
		t.Fatal("redirect followed or status accepted")
	}
	r, e = proxykit.Check(context.Background(), s, proxykit.CheckOptions{URL: origin.URL + "/redirect", StatusCodes: []int{302}})
	if e != nil || !r.OK {
		t.Fatal("custom status rejected")
	}
	_, e = proxykit.Check(context.Background(), s, proxykit.CheckOptions{URL: origin.URL})
	var op *proxykit.OpError
	if !errors.As(e, &op) || op.Stage != proxykit.StageHTTP || op.StatusCode != 503 {
		t.Fatal("HTTP status phase lost")
	}
	tlsOrigin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer tlsOrigin.Close()
	_, e = proxykit.Check(context.Background(), s, proxykit.CheckOptions{URL: tlsOrigin.URL})
	if !errors.As(e, &op) || op.Stage != proxykit.StageTargetTLS {
		t.Fatalf("HTTPS failure stage: %v", e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(tlsOrigin.Certificate())
	r, e = proxykit.Check(context.Background(), s, proxykit.CheckOptions{URL: tlsOrigin.URL, TLSConfig: &tls.Config{RootCAs: roots}})
	if e != nil || !r.OK {
		t.Fatalf("HTTPS success: %v", e)
	}
}

func TestCheckTimeoutAndOptions(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer origin.Close()
	var hits atomic.Int32
	s, _ := connectProxy(t, false, "", "", &hits)
	_, e := proxykit.Check(context.Background(), s, proxykit.CheckOptions{URL: origin.URL, Timeout: 40 * time.Millisecond})
	if !proxykit.IsTimeout(e) {
		t.Fatalf("check timeout: %v", e)
	}
	for _, o := range []proxykit.CheckOptions{{}, {Target: "host:80", URL: "http://host"}, {URL: "ftp://host"}, {URL: "http://u:p@host"}, {URL: "http://host:0"}, {Target: "host:80", Timeout: -1}, {Target: "host:80", StatusCodes: []int{999}}} {
		if _, e = proxykit.Check(context.Background(), s, o); e == nil {
			t.Fatal("invalid check options accepted")
		}
	}
}

func TestDetectEveryProtocol(t *testing.T) {
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
			s.Protocol = proxykit.Auto
			r, e := proxykit.Detect(context.Background(), s, proxykit.DetectOptions{Target: echoTarget(t), Timeout: time.Second, DialOptions: proxykit.DialOptions{TLSConfig: cfg}})
			if e != nil || r.Proxy.Protocol != p || len(r.Attempts) != 3 {
				t.Fatalf("detect: %v %v", r.Proxy, e)
			}
			for _, a := range r.Attempts {
				if a.Duration <= 0 {
					t.Fatal("missing attempt timing")
				}
			}
		})
	}
}

func TestDetectionDoesNotConfuseHandshakeWithHealth(t *testing.T) {
	var hits atomic.Int32
	s, _ := connectProxy(t, false, "u", "p", &hits)
	s.Password = "wrong"
	s.Protocol = proxykit.Auto
	r, e := proxykit.Detect(context.Background(), s, proxykit.DetectOptions{Target: "target.test:443", Candidates: []proxykit.Protocol{proxykit.HTTP}})
	if !errors.Is(e, proxykit.ErrAuth) || r.Proxy.Protocol != "" {
		t.Fatalf("407 accepted as detected proxy: %v", e)
	}
	s = socksProxy(t, "u", "p", 5, nil)
	s.Protocol = proxykit.Auto
	_, e = proxykit.Detect(context.Background(), s, proxykit.DetectOptions{Target: "target.test:443", Candidates: []proxykit.Protocol{proxykit.SOCKS5}})
	if !errors.Is(e, proxykit.ErrRejected) {
		t.Fatalf("SOCKS greeting accepted without CONNECT: %v", e)
	}
	s.Password = "wrong"
	_, e = proxykit.Detect(context.Background(), s, proxykit.DetectOptions{Target: "target.test:443", Candidates: []proxykit.Protocol{proxykit.SOCKS5}})
	if !errors.Is(e, proxykit.ErrAuth) {
		t.Fatalf("SOCKS credentials not checked: %v", e)
	}
}

func TestDetectionCancelsAndClosesLosingAttempts(t *testing.T) {
	var live atomic.Int32
	addr := tcpFixture(t, func(c net.Conn) { live.Add(1); defer live.Add(-1); _, _ = io.Copy(io.Discard, c) })
	s := specFor(t, proxykit.Auto, addr)
	started := time.Now()
	_, e := proxykit.Detect(context.Background(), s, proxykit.DetectOptions{Target: "host.test:443", Timeout: 30 * time.Millisecond})
	if !proxykit.IsTimeout(e) || time.Since(started) > time.Second {
		t.Fatalf("detection timeout: %v", e)
	}
	deadline := time.Now().Add(time.Second)
	for live.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if live.Load() != 0 {
		t.Fatal("detection leaked sockets")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = proxykit.Detect(ctx, s, proxykit.DetectOptions{Target: "host.test:443"})
	if !errors.Is(e, context.Canceled) {
		t.Fatal("parent cancellation lost")
	}
}

func TestResolveExplicitDoesNotProbe(t *testing.T) {
	var calls atomic.Int32
	opts := proxykit.DetectOptions{DialOptions: proxykit.DialOptions{Forward: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("unexpected dial")
	}}}
	s, e := proxykit.Resolve(context.Background(), "https://host.test:443", proxykit.ParseOptions{}, opts)
	if e != nil || s.Protocol != proxykit.HTTPS || calls.Load() != 0 {
		t.Fatal("explicit protocol was probed/overridden")
	}
}

func TestBatchBoundsConcurrencyAndPreservesOrder(t *testing.T) {
	var active, maxSeen atomic.Int32
	forward := func(ctx context.Context, network, addr string) (net.Conn, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for {
			m := maxSeen.Load()
			if n <= m || maxSeen.CompareAndSwap(m, n) {
				break
			}
		}
		select {
		case <-time.After(5 * time.Millisecond):
			return nil, errors.New("fixture failure")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	specs := make([]proxykit.Spec, 20)
	for i := range specs {
		specs[i] = proxykit.Spec{Protocol: proxykit.HTTP, Host: "host.test", Port: i + 1, Username: "", Password: ""}
	}
	results, e := proxykit.CheckAll(context.Background(), specs, proxykit.BatchOptions{
		Check: proxykit.CheckOptions{Target: "target.test:443"},
		Dial:  proxykit.DialOptions{Forward: forward}, Concurrency: 3,
	})
	if e != nil || len(results) != len(specs) || maxSeen.Load() > 3 || maxSeen.Load() < 2 {
		t.Fatalf("concurrency: %d %v", maxSeen.Load(), e)
	}
	for i, r := range results {
		if r.Result.Proxy != specs[i] || r.Err == nil || r.Result.OK {
			t.Fatal("outcomes lost order/errors")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results, e = proxykit.CheckAll(ctx, specs, proxykit.BatchOptions{
		Check: proxykit.CheckOptions{Target: "target.test:443"}, Concurrency: 2,
	})
	if !errors.Is(e, context.Canceled) {
		t.Fatal("batch cancellation lost")
	}
	for _, r := range results {
		if !errors.Is(r.Err, context.Canceled) {
			t.Fatal("unstarted outcome missing cancellation")
		}
	}
}

func TestDialerResolvesAutoWithItsConfiguredRoute(t *testing.T) {
	var hits, forwarded atomic.Int32
	spec, _ := connectProxy(t, false, "u", "p", &hits)
	target := echoTarget(t)
	client, err := proxykit.New(context.Background(), spec.Address()+":u:p", proxykit.Options{
		Dial: proxykit.DialOptions{Forward: func(ctx context.Context, network, addr string) (net.Conn, error) {
			forwarded.Add(1)
			if addr != spec.Address() {
				t.Errorf("discovery route changed to %s", addr)
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}},
		Target: target, Candidates: []proxykit.Protocol{proxykit.HTTP},
	})
	if err != nil || client.Spec().Protocol != proxykit.HTTP {
		t.Fatalf("client discovery: %v", err)
	}
	result, err := client.Check(context.Background(), proxykit.CheckOptions{Target: target})
	if err != nil || !result.OK {
		t.Fatalf("resolved client check: %v", err)
	}
	conn, err := client.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	assertEcho(t, conn)
	if forwarded.Load() != 3 || hits.Load() != 3 {
		t.Fatalf("discovery/check/traffic route diverged: forwarded=%d hits=%d", forwarded.Load(), hits.Load())
	}
}
