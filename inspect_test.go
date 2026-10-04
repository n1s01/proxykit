package proxykit_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n1s01/proxykit"
)

func TestInspectAutoReportsRealLatency(t *testing.T) {
	s := socksProxy(t, "u", "p", 0, nil)
	s.Protocol = proxykit.Auto
	const lookup = 300 * time.Millisecond
	info, e := proxykit.Inspect(context.Background(), s, proxykit.InspectOptions{
		Target: echoTarget(t),
		Geo: func(ctx context.Context, _ *http.Client) (proxykit.Geo, error) {
			time.Sleep(lookup)
			return proxykit.Geo{IP: "203.0.113.7", Country: "de"}, nil
		},
	})
	if e != nil || info.GeoErr != nil {
		t.Fatalf("inspect: %+v %v", info, e)
	}
	if info.Proxy.Protocol != proxykit.SOCKS5 || info.Country != "DE" || info.IP != "203.0.113.7" {
		t.Fatalf("protocol or geo: %+v", info)
	}
	if info.Latency < 0 || info.Latency >= lookup || info.Duration < lookup {
		t.Fatalf("latency includes other work: latency=%s duration=%s", info.Latency, info.Duration)
	}
}

func TestInspectGeoTravelsThroughProxy(t *testing.T) {
	var hits atomic.Int32
	s, _ := connectProxy(t, false, "u", "p", &hits)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "nl")
	}))
	defer origin.Close()
	d, e := proxykit.NewDialer(s, proxykit.DialOptions{})
	if e != nil {
		t.Fatal(e)
	}
	info, e := d.Inspect(context.Background(), proxykit.InspectOptions{
		Target: echoTarget(t),
		Geo: func(ctx context.Context, client *http.Client) (proxykit.Geo, error) {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL, nil)
			resp, e := client.Do(req)
			if e != nil {
				return proxykit.Geo{}, e
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return proxykit.Geo{Country: string(b)}, nil
		},
	})
	if e != nil || info.GeoErr != nil || info.Country != "NL" || info.Latency < 0 {
		t.Fatalf("inspect: %+v %v %v", info, info.GeoErr, e)
	}
	if hits.Load() != 2 {
		t.Fatalf("expected latency and geo tunnels through the proxy, got %d", hits.Load())
	}
}

func TestInspectGeoFailureAndSkip(t *testing.T) {
	var hits atomic.Int32
	s, _ := connectProxy(t, false, "", "", &hits)
	target := echoTarget(t)
	info, e := proxykit.Inspect(context.Background(), s, proxykit.InspectOptions{
		Target: target,
		Geo: func(context.Context, *http.Client) (proxykit.Geo, error) {
			return proxykit.Geo{}, errors.New("service down")
		},
	})
	var op *proxykit.OpError
	if e != nil || !errors.As(info.GeoErr, &op) || op.Stage != proxykit.StageGeo || info.Country != "" || info.Latency < 0 {
		t.Fatalf("geo failure must not fail inspect: %+v %v %v", info, info.GeoErr, e)
	}
	called := false
	info, e = proxykit.Inspect(context.Background(), s, proxykit.InspectOptions{
		Target: target, SkipGeo: true,
		Geo: func(context.Context, *http.Client) (proxykit.Geo, error) { called = true; return proxykit.Geo{}, nil },
	})
	if e != nil || called || info.GeoErr != nil {
		t.Fatalf("SkipGeo: %+v %v", info, e)
	}
	_, e = proxykit.Inspect(context.Background(), s, proxykit.InspectOptions{Target: target, GeoTimeout: -1})
	if !errors.Is(e, proxykit.ErrInvalid) {
		t.Fatalf("negative geo timeout: %v", e)
	}
}

func TestInspectUnreachable(t *testing.T) {
	s := socksProxy(t, "", "", 5, nil)
	called := false
	geo := func(context.Context, *http.Client) (proxykit.Geo, error) { called = true; return proxykit.Geo{}, nil }
	info, e := proxykit.Inspect(context.Background(), s, proxykit.InspectOptions{Target: "192.0.2.1:443", Geo: geo})
	if !errors.Is(e, proxykit.ErrRejected) || info.Latency != 0 || called {
		t.Fatalf("explicit: %+v %v", info, e)
	}
	s.Protocol = proxykit.Auto
	info, e = proxykit.Inspect(context.Background(), s, proxykit.InspectOptions{Target: "192.0.2.1:443", Geo: geo, Timeout: 2 * time.Second})
	var de *proxykit.DetectionError
	if !errors.As(e, &de) || info.Proxy.Protocol != proxykit.Auto || info.Latency != 0 || called {
		t.Fatalf("auto: %+v %v", info, e)
	}
	if _, e = proxykit.Inspect(context.Background(), s, proxykit.InspectOptions{}); !errors.Is(e, proxykit.ErrInvalid) {
		t.Fatalf("missing target: %v", e)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestIPWhoIs(t *testing.T) {
	reply := func(code int, body string) *http.Client {
		return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://ipwho.is/" {
				t.Fatalf("unexpected URL %s", r.URL)
			}
			return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		})}
	}
	geo, e := proxykit.IPWhoIs(context.Background(), reply(200, `{"success":true,"ip":"203.0.113.7","country_code":"fr"}`))
	if e != nil || geo.IP != "203.0.113.7" || geo.Country != "FR" {
		t.Fatalf("geo: %+v %v", geo, e)
	}
	if _, e = proxykit.IPWhoIs(context.Background(), reply(200, `{"success":false}`)); !errors.Is(e, proxykit.ErrInvalid) {
		t.Fatalf("unsuccessful lookup: %v", e)
	}
	if _, e = proxykit.IPWhoIs(context.Background(), reply(503, ``)); !errors.Is(e, proxykit.ErrStatus) {
		t.Fatalf("status: %v", e)
	}
}
