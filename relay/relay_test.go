package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/n1s01/proxykit"
)

type dialFunc func(context.Context, string, string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

func TestRelayWorksWithIndependentTunnelImplementation(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer origin.Close()
	originURL, _ := url.Parse(origin.URL)
	dialer := dialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != originURL.Host {
			t.Errorf("relay changed target to %s", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	})
	relay, err := Start(dialer, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	proxyURL, _ := url.Parse(relay.URL())
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Second}
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatal("relay failed to adapt injected tunnel")
	}
}

func TestRelayRejectsAbsentDependency(t *testing.T) {
	if _, err := Start(nil, Options{}); !errors.Is(err, proxykit.ErrInvalid) {
		t.Fatalf("nil dependency was accepted: %v", err)
	}
	var dialer *proxykit.Dialer
	if _, err := Start(dialer, Options{}); !errors.Is(err, proxykit.ErrInvalid) {
		t.Fatalf("typed nil dependency was accepted: %v", err)
	}
}

func TestConnectHandlesInvalidDialerResults(t *testing.T) {
	t.Run("nil connection", func(t *testing.T) {
		r := &Server{dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, nil
		})}
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodConnect, "/", nil)
		req.Host = "target.test:443"
		r.connect(w, req)
		if w.Code != http.StatusBadGateway {
			t.Fatalf("invalid upstream result: status %d", w.Code)
		}
	})
	t.Run("connection with error", func(t *testing.T) {
		conn, peer := net.Pipe()
		defer peer.Close()
		r := &Server{dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
			return conn, errors.New("upstream failure")
		})}
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodConnect, "/", nil)
		req.Host = "target.test:443"
		r.connect(w, req)
		if w.Code != http.StatusBadGateway {
			t.Fatalf("failed upstream result: status %d", w.Code)
		}
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, err := peer.Read(b[:]); !errors.Is(err, io.EOF) {
			t.Fatalf("failed upstream connection was not closed: %v", err)
		}
	})
}
