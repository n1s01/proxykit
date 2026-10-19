package proxykit_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n1s01/proxykit"
)

func TestSpeedTestMeasuresHealthAndDownload(t *testing.T) {
	var hits atomic.Int32
	s, _ := connectProxy(t, false, "", "", &hits)
	const size = 256 << 10
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept-Encoding"); got != "identity" {
			t.Errorf("compressed speed test: %q", got)
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		_, _ = w.Write(make([]byte, size))
	}))
	defer origin.Close()

	result, err := proxykit.SpeedTest(context.Background(), s, proxykit.SpeedTestOptions{
		URL: origin.URL, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("speed test: %v", err)
	}
	if !result.Health.OK || result.Health.StatusCode != 200 || result.Health.TunnelLatency < 0 {
		t.Fatalf("health: %+v", result.Health)
	}
	if !result.Speed.Complete || result.Speed.Bytes != size {
		t.Fatalf("download: %+v", result.Speed)
	}
	if result.Speed.BytesPerSecond <= 0 || result.Speed.MegabitsPerSecond <= 0 || result.Speed.Duration <= 0 {
		t.Fatalf("missing throughput: %+v", result.Speed)
	}
}

func TestSpeedTestByteLimitStopsDownload(t *testing.T) {
	var hits atomic.Int32
	s, _ := connectProxy(t, false, "", "", &hits)
	const size, limit = 1 << 20, 64 << 10
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(size))
		_, _ = io.CopyN(w, zeroReader{}, size)
	}))
	defer origin.Close()

	result, err := proxykit.SpeedTest(context.Background(), s, proxykit.SpeedTestOptions{
		URL: origin.URL, MaxBytes: limit, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("limited speed test: %v", err)
	}
	if !result.Health.OK || !result.Speed.Complete || result.Speed.Bytes != limit {
		t.Fatalf("limit not applied: health=%+v speed=%+v", result.Health, result.Speed)
	}
}

func TestSpeedTestReportsPartialMeasurementOnTimeout(t *testing.T) {
	var hits atomic.Int32
	s, _ := connectProxy(t, false, "", "", &hits)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(1<<20))
		_, _ = w.Write(make([]byte, 32<<10))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer origin.Close()

	result, err := proxykit.SpeedTest(context.Background(), s, proxykit.SpeedTestOptions{
		URL: origin.URL, MaxBytes: 1 << 20, MaxDuration: 100 * time.Millisecond,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("partial speed test: %v", err)
	}
	if !result.Health.OK || result.Speed.Complete || result.Speed.Bytes == 0 || result.Speed.BytesPerSecond <= 0 {
		t.Fatalf("partial measurement: health=%+v speed=%+v", result.Health, result.Speed)
	}
}

func TestSpeedTestReportsHTTPFailureAsUnhealthy(t *testing.T) {
	var hits atomic.Int32
	s, _ := connectProxy(t, false, "", "", &hits)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer origin.Close()

	result, err := proxykit.SpeedTest(context.Background(), s, proxykit.SpeedTestOptions{URL: origin.URL})
	var op *proxykit.OpError
	if !errors.As(err, &op) || op.Stage != proxykit.StageHTTP || result.Health.OK || result.Speed.Bytes != 0 {
		t.Fatalf("unhealthy endpoint: %+v %+v %v", result.Health, result.Speed, err)
	}
}

func TestSpeedTestRejectsInvalidOptions(t *testing.T) {
	valid := proxykit.Spec{Protocol: proxykit.HTTP, Host: "proxy.test", Port: 80}
	for _, opts := range []proxykit.SpeedTestOptions{
		{},
		{URL: "http://target.test", Timeout: -1},
		{URL: "http://target.test", MaxBytes: -1},
		{URL: "http://target.test", MaxDuration: -1},
	} {
		if _, err := proxykit.SpeedTest(context.Background(), valid, opts); !errors.Is(err, proxykit.ErrInvalid) {
			t.Fatalf("invalid speed options accepted: %+v %v", opts, err)
		}
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { return len(p), nil }
