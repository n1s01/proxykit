package proxykit

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// SpeedTestOptions configures a combined reachability and download-speed test
// of one HTTP endpoint reached through a proxy.
type SpeedTestOptions struct {
	// URL is the http(s) endpoint to download. It is required. Redirects are
	// deliberately not followed.
	URL string
	// TLSConfig controls TLS to the target. TLS to the proxy is configured on
	// the Dialer or with DialOptions.
	TLSConfig *tls.Config
	// Timeout bounds the whole test, including the body download. Zero uses
	// 15 seconds.
	Timeout time.Duration
	// StatusCodes defaults to 200..299.
	StatusCodes []int
	// MaxBytes caps the downloaded body. Zero uses 10 MiB. The endpoint should
	// return at least this much data for a meaningful measurement.
	MaxBytes int64
	// MaxDuration caps the body download separately from Timeout. Zero uses
	// 10 seconds. A partial measurement is still reported when time runs out.
	MaxDuration time.Duration
}

// SpeedResult reports the HTTP body read through the proxy.
type SpeedResult struct {
	Bytes             int64         `json:"bytes"`
	Duration          time.Duration `json:"duration"`
	BytesPerSecond    float64       `json:"bytes_per_second"`
	MegabitsPerSecond float64       `json:"megabits_per_second"`
	// Complete is true when the body ended or MaxBytes was reached. It is false
	// when MaxDuration or Timeout stopped the download early.
	Complete bool `json:"complete"`
}

// SpeedTestResult combines a health check with the measured download speed.
// Health contains credentials when marshaled as JSON, like CheckResult.
type SpeedTestResult struct {
	Health CheckResult `json:"health"`
	Speed  SpeedResult `json:"speed"`
}

// SpeedTest checks one proxy and measures download throughput from URL through
// it. It uses the default connection settings; construct a Dialer for custom
// routing, proxy TLS or VPN bypass, then call its SpeedTest method.
func SpeedTest(ctx context.Context, spec Spec, opts SpeedTestOptions) (SpeedTestResult, error) {
	d, err := NewDialer(spec, DialOptions{})
	if err != nil {
		return SpeedTestResult{Health: CheckResult{Proxy: spec}}, err
	}
	return d.SpeedTest(ctx, opts)
}

// SpeedTest measures health and download speed through the configured dialer.
// Health means a successful status response; Speed reads the body afterwards on
// the same tunnel. A speed failure still leaves Health.OK set when the headers
// arrived.
func (d *Dialer) SpeedTest(ctx context.Context, opts SpeedTestOptions) (SpeedTestResult, error) {
	if d == nil {
		return SpeedTestResult{}, invalid("nil speed test dialer")
	}
	return speedTest(ctx, d.spec, d, opts)
}

func speedTest(parent context.Context, s Spec, d ContextDialer, opts SpeedTestOptions) (result SpeedTestResult, err error) {
	if opts.URL == "" {
		return result, invalid("speed test requires URL")
	}
	if opts.Timeout < 0 {
		return result, invalid("negative speed test timeout")
	}
	if opts.MaxBytes < 0 {
		return result, invalid("negative speed test byte limit")
	}
	if opts.MaxDuration < 0 {
		return result, invalid("negative speed test duration")
	}
	maxBytes := opts.MaxBytes
	if maxBytes == 0 {
		maxBytes = 10 << 20
	}
	maxDuration := opts.MaxDuration
	if maxDuration == 0 {
		maxDuration = 10 * time.Second
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	checkOpts := CheckOptions{
		URL: opts.URL, TLSConfig: opts.TLSConfig,
		Timeout: timeout, StatusCodes: opts.StatusCodes,
	}
	result.Health, err = checkResponse(parent, s, d, checkOpts, func(resp *http.Response, conn net.Conn) error {
		var speedErr error
		result.Speed, speedErr = downloadSpeed(resp, conn, s.Protocol, maxBytes, maxDuration)
		return speedErr
	})
	return result, err
}

// downloadSpeed reads the body until EOF, maxBytes or the earlier of
// maxDuration and the request deadline. Partial results are returned on timeout.
func downloadSpeed(resp *http.Response, conn net.Conn, protocol Protocol, maxBytes int64, maxDuration time.Duration) (SpeedResult, error) {
	started := time.Now()
	deadline := started.Add(maxDuration)
	if requestDeadline, ok := resp.Request.Context().Deadline(); ok && requestDeadline.Before(deadline) {
		deadline = requestDeadline
	}
	if conn != nil {
		if e := conn.SetReadDeadline(deadline); e != nil {
			return SpeedResult{}, &OpError{Stage: StageHTTP, Protocol: protocol, Err: e}
		}
	}
	n, readErr := io.CopyN(io.Discard, resp.Body, maxBytes)
	elapsed := time.Since(started)
	result := SpeedResult{Bytes: n, Duration: elapsed}
	if elapsed > 0 {
		result.BytesPerSecond = float64(n) / elapsed.Seconds()
		result.MegabitsPerSecond = result.BytesPerSecond * 8 / 1e6
	}
	// io.EOF means the endpoint sent less than MaxBytes; nil means the cap was hit.
	if readErr == nil || errors.Is(readErr, io.EOF) {
		result.Complete = true
		return result, nil
	}
	if n > 0 && IsTimeout(readErr) {
		return result, nil
	}
	return result, &OpError{Stage: StageHTTP, Protocol: protocol, Err: readErr}
}
