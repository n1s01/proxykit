package proxykit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Geo is the exit address of a proxy as seen by a geolocation service.
type Geo struct {
	IP string `json:"ip,omitempty"`
	// Country is an upper-case ISO 3166-1 alpha-2 code.
	Country string `json:"country,omitempty"`
}

// GeoFunc looks up the exit address. Every request made with client travels
// through the inspected proxy, so the service sees what the target would see.
type GeoFunc func(ctx context.Context, client *http.Client) (Geo, error)

// InspectOptions selects what Inspect measures and where.
type InspectOptions struct {
	// Target is the host:port used for protocol discovery and Latency. Pick
	// the host the application will actually reach through the proxy.
	Target string
	// Timeout bounds discovery and the latency measurement; zero uses 10 seconds.
	Timeout time.Duration
	// Candidates selects discovery protocols for Auto; nil tries SOCKS5, HTTP, HTTPS.
	Candidates []Protocol
	// Dial controls connections to the proxy. Dialer.Inspect ignores it, along
	// with Candidates: the dialer is already resolved and configured.
	Dial DialOptions
	// Geo defaults to IPWhoIs, the only request the library sends to a third
	// party on its own. SkipGeo disables the lookup entirely.
	Geo     GeoFunc
	SkipGeo bool
	// GeoTimeout bounds the lookup separately from Timeout; zero uses 5 seconds.
	GeoTimeout time.Duration
}

// Info is everything Inspect learned about one proxy. Proxy contains
// credentials when marshaled as JSON; durations encode as nanoseconds.
type Info struct {
	// Proxy has a concrete protocol once discovery succeeded.
	Proxy     Spec      `json:"proxy"`
	Target    string    `json:"target"`
	StartedAt time.Time `json:"started_at"`
	// Latency is the time one tunnel to Target took: TCP to the proxy, proxy
	// TLS, authentication and CONNECT. Discovery of the other protocols and
	// the geolocation lookup are never part of it.
	Latency time.Duration `json:"latency"`
	Geo
	// GeoErr reports a failed lookup. A proxy without a known country is still
	// usable, so it does not fail Inspect.
	GeoErr error `json:"-"`
	// Duration covers the whole inspection, including the geolocation lookup.
	Duration time.Duration `json:"duration"`
}

// Inspect resolves the protocol when it is Auto, measures the tunnel latency to
// Target and looks up the exit country. An error means the proxy could not
// open a tunnel to Target; Info still carries what was learned before it.
func Inspect(ctx context.Context, spec Spec, opts InspectOptions) (Info, error) {
	started := time.Now()
	info := Info{Proxy: spec, Target: opts.Target, StartedAt: started.UTC()}
	if spec.Protocol != Auto {
		d, err := NewDialer(spec, opts.Dial)
		if err != nil {
			info.Duration = time.Since(started)
			return info, err
		}
		return d.Inspect(ctx, opts)
	}
	found, err := Detect(ctx, spec, DetectOptions{
		Target: opts.Target, Candidates: opts.Candidates,
		Timeout: opts.Timeout, DialOptions: opts.Dial,
	})
	if err == nil {
		var d *Dialer
		if d, err = NewDialer(found.Proxy, opts.Dial); err == nil {
			info.Proxy = found.Proxy
			// The winning attempt already is one clean tunnel to Target.
			for _, attempt := range found.Attempts {
				if attempt.Protocol == found.Proxy.Protocol {
					info.Latency = attempt.Duration
				}
			}
			err = d.geo(ctx, &info, opts)
		}
	}
	info.Duration = time.Since(started)
	return info, err
}

// Inspect measures latency and exit country through the configured dialer.
func (d *Dialer) Inspect(ctx context.Context, opts InspectOptions) (Info, error) {
	if d == nil {
		return Info{}, invalid("nil inspect dialer")
	}
	started := time.Now()
	info := Info{Proxy: d.spec, Target: opts.Target, StartedAt: started.UTC()}
	result, err := d.Check(ctx, CheckOptions{Target: opts.Target, Timeout: opts.Timeout})
	info.Latency = result.TunnelLatency
	if err == nil {
		err = d.geo(ctx, &info, opts)
	} else {
		info.Latency = 0
	}
	info.Duration = time.Since(started)
	return info, err
}

// geo fills the exit address. Only cancellation of the caller's context is
// returned as an error; lookup failures land in Info.GeoErr.
func (d *Dialer) geo(parent context.Context, info *Info, opts InspectOptions) error {
	if opts.SkipGeo {
		return parent.Err()
	}
	if opts.GeoTimeout < 0 {
		return invalid("negative geo timeout")
	}
	timeout := opts.GeoTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	lookup := opts.Geo
	if lookup == nil {
		lookup = IPWhoIs
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	tr := d.Transport()
	defer tr.CloseIdleConnections()
	geo, err := lookup(ctx, &http.Client{Transport: tr})
	if e := parent.Err(); e != nil {
		return e
	}
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		info.GeoErr = &OpError{Stage: StageGeo, Protocol: d.spec.Protocol, Err: err}
		return nil
	}
	geo.Country = strings.ToUpper(geo.Country)
	info.Geo = geo
	return nil
}

// IPWhoIs is the default GeoFunc. It asks https://ipwho.is/ through the proxy.
func IPWhoIs(ctx context.Context, client *http.Client) (Geo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipwho.is/", nil)
	if err != nil {
		return Geo{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Geo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Geo{}, fmt.Errorf("%w: %d", ErrStatus, resp.StatusCode)
	}
	var data struct {
		Success     bool   `json:"success"`
		IP          string `json:"ip"`
		CountryCode string `json:"country_code"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&data); err != nil {
		return Geo{}, err
	}
	if !data.Success || len(data.CountryCode) != 2 || net.ParseIP(data.IP) == nil {
		return Geo{}, invalid("geolocation response")
	}
	return Geo{IP: data.IP, Country: strings.ToUpper(data.CountryCode)}, nil
}
