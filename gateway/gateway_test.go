package gateway_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/n1s01/proxykit"
	"github.com/n1s01/proxykit/gateway"
)

func spec(username string) proxykit.Spec {
	return proxykit.Spec{Protocol: proxykit.HTTP, Host: "gw.example", Port: 6969, Username: username, Password: "secret"}
}

func TestSplit(t *testing.T) {
	ssid := gateway.Format{Country: "country", Session: "ssid"}
	tests := []struct {
		name   string
		format gateway.Format
		in     string
		base   string
		want   gateway.Params
	}{
		{"nova sticky", gateway.Nova, "acct1-country-RU-session-ab12cd34ef-time-1440", "acct1",
			gateway.Params{Country: "RU", Session: "ab12cd34ef", TTL: 24 * time.Hour}},
		{"nova rotating", gateway.Nova, "acct1-country-RU", "acct1", gateway.Params{Country: "RU"}},
		{"no tags", gateway.Nova, "acct1", "acct1", gateway.Params{}},
		{"custom session tag", ssid, "name_x-country-SI-ssid-G4h30cvPLL", "name_x",
			gateway.Params{Country: "SI", Session: "G4h30cvPLL"}},
		{"tag of another format is kept", ssid, "acct1-country-SI-session-zz", "acct1-session-zz",
			gateway.Params{Country: "SI"}},
		{"hyphenated base and unknown tag", gateway.Nova, "my-acct-city-moscow-country-RU-session-s1", "my-acct-city-moscow",
			gateway.Params{Country: "RU", Session: "s1"}},
		{"base equal to a tag", gateway.Nova, "country-country-RU", "country", gateway.Params{Country: "RU"}},
		{"value equal to a tag", gateway.Nova, "acct1-session-time-time-5", "acct1",
			gateway.Params{Session: "time", TTL: 5 * time.Minute}},
		{"separator and unit", gateway.Format{Separator: "_", Session: "sid", TTL: "life", TTLUnit: time.Second},
			"acct-1_sid_q7_life_90", "acct-1", gateway.Params{Session: "q7", TTL: 90 * time.Second}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, got, err := tt.format.Split(spec(tt.in))
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("params = %+v, want %+v", got, tt.want)
			}
			if want := spec(tt.base); base != want {
				t.Fatalf("base username = %q, want %q", base.Username, want.Username)
			}
			again, err := tt.format.Apply(base, got)
			if err != nil {
				t.Fatal(err)
			}
			if _, params, err := tt.format.Split(again); err != nil || params != got {
				t.Fatalf("round trip = %+v, %v", params, err)
			}
		})
	}
}

func TestApplyReplacesTags(t *testing.T) {
	sticky := spec("acct1-country-RU-session-old-time-1440")
	tests := []struct {
		name   string
		params gateway.Params
		want   string
	}{
		{"country only drops the session", gateway.Params{Country: "DE"}, "acct1-country-DE"},
		{"new session", gateway.Params{Country: "RU", Session: "new", TTL: 30 * time.Minute}, "acct1-country-RU-session-new-time-30"},
		{"session without ttl", gateway.Params{Session: "new"}, "acct1-session-new"},
		{"nothing", gateway.Params{}, "acct1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := gateway.Nova.Apply(sticky, tt.params)
			if err != nil {
				t.Fatal(err)
			}
			if want := spec(tt.want); got != want {
				t.Fatalf("username = %q, want %q", got.Username, tt.want)
			}
		})
	}
}

func TestApplyKeepsUnknownTokens(t *testing.T) {
	got, err := gateway.Nova.Apply(spec("my-acct-city-moscow-country-RU"), gateway.Params{Country: "DE", Session: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "my-acct-city-moscow-country-DE-session-s1"; got.Username != want {
		t.Fatalf("username = %q, want %q", got.Username, want)
	}
}

func TestInPassword(t *testing.T) {
	format := gateway.Format{Separator: "_", Country: "country", Session: "session", InPassword: true}
	in := proxykit.Spec{Protocol: proxykit.SOCKS5, Host: "gw.example", Port: 1080, Username: "acct", Password: "pw_country_us_session_s1"}
	base, params, err := format.Split(in)
	if err != nil {
		t.Fatal(err)
	}
	if base.Username != "acct" || base.Password != "pw" || params != (gateway.Params{Country: "us", Session: "s1"}) {
		t.Fatalf("base = %q/%q, params = %+v", base.Username, base.Password, params)
	}
	out, err := format.Apply(base, gateway.Params{Country: "fr"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Username != "acct" || out.Password != "pw_country_fr" {
		t.Fatalf("applied = %q/%q", out.Username, out.Password)
	}
}

func TestInvalid(t *testing.T) {
	long := proxykit.Spec{Protocol: proxykit.SOCKS5, Host: "gw.example", Port: 1080, Username: strings.Repeat("a", 250), Password: "secret"}
	tests := []struct {
		name string
		run  func() error
	}{
		{"repeated tag", func() error { _, _, err := gateway.Nova.Split(spec("a-country-RU-country-DE")); return err }},
		{"tag without value", func() error { _, _, err := gateway.Nova.Split(spec("a-country")); return err }},
		{"empty value", func() error { _, _, err := gateway.Nova.Split(spec("a-country--session-s1")); return err }},
		{"non-numeric ttl", func() error { _, _, err := gateway.Nova.Split(spec("a-session-s1-time-1h")); return err }},
		{"zero ttl", func() error { _, _, err := gateway.Nova.Split(spec("a-session-s1-time-0")); return err }},
		{"ttl overflow", func() error {
			_, _, err := gateway.Nova.Split(spec("a-session-s1-time-9223372036854775807"))
			return err
		}},
		{"apply over malformed tags", func() error {
			_, err := gateway.Nova.Apply(spec("a-country"), gateway.Params{Country: "RU"})
			return err
		}},
		{"ttl without session", func() error {
			_, err := gateway.Nova.Apply(spec("a"), gateway.Params{TTL: time.Hour})
			return err
		}},
		{"ttl not a multiple of the unit", func() error {
			_, err := gateway.Nova.Apply(spec("a"), gateway.Params{Session: "s1", TTL: 90 * time.Second})
			return err
		}},
		{"negative ttl", func() error {
			_, err := gateway.Nova.Apply(spec("a"), gateway.Params{Session: "s1", TTL: -time.Minute})
			return err
		}},
		{"value with separator", func() error {
			_, err := gateway.Nova.Apply(spec("a"), gateway.Params{Session: "s-1"})
			return err
		}},
		{"value with space", func() error {
			_, err := gateway.Nova.Apply(spec("a"), gateway.Params{Country: "R U"})
			return err
		}},
		{"parameter without a tag", func() error {
			_, err := gateway.Format{Country: "country"}.Apply(spec("a"), gateway.Params{Session: "s1"})
			return err
		}},
		{"no credentials", func() error {
			_, err := gateway.Nova.Apply(proxykit.Spec{Protocol: proxykit.HTTP, Host: "gw.example", Port: 6969}, gateway.Params{Country: "RU"})
			return err
		}},
		{"socks5 username limit", func() error {
			_, err := gateway.Nova.Apply(long, gateway.Params{Country: "RU"})
			return err
		}},
		{"format without tags", func() error { _, _, err := gateway.Format{}.Split(spec("a")); return err }},
		{"duplicate format tags", func() error {
			_, _, err := gateway.Format{Country: "x", Session: "x"}.Split(spec("a"))
			return err
		}},
		{"format tag with separator", func() error {
			_, _, err := gateway.Format{Session: "session-id"}.Split(spec("a"))
			return err
		}},
		{"negative unit", func() error {
			_, _, err := gateway.Format{TTL: "time", TTLUnit: -time.Second}.Split(spec("a"))
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if !errors.Is(err, proxykit.ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("error leaks credentials: %v", err)
			}
		})
	}
}

func TestNewSession(t *testing.T) {
	first, second := gateway.NewSession(), gateway.NewSession()
	if first == second {
		t.Fatalf("sessions repeat: %q", first)
	}
	for _, session := range []string{first, second} {
		if len(session) != 10 || strings.Trim(session, "abcdefghijklmnopqrstuvwxyz0123456789") != "" {
			t.Fatalf("session = %q", session)
		}
	}
}

func TestParsedLineToDialer(t *testing.T) {
	lines := []string{
		"gw.example:6969:acct1-country-RU-session-ab12cd34ef-time-1440:secret",
		"name_x-country-SI-session-G4h30cvPLL:secret:gw.example:17522",
	}
	for _, line := range lines {
		parsed, err := proxykit.ParseWithOptions(line, proxykit.ParseOptions{DefaultProtocol: proxykit.HTTP})
		if err != nil {
			t.Fatal(err)
		}
		_, params, err := gateway.Nova.Split(parsed)
		if err != nil || !params.Sticky() {
			t.Fatalf("params = %+v, %v", params, err)
		}
		params.Session = gateway.NewSession()
		rotated, err := gateway.Nova.Apply(parsed, params)
		if err != nil {
			t.Fatal(err)
		}
		dialer, err := proxykit.NewDialer(rotated, proxykit.DialOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if got := dialer.Spec().Username; !strings.Contains(got, "-session-"+params.Session) {
			t.Fatalf("username = %q", got)
		}
	}
}

func TestNew(t *testing.T) {
	ctx := context.Background()
	opts := proxykit.Options{Parse: proxykit.ParseOptions{DefaultProtocol: proxykit.SOCKS5}}
	d, err := gateway.Nova.New(ctx, "gw.example:6969:acct1:secret", gateway.Params{Country: "RU", TTL: 24 * time.Hour}, opts)
	if err != nil {
		t.Fatal(err)
	}
	got := d.Spec()
	_, params, err := gateway.Nova.Split(got)
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != proxykit.SOCKS5 || params.Country != "RU" || len(params.Session) != 10 || params.TTL != 24*time.Hour {
		t.Fatalf("spec = %v, params = %+v", got, params)
	}
	if want := "acct1-country-RU-session-" + params.Session + "-time-1440"; got.Username != want {
		t.Fatalf("username = %q, want %q", got.Username, want)
	}

	d, err = gateway.Nova.New(ctx, "http://acct1:secret@gw.example:6969", gateway.Params{Country: "DE"}, proxykit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Spec().URL().String(); got != "http://acct1-country-DE:secret@gw.example:6969" {
		t.Fatalf("url = %q", got)
	}

	if _, err = gateway.Nova.New(ctx, "gw.example:6969:acct1:secret", gateway.Params{Session: "s-1"}, opts); !errors.Is(err, proxykit.ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = gateway.Nova.New(canceled, "gw.example:6969:acct1:secret", gateway.Params{}, opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

// TestNewDetectsProtocol runs discovery with the tagged credentials against a
// loopback HTTP proxy that accepts only them.
func TestNewDetectsProtocol(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("acct1-country-RU-session-s1-time-30:secret"))
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				r := bufio.NewReader(c)
				status := "407 Proxy Authentication Required"
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimSpace(line)
					if line == "" {
						break
					}
					if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(name, "Proxy-Authorization") && strings.TrimSpace(value) == want {
						status = "200 Connection established"
					}
				}
				_, _ = c.Write([]byte("HTTP/1.1 " + status + "\r\n\r\n"))
			}()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d, err := gateway.Nova.New(ctx, "127.0.0.1:"+port+":acct1:secret",
		gateway.Params{Country: "RU", Session: "s1", TTL: 30 * time.Minute},
		proxykit.Options{Target: "target.example:443"})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Spec(); got.Protocol != proxykit.HTTP || got.Username != "acct1-country-RU-session-s1-time-30" {
		t.Fatalf("spec = %v, username = %q", got, got.Username)
	}
}

func Example() {
	parsed, _ := proxykit.Parse("http://acct1-country-RU-session-ab12cd34ef-time-1440:secret@gw.example:6969")

	base, params, _ := gateway.Nova.Split(parsed)
	fmt.Println(base.Username, params.Country, params.Session, params.TTL)

	sticky, _ := gateway.Nova.Apply(base, gateway.Params{Country: "DE", Session: "mysession1", TTL: 30 * time.Minute})
	fmt.Println(sticky.Username)

	rotating, _ := gateway.Nova.Apply(sticky, gateway.Params{Country: "DE"})
	fmt.Println(rotating.Username)
	// Output:
	// acct1 RU ab12cd34ef 24h0m0s
	// acct1-country-DE-session-mysession1-time-30
	// acct1-country-DE
}
