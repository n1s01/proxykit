package proxykit

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseFormats(t *testing.T) {
	cases := []struct {
		raw  string
		want Spec
	}{
		{"host.test:8080", Spec{Protocol: Auto, Host: "host.test", Port: 8080, Username: "", Password: ""}},
		{"user:pass:HOST.test@3128", Spec{Protocol: Auto, Host: "host.test", Port: 3128, Username: "user", Password: "pass"}},
		{"host.test:3128:user:pass", Spec{Protocol: Auto, Host: "host.test", Port: 3128, Username: "user", Password: "pass"}},
		{"user:pass:host.test:3128", Spec{Protocol: Auto, Host: "host.test", Port: 3128, Username: "user", Password: "pass"}},
		{"HTTP://user:p%40ss%3A%2F%25@host.test:3128/", Spec{Protocol: HTTP, Host: "host.test", Port: 3128, Username: "user", Password: "p@ss:/%"}},
		{"socks5h://[2001:db8::1]:1080", Spec{Protocol: SOCKS5, Host: "2001:db8::1", Port: 1080, Username: "", Password: ""}},
		{"[::1]:1080", Spec{Protocol: Auto, Host: "::1", Port: 1080, Username: "", Password: ""}},
		{"https://u:p@[::1]:8443", Spec{Protocol: HTTPS, Host: "::1", Port: 8443, Username: "u", Password: "p"}},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			s, e := Parse(tc.raw)
			if e != nil || s != tc.want {
				t.Fatalf("got %v, %v; want %v", s, e, tc.want)
			}
			round, e := Parse(s.URL().String())
			if e != nil || round != s {
				t.Fatalf("URL round trip: %v", e)
			}
		})
	}
}

func TestParseRejectsInvalidAndAmbiguous(t *testing.T) {
	for _, raw := range []string{"", "null", "http://host:0", "http://host:65536", "http://:80", "http://host:-1", "ftp://host:80", "socks4://host:80", "http://host", "http://host:80/path", "http://host:80?x=1", "http://host:80#x", "http://u:se%ZZcret@host:80", "http://ho st:80", "http://host:80\r\nX: y", "http://u%3As:p@host:80", "socks5://:p@host:1080", "socks5://u:@host:1080", "2001:db8::1:80", "http://[invalid]:80", "[invalid]:80"} {
		t.Run(raw, func(t *testing.T) {
			if _, e := Parse(raw); e == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
	if _, e := Parse("host:123:user:456"); !errors.Is(e, ErrAmbiguous) {
		t.Fatalf("expected ambiguity, got %v", e)
	}
	s, e := ParseWithOptions("host:123:user:456", ParseOptions{DefaultProtocol: HTTP, Layout: HostPortUserPass})
	if e != nil || s.Host != "host" || s.Port != 123 || s.Password != "456" || s.Protocol != HTTP {
		t.Fatalf("explicit layout: %v %v", s, e)
	}
	s, e = ParseWithOptions("host:123:user:456", ParseOptions{Layout: UserPassHostPort})
	if e != nil || s.Host != "user" || s.Port != 456 || s.Password != "123" {
		t.Fatalf("reverse layout: %v %v", s, e)
	}
	if _, e = Parse("socks5://" + strings.Repeat("u", 256) + ":p@host:80"); e == nil {
		t.Fatal("accepted oversized auth")
	}
}

func TestJSON(t *testing.T) {
	for _, raw := range []string{`"socks5://u:p@host:1080"`, `["socks5","host",1080,true,"u","p"]`, `["socks5h","host","1080",null,"u","p"]`, `{"protocol":"socks5","host":"host","port":1080,"username":"u","password":"p"}`} {
		s, e := ParseJSON([]byte(raw), ParseOptions{})
		if e != nil || s != (Spec{Protocol: SOCKS5, Host: "host", Port: 1080, Username: "u", Password: "p"}) {
			t.Fatalf("JSON: %v %v", s, e)
		}
	}
	for _, raw := range []string{`null`, `[]`, `["http","host",1.5]`, `["http","host",-1]`, `["socks5","host",1080,false]`, `["http","host",80,true,42]`, `{"host":"host","port":80,"unknown":true}`, `{"host":"host","port":80} {}`, `["http","host",80,true,"u","p",7]`} {
		if _, e := ParseJSON([]byte(raw), ParseOptions{}); e == nil {
			t.Fatalf("accepted JSON %s", raw)
		}
	}
	s, e := ParseJSON([]byte(`{"host":"host","port":80}`), ParseOptions{DefaultProtocol: HTTPS})
	if e != nil || s.Protocol != HTTPS {
		t.Fatal("JSON default protocol lost")
	}
}

func TestNoSecretInFormattingOrErrors(t *testing.T) {
	s := Spec{Protocol: HTTP, Host: "host", Port: 80, Username: "private-user", Password: "private-password"}
	for _, text := range []string{fmt.Sprint(s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s)} {
		if strings.Contains(text, s.Username) || strings.Contains(text, s.Password) {
			t.Fatal("credential leak")
		}
	}
	_, e := Parse("http://private-user:private-password@host:bad")
	if e == nil || strings.Contains(e.Error(), "private") {
		t.Fatal("parse error leaked input")
	}
	op := &OpError{Stage: StageAuth, Protocol: HTTP, Err: errors.New("private-password")}
	if strings.Contains(op.Error(), "private") {
		t.Fatal("operation error leaked cause")
	}
	specs, errs := ParseLines("# comment\r\nhost:80\r\n\nbad\nhost:80", ParseOptions{})
	if len(specs) != 2 || len(errs) != 1 || errs[0].Line != 4 {
		t.Fatal("line import contract")
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"host:80", "socks5://u:p@[::1]:1080", "host:1:user:2", "http://u:p%40x@host:80", "host:80@u:p", "host@80@u@p", "80@[::1]", "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		s, e := Parse(raw)
		if e != nil {
			return
		}
		if e = s.Validate(); e != nil {
			t.Fatal(e)
		}
		round, e := Parse(s.URL().String())
		if e != nil || round != s {
			t.Fatal("successful parse cannot round trip")
		}
	})
}
