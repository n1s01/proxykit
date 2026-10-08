package proxykit

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestExplicitLayoutsAllOrdersAndSeparators(t *testing.T) {
	// All 24 colon orders, the 12 orders with adjacent host/port joined by @, and
	// the 8 orders with @ between a credential pair and an endpoint pair.
	// Exercise DNS/IPv4/IPv6 and protocol prefixes. Numeric credentials ensure that field roles come from the layout.
	orders := permutations([]string{"host", "port", "login", "pass"})
	if len(orders) != 24 {
		t.Fatal("incomplete permutation fixture")
	}
	for _, host := range []string{"Proxy.Example", "192.0.2.1", "[2001:db8::1]"} {
		for _, prefix := range []string{"", "http://", "https://", "socks5://", "socks5h://", "auto://"} {
			for _, order := range orders {
				for mask := 0; mask < 8; mask++ {
					if !allowedLayoutMask(order, mask) {
						continue
					}
					layout, raw := layoutInput(order, mask, map[string]string{
						"host": host, "port": "1080", "login": "123", "pass": "456",
					})
					t.Run(fmt.Sprintf("%s/%s/%s", host, prefix, layout), func(t *testing.T) {
						wantProtocol := HTTP
						if prefix != "" && prefix != "auto://" {
							wantProtocol, _ = ParseProtocol(strings.TrimSuffix(prefix, "://"))
						}
						want := Spec{Protocol: wantProtocol, Host: strings.ToLower(strings.Trim(host, "[]")), Port: 1080, Username: "123", Password: "456"}
						spec, err := ParseWithOptions(prefix+raw, ParseOptions{
							Layout: Layout(layout), DefaultProtocol: HTTP,
						})
						if err != nil || spec != want {
							t.Fatalf("layout failed: %v", err)
						}
						round, err := Parse(spec.URL().String())
						if err != nil || round != want {
							t.Fatalf("normalized URL failed to round trip: %v", err)
						}
					})
				}
			}
		}
	}
}

func permutations(fields []string) [][]string {
	if len(fields) == 0 {
		return [][]string{{}}
	}
	var out [][]string
	for i, field := range fields {
		rest := append([]string(nil), fields[:i]...)
		rest = append(rest, fields[i+1:]...)
		for _, tail := range permutations(rest) {
			out = append(out, append([]string{field}, tail...))
		}
	}
	return out
}

// A single @ may join the adjacent endpoint fields or divide a credential pair
// from an endpoint pair.
func allowedLayoutMask(order []string, mask int) bool {
	if mask == 0 {
		return true
	}
	endpoint := func(field string) bool { return field == "host" || field == "port" }
	for i := 0; i+1 < len(order); i++ {
		if mask != 1<<i {
			continue
		}
		if endpoint(order[i]) && endpoint(order[i+1]) {
			return true
		}
		return i == 1 && endpoint(order[0]) == endpoint(order[1]) && endpoint(order[2]) == endpoint(order[3])
	}
	return false
}

func TestAtCannotSeparateCredentialFields(t *testing.T) {
	for _, order := range permutations([]string{"host", "port", "login", "pass"}) {
		for mask := 1; mask < 8; mask++ {
			if allowedLayoutMask(order, mask) {
				continue
			}
			layout, raw := layoutInput(order, mask, map[string]string{
				"host": "host.test", "port": "8080", "login": "u", "pass": "p",
			})
			if _, err := ParseWithOptions(raw, ParseOptions{Layout: Layout(layout)}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid @ layout accepted: %s", layout)
			}
		}
	}
	for _, raw := range []string{"u@p:host.test:8080", "host.test:8080:u@p", "host.test@8080@u@p", "u:p@host.test@8080"} {
		if _, err := Parse(raw); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid compact @ format accepted: %v", err)
		}
	}
}

func TestIPLayoutAlias(t *testing.T) {
	spec, err := ParseWithOptions("192.0.2.1@1080:secret:alice", ParseOptions{Layout: "ip@port:pass:login"})
	if err != nil || spec.Host != "192.0.2.1" || spec.Port != 1080 || spec.Username != "alice" || spec.Password != "secret" {
		t.Fatalf("ip alias: %v", err)
	}
}

func layoutInput(order []string, mask int, values map[string]string) (string, string) {
	var layout, raw strings.Builder
	for i, field := range order {
		if i > 0 {
			separator := byte(':')
			if mask&(1<<(i-1)) != 0 {
				separator = '@'
			}
			layout.WriteByte(separator)
			raw.WriteByte(separator)
		}
		layout.WriteString(field)
		raw.WriteString(values[field])
	}
	return layout.String(), raw.String()
}

func TestAutomaticLayoutsAndReverseEndpoint(t *testing.T) {
	for _, raw := range []string{
		"proxy.example:1080:login:pass",
		"login:pass:proxy.example:1080",
		"proxy.example@1080:login:pass",
		"login:pass:proxy.example@1080",
		"1080@proxy.example:login:pass",
		"proxy.example:login!:1080:pass!",
		"http://proxy.example@1080:login:pass",
	} {
		t.Run(raw, func(t *testing.T) {
			spec, err := Parse(raw)
			user, pass := "login", "pass"
			if strings.Contains(raw, "!") {
				user, pass = "login!", "pass!"
			}
			if err != nil || spec.Host != "proxy.example" || spec.Port != 1080 || spec.Username != user || spec.Password != pass {
				t.Fatalf("automatic format: %v", err)
			}
		})
	}
	for _, raw := range []string{"proxy.example:1080", "1080:proxy.example", "proxy.example@1080", "1080@proxy.example", "1080@[::1]", "http://1080:proxy.example"} {
		spec, err := Parse(raw)
		if err != nil || spec.Port != 1080 || spec.HasAuth() {
			t.Fatalf("two-field format failed: %v", err)
		}
	}
	for _, raw := range []string{"123:456", "login:proxy.example:1080:pass", "host:123:user:456"} {
		if _, err := Parse(raw); !errors.Is(err, ErrAmbiguous) {
			t.Fatalf("ambiguous fields were guessed: %v", err)
		}
	}
}

func TestAtDividesCredentialsFromEndpoint(t *testing.T) {
	for _, raw := range []string{
		"login:pass@proxy.example:1080",
		"proxy.example:1080@login:pass",
		"http://login:pass@proxy.example:1080",
	} {
		spec, err := Parse(raw)
		if err != nil || spec.Host != "proxy.example" || spec.Port != 1080 || spec.Username != "login" || spec.Password != "pass" {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	// The URL authority order wins when a numeric password makes both readings valid.
	spec, err := Parse("login:8080@host.test:3071")
	if err != nil || spec.Host != "host.test" || spec.Port != 3071 || spec.Username != "login" || spec.Password != "8080" {
		t.Fatalf("numeric password changed endpoint: %v", err)
	}
	spec, err = Parse("192.0.2.1:8080@login:pass")
	if err != nil || spec.Host != "192.0.2.1" || spec.Port != 8080 || spec.Username != "login" || spec.Password != "pass" {
		t.Fatalf("reversed credentials: %v", err)
	}
	spec, err = ParseWithOptions("secret:alice@[::1]:1080", ParseOptions{Layout: "pass:login@host:port"})
	if err != nil || spec.Host != "::1" || spec.Port != 1080 || spec.Username != "alice" || spec.Password != "secret" {
		t.Fatalf("explicit credential layout: %v", err)
	}
	specs, failures := ParseLines("j3q9jBNN:xBYEKEAf@dc01.proxy.example:3071\n0KHdNey2:3fphh1oy@dc04.proxy.example:3071", ParseOptions{})
	if len(specs) != 2 || len(failures) != 0 || specs[1].Host != "dc04.proxy.example" || specs[1].Username != "0KHdNey2" {
		t.Fatal("credential list was not parsed")
	}
}

func TestNumericCredentialsKeepEndpointWithAtSeparator(t *testing.T) {
	for _, raw := range []string{"host@80:login:90", "login:90:host@80", "http://host@80:login:90"} {
		spec, err := Parse(raw)
		if err != nil || spec.Host != "host" || spec.Port != 80 || spec.Username != "login" || spec.Password != "90" {
			t.Fatalf("numeric password changed endpoint: %v", err)
		}
	}
	spec, err := ParseWithOptions("host@80:90:login", ParseOptions{Layout: "host@port:pass:login"})
	if err != nil || spec.Host != "host" || spec.Port != 80 || spec.Username != "login" || spec.Password != "90" {
		t.Fatalf("explicit password order ignored: %v", err)
	}
}

func TestExplicitOptionalCredentialsAndAliases(t *testing.T) {
	cases := []struct {
		raw    string
		layout Layout
		user   string
		pass   string
	}{
		{"8080@host.test", "port@host", "", ""},
		{"host.test:8080:login", "host:port:username", "login", ""},
		{"secret:8080@host.test", "password:port@host", "", "secret"},
		{"secret:login:host.test@8080", "pass:user:host@port", "login", "secret"},
		{"host.test@8080::secret", "host@port:login:password", "", "secret"},
		{"host.test@8080:login:", "host@port:user:pass", "login", ""},
		{"host.test:8080:login:p%40ss", " HOST : PORT : LOGIN : PASSWORD ", "login", "p%40ss"},
	}
	for _, tc := range cases {
		spec, err := ParseWithOptions(tc.raw, ParseOptions{Layout: tc.layout, DefaultProtocol: HTTP})
		if err != nil || spec.Host != "host.test" || spec.Port != 8080 || spec.Username != tc.user || spec.Password != tc.pass {
			t.Fatalf("optional fields or aliases: %v", err)
		}
	}
}

func TestLayoutsRejectInvalidInputsWithoutExposingCredentials(t *testing.T) {
	for _, layout := range []Layout{"host", "host:login", "host:port:user:login", "host:port:pass:password", "host:port:unknown", "host:port:user:pass:extra", "host/port", "host::port"} {
		if _, err := ParseWithOptions("host.test:80", ParseOptions{Layout: layout}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid layout accepted: %v", err)
		}
	}
	for _, raw := range []string{
		"host.test@80:private-login:private-password", // Separator mismatch.
		"host.test:0:private-login:private-password",
		"[invalid]:80:private-login:private-password",
		"[::1]suffix:80:private-login:private-password",
		"[::1:80:private-login:private-password",
		"host.test:80:private-login:private-password:extra",
		"host.test:80:private-login:private-password\r\ninjected",
	} {
		_, err := ParseWithOptions(raw, ParseOptions{Layout: HostPortUserPass})
		if err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("invalid input accepted or credentials leaked")
		}
	}
	for _, raw := range []string{"socks4://host.test:80:p:u", "unknown://host.test:80:p:u"} {
		if _, err := ParseWithOptions(raw, ParseOptions{Layout: "host:port:pass:login"}); !errors.Is(err, ErrProtocol) {
			t.Fatal("unsupported protocol prefix ignored")
		}
	}
	// A failed URL credential validation must not become another format/endpoint.
	for _, raw := range []string{"http://u%3As:p@host:80", "http://u:se%ZZcret@host:80", "http://user:123@host:80/path", "socks5://:p@host:1080"} {
		if _, err := Parse(raw); err == nil {
			t.Fatal("failed URL was reinterpreted")
		}
	}
}

func TestLayoutsFlowThroughJSONAndLines(t *testing.T) {
	opts := ParseOptions{Layout: "pass:login:port@host", DefaultProtocol: HTTPS}
	want := Spec{Protocol: HTTPS, Host: "host.test", Port: 8080, Username: "u", Password: "p"}
	spec, err := ParseJSON([]byte(`"p:u:8080@host.test"`), opts)
	if err != nil || spec != want {
		t.Fatalf("JSON string layout: %v", err)
	}
	specs, failures := ParseLines("# list\np:u:8080@host.test\nbad", opts)
	if len(specs) != 1 || specs[0] != want || len(failures) != 1 || failures[0].Line != 3 {
		t.Fatal("line layout lost values or error positions")
	}
}

func FuzzParseWithLayout(f *testing.F) {
	for _, seed := range [][2]string{
		{"pass:login:port@host", "p:u:1080@[::1]"},
		{"host:port:pass:login", "host.test:80:p:u"},
		{"host@port", "host.test@80"},
		{"invalid", "\x00"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, layout, raw string) {
		spec, err := ParseWithOptions(raw, ParseOptions{Layout: Layout(layout)})
		if err != nil {
			return
		}
		if err := spec.Validate(); err != nil {
			t.Fatal("successful layout parse is invalid")
		}
		round, err := Parse(spec.URL().String())
		if err != nil || round != spec {
			t.Fatal("successful layout parse cannot round trip")
		}
	})
}
