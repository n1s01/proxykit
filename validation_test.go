package proxykit

import (
	"errors"
	"testing"
)

func TestStructuredEndpointsEnforceProtocolConstraints(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
		want error
	}{
		{"unresolved configuration is representable", Spec{Protocol: Auto, Host: "host.test", Port: 80}, nil},
		{"unknown protocol", Spec{Protocol: "other", Host: "host.test", Port: 80}, ErrProtocol},
		{"empty host", Spec{Protocol: HTTP, Port: 80}, ErrInvalid},
		{"port out of range", Spec{Protocol: HTTP, Host: "host.test", Port: 65536}, ErrInvalid},
		{"HTTP user colon", Spec{Protocol: HTTP, Host: "host.test", Port: 80, Username: "a:b", Password: "p"}, ErrInvalid},
		{"SOCKS missing password", Spec{Protocol: SOCKS5, Host: "host.test", Port: 1080, Username: "u"}, ErrInvalid},
		{"password control character", Spec{Protocol: HTTP, Host: "host.test", Port: 80, Password: "p\r\n"}, ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.spec.Validate()
			if !errors.Is(err, tc.want) {
				t.Fatalf("validation: got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestTargetsRejectHeaderInjection(t *testing.T) {
	for _, raw := range []string{"target.test:443\r\nInjected: yes", "target.test:0", "target.test:65536", "target.test", "[invalid]:80"} {
		if _, _, err := parseTarget(raw); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid target accepted: %v", err)
		}
	}
	host, port, err := parseTarget("[2001:db8::1]:443")
	if err != nil || host != "2001:db8::1" || port != 443 {
		t.Fatalf("valid IPv6 target: %s %d %v", host, port, err)
	}
}
