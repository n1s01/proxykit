package proxykit

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// Protocol describes the wire protocol used to reach a proxy.
type Protocol string

const (
	Auto   Protocol = "auto"
	HTTP   Protocol = "http"
	HTTPS  Protocol = "https"
	SOCKS5 Protocol = "socks5"
)

// Spec is a value; callers should treat it as immutable after constructing a Dialer.
// String and GoString redact credentials. URL and JSON intentionally contain them.
// SOCKS5 always sends target domain names to the proxy (remote DNS).
type Spec struct {
	Protocol Protocol `json:"protocol"`
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
}

func (s Spec) Address() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }
func (s Spec) HasAuth() bool   { return s.Username != "" || s.Password != "" }
func (s Spec) String() string {
	auth := ""
	if s.HasAuth() {
		auth = "REDACTED@"
	}
	return string(s.Protocol) + "://" + auth + s.Address()
}
func (s Spec) GoString() string { return s.String() }

// URL is an explicit credential-bearing export, suitable for clients accepting URLs.
func (s Spec) URL() *url.URL {
	u := &url.URL{Scheme: string(s.Protocol), Host: s.Address()}
	if s.HasAuth() {
		u.User = url.UserPassword(s.Username, s.Password)
	}
	return u
}

// ParseProtocol normalizes a scheme, including socks and socks5h aliases.
// An empty string means Auto; unknown schemes return ErrProtocol.
func ParseProtocol(raw string) (Protocol, error) {
	switch strings.ToLower(raw) {
	case "", "auto":
		return Auto, nil
	case "http":
		return HTTP, nil
	case "https":
		return HTTPS, nil
	case "socks", "socks5", "socks5h":
		return SOCKS5, nil
	default:
		return "", ErrProtocol
	}
}

func invalid(field string) error { return fmt.Errorf("%w: %s", ErrInvalid, field) }

// Validate permits Auto, but NewDialer requires a concrete protocol.
func (s Spec) Validate() error {
	if s.Protocol != Auto && s.Protocol != HTTP && s.Protocol != HTTPS && s.Protocol != SOCKS5 {
		return ErrProtocol
	}
	if err := validateHost(s.Host); err != nil {
		return err
	}
	if s.Port < 1 || s.Port > 65535 {
		return invalid("port must be in 1..65535")
	}
	if strings.ContainsAny(s.Username+s.Password, "\r\n\x00") {
		return invalid("control characters in credentials")
	}
	if s.HasAuth() && s.Protocol == SOCKS5 && (len(s.Username) < 1 || len(s.Username) > 255 || len(s.Password) < 1 || len(s.Password) > 255) {
		return invalid("SOCKS5 username and password must each be 1..255 bytes")
	}
	if s.HasAuth() && (s.Protocol == HTTP || s.Protocol == HTTPS) && strings.Contains(s.Username, ":") {
		return invalid("HTTP Basic username contains a colon")
	}
	return nil
}

func validateHost(host string) error {
	if host == "" || strings.ContainsAny(host, "[]/@?#%\\") || strings.IndexFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return invalid("host")
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return invalid("IPv6 address")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if len(host) > 253 {
		return invalid("host length")
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return invalid("DNS label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return invalid("host must be ASCII DNS or IP; convert IDNs to punycode")
			}
		}
	}
	return nil
}

func parsePort(raw string) (int, error) {
	if raw == "" {
		return 0, invalid("port")
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, invalid("port")
		}
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, invalid("port must be in 1..65535")
	}
	return n, nil
}
func parseTarget(addr string) (string, int, error) {
	h, p, e := net.SplitHostPort(addr)
	if e != nil {
		return "", 0, invalid("target requires host:port")
	}
	if strings.HasPrefix(addr, "[") && (net.ParseIP(h) == nil || !strings.Contains(h, ":")) {
		return "", 0, invalid("brackets require an IPv6 address")
	}
	if e = validateHost(h); e != nil {
		return "", 0, e
	}
	n, e := parsePort(p)
	return h, n, e
}
