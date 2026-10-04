package proxykit

import (
	"net"
	"net/url"
	"strings"
)

// Layout describes field order and separators in a proxy string. Use host and
// port once each, and optionally user/login/username and pass/password once each.
// ip is an alias for host. The @ separator is allowed only between host and port;
// all other fields use :. IPv6 fields must be bracketed. For example,
// Layout("port@host:pass:login") assigns all four fields explicitly.
type Layout string

const (
	LayoutAuto       Layout = ""
	HostPortUserPass Layout = "host:port:user:pass"
	UserPassHostPort Layout = "user:pass:host:port"
)

// ParseOptions supplies explicit defaults for otherwise underspecified inputs.
type ParseOptions struct {
	// DefaultProtocol assigns a known protocol to bare inputs. Zero means Auto.
	DefaultProtocol Protocol
	// Layout explicitly assigns fields in nonstandard formats. Zero uses common
	// conventions, then accepts other orders only if their assignment is unique.
	Layout Layout
}

// Parse parses one endpoint without guessing an absent wire protocol.
func Parse(raw string) (Spec, error) { return ParseWithOptions(raw, ParseOptions{}) }

// ParseWithOptions accepts standard URLs and fields separated by :; @ may
// separate host and port in compact inputs. A nonzero Layout
// defines field order and exact separators, including after a protocol prefix.
// Auto uses conventional host:port:user:pass and user:pass:host:port orders first.
// Other orders are accepted only when unambiguous, with user before password.
// URL credentials use percent escaping; explicit-layout credentials are literal.
func ParseWithOptions(raw string, opts ParseOptions) (Spec, error) {
	p, err := validateOptions(opts)
	if err != nil {
		return Spec{}, err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Spec{}, invalid("empty input")
	}
	body := raw
	prefixed := false
	if at := strings.Index(raw, "://"); at >= 0 {
		prefixed = true
		protocol, err := ParseProtocol(raw[:at])
		if err != nil {
			return Spec{}, err
		}
		if protocol != Auto {
			p = protocol
		}
		body = raw[at+3:]
	}
	if opts.Layout != LayoutAuto {
		layout, _ := parseLayout(opts.Layout) // Already validated before input parsing.
		return parseFields(body, p, layout)
	}
	// A valid URL has declared field roles. Never reinterpret failed credentials
	// on a valid authority as a different endpoint during automatic parsing.
	if prefixed {
		spec, urlErr := parseURL(raw, p)
		if urlErr == nil {
			return spec, nil
		}
		if at := strings.LastIndex(body, "@"); at >= 0 {
			if _, _, err := parseTarget(strings.TrimSuffix(body[at+1:], "/")); err == nil {
				return Spec{}, urlErr
			}
		}
		if strings.ContainsAny(body, "/?#%") {
			return Spec{}, urlErr
		}
	}
	return parseAutoFields(body, p)
}

func validateOptions(opts ParseOptions) (Protocol, error) {
	if opts.Layout != LayoutAuto {
		if _, err := parseLayout(opts.Layout); err != nil {
			return "", err
		}
	}
	return ParseProtocol(string(opts.DefaultProtocol))
}

func parseURL(raw string, defaultProtocol Protocol) (Spec, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Spec{}, invalid("URL syntax or escaping")
	}
	p, err := ParseProtocol(u.Scheme)
	if err != nil {
		return Spec{}, err
	}
	if p == Auto {
		p = defaultProtocol
	}
	if u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || u.Path != "" && u.Path != "/" {
		return Spec{}, invalid("URL must contain only a proxy authority")
	}
	host, n, err := parseTarget(u.Host)
	if err != nil {
		return Spec{}, invalid("URL requires an explicit port and bracketed IPv6")
	}
	s := Spec{Protocol: p, Host: host, Port: n}
	if u.User != nil {
		s.Username = u.User.Username()
		s.Password, _ = u.User.Password()
	}
	return validated(s)
}

func validated(s Spec) (Spec, error) {
	if err := s.Validate(); err != nil {
		return Spec{}, err
	}
	if net.ParseIP(s.Host) == nil {
		s.Host = strings.ToLower(s.Host)
	}
	return s, nil
}
