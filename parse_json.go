package proxykit

import (
	"encoding/json"
	"strings"
)

// ParseJSON accepts a string, Spec object or Telethon-style tuple
// [protocol, host, port, rdns, username, password]. Explicit local DNS (false)
// is rejected, since silently changing routing semantics is unsafe.
// null means no proxy in some applications; here it is an invalid
func ParseJSON(raw []byte, opts ParseOptions) (Spec, error) {
	if _, err := validateOptions(opts); err != nil {
		return Spec{}, err
	}
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return Spec{}, invalid("empty JSON")
	}
	switch raw[0] {
	case '"':
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return Spec{}, invalid("JSON string")
		}
		return ParseWithOptions(s, opts)
	case '{':
		var s Spec
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if dec.Decode(&s) != nil || !json.Valid(raw) {
			return Spec{}, invalid("JSON object")
		}
		p, e := ParseProtocol(string(s.Protocol))
		if e != nil {
			return Spec{}, e
		}
		if p == Auto {
			p, e = ParseProtocol(string(opts.DefaultProtocol))
			if e != nil {
				return Spec{}, e
			}
		}
		s.Protocol = p
		return validated(s)
	case '[':
		var parts []json.RawMessage
		if json.Unmarshal(raw, &parts) != nil || len(parts) < 3 || len(parts) > 6 {
			return Spec{}, invalid("JSON tuple length")
		}
		var p, h, u, pw string
		if json.Unmarshal(parts[0], &p) != nil || json.Unmarshal(parts[1], &h) != nil {
			return Spec{}, invalid("tuple protocol/host must be strings")
		}
		var n int
		if json.Unmarshal(parts[2], &n) != nil {
			var ns string
			if json.Unmarshal(parts[2], &ns) != nil {
				return Spec{}, invalid("tuple port")
			}
			var e error
			n, e = parsePort(ns)
			if e != nil {
				return Spec{}, e
			}
		}
		if len(parts) > 3 && string(parts[3]) != "null" {
			var rdns bool
			if json.Unmarshal(parts[3], &rdns) != nil || !rdns {
				return Spec{}, invalid("tuple requires remote DNS")
			}
		}
		if len(parts) > 4 && string(parts[4]) != "null" && json.Unmarshal(parts[4], &u) != nil {
			return Spec{}, invalid("tuple username")
		}
		if len(parts) > 5 && string(parts[5]) != "null" && json.Unmarshal(parts[5], &pw) != nil {
			return Spec{}, invalid("tuple password")
		}
		pr, e := ParseProtocol(p)
		if e != nil {
			return Spec{}, e
		}
		if pr == Auto {
			pr, e = ParseProtocol(string(opts.DefaultProtocol))
			if e != nil {
				return Spec{}, e
			}
		}
		return validated(Spec{Protocol: pr, Host: h, Port: n, Username: u, Password: pw})
	default:
		return Spec{}, invalid("expected JSON string, object or tuple")
	}
}
