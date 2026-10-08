package proxykit

import (
	"net"
	"strings"
)

type proxyField uint8

const (
	fieldHost proxyField = iota
	fieldPort
	fieldUser
	fieldPass
)

type fieldLayout struct {
	fields     []proxyField
	separators []byte
}

// parseLayout validates a tiny declarative format, not a regular expression.
func parseLayout(layout Layout) (fieldLayout, error) {
	words, separators, err := splitFields(string(layout))
	if err != nil {
		return fieldLayout{}, invalid("layout syntax")
	}
	out := fieldLayout{separators: separators}
	seen := [4]bool{}
	for _, word := range words {
		var field proxyField
		switch strings.ToLower(strings.TrimSpace(word)) {
		case "host", "ip":
			field = fieldHost
		case "port":
			field = fieldPort
		case "user", "username", "login":
			field = fieldUser
		case "pass", "password":
			field = fieldPass
		default:
			return fieldLayout{}, invalid("unknown layout field")
		}
		if seen[field] {
			return fieldLayout{}, invalid("duplicate layout field")
		}
		seen[field] = true
		out.fields = append(out.fields, field)
	}
	if !seen[fieldHost] || !seen[fieldPort] {
		return fieldLayout{}, invalid("layout requires host and port")
	}
	if !validSeparators(out.fields, separators) {
		return fieldLayout{}, invalid("@ must separate host and port, or credentials and endpoint")
	}
	return out, nil
}

// validSeparators allows a single @, either joining the endpoint pair or
// dividing a credential pair from an adjacent host and port.
func validSeparators(fields []proxyField, separators []byte) bool {
	at := -1
	for i, separator := range separators {
		if separator != '@' {
			continue
		}
		if at >= 0 {
			return false
		}
		at = i
	}
	if at < 0 {
		return true
	}
	if isEndpoint(fields[at]) && isEndpoint(fields[at+1]) {
		return true
	}
	return at == 1 && len(fields) == 4 &&
		isEndpoint(fields[0]) == isEndpoint(fields[1]) && isEndpoint(fields[2]) == isEndpoint(fields[3])
}

func isEndpoint(field proxyField) bool { return field == fieldHost || field == fieldPort }

// splitFields bounds allocations and keeps bracketed IPv6 addresses intact.
// Empty credentials are meaningful, so fields are not trimmed or discarded.
func splitFields(raw string) ([]string, []byte, error) {
	fields := make([]string, 0, 4)
	separators := make([]byte, 0, 3)
	start := 0
	bracket := false
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '[':
			if i == start {
				bracket = true
			}
		case ']':
			if bracket {
				bracket = false
				if i+1 < len(raw) && raw[i+1] != ':' && raw[i+1] != '@' {
					return nil, nil, invalid("characters after bracketed field")
				}
			}
		case ':', '@':
			if bracket {
				continue
			}
			if len(separators) == 3 {
				return nil, nil, invalid("expected two to four proxy fields")
			}
			fields = append(fields, raw[start:i])
			separators = append(separators, raw[i])
			start = i + 1
		}
	}
	if bracket {
		return nil, nil, invalid("unclosed bracketed field")
	}
	fields = append(fields, raw[start:])
	if len(fields) < 2 {
		return nil, nil, invalid("expected two to four proxy fields")
	}
	return fields, separators, nil
}

func fieldSpec(values []string, fields []proxyField, protocol Protocol) (Spec, error) {
	spec := Spec{Protocol: protocol}
	for i, field := range fields {
		value := values[i]
		switch field {
		case fieldHost:
			if strings.HasPrefix(value, "[") {
				if !strings.HasSuffix(value, "]") {
					return Spec{}, invalid("bracketed host")
				}
				value = value[1 : len(value)-1]
				if net.ParseIP(value) == nil || !strings.Contains(value, ":") {
					return Spec{}, invalid("brackets require an IPv6 address")
				}
			} else if strings.Contains(value, ":") {
				return Spec{}, invalid("IPv6 requires brackets")
			}
			spec.Host = value
		case fieldPort:
			port, err := parsePort(value)
			if err != nil {
				return Spec{}, err
			}
			spec.Port = port
		case fieldUser:
			spec.Username = value
		case fieldPass:
			spec.Password = value
		}
	}
	return validated(spec)
}

func parseFields(raw string, protocol Protocol, layout fieldLayout) (Spec, error) {
	values, separators, err := splitFields(raw)
	if err != nil {
		return Spec{}, err
	}
	if len(values) != len(layout.fields) || string(separators) != string(layout.separators) {
		return Spec{}, invalid("input does not match layout")
	}
	return fieldSpec(values, layout.fields, protocol)
}

func parseAutoFields(raw string, protocol Protocol) (Spec, error) {
	if ip := net.ParseIP(raw); ip != nil && strings.Contains(raw, ":") {
		return Spec{}, invalid("IPv6 requires brackets and a port")
	}
	values, separators, err := splitFields(raw)
	if err != nil {
		return Spec{}, err
	}
	var candidates []Spec
	add := func(fields []proxyField) {
		if !validSeparators(fields, separators) {
			return
		}
		spec, err := fieldSpec(values, fields, protocol)
		if err != nil {
			return
		}
		for _, existing := range candidates {
			if existing == spec {
				return
			}
		}
		candidates = append(candidates, spec)
	}
	if len(values) == 4 {
		// user:pass@host:port is the URL authority order, so it wins over the
		// reversed host:port@user:pass reading when both happen to be valid.
		if separators[1] == '@' {
			add([]proxyField{fieldUser, fieldPass, fieldHost, fieldPort})
			if len(candidates) == 1 {
				return candidates[0], nil
			}
		}
		// Keep conventional field orders.
		add([]proxyField{fieldHost, fieldPort, fieldUser, fieldPass})
		add([]proxyField{fieldUser, fieldPass, fieldHost, fieldPort})
		if len(candidates) > 0 {
			return uniqueSpec(candidates)
		}
	}
	// Outside conventional formats, enumerate endpoint positions without guessing
	// from port numbers or credential spelling. Remaining credentials follow input
	// order (user, then password); a different order requires an explicit Layout.
	for host := range values {
		for port := range values {
			if host == port {
				continue
			}
			fields := make([]proxyField, len(values))
			credential := fieldUser
			for i := range values {
				switch i {
				case host:
					fields[i] = fieldHost
				case port:
					fields[i] = fieldPort
				default:
					fields[i] = credential
					credential = fieldPass
				}
			}
			add(fields)
		}
	}
	return uniqueSpec(candidates)
}

func uniqueSpec(candidates []Spec) (Spec, error) {
	switch len(candidates) {
	case 0:
		return Spec{}, invalid("proxy fields; specify a layout")
	case 1:
		return candidates[0], nil
	default:
		return Spec{}, ErrAmbiguous
	}
}
