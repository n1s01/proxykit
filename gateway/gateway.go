package gateway

import (
	"context"
	"crypto/rand"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/n1s01/proxykit"
)

// Format describes how one provider encodes parameters into credentials.
// A tag is followed by its value: base-country-RU-session-abc123-time-1440.
// An empty tag name means the provider has no such parameter.
type Format struct {
	// Separator joins the base, tags and values. Zero uses "-".
	Separator string
	Country   string
	Session   string
	TTL       string
	// TTLUnit is the unit of the number after the TTL tag. Zero uses time.Minute.
	TTLUnit time.Duration
	// InPassword selects the password instead of the username as the tagged field.
	InPassword bool
}

// Nova is the NovaProxy username format; time is in minutes.
var Nova = Format{Country: "country", Session: "session", TTL: "time"}

// Params are the provider parameters of one endpoint. Values are literal:
// country case is whatever the provider expects.
type Params struct {
	Country string
	// Session pins the exit address. Empty means a new address per connection.
	Session string
	// TTL is the sticky session lifetime; zero leaves it to the provider.
	TTL time.Duration
}

// Sticky reports whether the exit address is pinned to a session.
func (p Params) Sticky() bool { return p.Session != "" }

func invalid(field string) error { return fmt.Errorf("%w: %s", proxykit.ErrInvalid, field) }

// Split returns the endpoint without the tags of f, and their values. The
// first token is always the base; tokens f does not name are kept in place.
func (f Format) Split(spec proxykit.Spec) (proxykit.Spec, Params, error) {
	sep, unit, err := f.settings()
	if err != nil {
		return proxykit.Spec{}, Params{}, err
	}
	rest, p, err := f.scan(f.field(spec), sep, unit)
	if err != nil {
		return proxykit.Spec{}, Params{}, err
	}
	return f.withField(spec, strings.Join(rest, sep)), p, nil
}

// Apply returns the endpoint carrying exactly p: tags of f already present in
// spec are replaced or removed, so an empty Session turns a sticky endpoint
// into a rotating one. Tokens f does not name are kept.
func (f Format) Apply(spec proxykit.Spec, p Params) (proxykit.Spec, error) {
	sep, unit, err := f.settings()
	if err != nil {
		return proxykit.Spec{}, err
	}
	rest, _, err := f.scan(f.field(spec), sep, unit)
	if err != nil {
		return proxykit.Spec{}, err
	}
	if rest[0] == "" {
		return proxykit.Spec{}, invalid("tagged credential is empty")
	}
	if p.TTL < 0 {
		return proxykit.Spec{}, invalid("negative session TTL")
	}
	if p.TTL > 0 && p.Session == "" {
		return proxykit.Spec{}, invalid("session TTL requires a session")
	}
	if p.TTL%unit != 0 {
		return proxykit.Spec{}, invalid("session TTL is not a multiple of the format unit")
	}
	ttl := ""
	if p.TTL > 0 {
		ttl = strconv.FormatInt(int64(p.TTL/unit), 10)
	}
	for _, pair := range [...]struct{ tag, value string }{
		{f.Country, p.Country}, {f.Session, p.Session}, {f.TTL, ttl},
	} {
		if pair.value == "" {
			continue
		}
		if pair.tag == "" {
			return proxykit.Spec{}, invalid("format has no tag for a requested parameter")
		}
		if strings.Contains(pair.value, sep) || strings.IndexFunc(pair.value, func(r rune) bool {
			return unicode.IsSpace(r) || unicode.IsControl(r)
		}) >= 0 {
			return proxykit.Spec{}, invalid("parameter value contains a separator or space")
		}
		rest = append(rest, pair.tag, pair.value)
	}
	out := f.withField(spec, strings.Join(rest, sep))
	if err = out.Validate(); err != nil {
		return proxykit.Spec{}, err
	}
	return out, nil
}

// New parses a plain provider line such as "host:port:user:pass", applies p and
// returns a ready dialer; Dialer.Spec is the finished endpoint. A TTL without a
// Session gets a fresh NewSession. Like proxykit.New, an input without a
// protocol is resolved by discovery against opts.Target, which opens connections.
func (f Format) New(ctx context.Context, input string, p Params, opts proxykit.Options) (*proxykit.Dialer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	spec, err := proxykit.ParseWithOptions(input, opts.Parse)
	if err != nil {
		return nil, err
	}
	if p.TTL > 0 && p.Session == "" {
		p.Session = NewSession()
	}
	if spec, err = f.Apply(spec, p); err != nil {
		return nil, err
	}
	if spec.Protocol == proxykit.Auto {
		found, err := proxykit.Detect(ctx, spec, proxykit.DetectOptions{
			Target: opts.Target, Candidates: opts.Candidates,
			Timeout: opts.Dial.Timeout, DialOptions: opts.Dial,
		})
		if err != nil {
			return nil, err
		}
		spec = found.Proxy
	}
	return proxykit.NewDialer(spec, opts.Dial)
}

func (f Format) settings() (string, time.Duration, error) {
	sep := f.Separator
	if sep == "" {
		sep = "-"
	}
	unit := f.TTLUnit
	if unit == 0 {
		unit = time.Minute
	}
	if unit < 0 {
		return "", 0, invalid("negative TTL unit")
	}
	tags := [...]string{f.Country, f.Session, f.TTL}
	named := false
	for i, tag := range tags {
		if tag == "" {
			continue
		}
		named = true
		if strings.Contains(tag, sep) {
			return "", 0, invalid("format tag contains the separator")
		}
		for _, other := range tags[:i] {
			if other == tag {
				return "", 0, invalid("duplicate format tag")
			}
		}
	}
	if !named {
		return "", 0, invalid("format names no tags")
	}
	return sep, unit, nil
}

func (f Format) field(spec proxykit.Spec) string {
	if f.InPassword {
		return spec.Password
	}
	return spec.Username
}

func (f Format) withField(spec proxykit.Spec, value string) proxykit.Spec {
	if f.InPassword {
		spec.Password = value
	} else {
		spec.Username = value
	}
	return spec
}

// scan separates the tags of f from every other token, preserving their order.
func (f Format) scan(field, sep string, unit time.Duration) ([]string, Params, error) {
	tokens := strings.Split(field, sep)
	rest := tokens[:1:1]
	var p Params
	var seen [3]bool
	for i := 1; i < len(tokens); i++ {
		var kind int
		switch tokens[i] {
		case "":
			kind = -1
		case f.Country:
			kind = 0
		case f.Session:
			kind = 1
		case f.TTL:
			kind = 2
		default:
			kind = -1
		}
		if kind < 0 {
			rest = append(rest, tokens[i])
			continue
		}
		if seen[kind] {
			return nil, Params{}, invalid("repeated credential tag")
		}
		seen[kind] = true
		i++
		if i == len(tokens) || tokens[i] == "" {
			return nil, Params{}, invalid("credential tag without a value")
		}
		switch kind {
		case 0:
			p.Country = tokens[i]
		case 1:
			p.Session = tokens[i]
		case 2:
			ttl, err := parseTTL(tokens[i], unit)
			if err != nil {
				return nil, Params{}, err
			}
			p.TTL = ttl
		}
	}
	return rest, p, nil
}

func parseTTL(raw string, unit time.Duration) (time.Duration, error) {
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, invalid("session TTL")
		}
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 1 || n > math.MaxInt64/int64(unit) {
		return 0, invalid("session TTL")
	}
	return time.Duration(n) * unit, nil
}

const sessionAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// NewSession returns a random ten-character session identifier. It panics
// only if the system random source fails.
func NewSession() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic("gateway: random source: " + err.Error())
	}
	for i := range b {
		b[i] = sessionAlphabet[int(b[i])%len(sessionAlphabet)]
	}
	return string(b)
}
