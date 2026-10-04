package proxykit

import (
	"fmt"
	"strings"
)

// LineError associates a parsing error with a one-based input line number.
type LineError struct {
	Line int
	Err  error
}

func (e LineError) Error() string { return fmt.Sprintf("line %d: %v", e.Line, e.Err) }
func (e LineError) Unwrap() error { return e.Err }

// ParseLines preserves order and duplicates. Deduplication is application policy.
// Empty lines and lines beginning with # are ignored; secrets are never echoed.
func ParseLines(text string, opts ParseOptions) ([]Spec, []LineError) {
	var specs []Spec
	var errs []LineError
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s, e := ParseWithOptions(line, opts)
		if e != nil {
			errs = append(errs, LineError{i + 1, e})
		} else {
			specs = append(specs, s)
		}
	}
	return specs, errs
}
