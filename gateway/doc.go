// Package gateway reads and writes the parameters rotating proxy providers
// encode into credentials: exit country, sticky session and session lifetime,
// as in "user-country-RU-session-abc123-time-1440". A Format names the tags of
// one provider; Split and Apply convert between a proxykit.Spec and Params.
//
// Format.New does all of it from one input line and returns a ready Dialer.
//
// Split and Apply perform no network I/O; the package keeps no state. Choosing when to
// change a session and which session belongs to which account is application
// policy: build a new Spec, then a new proxykit.Dialer.
package gateway
