// Package relay adapts authenticated proxy tunnels to a loopback HTTP proxy for
// browsers. Start accepts any context-aware tunnel dialer, including a
// proxykit.Dialer. The caller must close the returned Server.
package relay
