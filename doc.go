// Package proxykit parses proxy endpoints, establishes cancellable TCP tunnels,
// detects protocols, and checks target reachability. It supports HTTP CONNECT,
// HTTPS CONNECT and SOCKS5 CONNECT, using only the Go standard library.
//
// Parsing never performs network I/O. An endpoint without a protocol remains
// Auto until explicitly resolved; dialing never falls back to a direct route.
// Applications own storage, scheduling, rotation and health policy.
//
// DialOptions.Bypass binds connections to the proxy to a physical interface,
// around VPN/WARP tunnels. Inspect reports protocol, real tunnel latency and
// exit country in one call.
//
// New is the high-level entry point: it returns a Dialer after parsing and any
// required discovery. Dialer shares its configuration across traffic, checks
// and HTTP transports. The optional relay subpackage provides a browser adapter;
// gateway reads and writes rotating-proxy parameters encoded in credentials.
// Public types are defined here; protocol handshakes are private implementation.
package proxykit
