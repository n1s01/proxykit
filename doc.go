// Package proxykit turns a proxy string into a working TCP tunnel.
//
// # What it does
//
//	"user:pass@host:1080" --Parse--> Spec --New/NewDialer--> *Dialer --DialContext--> net.Conn
//	                                                            ├── Transport()  -> *http.Transport
//	                                                            ├── Check()      -> reachability
//	                                                            ├── SpeedTest()  -> health + throughput
//	                                                            └── Inspect()    -> protocol, latency, country
//
// Protocols: HTTP CONNECT, HTTPS CONNECT, SOCKS5 CONNECT. Standard library only.
//
// # Defaults (zero values are the recommended configuration)
//
//   - VPN bypass is ON. The socket to the proxy is pinned to a physical
//     interface, around VPN/WARP/TUN, and the proxy name is resolved over
//     public DNS on that interface. Turn it off only through
//     DialOptions.Advanced (DisableBypass or Forward). Dialer.Route reports
//     which route is in use.
//   - No silent fallback. No direct connection to the target, no route
//     through the VPN when no physical interface exists (ErrNoInterface), no
//     downgrade on platforms without bypass (ErrBypassUnsupported).
//   - Parse never touches the network. A string without a scheme stays Auto;
//     only New/Detect probe the network to pick a protocol.
//   - Errors are *OpError with a Stage; match causes with errors.Is against
//     the Err* sentinels. Error text never contains credentials.
//
// # Platforms
//
// Bypass is implemented on darwin/ios, linux/android and windows. Everything
// OS-specific is in platform_<os>.go behind the platformBackend interface
// (platform.go); CurrentPlatform reports what this binary was built with.
//
// # Out of scope
//
// Storage, scheduling, rotation, retries and health policy belong to the
// application. Subpackages: relay (local HTTP proxy for browsers) and
// gateway (rotating-proxy parameters encoded in credentials).
//
// Contributors and coding agents: start with AGENTS.md at the module root.
package proxykit
