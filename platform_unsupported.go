//go:build !darwin && !linux && !windows

// Platform backend for every OS without interface binding (FreeBSD, OpenBSD,
// NetBSD, Solaris, Plan 9, js/wasm, wasip1, ...). Contract: platformBackend
// in platform.go. Adding an OS means a new platform_<os>.go and narrowing the
// build tag above.

package proxykit

import (
	"net"
	"runtime"
)

var backend platformBackend = unsupportedBackend{}

type unsupportedBackend struct{}

func (unsupportedBackend) info() Platform {
	return Platform{
		OS:     runtime.GOOS,
		Bypass: false,
		Notes: []string{
			"no interface binding: set DialOptions.Advanced.DisableBypass to use the system route",
		},
	}
}

func (unsupportedBackend) bind(uintptr, bool, *net.Interface) error { return ErrBypassUnsupported }

func (unsupportedBackend) physicalName(string) bool { return false }

func (unsupportedBackend) defaultRoutes() []int { return nil }
