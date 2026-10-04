//go:build !darwin && !linux && !windows

package proxykit

import "net"

const bindSupported = false

func physicalName(string) bool { return false }

func bindSocket(uintptr, bool, *net.Interface) error { return ErrBypassUnsupported }
