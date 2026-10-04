//go:build linux

package proxykit

import (
	"net"
	"syscall"
)

const bindSupported = true

func physicalName(name string) bool { return !virtualName(name) }

func bindSocket(fd uintptr, _ bool, iface *net.Interface) error {
	return syscall.BindToDevice(int(fd), iface.Name)
}
