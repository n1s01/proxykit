package relay

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/n1s01/proxykit"
)

func invalid(field string) error { return fmt.Errorf("%w: %s", proxykit.ErrInvalid, field) }

func validateTarget(addr string) (string, int, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, invalid("target requires host:port")
	}
	if strings.HasPrefix(addr, "[") && (net.ParseIP(host) == nil || !strings.Contains(host, ":")) {
		return "", 0, invalid("brackets require an IPv6 address")
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return "", 0, invalid("target port")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, invalid("target port")
	}
	err = (proxykit.Spec{Protocol: proxykit.HTTP, Host: host, Port: n}).Validate()
	return host, n, err
}
