// Command bypass checks that proxykit routes around a VPN on this machine.
// Run it with the VPN switched on: the normal route must show the VPN address,
// the bypass route the real one. An optional argument is a proxy to inspect
// through the bypass route.
//
//	bypass [-iface NAME] [-target host:port] [proxy]
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/n1s01/proxykit"
)

const ipService = "https://api.ipify.org"

var out io.Writer = os.Stdout

func main() {
	iface := flag.String("iface", "", "pin a network interface by name")
	target := flag.String("target", "web.telegram.org:443", "host:port for the proxy check")
	flag.Parse()
	if f, err := os.Create("bypass-report.txt"); err == nil {
		defer f.Close()
		out = io.MultiWriter(os.Stdout, f)
	}
	ok := run(*iface, *target, flag.Arg(0))
	fmt.Fprintln(out, "\nReport saved to bypass-report.txt. Press Enter to exit.")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	if !ok {
		os.Exit(1)
	}
}

func run(iface, target, proxy string) bool {
	fmt.Fprintf(out, "proxykit bypass check: %s/%s, supported=%v\n\n", runtime.GOOS, runtime.GOARCH, proxykit.BypassSupported())
	listInterfaces()

	opts := proxykit.BypassOptions{Interface: iface}
	bound, err := proxykit.BypassDialContext(opts)
	if err != nil {
		fmt.Fprintf(out, "\nFAIL: bypass is unavailable: %v\n", err)
		return false
	}
	fmt.Fprintln(out, "\n[1] normal route (what the system does by default)")
	normalLocal, normalIP, normalErr := probe((&net.Dialer{}).DialContext)
	report(normalLocal, normalIP, normalErr)
	fmt.Fprintln(out, "\n[2] bypass route (bound to the physical interface)")
	boundLocal, boundIP, boundErr := probe(bound)
	report(boundLocal, boundIP, boundErr)

	fmt.Fprintln(out)
	ok := boundErr == nil
	switch {
	case boundErr != nil:
		fmt.Fprintln(out, "RESULT: FAIL - the bypass route could not connect.")
	case normalErr != nil:
		fmt.Fprintln(out, "RESULT: OK - the bypass route works while the normal route is down.")
	case normalIP != boundIP:
		fmt.Fprintln(out, "RESULT: OK - the bypass route leaves through a different address than the VPN.")
	default:
		fmt.Fprintln(out, "RESULT: INCONCLUSIVE - both routes show the same address.")
		fmt.Fprintln(out, "        Either the VPN is off, or the bypass did not leave the tunnel.")
		fmt.Fprintln(out, "        Switch the VPN on and run again; if it is on, try -iface NAME.")
	}

	if proxy != "" {
		fmt.Fprintf(out, "\n[3] proxy through the bypass route, target %s\n", target)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		spec, err := proxykit.Parse(proxy)
		if err != nil {
			fmt.Fprintf(out, "    cannot parse proxy: %v\n", err)
			return false
		}
		info, err := proxykit.Inspect(ctx, spec, proxykit.InspectOptions{
			Target: target, Dial: proxykit.DialOptions{Bypass: &opts},
		})
		if err != nil {
			fmt.Fprintf(out, "    FAIL: %v (%v)\n", err, unwrapAll(err))
			return false
		}
		fmt.Fprintf(out, "    protocol=%s latency=%s country=%s exit-ip=%s\n", info.Proxy.Protocol, info.Latency.Round(time.Millisecond), info.Country, info.IP)
		if info.GeoErr != nil {
			fmt.Fprintf(out, "    country lookup failed: %v\n", unwrapAll(info.GeoErr))
		}
	}
	return ok
}

func listInterfaces() {
	fmt.Fprintln(out, "network interfaces:")
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(out, "  cannot list: %v\n", err)
		return
	}
	for _, iface := range ifaces {
		var addrs []string
		list, _ := iface.Addrs()
		for _, addr := range list {
			addrs = append(addrs, addr.String())
		}
		fmt.Fprintf(out, "  #%d %q flags=%s addrs=%s\n", iface.Index, iface.Name, iface.Flags, strings.Join(addrs, ", "))
	}
}

// probe asks the address service over one connection opened by dial and
// returns the local socket address together with the address the world sees.
func probe(dial proxykit.DialContextFunc) (local, ip string, err error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, e := dial(ctx, network, addr)
			if e == nil {
				local = c.LocalAddr().String()
			}
			return c, e
		},
	}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ipService, nil)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return local, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	return local, strings.TrimSpace(string(body)), err
}

func report(local, ip string, err error) {
	if local != "" {
		fmt.Fprintf(out, "    local socket: %s\n", local)
	}
	if err != nil {
		fmt.Fprintf(out, "    error: %v\n", err)
		return
	}
	fmt.Fprintf(out, "    public address: %s\n", ip)
}

// unwrapAll prints the cause proxykit keeps out of its own error text.
func unwrapAll(err error) error {
	for {
		inner, ok := err.(interface{ Unwrap() error })
		if !ok || inner.Unwrap() == nil {
			return err
		}
		err = inner.Unwrap()
	}
}
