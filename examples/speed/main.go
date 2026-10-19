// Example health and speed test. Set PROXY_URL and TARGET_URL before running.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/n1s01/proxykit"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	proxyInput, targetURL := os.Getenv("PROXY_URL"), os.Getenv("TARGET_URL")
	if proxyInput == "" || targetURL == "" {
		return fmt.Errorf("set PROXY_URL and TARGET_URL")
	}
	u, err := url.ParseRequestURI(targetURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("TARGET_URL must be an absolute HTTP(S) URL")
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	proxy, err := proxykit.New(ctx, proxyInput, proxykit.Options{
		Target: net.JoinHostPort(u.Hostname(), port),
	})
	if err != nil {
		return err
	}
	result, err := proxy.SpeedTest(ctx, proxykit.SpeedTestOptions{URL: targetURL})
	if err != nil {
		return err
	}
	fmt.Printf("proxy=%s health=%t status=%d tunnel=%s speed=%.2f Mbps bytes=%d complete=%t\n",
		proxy.Spec(), result.Health.OK, result.Health.StatusCode,
		result.Health.TunnelLatency, result.Speed.MegabitsPerSecond,
		result.Speed.Bytes, result.Speed.Complete)
	return nil
}
