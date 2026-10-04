// Example HTTP client. Set PROXY_URL and TARGET_URL before running.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	proxy, err := proxykit.New(ctx, proxyInput, proxykit.Options{
		Target: net.JoinHostPort(u.Hostname(), port),
	})
	if err != nil {
		return err
	}
	tr := proxy.Transport()
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Printf("proxy=%s status=%d\n", proxy.Spec(), resp.StatusCode)
	return nil
}
