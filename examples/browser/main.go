// Example browser adapter. Set PROXY_URL and TARGET_ADDR for discovery.
// The adapter remains active until Ctrl+C; start Chromium with the printed flag.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/n1s01/proxykit"
	"github.com/n1s01/proxykit/relay"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	input, target := os.Getenv("PROXY_URL"), os.Getenv("TARGET_ADDR")
	if input == "" || target == "" {
		return fmt.Errorf("set PROXY_URL and TARGET_ADDR")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	setup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	proxy, err := proxykit.New(setup, input, proxykit.Options{
		Target: target,
	})
	if err != nil {
		return err
	}
	relay, err := relay.Start(proxy, relay.Options{})
	if err != nil {
		return err
	}
	defer relay.Close()
	fmt.Printf("--proxy-server=%s\n", relay.URL())
	<-ctx.Done()
	return nil
}
