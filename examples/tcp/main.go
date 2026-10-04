// Example TCP tunnel. Set PROXY_URL and TARGET_ADDR (host:port).
package main

import (
	"context"
	"fmt"
	"log"
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
	input, target := os.Getenv("PROXY_URL"), os.Getenv("TARGET_ADDR")
	if input == "" || target == "" {
		return fmt.Errorf("set PROXY_URL and TARGET_ADDR")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	proxy, err := proxykit.New(ctx, input, proxykit.Options{
		Target: target,
	})
	if err != nil {
		return err
	}
	conn, err := proxy.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Pass conn to your TCP protocol. Its lifetime belongs to this caller.
	fmt.Printf("tunnel established via %s\n", proxy.Spec())
	return nil
}
