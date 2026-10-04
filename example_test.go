package proxykit_test

import (
	"context"
	"fmt"

	"github.com/n1s01/proxykit"
)

func ExampleNew() {
	dialer, err := proxykit.New(context.Background(), "socks5://user:pass@host.test:1080", proxykit.Options{})
	if err != nil {
		panic(err)
	}
	fmt.Println(dialer.Spec())
	// Output: socks5://REDACTED@host.test:1080
}

func ExampleParse() {
	p, err := proxykit.Parse("socks5h://user:pass@[::1]:1080")
	if err != nil {
		panic(err)
	}
	fmt.Println(p.Protocol)
	fmt.Println(p)
	// Output:
	// socks5
	// socks5://REDACTED@[::1]:1080
}

func ExampleParseWithOptions() {
	p, err := proxykit.ParseWithOptions("host:123:user:456", proxykit.ParseOptions{
		Layout:          proxykit.HostPortUserPass,
		DefaultProtocol: proxykit.HTTP,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(p)
	// Output: http://REDACTED@host:123
}

func ExampleNew_arbitraryOrder() {
	dialer, err := proxykit.New(context.Background(), "socks5://host.test@1080:pass:login", proxykit.Options{
		Parse: proxykit.ParseOptions{Layout: "host@port:pass:login"},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(dialer.Spec().Address(), dialer.Spec().Username)
	// Output: host.test:1080 login
}
