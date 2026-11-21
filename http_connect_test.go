package proxykit

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"
)

// fakeConnectProxy answers one CONNECT with 200 followed by extra bytes.
func fakeConnectProxy(t *testing.T, extra string) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		br := bufio.NewReader(server)
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\n\r\n"+extra)
		if extra != "" {
			return
		}
		_, _ = io.WriteString(server, "later")
	}()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	return client
}

func TestHTTPConnectReturnsSocketWhenNothingBuffered(t *testing.T) {
	c := fakeConnectProxy(t, "")
	defer c.Close()
	tunnel, _, err := httpConnect(c, Spec{Protocol: HTTP, Host: "proxy.test", Port: 8080}, "target.test:443")
	if err != nil {
		t.Fatal(err)
	}
	if tunnel != c {
		t.Fatalf("tunnel is %T, want the socket itself", tunnel)
	}
	b, _ := io.ReadAll(tunnel)
	if string(b) != "later" {
		t.Fatalf("tunnel read %q", b)
	}
}

func TestHTTPConnectKeepsBytesAfterHeaders(t *testing.T) {
	c := fakeConnectProxy(t, "early")
	defer c.Close()
	tunnel, _, err := httpConnect(c, Spec{Protocol: HTTP, Host: "proxy.test", Port: 8080}, "target.test:443")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(tunnel)
	if string(b) != "early" {
		t.Fatalf("bytes after the CONNECT response were lost: %q", b)
	}
}
