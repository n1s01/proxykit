package proxykit

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type dialFunc func(context.Context, string, string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	return f(ctx, network, target)
}

func TestCheckUsesInjectedTunnelAndClosesIt(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	spec := Spec{Protocol: HTTP, Host: "proxy.test", Port: 80}
	dialer := dialFunc(func(ctx context.Context, network, target string) (net.Conn, error) {
		if network != "tcp" || target != "target.test:443" {
			t.Errorf("unexpected dial destination %s %s", network, target)
		}
		return client, nil
	})
	result, err := check(context.Background(), spec, dialer, CheckOptions{Target: "target.test:443"})
	if err != nil || !result.OK {
		t.Fatalf("check: %v", err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	var data [1]byte
	if _, err := peer.Read(data[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("checked tunnel was not closed: %v", err)
	}
}

func TestInvalidCheckDoesNotTouchDialer(t *testing.T) {
	dialer := dialFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("invalid configuration caused network I/O")
		return nil, nil
	})
	_, err := check(context.Background(), Spec{}, dialer, CheckOptions{})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid options: %v", err)
	}
}

func TestDetectDependsOnlyOnFactoryContract(t *testing.T) {
	spec := Spec{Protocol: Auto, Host: "proxy.test", Port: 80}
	peerClosed := make(chan struct{})
	factory := func(candidate Spec) (ContextDialer, error) {
		return dialFunc(func(ctx context.Context, network, target string) (net.Conn, error) {
			if candidate.Protocol != HTTP {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			client, peer := net.Pipe()
			go func() { defer close(peerClosed); defer peer.Close(); _, _ = io.Copy(io.Discard, peer) }()
			return client, nil
		}), nil
	}
	result, err := detect(context.Background(), spec, DetectOptions{Target: "target.test:443"}, factory)
	if err != nil || result.Proxy.Protocol != HTTP || len(result.Attempts) != 3 {
		t.Fatalf("factory detection: %v %v", result.Proxy, err)
	}
	select {
	case <-peerClosed:
	case <-time.After(time.Second):
		t.Fatal("discovery tunnel was retained")
	}
	for _, attempt := range result.Attempts {
		if attempt.Protocol != HTTP && !errors.Is(attempt.Err, context.Canceled) {
			t.Fatal("losing factory call was not canceled")
		}
	}
}
