package relay

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/n1s01/proxykit"
)

// Options bounds accepted request setup and concurrent upstream work.
type Options struct {
	// MaxConcurrent bounds active upstream requests/tunnels; zero uses 128.
	MaxConcurrent int
	// HeaderTimeout bounds HTTP request headers; zero uses 5 seconds.
	HeaderTimeout time.Duration
}

// Server is an unauthenticated HTTP proxy bound exclusively to 127.0.0.1.
// It forwards HTTP requests and CONNECT tunnels through one configured Dialer.
// Browser HTTPS and WebSocket traffic work inside CONNECT; HTTP Upgrade requests
// outside a CONNECT tunnel are unsupported. Any local process can use the relay.
type Server struct {
	ln        net.Listener
	server    *http.Server
	transport *http.Transport
	dialer    Dialer
	ctx       context.Context
	cancel    context.CancelFunc
	sem       chan struct{}
	mu        sync.Mutex
	closed    bool
	tunnels   map[net.Conn]struct{}
	wg        sync.WaitGroup
	once      sync.Once
	err       error
	done      chan struct{}
}

// Start starts a loopback-only HTTP proxy. The caller owns Close.
func Start(d Dialer, opts Options) (*Server, error) {
	if d == nil {
		return nil, invalid("nil relay dialer")
	}
	if native, ok := d.(*proxykit.Dialer); ok && native == nil {
		return nil, invalid("nil relay dialer")
	}
	if opts.MaxConcurrent < 0 || opts.HeaderTimeout < 0 {
		return nil, invalid("negative relay option")
	}
	n := opts.MaxConcurrent
	if n == 0 {
		n = 128
	}
	headerTimeout := opts.HeaderTimeout
	if headerTimeout == 0 {
		headerTimeout = 5 * time.Second
	}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Server{ln: ln, transport: proxykit.NewHTTPTransport(d), dialer: d, ctx: ctx, cancel: cancel, sem: make(chan struct{}, n), tunnels: map[net.Conn]struct{}{}, done: make(chan struct{})}
	r.server = &http.Server{Handler: http.HandlerFunc(r.handle), ReadHeaderTimeout: headerTimeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 64 << 10, BaseContext: func(net.Listener) context.Context { return ctx }, ErrorLog: log.New(io.Discard, "", 0)}
	go func() {
		defer close(r.done)
		_ = r.server.Serve(ln)
	}()
	return r, nil
}

// URL is suitable for Chromium's --proxy-server flag; it contains no credentials.
func (r *Server) URL() string { return "http://" + r.ln.Addr().String() }

// Close is idempotent and interrupts both active handshakes and established
// tunnels. It waits for accepted handlers and the listener goroutine to exit.
func (r *Server) Close() error {
	r.once.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.cancel()
		for c := range r.tunnels {
			_ = c.Close()
		}
		r.mu.Unlock()
		r.err = r.server.Close()
		if errors.Is(r.err, http.ErrServerClosed) {
			r.err = nil
		}
		r.transport.CloseIdleConnections()
		r.wg.Wait()
		<-r.done
	})
	return r.err
}

func (r *Server) handle(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		http.Error(w, "relay closed", 503)
		return
	}
	r.wg.Add(1)
	r.mu.Unlock()
	defer r.wg.Done()
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-req.Context().Done():
		return
	case <-r.ctx.Done():
		return
	}
	if req.Method == http.MethodConnect {
		r.connect(w, req)
		return
	}
	if req.URL.Scheme != "http" || req.URL.Host == "" || req.URL.User != nil || req.Header.Get("Upgrade") != "" {
		http.Error(w, "expected absolute HTTP URL or CONNECT", 400)
		return
	}
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "80"
	}
	if _, _, e := validateTarget(net.JoinHostPort(host, port)); e != nil {
		http.Error(w, "invalid target", 400)
		return
	}
	out := req.Clone(req.Context())
	out.RequestURI = ""
	out.Header = req.Header.Clone()
	stripHopHeaders(out.Header)
	resp, e := r.transport.RoundTrip(out)
	if e != nil {
		http.Error(w, "upstream connection failed", 502)
		return
	}
	defer resp.Body.Close()
	stripHopHeaders(resp.Header)
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (r *Server) connect(w http.ResponseWriter, req *http.Request) {
	if _, _, e := validateTarget(req.Host); e != nil {
		http.Error(w, "invalid CONNECT target", 400)
		return
	}
	up, e := r.dialer.DialContext(req.Context(), "tcp", req.Host)
	if e != nil {
		if up != nil {
			_ = up.Close()
		}
		http.Error(w, "upstream connection failed", 502)
		return
	}
	if up == nil {
		http.Error(w, "upstream connection failed", 502)
		return
	}
	defer up.Close()
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT unavailable", 500)
		return
	}
	client, rw, e := hj.Hijack()
	if e != nil {
		return
	}
	defer client.Close()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.tunnels[client] = struct{}{}
	r.tunnels[up] = struct{}{}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.tunnels, client)
		delete(r.tunnels, up)
		r.mu.Unlock()
	}()
	if e = client.SetDeadline(time.Time{}); e != nil {
		return
	}
	if e = writeEstablished(client); e != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(up, rw)
		_ = up.Close()
		_ = client.Close()
		close(done)
	}()
	_, _ = io.Copy(client, up)
	_ = client.Close()
	_ = up.Close()
	<-done
}

func stripHopHeaders(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(token))
		}
	}
	for _, key := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(key)
	}
}

func writeEstablished(conn net.Conn) error {
	_, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	return err
}
