package proxykit

import (
	"bufio"
	"encoding/base64"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
)

type httpConnector struct{ spec Spec }

func (h httpConnector) Connect(conn net.Conn, target targetInfo) (net.Conn, Stage, int, error) {
	conn, code, err := httpConnect(conn, h.spec, target.address)
	stage := StageConnect
	if code == http.StatusProxyAuthRequired {
		stage = StageAuth
	}
	return conn, stage, code, err
}

func httpConnect(c net.Conn, s Spec, target string) (net.Conn, int, error) {
	var b strings.Builder
	b.WriteString("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n")
	if s.HasAuth() {
		b.WriteString("Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(s.Username+":"+s.Password)) + "\r\n")
	}
	b.WriteString("\r\n")
	if e := writeAll(c, []byte(b.String())); e != nil {
		return c, 0, e
	}
	// Bound untrusted headers without limiting subsequent tunnel reads. CONNECT
	// response bodies must not be closed/read on success: those bytes are the tunnel.
	lr := &io.LimitedReader{R: c, N: 64 << 10}
	br := bufio.NewReader(lr)
	resp, e := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if e != nil {
		return c, 0, e
	}
	if lr.N == 0 {
		return c, 0, invalid("CONNECT response headers exceed limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		e = ErrRejected
		if resp.StatusCode == 407 {
			e = ErrAuth
		}
		return c, resp.StatusCode, e
	}
	lr.N = math.MaxInt64
	return &bufferedConn{Conn: c, reader: br}, resp.StatusCode, nil
}
