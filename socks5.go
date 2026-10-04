package proxykit

import (
	"io"
	"net"
)

type socksConnector struct{ spec Spec }

func (s socksConnector) Connect(conn net.Conn, target targetInfo) (net.Conn, Stage, int, error) {
	stage, code, err := s.socksConnect(conn, target.host, target.port)
	return conn, stage, code, err
}

func (d socksConnector) socksConnect(c net.Conn, host string, port int) (Stage, int, error) {
	methods := []byte{0}
	if d.spec.HasAuth() {
		methods = append(methods, 2)
	}
	if e := writeAll(c, append([]byte{5, byte(len(methods))}, methods...)); e != nil {
		return StageNegotiation, 0, e
	}
	var reply [2]byte
	if _, e := io.ReadFull(c, reply[:]); e != nil {
		return StageNegotiation, 0, e
	}
	if reply[0] != 5 {
		return StageNegotiation, 0, ErrProtocol
	}
	switch reply[1] {
	case 0:
	case 2:
		if !d.spec.HasAuth() {
			return StageAuth, 0, ErrAuth
		}
		auth := append([]byte{1, byte(len(d.spec.Username))}, []byte(d.spec.Username)...)
		auth = append(auth, byte(len(d.spec.Password)))
		auth = append(auth, []byte(d.spec.Password)...)
		if e := writeAll(c, auth); e != nil {
			return StageAuth, 0, e
		}
		if _, e := io.ReadFull(c, reply[:]); e != nil {
			return StageAuth, 0, e
		}
		if reply[0] != 1 {
			return StageAuth, 0, ErrProtocol
		}
		if reply[1] != 0 {
			return StageAuth, int(reply[1]), ErrAuth
		}
	case 255:
		return StageAuth, 0, ErrAuth
	default:
		return StageNegotiation, int(reply[1]), ErrProtocol
	}
	packet := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			packet = append(packet, 1)
			packet = append(packet, ip4...)
		} else {
			packet = append(packet, 4)
			packet = append(packet, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return StageConnect, 0, invalid("SOCKS target domain length")
		}
		packet = append(packet, 3, byte(len(host)))
		packet = append(packet, []byte(host)...)
	}
	packet = append(packet, byte(port>>8), byte(port))
	if e := writeAll(c, packet); e != nil {
		return StageConnect, 0, e
	}
	var header [4]byte
	if _, e := io.ReadFull(c, header[:]); e != nil {
		return StageConnect, 0, e
	}
	if header[0] != 5 || header[2] != 0 {
		return StageConnect, 0, ErrProtocol
	}
	if header[1] != 0 {
		return StageConnect, int(header[1]), ErrRejected
	}
	n := 0
	switch header[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var length [1]byte
		if _, e := io.ReadFull(c, length[:]); e != nil {
			return StageConnect, 0, e
		}
		n = int(length[0])
		if n == 0 {
			return StageConnect, 0, ErrProtocol
		}
	default:
		return StageConnect, 0, ErrProtocol
	}
	_, e := io.CopyN(io.Discard, c, int64(n+2))
	return StageConnect, 0, e
}
