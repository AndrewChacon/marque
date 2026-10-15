package proxy

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// SOCKS5 wire protocol constants (RFC 1928). Only the CONNECT command
// is supported — this is a pentest-scope proxy, not a general SOCKS5
// router; BIND and UDP ASSOCIATE have no use case here.
const (
	socks5Version = 0x05

	socks5MethodNoAuth       = 0x00
	socks5MethodNoAcceptable = 0xFF

	socks5CmdConnect = 0x01

	socks5ATYPIPv4   = 0x01
	socks5ATYPDomain = 0x03
	socks5ATYPIPv6   = 0x04

	socks5ReplySucceeded           = 0x00
	socks5ReplyGeneralFailure      = 0x01
	socks5ReplyNotAllowedByRuleset = 0x02
)

func (p *Proxy) serveSOCKS5(conn net.Conn, br *bufio.Reader) {
	// handleConn already set a read deadline covering the handshake,
	// starting from its own protocol-detection peek; clear it below
	// once a full request has been parsed.
	if err := socks5Greeting(br, conn); err != nil {
		return
	}

	host, port, err := socks5ReadRequest(br)
	if err != nil {
		// Best-effort rejection notice — we're already bailing out, so
		// a failed write here changes nothing.
		_ = socks5WriteReply(conn, socks5ReplyGeneralFailure)
		return
	}
	conn.SetReadDeadline(time.Time{})

	target, decision := p.connect(host, port)
	if target == nil {
		rep := byte(socks5ReplyGeneralFailure)
		if !decision.Allowed {
			rep = socks5ReplyNotAllowedByRuleset
		}
		_ = socks5WriteReply(conn, rep)
		return
	}
	defer target.Close()

	if err := socks5WriteReply(conn, socks5ReplySucceeded); err != nil {
		return
	}
	relay(conn, br, target)
}

// socks5Greeting reads the client's method-negotiation message and
// replies, accepting only the no-auth method. This is a local
// safety-net tool, not a multi-tenant gateway — authentication isn't
// the point (see THREAT_MODEL.md).
func socks5Greeting(r *bufio.Reader, w io.Writer) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version %d", header[0])
	}

	methods := make([]byte, header[1])
	if _, err := io.ReadFull(r, methods); err != nil {
		return err
	}

	for _, m := range methods {
		if m == socks5MethodNoAuth {
			_, err := w.Write([]byte{socks5Version, socks5MethodNoAuth})
			return err
		}
	}
	w.Write([]byte{socks5Version, socks5MethodNoAcceptable})
	return fmt.Errorf("client offered no acceptable authentication method")
}

func socks5ReadRequest(r *bufio.Reader) (host, port string, err error) {
	header := make([]byte, 4)
	if _, err = io.ReadFull(r, header); err != nil {
		return "", "", err
	}
	if header[0] != socks5Version {
		return "", "", fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	if header[1] != socks5CmdConnect {
		return "", "", fmt.Errorf("unsupported SOCKS command %d", header[1])
	}

	switch header[3] {
	case socks5ATYPIPv4:
		addr := make([]byte, net.IPv4len)
		if _, err = io.ReadFull(r, addr); err != nil {
			return "", "", err
		}
		host = net.IP(addr).String()
	case socks5ATYPIPv6:
		addr := make([]byte, net.IPv6len)
		if _, err = io.ReadFull(r, addr); err != nil {
			return "", "", err
		}
		host = net.IP(addr).String()
	case socks5ATYPDomain:
		length := make([]byte, 1)
		if _, err = io.ReadFull(r, length); err != nil {
			return "", "", err
		}
		domain := make([]byte, length[0])
		if _, err = io.ReadFull(r, domain); err != nil {
			return "", "", err
		}
		host = string(domain)
	default:
		return "", "", fmt.Errorf("unsupported address type %d", header[3])
	}

	portBytes := make([]byte, 2)
	if _, err = io.ReadFull(r, portBytes); err != nil {
		return "", "", err
	}
	port = strconv.Itoa(int(binary.BigEndian.Uint16(portBytes)))
	return host, port, nil
}

// socks5WriteReply sends a CONNECT reply. BND.ADDR/BND.PORT are
// conventionally 0.0.0.0:0 for a CONNECT-only proxy — real SOCKS5
// clients don't rely on these fields for anything once CONNECT
// succeeds.
func socks5WriteReply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{socks5Version, rep, 0x00, socks5ATYPIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
