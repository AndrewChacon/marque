package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"time"
)

// serveHTTPConnect handles the CONNECT method only — tunneling, the
// same job SOCKS5 does. A full HTTP forward proxy (relaying plain
// GET/POST with an absolute-form request line) is explicitly out of
// scope; anything that needs that should use the SOCKS5 listener
// instead.
func (p *Proxy) serveHTTPConnect(conn net.Conn, br *bufio.Reader) {
	// handleConn already set a read deadline covering the handshake;
	// clear it below once a full request has been parsed.
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		fmt.Fprint(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}

	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		fmt.Fprint(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	conn.SetReadDeadline(time.Time{})

	target, decision := p.connect(host, port)
	if target == nil {
		status := "502 Bad Gateway"
		if !decision.Allowed {
			status = "403 Forbidden"
		}
		fmt.Fprintf(conn, "HTTP/1.1 %s\r\n\r\n", status)
		return
	}
	defer target.Close()

	if _, err := fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	relay(conn, br, target)
}
