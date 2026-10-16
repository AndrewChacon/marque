package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/AndrewChacon/red-marque/pkg/audit"
	"github.com/stretchr/testify/require"
)

// TestServeHTTPConnect_ReturnsWithoutRelayingWhenReplyWriteFails is
// httpconnect.go's first dedicated white-box test — the file
// previously had none of its own, relying only on proxy_test.go's
// end-to-end httpConnect helper for indirect coverage. It closes the
// "200 Connection Established" reply-write-failure gap
// (httpconnect.go:43) the same way the SOCKS5 equivalent in
// proxy_test.go does: a synthetic failing Write instead of an
// unreproducible connection-reset race.
func TestServeHTTPConnect_ReturnsWithoutRelayingWhenReplyWriteFails(t *testing.T) {
	targetAddr, _ := startEchoTarget(t)
	targetHost, targetPort := splitHostPortInt(t, targetAddr)

	s := mustScope(t, fmt.Sprintf(`
scope:
  include:
    - %s
`, targetHost))

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(auditPath)
	require.NoError(t, err)
	t.Cleanup(func() { log.Close() })

	p := &Proxy{Scope: s, Audit: log}

	reqText := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", targetHost, targetPort, targetHost, targetPort)
	br := bufio.NewReader(bytes.NewReader([]byte(reqText)))
	conn := &writeFailAfterConn{Conn: pipeConnDrainingOtherEnd(t), succeedWrites: 0}

	done := make(chan struct{})
	go func() {
		p.serveHTTPConnect(conn, br)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveHTTPConnect did not return — a failed reply write must not fall through into relay()")
	}
}
