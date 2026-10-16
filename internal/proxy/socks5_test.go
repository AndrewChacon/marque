package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These are direct, white-box unit tests against socks5Greeting and
// socks5ReadRequest's wire parsing — hand-crafted byte sequences
// rather than real TCP connections, so every truncated/malformed
// input shape can be covered quickly and precisely. The project's
// fail-closed guarantee depends on this parser rejecting bad input
// cleanly rather than panicking or misbehaving; these were previously
// untested gaps surfaced by a coverage pass, not known bugs.

func TestSocks5Greeting_TruncatedHeader(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{socks5Version})) // missing NMETHODS byte
	var out bytes.Buffer
	err := socks5Greeting(r, &out)
	require.Error(t, err)
}

func TestSocks5Greeting_UnsupportedVersion(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{0x04, 0x01, socks5MethodNoAuth}))
	var out bytes.Buffer
	err := socks5Greeting(r, &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported SOCKS version")
}

func TestSocks5Greeting_TruncatedMethodsList(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{socks5Version, 0x05})) // claims 5 methods, provides none
	var out bytes.Buffer
	err := socks5Greeting(r, &out)
	require.Error(t, err)
}

func TestSocks5ReadRequest_TruncatedHeader(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{socks5Version, socks5CmdConnect})) // missing RSV + ATYP
	_, _, err := socks5ReadRequest(r)
	require.Error(t, err)
}

func TestSocks5ReadRequest_UnsupportedVersion(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{0x04, socks5CmdConnect, 0x00, socks5ATYPIPv4}))
	_, _, err := socks5ReadRequest(r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported SOCKS version")
}

func TestSocks5ReadRequest_UnsupportedCommand(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{socks5Version, 0x02 /* BIND, not CONNECT */, 0x00, socks5ATYPIPv4}))
	_, _, err := socks5ReadRequest(r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported SOCKS command")
}

func TestSocks5ReadRequest_UnsupportedAddressType(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{socks5Version, socks5CmdConnect, 0x00, 0x02 /* unsupported ATYP */}))
	_, _, err := socks5ReadRequest(r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported address type")
}

func TestSocks5ReadRequest_TruncatedIPv4Address(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{socks5Version, socks5CmdConnect, 0x00, socks5ATYPIPv4, 10, 0})) // only 2 of 4 address bytes
	_, _, err := socks5ReadRequest(r)
	require.Error(t, err)
}

func TestSocks5ReadRequest_TruncatedIPv6Address(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{socks5Version, socks5CmdConnect, 0x00, socks5ATYPIPv6, 0x20, 0x01})) // only 2 of 16 address bytes
	_, _, err := socks5ReadRequest(r)
	require.Error(t, err)
}

func TestSocks5ReadRequest_TruncatedDomainLength(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{socks5Version, socks5CmdConnect, 0x00, socks5ATYPDomain})) // missing length byte
	_, _, err := socks5ReadRequest(r)
	require.Error(t, err)
}

func TestSocks5ReadRequest_TruncatedDomainBody(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{socks5Version, socks5CmdConnect, 0x00, socks5ATYPDomain, 10, 'a', 'b', 'c'})) // claims 10 bytes, only 3 given
	_, _, err := socks5ReadRequest(r)
	require.Error(t, err)
}

func TestSocks5ReadRequest_TruncatedPort(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{socks5Version, socks5CmdConnect, 0x00, socks5ATYPIPv4, 10, 0, 0, 1, 0x00})) // only 1 of 2 port bytes
	_, _, err := socks5ReadRequest(r)
	require.Error(t, err)
}

func TestSocks5ReadRequest_ValidDomainRequest(t *testing.T) {
	domain := "example.com"
	buf := []byte{socks5Version, socks5CmdConnect, 0x00, socks5ATYPDomain, byte(len(domain))}
	buf = append(buf, []byte(domain)...)
	buf = append(buf, 0x01, 0xBB) // port 443
	r := bufio.NewReader(bytes.NewReader(buf))

	host, port, err := socks5ReadRequest(r)
	require.NoError(t, err)
	assert.Equal(t, "example.com", host)
	assert.Equal(t, "443", port)
}

type erroringWriter struct{}

func (erroringWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("simulated write failure") }

// TestSocks5WriteReply_PropagatesWriteError confirms the write
// failure itself surfaces correctly. serveSOCKS5's own call site
// (`if err := socks5WriteReply(...); err != nil { return }`) has its
// own deterministic test too — see
// TestServeSOCKS5_ReturnsWithoutRelayingWhenSuccessReplyWriteFails in
// proxy_test.go, which forces the failure with a synthetic net.Conn
// wrapper instead of relying on an unreproducible connection-reset
// race.
func TestSocks5WriteReply_PropagatesWriteError(t *testing.T) {
	err := socks5WriteReply(erroringWriter{}, socks5ReplySucceeded)
	require.Error(t, err)
}
