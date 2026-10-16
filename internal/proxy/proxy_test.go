package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AndrewChacon/marque/pkg/audit"
	"github.com/AndrewChacon/marque/pkg/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- test fixtures -----------------------------------------------------

func mustScope(t *testing.T, scopeYAML string) *scope.Scope {
	return mustScopeMode(t, "enforce", scopeYAML)
}

func mustScopeMode(t *testing.T, mode, scopeYAML string) *scope.Scope {
	t.Helper()
	doc := fmt.Sprintf(`
engagement:
  name: test
  start: %s
  end: %s
mode: %s
%s
`, time.Now().Add(-time.Hour).Format(time.RFC3339), time.Now().Add(time.Hour).Format(time.RFC3339), mode, scopeYAML)
	s, err := scope.Parse([]byte(doc))
	require.NoError(t, err)
	return s
}

// startProxy wires a Proxy to a real loopback listener and returns its
// address plus a channel receiving every Decision it makes.
func startProxy(t *testing.T, s *scope.Scope, resolver Resolver) (addr string, decisions chan scope.Decision) {
	t.Helper()

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(auditPath)
	require.NoError(t, err)
	t.Cleanup(func() { log.Close() })

	decisions = make(chan scope.Decision, 16)
	p := &Proxy{
		Scope:      s,
		Audit:      log,
		Resolver:   resolver,
		OnDecision: func(d scope.Decision) { decisions <- d },
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go p.Serve(ln)

	return ln.Addr().String(), decisions
}

// startEchoTarget is the "real target" every test connects through the
// proxy to — it just echoes back whatever it receives, which is
// enough to prove bytes actually flowed end to end through the real
// relay, not a mock.
func startEchoTarget(t *testing.T) (addr string, connCount *int32) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	connCount = new(int32)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(connCount, 1)
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	return ln.Addr().String(), connCount
}

func splitHostPortInt(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return host, port
}

// --- hand-rolled SOCKS5 test client -------------------------------------
//
// Deliberately not using golang.org/x/net/proxy here — pulling it into
// this module, even just for tests, would re-trigger the go.mod
// version-floor bump that was fixed earlier. The protocol is small
// enough to drive by hand.

func socks5Connect(t *testing.T, proxyAddr string, atyp byte, target string, port int) (net.Conn, byte) {
	t.Helper()

	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)

	_, err = conn.Write([]byte{socks5Version, 0x01, socks5MethodNoAuth})
	require.NoError(t, err)

	greet := make([]byte, 2)
	_, err = io.ReadFull(conn, greet)
	require.NoError(t, err)
	require.Equal(t, byte(socks5Version), greet[0])
	require.Equal(t, byte(socks5MethodNoAuth), greet[1], "server must accept no-auth")

	var req []byte
	switch atyp {
	case socks5ATYPDomain:
		req = append([]byte{socks5Version, socks5CmdConnect, 0x00, socks5ATYPDomain, byte(len(target))}, []byte(target)...)
	case socks5ATYPIPv4:
		ip := net.ParseIP(target).To4()
		require.NotNil(t, ip, "IPv4 path requires an IPv4 target")
		req = append([]byte{socks5Version, socks5CmdConnect, 0x00, socks5ATYPIPv4}, ip...)
	case socks5ATYPIPv6:
		ip := net.ParseIP(target).To16()
		require.NotNil(t, ip, "IPv6 path requires an IPv6 target")
		req = append([]byte{socks5Version, socks5CmdConnect, 0x00, socks5ATYPIPv6}, ip...)
	default:
		t.Fatalf("unsupported ATYP %d in test helper", atyp)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)

	_, err = conn.Write(req)
	require.NoError(t, err)

	reply := make([]byte, 4)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, byte(socks5Version), reply[0])

	bnd := make([]byte, net.IPv4len+2) // our server always replies with an IPv4 BND.ADDR/PORT
	_, err = io.ReadFull(conn, bnd)
	require.NoError(t, err)

	return conn, reply[1]
}

// --- hand-rolled HTTP CONNECT test client -------------------------------

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// writeFailAfterConn wraps a real net.Conn (so Read/deadlines/Close
// behave exactly as production code expects) but makes every Write
// call after the first succeedWrites calls fail deterministically —
// used to exercise a specific downstream reply-write failure branch
// without depending on an unreproducible connection-reset race.
type writeFailAfterConn struct {
	net.Conn
	succeedWrites int
	writeCount    int
}

func (c *writeFailAfterConn) Write(p []byte) (int, error) {
	c.writeCount++
	if c.writeCount > c.succeedWrites {
		return 0, fmt.Errorf("simulated write failure")
	}
	return c.Conn.Write(p)
}

// pipeConnDrainingOtherEnd returns one end of a net.Pipe(), with a
// goroutine continuously discarding from the other end so writes on
// the returned end never block waiting for a reader.
func pipeConnDrainingOtherEnd(t *testing.T) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	go io.Copy(io.Discard, b)
	t.Cleanup(func() { a.Close(); b.Close() })
	return a
}

// TestServeSOCKS5_ReturnsWithoutRelayingWhenSuccessReplyWriteFails
// closes a gap the original audit left untested: serveSOCKS5's one
// guarded write (socks5.go:61, `if err := socks5WriteReply(...); err
// != nil { return }`) now gets a deterministic repro via a synthetic
// failing Write, instead of relying on a real connection-reset race.
// If that guard were ever removed, this test would hang (relay()
// would run on a doomed connection instead of returning), not
// silently pass.
func TestServeSOCKS5_ReturnsWithoutRelayingWhenSuccessReplyWriteFails(t *testing.T) {
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

	ip := net.ParseIP(targetHost).To4()
	require.NotNil(t, ip)
	req := []byte{socks5Version, 0x01, socks5MethodNoAuth} // greeting: must succeed
	req = append(req, socks5Version, socks5CmdConnect, 0x00, socks5ATYPIPv4)
	req = append(req, ip...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(targetPort))
	req = append(req, portBytes...)

	conn := &writeFailAfterConn{Conn: pipeConnDrainingOtherEnd(t), succeedWrites: 1} // greeting ack succeeds; the CONNECT success reply does not
	br := bufio.NewReader(bytes.NewReader(req))

	done := make(chan struct{})
	go func() {
		p.serveSOCKS5(conn, br)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveSOCKS5 did not return — a failed reply write must not fall through into relay()")
	}
}

func httpConnect(t *testing.T, proxyAddr, target string) (net.Conn, int) {
	t.Helper()

	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)

	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	require.NoError(t, err)
	for {
		line, err := br.ReadString('\n')
		require.NoError(t, err)
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	parts := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	require.Len(t, parts, 3)
	code, err := strconv.Atoi(parts[1])
	require.NoError(t, err)

	return &bufferedConn{Conn: conn, r: br}, code
}

func roundtrip(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	_, err := conn.Write([]byte(msg))
	require.NoError(t, err)

	buf := make([]byte, len(msg))
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, msg, string(buf))
}

// socks5ConnectSafe is socks5Connect's goroutine-safe sibling: plain
// error returns instead of require/t.Fatalf, which is what the
// concurrency test below actually needs — require/FailNow are
// documented as unsafe to call from any goroutine other than the
// test's own, and socks5Connect is called from N worker goroutines
// there, not the main test goroutine.
func socks5ConnectSafe(proxyAddr string, target string, port int) (rep byte, err error) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{socks5Version, 0x01, socks5MethodNoAuth}); err != nil {
		return 0, err
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		return 0, err
	}

	req := append([]byte{socks5Version, socks5CmdConnect, 0x00, socks5ATYPDomain, byte(len(target))}, []byte(target)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)
	if _, err := conn.Write(req); err != nil {
		return 0, err
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return 0, err
	}
	bnd := make([]byte, net.IPv4len+2)
	if _, err := io.ReadFull(conn, bnd); err != nil {
		return 0, err
	}
	return reply[1], nil
}

// TestProxy_ConcurrentConnectionsAreIndependentlyCorrect is the
// regression test for a gap the original code audit flagged: every
// other test in this file exercises exactly one connection against
// its own freshly-started Proxy, so nothing had ever actually proven
// this package's correctness under concurrent load — only code review
// had. Half the connections target an in-scope address, half an
// out-of-scope one, fired at the same shared Proxy simultaneously.
func TestProxy_ConcurrentConnectionsAreIndependentlyCorrect(t *testing.T) {
	targetAddr, connCount := startEchoTarget(t)
	targetHost, targetPort := splitHostPortInt(t, targetAddr)

	s := mustScope(t, fmt.Sprintf(`
scope:
  include:
    - %s
`, targetHost))
	proxyAddr, decisions := startProxy(t, s, nil)

	const n = 40

	// decisions is only buffered to 16 (startProxy's fixed size), and
	// each server-side connection handler must send its Decision there
	// (via p.notify, before replying to its client — see proxy.go's
	// connect/handleConn) before that client's socks5ConnectSafe call
	// can return. With n=40 in flight at once, draining decisions only
	// after wg.Wait() would deadlock: the channel fills, server-side
	// sends block, clients never get replies, wg.Wait() never returns,
	// and nothing is left to drain the channel. Draining concurrently,
	// starting before the connection goroutines are even fired, avoids
	// that entirely.
	var allowedDecisions, deniedDecisions int32
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for i := 0; i < n; i++ {
			d := <-decisions
			if d.Allowed {
				atomic.AddInt32(&allowedDecisions, 1)
			} else {
				atomic.AddInt32(&deniedDecisions, 1)
			}
		}
	}()

	var wg sync.WaitGroup
	reps := make([]byte, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				reps[i], errs[i] = socks5ConnectSafe(proxyAddr, targetHost, targetPort)
			} else {
				reps[i], errs[i] = socks5ConnectSafe(proxyAddr, "denied.example", 80)
			}
		}(i)
	}
	wg.Wait()

	select {
	case <-drainDone:
	case <-time.After(5 * time.Second):
		t.Fatal("did not receive all 40 decisions in time")
	}

	var allowedReplies, deniedReplies int
	for i := 0; i < n; i++ {
		require.NoError(t, errs[i], "connection %d", i)
		switch reps[i] {
		case socks5ReplySucceeded:
			allowedReplies++
		case socks5ReplyNotAllowedByRuleset:
			deniedReplies++
		default:
			t.Fatalf("connection %d: unexpected SOCKS5 reply code %d", i, reps[i])
		}
	}
	assert.Equal(t, n/2, allowedReplies)
	assert.Equal(t, n/2, deniedReplies)

	assert.Equal(t, int32(n/2), atomic.LoadInt32(&allowedDecisions))
	assert.Equal(t, int32(n/2), atomic.LoadInt32(&deniedDecisions))
	assert.Equal(t, int32(n/2), atomic.LoadInt32(connCount), "only the allowed half should have actually dialed the real target")
}

// --- fake resolver for the DNS-rebinding test ---------------------------

type fakeResolver struct {
	answers map[string]net.IP
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ip, ok := f.answers[host]
	if !ok {
		return nil, fmt.Errorf("fakeResolver: no answer configured for %q", host)
	}
	return []net.IPAddr{{IP: ip}}, nil
}

// --- tests ---------------------------------------------------------------

func TestProxy_SOCKS5_AllowsInScopeDomain(t *testing.T) {
	targetAddr, _ := startEchoTarget(t)
	targetHost, targetPort := splitHostPortInt(t, targetAddr)

	s := mustScope(t, fmt.Sprintf(`
scope:
  include:
    - %s
`, targetHost))
	proxyAddr, decisions := startProxy(t, s, nil)

	conn, rep := socks5Connect(t, proxyAddr, socks5ATYPDomain, targetHost, targetPort)
	defer conn.Close()
	require.Equal(t, byte(socks5ReplySucceeded), rep)
	roundtrip(t, conn, "hello")

	d := <-decisions
	assert.True(t, d.Allowed)
}

func TestProxy_SOCKS5_BlocksOutOfScope(t *testing.T) {
	targetAddr, connCount := startEchoTarget(t)
	targetHost, targetPort := splitHostPortInt(t, targetAddr)

	s := mustScope(t, `
scope:
  include:
    - 10.0.0.0/8
`)
	proxyAddr, decisions := startProxy(t, s, nil)

	conn, rep := socks5Connect(t, proxyAddr, socks5ATYPDomain, targetHost, targetPort)
	defer conn.Close()
	assert.Equal(t, byte(socks5ReplyNotAllowedByRuleset), rep)

	d := <-decisions
	assert.False(t, d.Allowed)
	assert.Equal(t, int32(0), atomic.LoadInt32(connCount), "a denied target must never actually be dialed")
}

func TestProxy_SOCKS5_LiteralIPv4(t *testing.T) {
	targetAddr, _ := startEchoTarget(t)
	targetHost, targetPort := splitHostPortInt(t, targetAddr)

	s := mustScope(t, fmt.Sprintf(`
scope:
  include:
    - %s/32
`, targetHost))
	proxyAddr, _ := startProxy(t, s, nil)

	conn, rep := socks5Connect(t, proxyAddr, socks5ATYPIPv4, targetHost, targetPort)
	defer conn.Close()
	require.Equal(t, byte(socks5ReplySucceeded), rep)
	roundtrip(t, conn, "ipv4 literal")
}

func TestProxy_HTTPConnect_AllowsInScope(t *testing.T) {
	targetAddr, _ := startEchoTarget(t)
	targetHost, _ := splitHostPortInt(t, targetAddr)

	s := mustScope(t, fmt.Sprintf(`
scope:
  include:
    - %s
`, targetHost))
	proxyAddr, decisions := startProxy(t, s, nil)

	conn, code := httpConnect(t, proxyAddr, targetAddr)
	defer conn.Close()
	require.Equal(t, 200, code)
	roundtrip(t, conn, "hello")

	d := <-decisions
	assert.True(t, d.Allowed)
}

func TestProxy_HTTPConnect_BlocksOutOfScope(t *testing.T) {
	targetAddr, connCount := startEchoTarget(t)

	s := mustScope(t, `
scope:
  include:
    - 10.0.0.0/8
`)
	proxyAddr, decisions := startProxy(t, s, nil)

	conn, code := httpConnect(t, proxyAddr, targetAddr)
	defer conn.Close()
	assert.Equal(t, 403, code)

	d := <-decisions
	assert.False(t, d.Allowed)
	assert.Equal(t, int32(0), atomic.LoadInt32(connCount))
}

// TestProxy_DNSRebinding is the test the project brief calls out by
// name: a hostname that passes CheckHost must still be blocked if the
// address it actually resolves to lands somewhere the scope file
// explicitly excludes — proving the re-check at connection time isn't
// bypassable by a hostname whose DNS answer points somewhere the
// operator specifically carved out. The recheck is exclude-only (see
// scope.CheckResolvedIP's doc comment): resolving outside of some
// unrelated include CIDR is not itself suspicious, since most real
// scope files describe a target by domain alone with no CIDR at all —
// only resolving into an exclude range is the actual rebinding
// concern this guards against.
func TestProxy_DNSRebinding(t *testing.T) {
	targetAddr, connCount := startEchoTarget(t)
	targetHost, targetPort := splitHostPortInt(t, targetAddr)

	s := mustScope(t, fmt.Sprintf(`
scope:
  include:
    - rebind.test
  exclude:
    - %s/32
`, targetHost))
	resolver := &fakeResolver{answers: map[string]net.IP{
		"rebind.test": net.ParseIP(targetHost), // resolves into the explicitly excluded range
	}}
	proxyAddr, decisions := startProxy(t, s, resolver)

	conn, rep := socks5Connect(t, proxyAddr, socks5ATYPDomain, "rebind.test", targetPort)
	defer conn.Close()
	assert.Equal(t, byte(socks5ReplyNotAllowedByRuleset), rep, "hostname-allowed but resolved-into-excluded-range must still be blocked")
	assert.Equal(t, int32(0), atomic.LoadInt32(connCount))

	d := <-decisions
	assert.False(t, d.Allowed)
	assert.Contains(t, d.Reason, "DNS rebinding")
	assert.Equal(t, targetHost+"/32", d.MatchedRule, "the exclude CIDR that caused the rebinding denial must be in the structured field, not just free text")
}

// TestProxy_DomainOnlyInclude_NoCIDRNeeded is the regression test for
// the bug where any domain-only include rule — the common case, since
// most real scope files describe a target by domain, not CIDR, and a
// third-party site's IP ranges are rarely stable or enumerable —
// could never actually succeed through the proxy. The DNS-rebinding
// recheck used to require the resolved IP to also independently match
// an include CIDR, a bar no domain without one could ever clear. It
// must now succeed on a domain-only scope with no CIDR rule at all,
// regardless of what IP the domain happens to resolve to, as long as
// that address isn't itself excluded.
func TestProxy_DomainOnlyInclude_NoCIDRNeeded(t *testing.T) {
	targetAddr, _ := startEchoTarget(t)
	targetHost, targetPort := splitHostPortInt(t, targetAddr)

	s := mustScope(t, `
scope:
  include:
    - facebook.test
`)
	resolver := &fakeResolver{answers: map[string]net.IP{"facebook.test": net.ParseIP(targetHost)}}
	proxyAddr, decisions := startProxy(t, s, resolver)

	conn, rep := socks5Connect(t, proxyAddr, socks5ATYPDomain, "facebook.test", targetPort)
	defer conn.Close()
	require.Equal(t, byte(socks5ReplySucceeded), rep, "a domain-only include rule must work with no CIDR at all")
	roundtrip(t, conn, "domain-only include, no CIDR needed")

	d := <-decisions
	assert.True(t, d.Allowed)
	assert.Equal(t, "facebook.test", d.Target, "the logged target should be the hostname, not the resolved IP")
	assert.Contains(t, d.Reason, "matched include facebook.test")
}

func TestProxy_WarnMode_RelaysDeniedTrafficButLogsIt(t *testing.T) {
	targetAddr, connCount := startEchoTarget(t)
	targetHost, targetPort := splitHostPortInt(t, targetAddr)

	s := mustScopeMode(t, "warn", `
scope:
  include:
    - 10.0.0.0/8
`)
	proxyAddr, decisions := startProxy(t, s, nil)

	conn, rep := socks5Connect(t, proxyAddr, socks5ATYPDomain, targetHost, targetPort)
	defer conn.Close()
	require.Equal(t, byte(socks5ReplySucceeded), rep, "warn mode must relay even a denied target")
	roundtrip(t, conn, "warned but allowed through")
	assert.Equal(t, int32(1), atomic.LoadInt32(connCount))

	d := <-decisions
	assert.False(t, d.Allowed, "the logged decision must still say denied")
	assert.Equal(t, scope.ModeWarn, d.Mode)
}

func TestProxy_DryRunMode_NeverDialsRealTarget(t *testing.T) {
	targetAddr, connCount := startEchoTarget(t)
	targetHost, targetPort := splitHostPortInt(t, targetAddr)

	s := mustScopeMode(t, "dry-run", fmt.Sprintf(`
scope:
  include:
    - %s
`, targetHost))
	proxyAddr, decisions := startProxy(t, s, nil)

	conn, rep := socks5Connect(t, proxyAddr, socks5ATYPDomain, targetHost, targetPort)
	defer conn.Close()
	assert.NotEqual(t, byte(socks5ReplySucceeded), rep, "dry-run must never actually connect")
	assert.Equal(t, int32(0), atomic.LoadInt32(connCount), "dry-run must never dial the real target, even for an allowed decision")

	d := <-decisions
	assert.True(t, d.Allowed, "the decision itself is still computed and logged — only the dial is skipped")
	assert.Equal(t, scope.ModeDryRun, d.Mode)
}

func TestProxy_Resolver_DefaultsToNetDefaultResolver(t *testing.T) {
	p := &Proxy{}
	assert.Same(t, net.DefaultResolver, p.resolver())

	fake := &fakeResolver{}
	p.Resolver = fake
	assert.Same(t, Resolver(fake), p.resolver())
}

// TestProxy_HostnameFullyAllowed is the full happy path for a genuine
// (non-IP-literal) hostname: CheckHost allows it, the resolver
// answers, and the resolved IP isn't excluded. Deliberately no CIDR
// rule in this scope at all — see TestProxy_DomainOnlyInclude_NoCIDRNeeded's
// doc comment for why that's the realistic shape of a scope file.
func TestProxy_HostnameFullyAllowed(t *testing.T) {
	targetAddr, _ := startEchoTarget(t)
	targetHost, targetPort := splitHostPortInt(t, targetAddr)

	s := mustScope(t, `
scope:
  include:
    - acme.test
`)
	resolver := &fakeResolver{answers: map[string]net.IP{"acme.test": net.ParseIP(targetHost)}}
	proxyAddr, decisions := startProxy(t, s, resolver)

	conn, rep := socks5Connect(t, proxyAddr, socks5ATYPDomain, "acme.test", targetPort)
	defer conn.Close()
	require.Equal(t, byte(socks5ReplySucceeded), rep)
	roundtrip(t, conn, "real hostname path")

	d := <-decisions
	assert.True(t, d.Allowed)
}

// TestProxy_HostnameDeniedDirectly covers decide's early-return path:
// a hostname that CheckHost itself rejects, before any resolution is
// even attempted.
func TestProxy_HostnameDeniedDirectly(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - 10.0.0.0/8
`)
	proxyAddr, decisions := startProxy(t, s, &fakeResolver{}) // no answers configured — its answer must not matter, since CheckHost denies before resolvedIP is ever consulted

	conn, rep := socks5Connect(t, proxyAddr, socks5ATYPDomain, "evil.example", 80)
	defer conn.Close()
	assert.Equal(t, byte(socks5ReplyNotAllowedByRuleset), rep)

	d := <-decisions
	assert.False(t, d.Allowed)
	assert.NotContains(t, d.Reason, "rebinding", "a plain domain-not-included denial shouldn't be mislabeled as a rebinding case")
}

// TestProxy_HostnameAllowedButUnresolvable covers decide's
// could-not-be-resolved branch: the hostname matches an include rule,
// but the resolver has no answer for it.
func TestProxy_HostnameAllowedButUnresolvable(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - unresolvable.test
`)
	resolver := &fakeResolver{answers: map[string]net.IP{}}
	proxyAddr, decisions := startProxy(t, s, resolver)

	conn, rep := socks5Connect(t, proxyAddr, socks5ATYPDomain, "unresolvable.test", 80)
	defer conn.Close()
	assert.Equal(t, byte(socks5ReplyNotAllowedByRuleset), rep)

	d := <-decisions
	assert.False(t, d.Allowed)
	assert.Contains(t, d.Reason, "could not be resolved")
	assert.Contains(t, d.Reason, "fakeResolver: no answer configured for", "the specific resolution error must be surfaced, not just the generic reason")
}

func TestProxy_DialFailureWhenNothingListening(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - 127.0.0.1/32
`)
	proxyAddr, decisions := startProxy(t, s, nil)

	// Grab a free port, then release it immediately — nothing listens there.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	freePort := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	conn, rep := socks5Connect(t, proxyAddr, socks5ATYPDomain, "127.0.0.1", freePort)
	defer conn.Close()
	assert.Equal(t, byte(socks5ReplyGeneralFailure), rep)

	d := <-decisions
	assert.True(t, d.Allowed, "the decision itself is correctly allowed; only the dial failed")
}

// TestDial_NilIPReturnsImmediately covers dial's own guard against a
// nil resolved IP — reachable in practice from connect()'s ModeWarn
// path, which always dials regardless of Allowed, including when
// resolution failed entirely and resolvedIP is nil.
func TestDial_NilIPReturnsImmediately(t *testing.T) {
	p := &Proxy{}
	want := scope.Decision{Allowed: false, Reason: "unresolvable"}
	conn, got := p.dial(nil, "80", want)
	assert.Nil(t, conn)
	assert.Equal(t, want, got)
}

// emptyAnswerResolver simulates a resolver that succeeds with zero
// addresses — a shape fakeResolver's map-based answers can't produce
// (it always returns exactly one address or an error), but one a real
// resolver implementation could legitimately return.
type emptyAnswerResolver struct{}

func (emptyAnswerResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, nil
}

func TestResolveTarget_ZeroAddressesIsAnError(t *testing.T) {
	p := &Proxy{Resolver: emptyAnswerResolver{}}
	_, err := p.resolveTarget("example.test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no addresses found")
}

// failingAuditor always errors, proving connect()'s fail-closed
// override: an audit failure must deny regardless of Mode, which
// isn't reachable from pkg/audit's own test suite since that would
// require breaking a real file out from under an open *audit.Log.
type failingAuditor struct{}

func (failingAuditor) Log(scope.Decision) error { return fmt.Errorf("simulated audit failure") }

func TestProxy_AuditLogFailureDeniesRegardlessOfMode(t *testing.T) {
	targetAddr, connCount := startEchoTarget(t)
	targetHost, targetPort := splitHostPortInt(t, targetAddr)

	s := mustScopeMode(t, "warn", fmt.Sprintf(`
scope:
  include:
    - %s
`, targetHost))

	decisions := make(chan scope.Decision, 1)
	p := &Proxy{Scope: s, Audit: failingAuditor{}, OnDecision: func(d scope.Decision) { decisions <- d }}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go p.Serve(ln)

	conn, rep := socks5Connect(t, ln.Addr().String(), socks5ATYPDomain, targetHost, targetPort)
	defer conn.Close()
	assert.Equal(t, byte(socks5ReplyNotAllowedByRuleset), rep, "an audit failure must deny even in warn mode")
	assert.Equal(t, int32(0), atomic.LoadInt32(connCount))

	d := <-decisions
	assert.Empty(t, d.MatchedRule, "a stale MatchedRule from before the audit failure would be misleading next to the failure reason")
}

func TestProxy_SOCKS5_IPv6Literal(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback not available in this environment")
	}
	connCount := new(int32)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(connCount, 1)
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })

	_, port := splitHostPortInt(t, ln.Addr().String())

	s := mustScope(t, `
scope:
  include:
    - "::1/128"
`)
	proxyAddr, _ := startProxy(t, s, nil)

	conn, rep := socks5Connect(t, proxyAddr, socks5ATYPIPv6, "::1", port)
	defer conn.Close()
	require.Equal(t, byte(socks5ReplySucceeded), rep)
	roundtrip(t, conn, "ipv6")
	assert.Equal(t, int32(1), atomic.LoadInt32(connCount))
}

func TestProxy_SOCKS5_RejectsUnsupportedAuthMethod(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - 10.0.0.0/8
`)
	proxyAddr, _ := startProxy(t, s, nil)

	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte{socks5Version, 0x01, 0x02}) // offers only username/password auth
	require.NoError(t, err)

	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	assert.Equal(t, byte(socks5MethodNoAcceptable), reply[1])

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	one := make([]byte, 1)
	_, err = conn.Read(one)
	assert.Error(t, err, "connection should be closed after an unacceptable auth negotiation, not left open")
}

func TestProxy_SOCKS5_RejectsUnsupportedCommand(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - 10.0.0.0/8
`)
	proxyAddr, _ := startProxy(t, s, nil)

	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte{socks5Version, 0x01, socks5MethodNoAuth})
	require.NoError(t, err)
	greet := make([]byte, 2)
	_, err = io.ReadFull(conn, greet)
	require.NoError(t, err)

	req := []byte{socks5Version, 0x02 /* BIND, unsupported */, 0x00, socks5ATYPIPv4, 10, 0, 0, 1, 0, 80}
	_, err = conn.Write(req)
	require.NoError(t, err)

	reply := make([]byte, 4)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	assert.Equal(t, byte(socks5ReplyGeneralFailure), reply[1])
}

func TestProxy_HTTPConnect_RejectsNonConnectMethod(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - 10.0.0.0/8
`)
	proxyAddr, _ := startProxy(t, s, nil)

	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	defer conn.Close()

	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, statusLine, "400")
}

func TestProxy_HTTPConnect_RejectsMissingPort(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - 10.0.0.0/8
`)
	proxyAddr, _ := startProxy(t, s, nil)

	conn, code := httpConnect(t, proxyAddr, "example.com")
	defer conn.Close()
	assert.Equal(t, 400, code)
}

// startProxyWithTimeout is like startProxy but lets a test shrink
// NetworkTimeout, so timeout behavior is observable in milliseconds
// instead of waiting out a real multi-minute OS-level connect
// timeout. A Proxy field, not shared package state, so concurrent
// tests (and the proxy's own background goroutines) never race on it.
func startProxyWithTimeout(t *testing.T, s *scope.Scope, timeout time.Duration) (addr string, decisions chan scope.Decision) {
	t.Helper()

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(auditPath)
	require.NoError(t, err)
	t.Cleanup(func() { log.Close() })

	decisions = make(chan scope.Decision, 16)
	p := &Proxy{
		Scope:          s,
		Audit:          log,
		NetworkTimeout: timeout,
		OnDecision:     func(d scope.Decision) { decisions <- d },
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go p.Serve(ln)

	return ln.Addr().String(), decisions
}

// TestProxy_DialTimeout guards against the real-world failure mode a
// pentest proxy hits constantly: scanning any real range includes
// unreachable or firewalled hosts, and a bare net.Dial with no
// timeout can hang for the OS's full SYN-retry window (1-2+ minutes
// on Linux) per such attempt. 10.255.255.1 is the standard
// "likely to hang, not instantly refuse" test address; the assertion
// is on wall-clock time, not the exact failure reason, since whether
// this specific address black-holes or refuses outright can vary by
// environment — what must always be true is that the proxy never
// hangs anywhere near the old unbounded default.
func TestProxy_DialTimeout(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - 10.255.255.1/32
`)
	proxyAddr, decisions := startProxyWithTimeout(t, s, 200*time.Millisecond)

	start := time.Now()
	conn, rep := socks5Connect(t, proxyAddr, socks5ATYPDomain, "10.255.255.1", 1)
	elapsed := time.Since(start)
	defer conn.Close()

	assert.Less(t, elapsed, 2*time.Second, "a dial to an unreachable address must not hang")
	assert.Equal(t, byte(socks5ReplyGeneralFailure), rep)

	d := <-decisions
	assert.True(t, d.Allowed, "the decision itself is correctly allowed; only the dial couldn't complete")
}

// TestProxy_HandshakeReadDeadline covers the other half of the same
// fix: a connection that opens but never sends its SOCKS5 greeting
// must not hold a goroutine open forever.
func TestProxy_HandshakeReadDeadline(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - 10.0.0.0/8
`)
	proxyAddr, _ := startProxyWithTimeout(t, s, 200*time.Millisecond)

	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	defer conn.Close()

	// Deliberately send nothing. A generous client-side deadline is
	// just a safety net so the test itself can't hang if the fix
	// regresses; the real assertion is how quickly it returns.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	one := make([]byte, 1)
	start := time.Now()
	_, err = conn.Read(one)
	elapsed := time.Since(start)

	assert.Error(t, err, "server must close a connection that never completes its handshake")
	assert.Less(t, elapsed, 1*time.Second, "should close near the server's 200ms handshake deadline, not the test's 2s fallback")
}
