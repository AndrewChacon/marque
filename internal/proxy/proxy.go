// Package proxy is a SOCKS5 + HTTP CONNECT proxy that enforces an
// engagement scope on every connection it relays. It contains no
// scope-matching or audit-logging logic of its own — every decision
// is one of pkg/scope's Check, CheckHost, or CheckResolvedIP methods,
// every record is pkg/audit.Log. See docs/THREAT_MODEL.md: this is a
// safety net for traffic routed through it, not a sandbox — a tool
// that bypasses the proxy entirely is invisible to it.
package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/AndrewChacon/marque/pkg/scope"
)

// defaultNetworkTimeout is used when Proxy.NetworkTimeout is zero.
const defaultNetworkTimeout = 10 * time.Second

// Auditor is the logging dependency Proxy needs — satisfied by
// *audit.Log without any wrapping. Declaring it as an interface
// (rather than depending on *audit.Log directly) is what makes the
// fail-closed-on-logging-failure behavior testable: a test can supply
// an Auditor that always errors, which isn't otherwise reachable from
// outside pkg/audit.
type Auditor interface {
	Log(scope.Decision) error
}

// Proxy serves SOCKS5 and HTTP CONNECT on the same listener,
// detecting which protocol a connection is speaking from its first
// byte.
type Proxy struct {
	Scope *scope.Scope
	Audit Auditor

	// Resolver resolves hostnames; nil defaults to net.DefaultResolver.
	Resolver Resolver

	// OnDecision, if set, is called once per connection attempt with
	// its final Decision — the hook a caller uses for a live stream.
	OnDecision func(scope.Decision)

	// NetworkTimeout bounds every network operation except the relay
	// itself: DNS resolution, dialing the target, and reading a
	// client's handshake. Zero means defaultNetworkTimeout. The relay
	// phase must stay unbounded — a long-lived interactive session
	// (reverse shell, SSH tunnel) tunneled through this proxy is
	// normal pentest traffic, not something to deadline.
	NetworkTimeout time.Duration
}

func (p *Proxy) timeout() time.Duration {
	if p.NetworkTimeout > 0 {
		return p.NetworkTimeout
	}
	return defaultNetworkTimeout
}

// Serve accepts connections on ln until Accept errors — including
// when ln is closed, which a caller doing a graceful shutdown should
// treat as a normal exit, not a failure.
func (p *Proxy) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go p.handleConn(conn)
	}
}

func (p *Proxy) handleConn(conn net.Conn) {
	defer conn.Close()

	// Bounds how long we wait for a client to even start speaking,
	// including this protocol-detection peek — a client that opens a
	// connection and sends nothing at all must not hold a goroutine
	// open indefinitely. Each protocol handler clears this once it has
	// successfully parsed a request; the dial/resolve/relay phase that
	// follows is deliberately unbounded (dial has its own timeout).
	conn.SetReadDeadline(time.Now().Add(p.timeout()))

	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		return
	}

	if first[0] == socks5Version {
		p.serveSOCKS5(conn, br)
	} else {
		p.serveHTTPConnect(conn, br)
	}
}

func (p *Proxy) resolver() Resolver {
	if p.Resolver != nil {
		return p.Resolver
	}
	return net.DefaultResolver
}

// resolveTarget returns host itself if it's already a literal IP, or
// resolves it otherwise. Resolution is always attempted regardless of
// scope — decide uses the result to re-check the actual address, and
// ModeWarn needs an address to dial even for a denied target.
func (p *Proxy) resolveTarget(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout())
	defer cancel()
	addrs, err := p.resolver().LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses found for %q", host)
	}
	return addrs[0].IP, nil
}

// decide is the DNS-rebinding close described in docs/THREAT_MODEL.md: a
// hostname-based decision and the IP it actually resolves to are not
// guaranteed to agree, so a hostname that passes CheckHost still has
// its resolved address re-checked with CheckResolvedIP before
// anything is trusted — see that method's doc comment for why this
// is deliberately an exclude-only recheck, not a second, independent
// CIDR match.
func (p *Proxy) decide(host string, resolvedIP net.IP, resolveErr error) scope.Decision {
	if ip := net.ParseIP(host); ip != nil {
		return p.Scope.Check(ip)
	}

	hostDecision := p.Scope.CheckHost(host)
	if !hostDecision.Allowed {
		return hostDecision
	}
	if resolvedIP == nil {
		reason := "hostname matched an include rule but could not be resolved"
		if resolveErr != nil {
			reason = fmt.Sprintf("hostname matched an include rule but could not be resolved: %v", resolveErr)
		}
		return p.deny(host, "", reason)
	}

	ipDecision := p.Scope.CheckResolvedIP(resolvedIP)
	if !ipDecision.Allowed {
		return p.deny(host, ipDecision.MatchedRule, fmt.Sprintf(
			"%q matched an include rule, but it resolves to %s, which is explicitly excluded (possible DNS rebinding): %s",
			host, resolvedIP, ipDecision.Reason,
		))
	}
	return scope.Decision{
		Allowed:     true,
		Mode:        p.Scope.Mode,
		Target:      host,
		MatchedRule: hostDecision.MatchedRule,
		Reason:      fmt.Sprintf("%s (resolved to %s)", hostDecision.Reason, resolvedIP),
	}
}

// deny builds a denial Decision for host with the Scope's Mode
// carried through — the fields decide()'s two deny cases would
// otherwise repeat.
func (p *Proxy) deny(host, rule, reason string) scope.Decision {
	return scope.Decision{Allowed: false, Mode: p.Scope.Mode, Target: host, MatchedRule: rule, Reason: reason}
}

func (p *Proxy) notify(d scope.Decision) {
	if p.OnDecision != nil {
		p.OnDecision(d)
	}
}

// connect resolves and scope-checks host, logs the resulting
// decision, and — depending on Mode — dials the checked address. It
// always dials the specific net.IP that was just checked, never the
// original hostname string: handing a hostname to net.Dial would let
// it re-resolve independently, silently defeating the check above.
//
// A logging failure is a hard deny no Mode can override — per
// docs/THREAT_MODEL.md, an unaudited allow is indistinguishable from no
// safety net at all.
func (p *Proxy) connect(host, port string) (net.Conn, scope.Decision) {
	resolvedIP, resolveErr := p.resolveTarget(host)
	decision := p.decide(host, resolvedIP, resolveErr)

	if err := p.Audit.Log(decision); err != nil {
		decision.Allowed = false
		decision.MatchedRule = ""
		decision.Reason = fmt.Sprintf("audit log write failed (%v); denying rather than proceed unaudited", err)
		p.notify(decision)
		return nil, decision
	}
	p.notify(decision)

	switch decision.Mode {
	case scope.ModeDryRun:
		return nil, decision
	case scope.ModeWarn:
		return p.dial(resolvedIP, port, decision)
	default: // scope.ModeEnforce
		if !decision.Allowed {
			return nil, decision
		}
		return p.dial(resolvedIP, port, decision)
	}
}

func (p *Proxy) dial(ip net.IP, port string, decision scope.Decision) (net.Conn, scope.Decision) {
	if ip == nil {
		return nil, decision
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), p.timeout())
	if err != nil {
		return nil, decision
	}
	return conn, decision
}

// relay copies bytes in both directions until either side closes.
// clientReader must be whatever already buffered the protocol
// handshake bytes (a bufio.Reader wrapping client) rather than client
// itself — a client that pipelines its first request right after the
// handshake would otherwise have those already-buffered bytes
// silently dropped.
func relay(client net.Conn, clientReader *bufio.Reader, target net.Conn) {
	done := make(chan struct{}, 1)
	go func() {
		io.Copy(target, clientReader)
		done <- struct{}{}
	}()
	io.Copy(client, target)
	client.Close()
	target.Close()
	<-done
}
