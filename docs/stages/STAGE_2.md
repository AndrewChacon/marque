# Stage 2 — The Proxy

## Goal

Build the first "real" consumer that proves `pkg/scope`/`pkg/audit`
work under live traffic: a SOCKS5 + HTTP CONNECT proxy, with nothing
in it but calls out to the library already built in Stage 1.

## Actionable items

1. `internal/proxy`: SOCKS5 + HTTP CONNECT, built entirely on
   `pkg/scope.Check` / `CheckHost` + `pkg/audit.Log` — no scope logic
   duplicated here; if scope-matching logic starts getting written
   inside this package, that's a sign it belongs in `pkg/scope`
   instead. (The brief originally said "via `golang.org/x/net/proxy`
   server-side primitives" — see Issues below, that package turned out
   not to have any.)
2. Re-check the resolved IP at connection time, independent of any
   earlier hostname-based decision — the DNS-rebinding close. Explicit
   test proving a hostname-allowed, IP-denied case gets blocked.
3. `marque proxy [--scope file.yaml] [--force]`: startup banner per
   `docs/UX_FLOW.md`, refuses to start on an expired engagement window
   without `--force`, live color-coded decision stream (green allow /
   red block).
4. Integration tests: spin up the real SOCKS5/HTTP proxy on loopback,
   assert actual allow/block behavior against real connections — not
   mocks.

(Added along the way: an optional `engagement.client` field on the
scope file, needed for the banner's "acme-2026q4 (Acme Corp)" mockup
in `docs/UX_FLOW.md`, which the schema had no field for.)

## What was implemented

### `pkg/scope`

- `Client` field (optional, trimmed, never validated beyond that) —
  the only Stage 2 change to the library itself.

### `internal/proxy`

- One listener serves both protocols, detected from the connection's
  first byte (`0x05` for SOCKS5, anything else treated as HTTP)
  instead of needing two separate ports.
- A shared pipeline (`connect`/`decide`/`resolveTarget` in `proxy.go`)
  is the actual enforcement point every protocol handler funnels
  through: a hostname target is checked twice — once by name
  (`CheckHost`), then again against whatever it actually resolves to
  (`Check`) — and the dial always targets the specific `net.IP` that
  was just checked, never the original hostname string, since handing
  `net.Dial` a hostname would let it re-resolve independently and
  silently defeat the whole check.
- Every decision, allow or deny, goes through `audit.Log` before
  anything else happens. `Proxy.Audit` is declared as a small
  `Auditor` interface (one method, matching `*audit.Log`'s own `Log`
  method) rather than depending on the concrete type directly —
  specifically so "an audit failure is a hard deny no Mode can
  override" has a real test, via a fake `Auditor` that always errors.
  That behavior isn't otherwise reachable from outside `pkg/audit`.
- `Mode` (`enforce`/`warn`/`dry-run`) is honored exactly per the
  godoc `pkg/scope.Mode` already had from Stage 1 — nothing new was
  invented here, just implemented faithfully.
- SOCKS5 is CONNECT-only (RFC 1928; BIND/UDP ASSOCIATE have no use
  case here), HTTP is CONNECT-tunneling-only — a full forward proxy
  relaying plain `GET`/`POST` is explicitly out of scope, matching the
  brief's own wording ("HTTP CONNECT proxy").
- Integration tests run against a real `Proxy.Serve` on a real
  loopback listener, no mocks: both protocols' allow/deny paths, the
  DNS-rebinding case, warn/dry-run mode, malformed protocol input,
  IPv4/IPv6 literals, dial failure, and the audit-failure hard-deny.
  89.2% coverage. A hand-rolled SOCKS5 test client is used throughout
  (see Issues below for why).

### `cmd/marque`

- `marque proxy --scope file.yaml [--force] [--listen addr]
  [--audit-log path] [--json]` — startup banner (now showing the
  client name when present), the `--force` gate as its own pure,
  directly-testable function (`checkProxyPreflight`), audit log
  defaulting to `audit.jsonl` next to `--scope`, graceful shutdown on
  `SIGINT`/`SIGTERM`.
- `validate.go`'s `warnColor` generalized into a shared `colorize`
  helper (`color.go`) used by both commands.
- Smoke-tested as a real static binary: real `curl` traffic through
  both SOCKS5 and HTTP CONNECT against a local target, confirmed
  allow/block behavior and matching audit log entries, confirmed the
  `--force` gate on an expired window, confirmed clean shutdown on a
  real `SIGINT`.

## Issues that arose, and how they were fixed

1. **The brief's tech-stack decision for SOCKS5 didn't hold up.**
   "`golang.org/x/net/proxy` server-side primitives" — checked
   directly via `go doc golang.org/x/net/proxy` before writing any
   proxy code, and that package only contains a *client* (`Dialer`,
   `SOCKS5()` for connecting *through* a proxy, `FromEnvironment`,
   `PerHost`). There's no server in it at all. **Fixed** by hand-rolling
   both the SOCKS5 and HTTP CONNECT servers against the standard
   library instead — confirmed with the user before writing any of it,
   since it meant deviating from an explicitly "decided" dependency.

2. **That same package would have been tempting to use just for
   tests** (driving the SOCKS5 server with a real client implementation
   instead of testing against our own assumptions) — but importing it
   anywhere in this module, even in `_test.go` files, would have
   re-triggered the exact `go.mod` version-floor bump (Go 1.26) that
   got fixed in Stage 1, for the whole module, including every
   importer of `pkg/scope`/`pkg/audit` who has nothing to do with the
   proxy. **Fixed** by hand-rolling a minimal SOCKS5 test client too —
   the protocol is small enough that this cost very little, and it
   kept the whole module on Go 1.24.4 with zero new dependencies.

3. **`cmd/marque` coverage dropped from 88.5% to 55.8%** after adding
   the proxy command — looked like a regression at first glance, but
   checking per-function coverage showed every single line of actual
   logic (`checkProxyPreflight`, `printProxyBanner`, `printDecision`)
   sitting at 100%; the only 0% functions were `runProxy` itself (the
   real blocking listener + signal-handling lifecycle) and the trivial
   command-construction wiring, same category as `main`/`newRootCmd`
   which were already 0% before this stage. **Not actually a gap** —
   a deliberate scoping decision: the real substance is already proven
   by `internal/proxy`'s integration tests, and the full lifecycle got
   verified by hand (real binary, real `curl`, real `Ctrl-C`) rather
   than with elaborate signal-injection test machinery for a thin CLI
   wiring layer.

4. **The manual smoke test's first HTTP CONNECT attempt returned an
   empty response** where a page body was expected. Not a proxy bug —
   `curl -x <proxy> http://...` only uses `CONNECT` tunneling for
   `https://` targets by default; for a plain `http://` target it sends
   a direct forward-proxy request instead, which is exactly the "full
   HTTP forward-proxying" mode this stage deliberately doesn't
   implement. The server correctly replied `400 Bad Request`. **Fixed**
   by re-running with `curl --proxytunnel` to force real `CONNECT`
   tunneling for the local target, confirming the allow path actually
   works — and confirming the documented limitation behaves exactly as
   specified rather than crashing or hanging.
