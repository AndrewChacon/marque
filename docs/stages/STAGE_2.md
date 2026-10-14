# Stage 2 — The Proxy

## Goal

Build the first "real" consumer that proves `pkg/scope`/`pkg/audit`
work under live traffic: a SOCKS5 + HTTP CONNECT proxy, with nothing
in it but calls out to the library already built in Stage 1.

## Actionable items

1. `internal/proxy`: SOCKS5 (via `golang.org/x/net/proxy` server-side
   primitives) + HTTP CONNECT, built entirely on `pkg/scope.Check` /
   `CheckHost` + `pkg/audit.Log` — no scope logic duplicated here; if
   scope-matching logic starts getting written inside this package,
   that's a sign it belongs in `pkg/scope` instead.
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

## What was implemented

_Not started yet._

## Issues that arose, and how they were fixed

_Not started yet._
