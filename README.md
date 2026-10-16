# RedMarque

[![CI](https://github.com/AndrewChacon/red-marque/actions/workflows/ci.yml/badge.svg)](https://github.com/AndrewChacon/red-marque/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/AndrewChacon/red-marque.svg)](https://pkg.go.dev/github.com/AndrewChacon/red-marque)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Mechanical scope enforcement for pentest engagements.** RedMarque
checks every target against a signed-off `scope.yaml` before traffic
reaches it — as a SOCKS5/HTTP CONNECT proxy, a one-off exec wrapper,
or a Go library you import directly — instead of leaving "is this
in scope?" to tester memory under time pressure.

A letter of marque made attacking a specific ship legal; without one,
the exact same act was piracy. A signed scope agreement is the pentest
industry's letter of marque — the only thing separating authorized
testing from a crime is whether the target falls inside the document
you were handed. RedMarque enforces that boundary mechanically instead
of trusting memory and discipline to hold under pressure at 2am on day
four of an engagement.

## What this is (and isn't)

RedMarque's threat model is **a mistaken keystroke, not a hostile
attacker** — it exists to catch a fat-fingered IP, a target list
copied from the wrong client's folder, a scan that kept running a few
hours after the window closed. It is a safety net for the tester, not
a sandbox that defeats the tester.

**It catches:**
- Traffic to a host outside the signed scope, or inside an excluded
  sub-range of an otherwise in-scope block (exclusions always win).
- DNS rebinding / TOCTOU — a hostname decision is re-checked against
  the *resolved* IP at connection time, since those two can legitimately
  disagree even with zero malicious intent anywhere in the chain.
- Continuing to operate after the engagement window has closed.
- An undetectable rewrite of the decision history — the audit log is
  hash-chained, so tampering leaves a detectable seam.

**It does not catch:**
- A tool that bypasses the configured proxy entirely (raw sockets,
  ignoring `HTTP_PROXY`, hardcoded egress). **This is the single
  biggest limitation of the whole project.**
- An operator deliberately trying to defeat their own tooling.
- Tamper-*proof* storage — the audit log is tamper-*evident* only.

Full reasoning, trust boundaries, and the complete in-scope/out-of-scope
list: [THREAT_MODEL.md](THREAT_MODEL.md).

## Install

```bash
go install github.com/AndrewChacon/red-marque/cmd/marque@latest
```

Or download a prebuilt binary for your OS/arch from the
[Releases page](https://github.com/AndrewChacon/red-marque/releases) —
checksummed and signed (cosign, keyless) static binaries, no runtime
dependencies.

Or build from source (Go 1.24+):

```bash
git clone https://github.com/AndrewChacon/red-marque
cd red-marque
go build -o marque ./cmd/marque
```

## Quickstart

```bash
# 1. Create an engagement from a signed ROE (interactive wizard, or --scope file.yaml)
marque engagement add acme-2026q4

# 2. Preflight — what's in scope, how long is the window
marque validate

# 3. Make it the active context
marque engagement use acme-2026q4

# 4. Enforce it — point Burp/proxychains/anything at the printed address
marque proxy
```

```
RedMarque — engagement: acme-2026q4 (Acme Corp)
window: 2026-10-14 → 2026-10-28 (14 days remaining)
mode: enforce · listening on 127.0.0.1:1080

backgrounded — pid 48213
  marque proxy status      check it's still running
  marque audit --tail      watch decisions live
  marque proxy stop        stop it
```

`marque proxy` backgrounds itself and hands your terminal straight
back — no second window needed. `marque audit --tail` picks up the
live decision feed whenever you want it:

```
$ marque audit --tail
ALLOW  10.0.1.5               matched include 10.0.0.0/16
BLOCK  10.0.5.9                matched exclude 10.0.5.0/24
```

Want the original always-visible, blocking behavior instead? `marque
proxy --foreground`.

Already have tooling you don't want to proxy? `marque run -- nmap -sV
target` checks argv against scope before exec'ing. Prefer proxychains?
`marque proxychains-config` emits a ready-to-use snippet. Full command
reference and both flows (single- and multi-engagement) are in
[docs/UX_FLOW.md](docs/UX_FLOW.md).

### Example `scope.yaml`

```yaml
engagement:
  name: acme-2026q4
  client: Acme Corp
  start: 2026-10-14T00:00:00Z
  end: 2026-10-28T00:00:00Z
scope:
  include:
    - 10.0.0.0/16
    - "*.acme-corp.test"
  exclude:
    - 10.0.5.0/24
```

`exclude` always wins, regardless of how specific the matching
`include` entry is — a broad `/16` grant with carved-out production
hosts is a common real ROE shape, and the carve-out has to hold.

`engagement.end` is optional — omit it for an open-ended engagement
(e.g. a bug bounty program with no fixed end date); `marque` then
shows "ongoing" everywhere a dated window would otherwise appear.

## CLI surface

```
marque engagement add <name> [--scope file.yaml]   # wizard or file import
marque engagement use <name>                        # set active context
marque engagement list                              # show all, with status
marque engagement current [--json] [--short]        # show what's active now
marque validate [--scope file.yaml]                 # preflight check
marque proxy [--scope file.yaml] [--force] [--foreground]  # SOCKS5 + HTTP CONNECT proxy, backgrounds by default
marque proxy stop                                   # stop the backgrounded proxy
marque proxy status                                 # check whether it's running
marque run [--scope file.yaml] -- <command>         # exec wrapper
marque audit [--scope file.yaml] --tail             # live decision feed
marque audit export --format json|markdown          # engagement-end artifact
marque proxychains-config                           # emit ready-to-use snippet
marque doctor                                       # preflight health check
marque version                                      # print version/build info
```

Every command accepts `--json` where output is structured, and honors
`NO_COLOR`.

## Using it as a library

`pkg/scope` and `pkg/audit` have no dependency on the proxy, the CLI,
or each other beyond the `Decision` type — they're meant to be
imported directly by third-party tools (an agent's tool-use loop, a
custom scanner), not just consumed through this CLI:

```go
s, err := scope.Load("scope.yaml")
if err != nil {
    log.Fatal(err)
}

d := s.CheckHost("target.acme-corp.test")
if !d.Allowed {
    log.Fatalf("out of scope: %s", d.Reason)
}
```

See [`examples/embedding`](examples/embedding) for a complete,
standalone, runnable example with no proxy or CLI involved, and
[ARCHITECTURE.md](ARCHITECTURE.md) for the full package layout and
public API.

## Prior art

The *concept* of "check a scope file before letting traffic through"
is not original, and pretending otherwise would be dishonest. It's
been implemented multiple times, independently — [slapy2-0/scopeguard](https://github.com/slapy2-0/scopeguard),
[lordx64/pentestkit](https://github.com/lordx64/pentestkit),
[0xSteph/pentest-ai](https://github.com/0xSteph/pentest-ai),
[ebottabi/hex](https://github.com/ebottabi/hex), and
[Thamidu-Nadun/ai-pentest-agent](https://github.com/Thamidu-Nadun/ai-pentest-agent)
each bake their own internal scope-guard into one scanner or one agent
framework. None of them is a standalone, protocol-level, importable
component — five different projects quietly reimplementing the same
guard logic because there's no shared dependency they could use
instead. That's RedMarque's reason to exist: the boring, well-tested
primitive other tools can depend on, instead of rewriting a worse
version of it internally.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — package layout, public API, dependency rationale
- [THREAT_MODEL.md](THREAT_MODEL.md) — adversary model, in/out of scope, fail-closed semantics
- [CHANGELOG.md](CHANGELOG.md) — notable changes, Keep a Changelog format
- [docs/UX_FLOW.md](docs/UX_FLOW.md) — full CLI flow, single- and multi-engagement
- [docs/stages](docs/stages) — build history: what was implemented at each stage and why
- [CONTRIBUTING.md](CONTRIBUTING.md) — local dev setup, running tests/lint, code style

## Lawful use

RedMarque is a defensive aid for engagements you are already
authorized to perform — it reduces the odds of an in-scope tester
accidentally touching something out of scope. It is not authorization
itself. Only use it against systems you hold a signed, written
engagement (Rules of Engagement / scope agreement) to test.
Unauthorized access to computer systems is illegal in most
jurisdictions regardless of what tooling was used. The authors and
contributors assume no liability for misuse.

## License

[Apache License 2.0](LICENSE).
