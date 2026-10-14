# RedMarque — Architecture

## Why a library, not another embedded scanner-side guard

A letter of marque made attacking a specific ship legal. Without one,
the exact same act was piracy. A signed scope agreement is the pentest
industry's letter of marque — the only thing separating authorized
testing from a crime is whether the target falls inside the document
you were handed. RedMarque enforces that boundary mechanically instead
of leaving it to tester memory and discipline.

### Prior art

The *concept* of "check a scope.yaml before letting traffic through" is
not original, and pretending otherwise would be dishonest. It's been
implemented multiple times, independently:

- [slapy2-0/scopeguard](https://github.com/slapy2-0/scopeguard) — "No
  scope, no scan." Scope-checks are baked into its own WiFi/network
  scanner modules.
- [lordx64/pentestkit](https://github.com/lordx64/pentestkit) — an AI
  pentest-agent framework with an internal "scope-guarded chokepoint"
  for its own agent's traffic.
- [0xSteph/pentest-ai](https://github.com/0xSteph/pentest-ai),
  [ebottabi/hex](https://github.com/ebottabi/hex),
  [Thamidu-Nadun/ai-pentest-agent](https://github.com/Thamidu-Nadun/ai-pentest-agent)
  — three more AI pentest-agent projects independently adding their own
  internal scope-enforcement guardrails.

**The actual gap**: every one of those bakes scope-checking into its own
internal logic, specific to one scanner or one agent framework. None of
them is a standalone, protocol-level, importable component. Five
different projects are quietly reimplementing the same guard logic
because there's no shared dependency they could use instead. That's
RedMarque's reason to exist: be the boring, well-tested primitive other
tools — including future AI pentest-agent frameworks — can depend on,
instead of rewriting a worse version of it internally.

This is also why `pkg/scope` and `pkg/audit` are designed and documented
as a real public API from day one, not retrofitted into one later — a
library nobody but its own CLI can comfortably import doesn't close the
gap above, it just becomes a sixth entry in the list.

## System shape

```
                     ┌─────────────────────────┐
third-party agent -->│   pkg/scope (public)     │<-- marque validate
loop (examples/      │   pkg/audit (public)     │<-- marque doctor
embedding)           └───────────▲─────────────┘<-- marque engagement *
                                  │
                      ┌───────────┴─────────────┐
                      │  internal/proxy          │
                      │  (SOCKS5 + HTTP CONNECT) │
                      │  internal/run            │
                      │  (argv exec wrapper)     │
                      └───────────▲─────────────┘
                                  │
                      ┌───────────┴─────────────┐
                      │  cmd/marque (cobra CLI)  │
                      │  wiring only             │
                      └──────────────────────────┘
```

The arrow direction is the point: `pkg/scope` and `pkg/audit` know
nothing about proxies, CLIs, or cobra. Everything downstream depends on
them; they depend on nothing downstream. A third party importing
`pkg/scope` pulls in a parser and a matcher, not a SOCKS5 server they
don't want.

## Package layout

- **`pkg/scope`** — the correctness-critical core. Scope file parsing,
  CIDR/domain matching, include/exclude resolution, engagement window
  checks. Zero knowledge of networking, proxies, or I/O beyond reading
  the scope file itself. This is what Stage 1 is actually about.
- **`pkg/audit`** — hash-chained decision logging. Zero knowledge of
  scope semantics beyond the `Decision` struct it's handed; doesn't
  import `pkg/scope`, only the other way around, so a consumer could use
  `pkg/audit` to log something unrelated to scope decisions if they
  wanted to.
- **`internal/proxy`** — SOCKS5 + HTTP CONNECT server. A consumer of
  `pkg/scope`/`pkg/audit`, not a place where scope logic gets
  duplicated. If scope-matching logic is ever being written inside this
  package, that's a sign it belongs in `pkg/scope` instead.
- **`internal/run`** — best-effort argv regex extraction + exec. Also a
  pure consumer of `pkg/scope`/`pkg/audit`.
- **`cmd/marque`** — cobra command tree. Wiring only: flag parsing,
  reading the active engagement context, calling into the packages
  above, formatting output. No scope logic, no proxy logic.
- **`examples/embedding`** — a runnable, standalone example of a
  hypothetical third-party agent loop calling `scope.Check()` directly,
  with no proxy involved. This is the proof that the "reusable library"
  positioning is real and not just a README claim.

`internal/` (not `pkg/`) for `proxy` and `run` is deliberate: they are
reference implementations, not part of the promised public API. Nothing
stops a third party from writing their own proxy against `pkg/scope`
instead of using ours — in fact that's the whole point — so we don't owe
`internal/proxy` the same compatibility guarantees we owe `pkg/scope`.

## `pkg/scope` — public API

```go
package scope

type Scope struct { /* unexported fields */ }

func Load(path string) (*Scope, error)

func (s *Scope) Check(ip net.IP) Decision
func (s *Scope) CheckHost(host string) Decision

type Decision struct {
    Allowed     bool
    Mode        Mode   // enforce | warn | dry-run, carried from the scope file
    Target      string // the IP or hostname that was checked
    MatchedRule string // the include/exclude rule that decided this, for audit/debugging
    Reason      string // human-readable, e.g. "matched exclude 10.0.5.0/24 within include 10.0.0.0/16"
}

type Mode int
const (
    ModeEnforce Mode = iota
    ModeWarn
    ModeDryRun
)
```

Two check methods, not one — **confirmed**: the brief's illustrative
`scope.Check(ip net.IP) Decision` covers re-checking a *resolved*
address (the DNS-rebinding close), but the scope file also allows domain
entries with wildcard subdomains, and `internal/run` needs to check a
hostname pulled out of argv before anything has been resolved at all.
`CheckHost` matches against domain rules (and, for a literal IP-shaped
string, falls through to the same logic as `Check`); `Check` matches
against CIDR rules. Both are pure and synchronous — no DNS resolution
happens inside `pkg/scope` itself, which is what keeps it dependency-free
and usable from inside anyone's own event loop without surprising
network calls.

### Include/exclude resolution — confirmed

**Rule: exclude always wins.** Any target matching an `exclude` entry is
denied, full stop, regardless of how specific the matching `include`
entry is. A `/32` exclude inside a `/16` include wins — but so does a
`/8` exclude that happens to swallow a narrower `/28` include sitting
inside it; specificity is not a factor, only list membership. This is
simpler to reason about and to explain to a tester under pressure than a
specificity-ranked rule, at the deliberate cost of one representational
gap: a scope file cannot express "exclude this broad range, except for
one small subset the client explicitly carved back in." If a real ROE
ever needs that shape, it has to be written as a narrower, more
surgical `include` list instead of a broad include plus a carve-out —
a limitation worth knowing about going in, not discovering mid-engagement.

Ties within the same list (two overlapping includes, or two overlapping
excludes) don't need a specificity tiebreaker under this rule — only
include-vs-exclude membership matters, and exclude wins that comparison
unconditionally.

### Engagement window

`engagement.start`/`engagement.end` are ISO 8601. `Check`/`CheckHost`
return `Allowed: false` for any check performed outside that window,
independent of CIDR/domain matching — an in-scope IP checked after the
window closes is still a denial, with `Reason` saying so explicitly
rather than looking like an ordinary scope miss.

### `engagement.client` (optional)

A free-text client name (e.g. `"Acme Corp"`), surfaced in `Scope.Client`.
Purely cosmetic — never validated beyond trimming, never required.
Added in Stage 2 so the proxy's startup banner and `marque validate`'s
output could show "acme-2026q4 (Acme Corp)" per `docs/UX_FLOW.md`'s
mockups, which had always shown a client name the schema had no field
for.

## `pkg/audit` — public API

```go
package audit

type Entry struct {
    Timestamp   time.Time
    Decision    scope.Decision
    Hash        string // sha256(prevHash + canonical entry bytes)
    PrevHash    string
}

func Open(path string) (*Log, error)
func (l *Log) Log(d scope.Decision) error
func Verify(path string) error // walks the chain, returns the first broken link, if any
```

Format is newline-delimited JSON (one `Entry` per line) — human-greppable,
diffable, and doesn't need a YAML dependency in a package whose whole
job is being as dependency-light as the thing it's chained to.
`pkg/audit` depends on `pkg/scope` only for the `Decision` type it logs;
nothing flows the other direction.

"Tamper-evident, not tamper-proof," stated plainly in the package doc
comment, not just in `THREAT_MODEL.md` — anyone importing this package
should see the honest guarantee at the point they're deciding whether to
rely on it.

## Dependencies, justified

| Dependency | Used by | Why it's there |
|---|---|---|
| `gopkg.in/yaml.v3` | `pkg/scope` | Scope file format is YAML per the brief; this is the de facto standard YAML lib for Go and the only third-party dependency `pkg/scope` needs. |
| `golang.org/x/net/proxy` | `internal/proxy` | SOCKS5 server-side primitives, maintained by the Go team — avoids hand-rolling a protocol implementation for code that isn't the correctness-critical core. |
| `spf13/cobra` | `cmd/marque` | CLI wiring only; isolated to the one package (`cmd/marque`) that's allowed to not be minimal, since it's wiring, not library surface a third party inherits. |
| `stretchr/testify` | all `_test.go` files | Test-only (`assert`/`require`), never shipped in the built binary or inherited by importers. |

`pkg/scope` and `pkg/audit` — the packages a third party actually
imports — depend on nothing beyond the YAML parser (and `pkg/audit`
depends on nothing third-party at all). That's a deliberate constraint,
not an accident: every dependency added to those two packages becomes a
dependency every importer is forced to take, including competing AI
agent frameworks evaluating whether to adopt this instead of writing
their own.

## Module path

Needs a real GitHub org/username before `go.mod` is created in Stage 1,
since the module path becomes part of the public import path every
third-party consumer writes (`import ".../redmarque/pkg/scope"`) and is
awkward to change later without breaking them. Placeholder until
confirmed: `github.com/<org>/redmarque`.

## Versioning

`pkg/scope` and `pkg/audit` are real public API from the first commit:
godoc on every exported symbol, semver tags starting at `v0.x` while the
API is still settling (expect it to move during Stage 1 TDD), no breaking
change without a major version bump once `v1.0.0` is tagged. The CLI
(`cmd/marque`, `internal/*`) isn't held to the same compatibility bar —
flag shapes can still evolve post-v1 without a major bump, since
`docs/UX_FLOW.md` governs CLI ergonomics, not API compatibility.

## Build & release

Static binaries (`CGO_ENABLED=0`), cross-compiled for
linux/darwin × amd64/arm64 via `goreleaser`, checksummed and signed.
`gofmt` + `golangci-lint` in CI with zero warnings tolerated on merge.
No install-time dependency fetching — the binary is the whole artifact.

## Testing strategy (summary — see README/CI config for full detail)

- TDD on `pkg/scope`: table-driven tests covering include/exclude,
  overlapping ranges at varying specificity, wildcard subdomains, IPv4
  and IPv6, expired windows, malformed files.
- Native Go fuzzing (`go test -fuzz`) on the scope file parser and the
  matcher — must never panic, must never fail open on garbage input.
- Integration tests against a real SOCKS5/HTTP proxy on loopback —
  actual connections, not mocked transport.
- Golden-file tests for the audit log format, including one that asserts
  the hash chain detectably breaks under tampering.
- `go test -race` always, in CI, matrixed over Linux/macOS.
- Target ≥85% coverage on `pkg/scope` and `pkg/audit` specifically —
  not a repo-wide average that lets the core hide behind well-tested CLI
  wiring.
