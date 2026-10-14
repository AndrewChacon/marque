# Stage 3 — Second Consumer, CLI Polish, Embedding Proof

## Goal

Prove `pkg/scope` is genuinely reusable outside RedMarque's own proxy,
and round out the CLI with the remaining thin wrappers over the
library.

## Actionable items

1. `marque run [--scope file.yaml] -- <command>`: best-effort regex
   extraction of IPs/hostnames from argv, checked against `pkg/scope`
   before exec. Explicitly not per-tool argument parsers for every
   pentest tool — that's out of scope.
2. `marque engagement add/use/list`: named-context layer per
   `docs/UX_FLOW.md`. `add` runs an interactive wizard or accepts
   `--scope file.yaml` non-interactively; `use` sets the active
   engagement; `list` shows all with status (active/expired/upcoming)
   — reuse the same status vocabulary `cmd/marque/validate.go`'s
   `windowStatus` already established in Stage 1, don't invent a
   second one.
3. `marque doctor`: preflight health check — is an engagement active,
   has it expired, is the scope file still parseable, is the proxy
   port free.
4. `marque proxychains-config`: emits a ready-to-use proxychains
   snippet.
5. `marque audit --tail` and `marque audit export --format
   json|markdown`: live decision feed and an engagement-end export
   artifact.
6. `examples/embedding/`: a standalone, runnable example of a
   hypothetical third-party agent loop calling `pkg/scope.Check()`
   directly, no proxy involved — the concrete proof the "reusable
   library" positioning is real, not just a README claim.
7. Credential redaction in HTTP proxy logging — no Authorization
   headers, cookies, or bodies in the audit log without an explicit
   opt-in flag.

_Note: fuzz tests for the parser and matcher were originally planned
for this stage but were already completed in Stage 1, ahead of
schedule._

## What was implemented

- **`internal/engagement`**: a `Store` struct (injectable `Root`, same
  DI-for-testability pattern as `internal/proxy`'s `Resolver`/
  `Auditor`) backing `~/.marque`. Active engagement is a single
  plain-text file (`~/.marque/active`); each named engagement gets its
  own `scope.yaml` and `audit.jsonl` under
  `~/.marque/engagements/<name>/`.
- **`cmd/marque/engagement.go`**: `resolvePaths`, the one shared place
  every scope-aware command resolves its scope file and audit log —
  explicit `--scope` always wins (audit log defaults to a sibling
  `audit.jsonl`), otherwise it falls back to the active engagement
  (audit log defaults to that engagement's own directory). `validate`
  and `proxy` were retrofitted onto this, dropping the Stage 2
  `MarkFlagRequired("scope")` now that `--scope` is a one-off override
  rather than mandatory, per `docs/UX_FLOW.md`.
- **`marque engagement add/use/list`**: wizard (`YYYY-MM-DD` dates,
  pure `runWizard(r, w, name)` function, independent of real stdin) or
  non-interactive `--scope file.yaml` import; `use` sets the active
  context and echoes back a loud warning if the window's already
  expired; `list` renders a table reusing the existing
  active/expired/upcoming status vocabulary, with a separate `→` arrow
  marking which engagement is currently selected — two different axes
  (window status vs. selected context), two different markers.
- **`marque run [--scope file.yaml] -- <command>`**: best-effort
  regex/URL extraction of IPs and hostnames from argv, checked against
  the resolved scope before exec. Any denial is loud and refuses to
  exec (non-zero exit); all decisions are audit-logged either way.
  Uses `syscall.Exec` (process replacement), not fork+wait.
- **`marque doctor`**: brew-doctor style PASS/WARN/FAIL checks — is an
  engagement active, does its scope file still parse, has its window
  expired or is it upcoming, is the default proxy port
  (`127.0.0.1:1080`) free. Exits non-zero on any FAIL.
- **`marque proxychains-config [--listen addr]`**: emits a
  `[ProxyList]` / `socks5 host port` snippet, default matching `marque
  proxy`'s own default `--listen`.
- **`marque audit [--scope file.yaml] --tail`**: polls the log file
  for newly appended bytes (not `bufio.Scanner`, which caches EOF and
  can't resume once a growing file hits it) and renders new decisions
  live through the same `printDecision` formatter `marque proxy` uses,
  so the two commands render identically.
- **`marque audit export --format json|markdown`**: full log dump plus
  engagement window/summary stats. Runs `audit.Verify()` first; a
  failed verification does not block the export (this is a reporting
  command, not an enforcement gate — a tester's own historical records
  aren't withheld for it) but is embedded as a loud warning banner in
  the exported artifact itself.
- **`examples/embedding/`**: a standalone `package main` in the same
  module, with its own `scope.yaml`, calling `scope.Load` +
  `CheckHost` directly over a hardcoded target list — no proxy, no
  CLI. Runnable via `go run ./examples/embedding` from the repo root.
- **Credential redaction**: confirmed as a documented non-issue rather
  than a feature to build — see "Design decision: no credential
  redaction" below.

## Design decision: no credential redaction

The Stage 3 actionable-items list (drafted ahead of implementation)
originally included "no Authorization headers, cookies, or bodies in
the audit log without an explicit opt-in flag." Before building it, we
checked whether there was actually anything to redact.

There isn't, and not for lack of effort — it's structural. The
proxy never decrypts `CONNECT`-tunneled HTTPS (the overwhelming
majority of real traffic); it relays encrypted bytes end-to-end
without inspecting them, so headers, cookies, and bodies are
architecturally invisible to it. Making them visible would require
full TLS interception — a private CA, forged leaf certs presented to
the client, breaking HSTS/cert-pinning assumptions the client may
rely on — which is a separate, Stage-2-sized architectural decision
(a MITM proxy), not a small Stage 3 add-on. The one thing that *is*
visible without MITM — the `CONNECT` request's own headers — carries
no credentials in practice, since this proxy has no upstream
proxy-auth of its own to expose. `THREAT_MODEL.md` already frames this
proxy as a safety net, not a traffic inspector; this is consistent
with that framing, not a scope cut made for lack of time.

## Issues that arose, and how they were fixed

- **Wizard test input needed a blank-line separator between
  include/exclude sections.** `promptList` keeps consuming lines into
  the current list until it sees a blank line; an early manual test
  that omitted the separator had its exclude line silently swallowed
  into the include list. This was a test-input mistake, not a code
  bug — confirmed by re-running the same wizard with a properly
  blank-line-separated transcript and getting the correct split.
- **A few test files picked up stray helper functions
  (`writeTestFile`, `readFile`, `splitNonEmptyLines`, `containsAll`)
  that just duplicated stdlib** (`os.ReadFile`, `strings.Split`,
  `strings.Contains`). Caught each time via a read-back before
  building, and removed in favor of calling stdlib directly — no
  reason to carry an indirection that adds nothing.
- **`doctor_test.go` and `engagement_use_test.go` briefly had an
  unused `fmt` import** papered over with a `var _ = fmt.Sprintf(...)`
  line. Removed the import and the hack together rather than leaving
  dead code in place.
- **Testing a detached command object (e.g.
  `newEngagementAddCmdWithStore(store)` built directly, not via the
  real root tree) prints cobra's own "Usage:" dump to stderr on
  error**, because only the real root command sets both
  `SilenceErrors` and `SilenceUsage`. Confirmed by building and
  running the actual binary that the real CLI (root → subcommand)
  does *not* double-print — this is purely a test-harness artifact of
  exercising a standalone command. Fixed by setting
  `cmd.SilenceErrors = true` on each such test's command instance;
  the harmless "Usage:" noise on those specific tests is accepted,
  matching the established pattern across the whole `cmd/marque` test
  suite rather than fighting cobra's own output wiring.
- **The validate/proxy retrofit left one test touching the real
  `$HOME`.** `TestValidateCmd_MissingScopeFlag` passed no `--scope`
  and, after the retrofit, would call `engagement.NewStore()` and
  resolve against the real `~/.marque` — no longer hermetic. Renamed
  to `TestValidateCmd_MissingScopeFlagNoActiveEngagement` and switched
  to an injected `engagement.Store{Root: t.TempDir()}`, consistent
  with every other test in the package.
- **A naive `--tail` implementation using `bufio.Scanner` doesn't
  work on a growing file** — once `Scan()` returns `false` at EOF it
  stays `false` forever, even after more data is appended to the same
  underlying file, which is exactly what a live tail needs to recover
  from. `tailAuditLog` instead tracks a `pending` byte buffer across
  polls and re-reads with plain `f.Read` calls each tick, which
  doesn't have that caching problem.
- **A naive tail test sharing a plain `bytes.Buffer` between the
  polling goroutine and the test's own `require.Eventually` assertion
  loop is a data race** (`go test -race` caught it immediately — two
  goroutines touching the same `bytes.Buffer` with no synchronization).
  Fixed with a small mutex-guarded `syncBuffer` test helper instead of
  reaching for a heavier synchronization primitive.
- **`examples/embedding`'s `scope.yaml` needed a path that works
  regardless of invocation directory.** A literal relative
  `"scope.yaml"` only resolves correctly if the binary happens to be
  run from inside `examples/embedding/`, which `go run
  ./examples/embedding` does not guarantee. Fixed by resolving the
  path relative to the source file itself via `runtime.Caller(0)`, the
  standard idiom for a self-contained runnable example.

## Manual verification

Walked `docs/UX_FLOW.md`'s own verification checklist end-to-end
against two engagements in a fresh, isolated `$HOME`:

1. `engagement add acme` / `engagement add globex` (one active window,
   one already expired), `engagement use acme`, `validate` with no
   `--scope` — banner correctly shows `acme-2026q4 (Acme Corp)`.
2. Switching `engagement use globex` and re-running `validate` shows
   `globex-oct (Globex Inc)` and the expired-window warning — never a
   stale client from the previous context. Switching back to `acme`
   restores its banner correctly. `engagement list`'s `→` arrow
   tracked the currently-selected context correctly across both
   switches, independent of each row's own active/expired STATUS.
3. `marque proxy` on the expired `globex` context refused to start
   without `--force`, exiting non-zero with an actionable message.
4. `marque proxy` on the active `acme` context started cleanly with no
   flags; an in-scope `curl --socks5` request was allowed, an excluded
   one was blocked — both printed live and both landed correctly in
   `audit.jsonl`'s hash chain.
5. `marque doctor` passed every check on the active engagement and
   correctly FAILed only the window check (independent port/scope-file
   checks still ran and passed) on the expired one.
6. `marque proxychains-config`, `marque run` (mixed allow/deny,
   non-zero exit and no exec on any denial), `marque audit --tail`
   (live-picked-up a decision from a concurrently running `marque
   run`), and `marque audit export --format json|markdown` (correct
   summary counts, full decision history) all behaved as documented.
7. `go run ./examples/embedding` runs standalone from the repo root
   with no proxy or CLI involved and prints sensible allow/deny output
   for its hardcoded target list.

`go build ./...`, `go vet ./...`, `gofmt -l .`, and `go test -race
./...` were run after every commit in this stage, consistent with
Stages 1 and 2.
