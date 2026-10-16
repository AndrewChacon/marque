# Contributing to Marque

## Before you start

`pkg/scope` and `pkg/audit` are the correctness-critical core — real
public API other tools import directly, not just consumed through
this CLI (see [ARCHITECTURE.md](../docs/ARCHITECTURE.md)). Changes there get
held to a higher bar than `cmd/marque`'s CLI wiring. If a change
touches the scope-file format or a fail-closed guarantee, open an
issue describing the change before sending a PR — those are
deliberate, load-bearing decisions, not incidental ones.

`docs/stages/*.md` has the full build history: what was implemented
at each stage, what issues came up, and why specific tradeoffs were
made. Worth a skim before touching an area you're unfamiliar with —
the reasoning behind a design choice is often there, not in the code.

## Local setup

Go 1.24+. No other toolchain dependencies to install beyond Go itself
and (optionally) `golangci-lint`:

```bash
go build ./...
go test -race ./...
```

Before opening a PR, run the same checks CI runs:

```bash
gofmt -l .                    # must print nothing
go vet ./...
go test -race ./...
go test -fuzz='^FuzzParse$' -fuzztime=10s ./pkg/scope/...
go test -fuzz='^FuzzCheckHost$' -fuzztime=10s ./pkg/scope/...
go test -fuzz='^FuzzCheck$' -fuzztime=10s ./pkg/scope/...
```

`golangci-lint` ([install instructions](https://golangci-lint.run/welcome/install/))
with this repo's `.golangci.yml`:

```bash
golangci-lint run
```

Coverage on `pkg/scope` and `pkg/audit` specifically is held to ≥85%
(not a repo-wide average — see `docs/ARCHITECTURE.md`'s Testing strategy
section):

```bash
go test -coverprofile=/tmp/cov.out ./pkg/scope/... ./pkg/audit/...
go tool cover -func=/tmp/cov.out | tail -1
```

## Code style

This codebase follows a few conventions consistently; matching them
keeps a PR easy to review:

- **No premature abstraction.** Three similar lines beat an early
  helper function. Don't add a flag, config option, or interface for
  a case nothing exercises yet.
- **Comments explain *why*, not *what*.** A well-named function
  already says what it does. A comment earns its place by capturing a
  non-obvious constraint, an invariant, or the reason a workaround
  exists — not by restating the code.
- **Dependency injection for testability, not for its own sake.**
  Commands follow `newXCmd()` (production, real `~/.marque`) calling
  through to `newXCmdWithStore(store *engagement.Store)` (nil in
  production, `&engagement.Store{Root: t.TempDir()}` in tests). Don't
  invent a new DI pattern for a new command — match the existing one.
- **Fail closed.** Any ambiguity, parse failure, or logging failure is
  a denial, never a silent allow. If you're adding a new failure mode
  anywhere in `pkg/scope`, `pkg/audit`, or a command that enforces
  scope, ask which way it fails before deciding anything else.
- **I/O separated from logic.** Functions that do real work take an
  `io.Reader`/`io.Writer` (or plain values) and are tested with
  `bytes.Buffer`s, not real stdin/stdout/files — see `runWizard` in
  `cmd/marque/engagement_add.go` for the pattern.
- **Tests are hermetic.** No test should touch the real `$HOME` or
  `~/.marque`. Root every test store at `t.TempDir()`.

## Commit style

One logical unit per commit (a new command, a bug fix, a doc update —
not a grab-bag). Commit messages explain *why* a change was made, not
just what changed; the diff already shows what changed. Run the full
check list above before every commit, not just before opening the PR.

## Reporting a security issue

Marque is a security tool whose core promise is fail-closed
enforcement — if you find a case where it fails open (allows
something `scope.yaml` says should be denied), please open an issue
describing the scope file and the target that got through rather than
posting exploit details publicly.
