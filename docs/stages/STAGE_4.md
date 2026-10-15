# Stage 4 — Hardening and Release

## Goal

Make this safe to hand to a stranger: documentation that's honest
about what the tool does and doesn't protect against, a real release
pipeline, and a final correctness pass.

## Actionable items

1. `README.md`: the letter-of-marque framing up top (near-verbatim
   from the original project brief), quickstart, example
   `scope.yaml`, an explicit "what this does and does not protect
   against," and the Prior Art section (already drafted in
   `ARCHITECTURE.md` — needs porting/adapting).
2. `CONTRIBUTING.md`, `LICENSE` (Apache-2.0 — patent grant,
   appropriate for a security tool), lawful-use disclaimer requiring
   written engagement authorization.
3. `goreleaser` config: signed/checksummed static binaries
   (`CGO_ENABLED=0`, confirmed necessary in Stage 1) for
   linux/darwin × amd64/arm64.
4. GitHub Actions CI: `gofmt` + `golangci-lint` (not yet run anywhere
   in this project — this is the first real check), `go test -race`,
   fuzz (short mode), matrixed over Linux/macOS.
5. Coverage check gate, final read-aloud pass on every exported symbol
   across both public packages.

## What was implemented

- **Stale-doc reconciliation**: `ARCHITECTURE.md`'s module-path section
  and `docs/UX_FLOW.md`'s install line still showed the unhyphenated
  `github.com/<org>/redmarque` placeholder from before `go.mod` was
  created — both now match the real
  `github.com/AndrewChacon/red-marque` path. `THREAT_MODEL.md`'s
  trust-boundary table said proxied traffic contents are "redacted by
  default" — describing a feature Stage 3 deliberately didn't build —
  corrected to state plainly that CONNECT-tunneled HTTPS is never
  captured in the first place.
- **`LICENSE`**: Apache-2.0.
- **Version reporting**: `cmd/marque/version.go` — `version`/`commit`/
  `date` package vars (default `dev`/`none`/`unknown`), overridable via
  goreleaser's `-ldflags -X main.xxx=...` template. `marque version`
  command plus `root.Version` wired for cobra's built-in `--version`/
  `-v` flags. Caught and fixed a cosmetic bug before it shipped:
  cobra's own `--version` template already prepends the binary name,
  so a naive `root.Version = "marque " + details` doubled it up
  ("marque version marque dev (...)") — split into `versionDetails()`
  (no prefix, used for `root.Version`) and `versionString()` (prefixed,
  used by the standalone `version` command's own output line).
- **`README.md`**: full rewrite from a 3-word stub. Letter-of-marque
  framing, a condensed protects-against/doesn't-protect-against
  section linking to `THREAT_MODEL.md`, install (go install/release
  binary/source), a quickstart mirroring `docs/UX_FLOW.md`'s own flow,
  an example `scope.yaml`, the CLI surface table, a library-embedding
  snippet, Prior Art ported from `ARCHITECTURE.md`, a lawful-use
  disclaimer, and doc links. Every command and the library snippet
  shown were run against a real build before being written down —
  including building a separate throwaway module with a `replace`
  directive pointing at the local repo, to confirm the exact `import
  "github.com/AndrewChacon/red-marque/pkg/scope"` snippet actually
  compiles and runs the way a real third-party consumer would use it.
- **`CONTRIBUTING.md`**: local dev setup, the exact check list CI
  runs, and this codebase's established conventions (DI pattern,
  fail-closed, comments-explain-why, hermetic tests) written down so
  a new contributor's first PR doesn't have to reverse-engineer house
  style from the diff history.
- **`.golangci.yml`**: first time any linter has run on this codebase.
  Default v2 set (errcheck/govet/ineffassign/staticcheck/unused) plus
  `gosec`, since this is a security tool. 129 lines of initial findings
  triaged one by one — every exclusion in the final config is scoped
  to a specific, justified category (see "Issues" below), not a
  blanket disable, and two real findings got fixed in code instead of
  configured away.
- **GitHub Actions CI** (`.github/workflows/ci.yml`): a `lint` job
  (gofmt/vet/golangci-lint, once on Ubuntu — these are OS-independent)
  and a `test` job (build/`test -race`/fuzz smoke/coverage gate,
  matrixed Ubuntu+macOS per `ARCHITECTURE.md`'s testing strategy).
  Every step was run locally first, same bar as the rest of this
  project — which is what caught the fuzz-regex bug below before it
  ever reached CI.
- **`.goreleaser.yml`**: `CGO_ENABLED=0` builds for linux/darwin ×
  amd64/arm64 (no Windows — `syscall.Exec` in `cmd/marque/run.go` is
  unix-only), ldflags wired to the version vars, tar.gz archives,
  SHA256 checksums, and cosign keyless signing (GitHub Actions OIDC,
  no stored private key) of the checksums file.
- **`.github/workflows/release.yml`**: triggers on `v*` tags, runs
  goreleaser with the `id-token: write` permission cosign's keyless
  flow needs. Built and verified but **not triggered this stage** — no
  tag has been pushed, per the explicit decision to stop at
  release-ready rather than cut the first real release as part of this
  work.
- **Doc-comment read-aloud pass**: every exported symbol in `pkg/scope`
  and `pkg/audit`. `pkg/audit`'s comments were already accurate and
  well-phrased with no changes needed; `pkg/scope` had exactly one
  awkward line fixed (`Decision`'s struct doc was missing the word
  "that").
- **Local release-pipeline verification**: `goreleaser check` (config
  valid), `goreleaser build --snapshot --clean` (all 4 cross-platform
  targets actually build, version injection confirmed by running the
  built binary's `marque version`), and `goreleaser release --snapshot
  --clean` (archives and checksums generate correctly; the signing
  step correctly invokes `cosign sign-blob` with exactly the right
  flags and file paths — confirmed via `ps aux` while it was running —
  and only blocks on the real OIDC device-flow prompt, which can only
  complete inside an actual GitHub Actions run).

## Issues that arose, and how they were fixed

- **errcheck's default behavior produced ~40 findings on its very
  first run, almost all in one "don't care" category**: writing CLI
  output (`fmt.Fprintf`/`Fprintln` to an `io.Writer`), closing a
  connection/file on an already-established cleanup path, setting a
  read deadline that only fails if the conn is already gone. None of
  these are the fail-closed-relevant writes this project actually
  cares about (audit log writes, scope decisions are already
  explicitly checked everywhere). Fixed by configuring precise,
  function-level `exclude-functions` entries for each real category
  (`(net.Conn).Close`, `fmt.Fprint*`, `io.Copy`, etc.) rather than
  either leaving ~40 call sites mechanically wrapped in `_ = ...` or
  disabling errcheck outright — the exclusions are specific enough
  that errcheck still catches a real future regression (e.g. a new
  unchecked `log.Log(d)` call).
- **gosec's G104 duplicates errcheck's own job**, with a cruder,
  not-per-function-configurable ruleset — fixed by disabling G104 in
  gosec's settings, since errcheck (with the excludes above) is
  already the authoritative "is this unchecked error OK" check.
- **gosec's G304 ("potential file inclusion via variable") fired on
  every `os.Open`/`os.ReadFile`/`os.OpenFile` call with a non-literal
  path** — which describes this project's entire job. `scope.Load` and
  `audit.Open` are *designed* to take an operator-supplied path, and
  `THREAT_MODEL.md` already states plainly that a scope file is
  trusted, operator-authored input, not adversarial data from a third
  party. Disabled G304 project-wide rather than scattering four
  identical-reasoning `#nosec` comments.
- **gosec's G115/G306 fired on test fixtures** (bounded integer
  conversions building protocol test bytes, a relaxed file permission
  on a throwaway `t.TempDir()` file) — excluded gosec for `_test.go`
  files specifically, since this scrutiny is meant for production
  code, not test fixtures.
- **Two genuine `errcheck` findings in `internal/proxy/socks5.go`**:
  two already-failing reply-write paths weren't checking the write's
  own error, inconsistent with a third call site in the same function
  that does check. Fixed in code (explicit `_ = ...` discard with a
  comment explaining why it's fine on an already-bailing-out path)
  rather than configured away, since the inconsistency itself was
  worth resolving.
- **One genuine `staticcheck` finding, in a test file written earlier
  this stage**: `cmd/marque/audit_test.go` used the deprecated
  `os.SEEK_END` instead of `io.SeekEnd`, which the actual production
  code already used correctly — pure leftover inconsistency, fixed
  directly.
- **`cmd/marque/run.go`'s one real gosec finding (G204, `syscall.Exec`
  with a variable path/argv) is inline-documented with `//nolint`
  rather than configured away** — it's the deliberate, already
  scope-checked purpose of that exact line, not a pattern to bless
  project-wide the way the categories above are.
- **`-fuzz=FuzzCheck` is a regex, and silently matches `FuzzCheckHost`
  too** — `go test -fuzz=FuzzCheck ./pkg/scope/...` fails with "will
  not fuzz, -fuzz matches more than one fuzz test." This was caught by
  actually running every command this stage wrote down (in
  `CONTRIBUTING.md` and the new CI workflow) rather than trusting it
  unverified — fixed by anchoring all three fuzz invocations with
  `^...$` in both places.
- **`goreleaser build --snapshot --clean` produced a `dist/` directory
  that wasn't in `.gitignore`** — caught via `git status` before it
  could get committed; added `/dist/` alongside the existing `/bin/`
  entry.
