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

_Not started yet._

## Issues that arose, and how they were fixed

_Not started yet._
