# Stage 1 — The Library

## Goal

Build the actual deliverable: `pkg/scope` and `pkg/audit`, with a
genuinely clean, importable public API — not just "good enough"
internals for the CLI. Prove it out with the first real CLI consumer,
`marque validate`.

## Actionable items

1. Write `THREAT_MODEL.md` and `ARCHITECTURE.md` before any proxy or
   network code — adversary model, library-first rationale, Prior Art.
2. `pkg/scope`, built with TDD: scope file parser, CIDR/domain
   matcher, include/exclude resolution, IPv4+IPv6, engagement windows.
   Public API finalized and godoc'd.
3. `pkg/audit`, built with TDD: hash-chained decision log,
   tamper-detection test.
4. `marque validate [--scope file.yaml]` working end-to-end as the
   first real consumer of the library.
5. (Added once the above was in place, same stage) A full code-review
   pass over all non-test code, and fixes for everything it surfaced.

## What was implemented

### Design docs

- `THREAT_MODEL.md`: the adversary is a mistaken keystroke or
  misconfigured tool, not a hostile actor evading the guard. Explicit
  in-scope/out-of-scope lists, fail-closed stated precisely.
- `ARCHITECTURE.md`: library-first rationale, Prior Art section
  (scopeguard, pentestkit, and three more AI pentest-agent projects
  independently reinventing the same guard logic), package layout,
  public API shapes, dependency justification.

### `pkg/scope`

- `Load`/`Parse` a YAML scope file into a `*Scope`.
- `Check(ip net.IP) Decision` and `CheckHost(host string) Decision` —
  two entry points instead of the brief's single illustrative
  signature, since domain rules need pre-resolution matching and CIDR
  rules need a resolved address.
- Matching rule, confirmed before writing it: **exclude always wins**,
  regardless of how specific the matching include rule is — no
  longest-prefix-match tiebreak.
- The engagement window is enforced inside the same `decide()` path as
  address matching — an expired or not-yet-started window denies
  regardless of what the CIDR/domain rules say.
- `IncludeRules`/`ExcludeRules` expose the declared rules in order, as
  plain strings — added once `marque validate` needed something to
  display; `Check`/`CheckHost` alone can only test one target at a
  time, not answer "what's in scope."
- 94.5% statement coverage; three native fuzz targets (`FuzzParse`,
  `FuzzCheck`, `FuzzCheckHost`) ran clean across millions of
  executions with zero crashers.

### `pkg/audit`

- Hash-chained, append-only JSONL log: `Open`, `Log`, `Verify`, `Close`.
- Explicitly tamper-evident, not tamper-proof — documented plainly in
  the package doc comment, not just in `THREAT_MODEL.md`.
- 88.5% statement coverage, including tests proving the chain
  detectably breaks on tampering and on reordering.

### `cmd/marque`

- Cobra command tree built via constructor functions (`newRootCmd`,
  `newValidateCmd`), not package-level vars — avoids flag state
  leaking between test runs that call `Execute()` more than once.
- `marque validate --scope file.yaml [--json]`: human-readable table
  or JSON output, warns (doesn't fail) on an expired window, since
  validate is a preflight check, not an enforcement point.
- Smoke-tested as a real static binary (confirmed `CGO_ENABLED=0`
  produces one) against valid, expired, and malformed scope files,
  including IPv6 and wildcard-domain rules.

## Issues that arose, and how they were fixed

1. **Go version floor crept to 1.26 for no reason.** An early
   `go get golang.org/x/net` (ahead of Stage 2's actual need for it)
   bumped `go.mod`'s directive and auto-downloaded a new toolchain.
   `go mod tidy` later pruned the unused dependency, but the version
   bump didn't revert on its own — every contributor and third-party
   importer was silently forced onto Go 1.26 for nothing. **Fixed:**
   manually lowered back to 1.24.4, matching what the real
   dependencies need.

2. **Default `go build` produces a dynamically-linked binary**, not
   the static one the project requires. Only static with
   `CGO_ENABLED=0` set explicitly. **Fixed for now** by always
   building that way; still needs to be codified in Stage 4's release
   tooling so it can't regress silently.

3. **`pkg/audit` coverage came in at 75.9%** on the first pass, below
   target — the gaps were real (recovering from a corrupt reopen,
   oversized lines, write-after-close), not just an unlucky count.
   **Fixed** with targeted tests for each, eventually landing at 88.5%.

4. **`Mode.String()`/`MarshalJSON()`/`UnmarshalJSON()` had zero direct
   test coverage** from `pkg/scope`'s own suite — they were only ever
   exercised incidentally by `pkg/audit` and `cmd/marque`'s tests.
   Found during a code-review pass, once coverage was checked
   per-package instead of through a truncated `tail` command that had
   been hiding it. **Fixed** with a dedicated `mode_test.go`;
   `pkg/scope` coverage in isolation went from a misreported 89% to a
   verified 94%.

5. **Duplicated branching in `addRule`** — the same
   `if include {...} else {...}` dispatch appeared three times over.
   **Fixed** by moving the declared-rule-string bookkeeping to
   `Parse`'s two call sites, where the direction is already
   unconditional.

6. **Redundant `time.Now()` calls in `cmd/marque/validate.go`** —
   three separate samples across one render of the table, plus a
   second, independent re-derivation of "is the window expired."
   **Fixed** by threading a single `now` through
   `windowStatus`/`windowSummary`.

7. **A dead regex branch** — `domainLabelRE` allowed uppercase
   letters, but its only caller always lowercases first. **Fixed** by
   narrowing it to `a-z0-9`.

8. **`validHostname` rejected single-label hostnames** (`webserver01`,
   `DC01`) — plausible for real internal engagements (AD/NetBIOS
   names, DNS search-domain-resolved short names), and would have
   silently broken a realistic scope file. **Fixed** by dropping the
   dot-required check; per-label validation already guards against
   garbage.

9. **`audit.Open()` only ever recovered the last entry's hash** — it
   never verified anything before it, so tampering earlier in the
   file would sit undetected until something explicitly called
   `Verify` (nothing does yet). **Fixed** by factoring the chain-walk
   into a shared `walkChain` used by both `Open` and `Verify`, so
   `Open` now verifies the entire existing chain before trusting it.

10. **That fix, done naively, would have made an ordinary crash
    mid-write look identical to real tampering** — and since RedMarque
    is fail-closed by design, that would brick a tester's ability to
    resume their own engagement after a routine crash. **Fixed** by
    distinguishing, in the error message only (not behavior —
    `Open()` still refuses to resume either way, by design, confirmed
    before implementing): a broken last line with nothing valid after
    it is reported as a likely incomplete write, not tampering; a
    break with good data following it is reported as compromised.
