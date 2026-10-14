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

_Not started yet._

## Issues that arose, and how they were fixed

_Not started yet._
