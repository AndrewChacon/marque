# RedMarque — Threat Model

## Why this document exists

Scope logic that guesses at its own threat model tends to drift toward
either theater (checks that look rigorous but protect against nothing
real) or a false sense of security (checks that quietly don't cover the
case that actually burns someone). Writing this down first, before any
proxy or network code exists, forces every later design choice —
fail-closed behavior, what gets re-checked and when, what the audit log
promises — to trace back to a specific adversary and a specific failure
mode instead of vibes.

## The adversary: a mistake, not an attacker

**RedMarque's threat model is a mistaken keystroke or a misconfigured
tool, not a hostile actor trying to evade the guard.**

The pentester holding the signed ROE is the trusted operator. RedMarque
exists because that operator — under time pressure, running a dozen
tools against a dozen targets, sometimes mid-engagement at 2am — is a
human who will eventually:

- fat-finger an IP or CIDR
- copy a target list from the wrong client's folder
- forget that a specific host was carved out as an explicit exclusion
- keep scanning a few hours (or days) after the engagement window
  technically closed
- point a tool at a hostname that resolves somewhere the tester didn't
  expect

None of this requires malice. All of it is routine, and all of it is
exactly what turns authorized testing into something that looks a lot
like unauthorized access the moment someone reviews it afterward. That
gap — authorized intent, unauthorized-looking action — is what
RedMarque closes.

This is a **safety net for the tester**, not a **sandbox against the
tester**. The distinction drives every scope decision below.

## In scope: what RedMarque is responsible for preventing

1. **Traffic reaching a host outside the signed scope**, whether that's
   caused by operator error, tool misconfiguration, or a stale target
   list, for any tool routed through the proxy or invoked via `run`.

2. **Traffic reaching a host inside an *excluded* sub-range of an
   otherwise in-scope block.** Exclusions are where real ROEs get
   violated most often — a broad `/16` grant with three carved-out
   production hosts is a common real-world shape, and the exclusion has
   to win even though it looks like a narrower, "less important" rule
   than the include.

3. **DNS rebinding / TOCTOU between hostname check and connection.** If
   a decision is made against a hostname and the connection is later
   made to whatever IP that hostname resolves to at connect time, those
   two points in time are not guaranteed to agree — CDNs, round-robin
   DNS, geo-routing, and short TTLs all change answers between requests
   even with zero malicious intent anywhere in the chain. The resolved
   IP is re-checked at connection time against the exclude rules,
   independent of whatever the hostname check already said — deliberately
   not a second, independent inclusion test (most real scope files
   describe a target by domain alone, with no CIDR a resolved address
   could ever separately match — requiring one would make domain-only
   include rules unusable), but enough to catch the failure mode that
   actually matters: a nominally in-scope hostname resolving into a
   range the scope file explicitly excludes. This is the one place the
   model does consider an adversarial-shaped failure (a target's
   infrastructure answering differently than expected) without
   requiring the adversary to be *attacking RedMarque* — it's just a
   mechanical correctness property of checking addresses, not names.

4. **Continuing to operate after the engagement window has closed.** An
   expired window is as much a scope violation as a wrong IP — the
   signed authorization has a time boundary, and that boundary is
   enforced the same way the spatial one is.

5. **An undetectable rewrite of the decision history.** The audit log
   can't be made un-tamperable from a local process with filesystem
   access, but it can be made so that tampering leaves a detectable
   seam (see "tamper-evident, not tamper-proof" below).

## Explicitly out of scope: what RedMarque cannot and does not protect against

Being honest about this list is as important as the in-scope list. A
safety-net tool that implies a stronger guarantee than it provides is
worse than one that's upfront about its edges.

1. **A tool or process that bypasses the configured proxy entirely.**
   If something opens a raw socket, ignores `HTTP_PROXY`/`ALL_PROXY`,
   hardcodes a different egress path, or runs on a machine where the
   proxy was never wired in, RedMarque never sees that traffic and
   cannot block it. `marque run` only catches what it can find via
   regex in argv — a tool that resolves a target at runtime from a
   config file, an API response, or internal logic is invisible to it.
   **This is the single most important limitation of the whole project
   and must stay prominent in the README, not buried here.**

2. **A hostile operator trying to defeat their own tooling on purpose.**
   If the person running RedMarque wants to attack something out of
   scope badly enough to patch the binary, run the target tool
   unproxied, or edit the scope file to include it, nothing in this
   design stops them. RedMarque assumes an operator who wants to stay
   in scope and occasionally fails to, not one who is actively working
   around the guard.

3. **Tamper-*proof* storage.** The audit log is hash-chained so
   retroactive edits are detectable (a broken chain is obvious on
   verification), but anyone with filesystem write access to the log
   can, in principle, regenerate a self-consistent chain from scratch.
   Tamper-evidence tells you *that* something changed if you didn't do
   it yourself; it does not stop someone with full local access from
   rewriting history convincingly. If that stronger guarantee is ever
   needed, it means external append-only storage or remote signing —
   explicitly not a v1 goal.

4. **Malformed or hostile scope files crashing or hanging the parser**
   is in scope for *fuzzing coverage* (the parser must never panic and
   must never fail open), but a scope file is treated as **trusted
   input written by the operator**, not adversarial input from a third
   party. RedMarque does not defend against a supply-chain-compromised
   scope file planted by someone other than the operator.

5. **Confidentiality of engagement data at rest.** `scope.yaml` and the
   audit log contain live client infrastructure details and are
   sensitive, but RedMarque does not encrypt them on disk. It's the
   operator's responsibility to protect `~/.marque/` the way they'd
   protect any other client-confidential working file (restrictive
   permissions, disk encryption, etc.) — this may get light tooling
   help later (e.g. `doctor` warning on loose permissions) but is not a
   cryptographic guarantee this tool makes.

6. **Vulnerabilities in the tools being run through the proxy.** RedMarque
   mediates *where* traffic is allowed to go, not whether the traffic
   itself is safe, well-formed, or exploit-free. A tool that's itself
   compromised is a problem RedMarque doesn't attempt to solve.

7. **Network-layer enforcement.** There is no firewall rule, network
   namespace, or mandatory routing underneath this — it's a userspace
   proxy and an argv-scanning exec wrapper. Anything that operates below
   that layer is outside what RedMarque can see or control.

## Trust boundaries

| Input                          | Trust level                              | Handling                                                        |
|---------------------------------|-------------------------------------------|------------------------------------------------------------------|
| `scope.yaml`                    | Trusted (operator-authored), but may be malformed by accident | Parsed defensively — fuzz-tested, never panics, fails closed on any parse error |
| Network destinations (proxy/run)| Untrusted — arbitrary, including attacker-influenced DNS answers | Re-checked at the IP level at connection time, never trusted from an earlier hostname-only decision |
| Audit log                       | Append-only output, not input              | Hash-chained so tampering is detectable on read/verify            |
| Proxied traffic contents (headers, bodies) | Potentially sensitive (credentials) | Never captured in the first place for CONNECT-tunneled HTTPS — the proxy relays encrypted bytes end-to-end without decrypting them, so there's nothing to redact. See `docs/stages/STAGE_3.md`'s "Design decision: no credential redaction" for the full reasoning. |

## Fail-closed, stated precisely

"Fail closed" means: whenever RedMarque cannot positively confirm a
destination is in scope and within the engagement window, it treats
that destination as out of scope. Concretely:

- Missing or unparsable scope file → refuse to start, not "allow
  everything until fixed."
- Expired engagement window → refuse to start without `--force`.
- A destination matched by neither an include nor an exclude rule →
  denied (there is no implicit allow).
- A decision that can't be logged (audit write failure) is treated as a
  reason to deny the action it would have logged, not to proceed
  unaudited — an unaudited allow is indistinguishable from no safety net
  at all.

`warn` and `dry-run` modes are deliberate, explicit exceptions to
fail-closed carved out for the operator's own diagnostic use (see
`ARCHITECTURE.md` for the exact semantics) — they exist so an operator
can observe what *would* be blocked before trusting `enforce`, and
choosing them is an explicit, visible opt-out, never a default or a
silent fallback.
