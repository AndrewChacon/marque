# RedMarque — User Flow & Intuitiveness Vision

## Why this doc exists

RedMarque enforces engagement scope mechanically instead of leaving it to
tester memory. That value proposition is worthless if the tool itself is
hard to use correctly under pressure — a scope-enforcement tool that's
confusing is just a new way to make the same mistake it's meant to
prevent. This doc defines the intended user experience and CLI surface
before implementation, so command shapes aren't improvised mid-build.

**Interface modality: CLI-only, no GUI.** Everything below is plain
terminal output (colored text, tables) — no separate app, no web UI.
Weighed against a TUI (k9s/lazygit-style — rejected for v1 as added
complexity outside the timeline, worth reconsidering post-v1) and a
local web dashboard (rejected — a local HTTP server is new attack
surface on a tool whose whole pitch is minimal surface area, and it's
what the closest existing competitor, `scopeguard`, already does — less
differentiated, not more). CLI-only keeps the single-static-binary story
intact and matches how pentesters actually work — often over SSH to a
dropbox with no browser available at all.

**Multi-engagement tracking uses named contexts** (kubectl/git-branch
style) — `marque engagement use <name>` sets an active engagement that
commands default to — specifically because the cross-client mix-up risk
is exactly the failure mode this tool exists to prevent, and making the
active engagement loud and unmissable everywhere mitigates the "forgot
which context is active" risk that model trades in for convenience.

---

## Single-engagement flow

**1. Install** — one static binary. Download a release binary, or
`go install github.com/AndrewChacon/red-marque/cmd/marque@latest`.
(Homebrew is a possible future option, not built for v1.) No venv, no
dependency resolution, nothing to configure first.

**2. Kick off the engagement** — pentester has a signed ROE in hand.

```
marque engagement add acme-2026q4
```

Interactive wizard (not a blank YAML file to hand-write):
- Engagement name, client, start/end dates
- "Paste your in-scope CIDRs/domains" (accepts comma- or newline-
  separated input, one prompt, not one-at-a-time nagging)
- "Any exclusions?" — its own explicit step, since exclusions are where
  real ROEs get missed if the tool treats them as an afterthought
- Writes `~/.marque/engagements/acme-2026q4/scope.yaml`

Non-interactive path: `marque engagement add acme-2026q4 --scope
./scope.yaml` for people who already have a file or are scripting this.

**3. Preflight** — before touching the network:

```
marque validate
```

Prints a human-readable table: what's in scope, what's excluded, days
remaining in the engagement window, any ambiguous include/exclude
overlaps. Has to be scannable in five seconds, not a wall of JSON.

**4. Activate it**

```
marque engagement use acme-2026q4
```

Every command defaults to this engagement from here on unless overridden.
Echoed back immediately, and visible in every subsequent command's
output header — never silent.

**5. Start enforcement**

```
marque proxy
```

Backgrounds itself by default — single-window operation was an
explicit, repeated ask from actually using this day to day: start it,
get the terminal straight back, keep working in the same window. The
startup banner prints once, with exactly how to check on it:

```
RedMarque — engagement: acme-2026q4 (Acme Corp)
window: 2026-10-14 → 2026-10-28 (14 days remaining)
mode: enforce · listening on 127.0.0.1:1080

backgrounded — pid 48213
  marque proxy status      check it's still running
  marque audit --tail      watch decisions live
  marque proxy stop        stop it
```

Decisions are fully captured in the audit log either way (hash-chained,
same as always) — `marque audit --tail` is how you watch them live once
backgrounded; there's no separate live feed printed to a terminal that
isn't there. `marque proxy --foreground` is the explicit opt-out back to
the original always-visible, blocking, color-coded live feed, for
scripting, containers, or anyone who specifically wants it.

**6. Point existing tools at it** — zero new workflow to learn:
- Burp → set upstream proxy to the printed address
- `marque proxychains-config > /tmp/pc.conf` emits a ready-to-use
  proxychains snippet — no one hand-writes proxychains.conf correctly on
  the first try
- Or skip proxy setup entirely: `marque run -- nmap -sV target`

**7. Mid-engagement scope change** (routine — clients add/remove hosts) —
edit the scope file, `marque proxy` hot-reloads on file change (or
`marque reload`) without restarting and breaking audit log continuity.

**8. Violations are loud, not logged-and-forgotten** — an out-of-scope
attempt prints an immediate, specific, red terminal interrupt: target,
rule violated, timestamp. The tester sees it in the moment, not three
weeks later reading a log.

**9. Wrap-up**

```
marque audit export --format markdown
```

Full decision log, any violations caught, the engagement window — an
artifact for the final report or the tester's own records. The
ROE-as-letter-of-marque framing only pays off if there's a record
proving you stayed inside it.

---

## Multi-engagement flow (named contexts)

```
marque engagement list
```

```
NAME           CLIENT       WINDOW                    STATUS
acme-2026q4    Acme Corp    Oct 14 – Oct 28 2026       ● active
globex-oct     Globex Inc   Oct 01 – Oct 10 2026       expired
initech-nov    Initech      Nov 03 – Nov 17 2026       upcoming
```

Switching is explicit and always confirmed back:

```
marque engagement use globex-oct
→ switched to globex-oct (Globex Inc) — WARNING: this engagement expired 4 days ago
```

**Mitigating the "magic state" risk** — three mandatory mitigations, not
optional polish:
- The active engagement name/client is printed in the header of *every*
  command's output, not just `use` and `proxy` — `validate`, `run`,
  `audit`, all of it.
- `marque proxy` refuses to start on an expired engagement window
  without an explicit `--force` (fail closed, same principle as the
  library itself).
- `--scope <path>` remains available as a one-off override on any
  command and always wins over the active context.

---

## Intuitiveness principles

- **Borrow idioms testers already know** — `engagement add/use/list`
  maps to the kubectl-context / git-branch mental model. Don't invent new
  verbs where a familiar one works.
- **Fail loud, never silent** — every block is an unmissable terminal
  event, not a line in a log nobody's tailing live.
- **`marque doctor`** — a preflight health check (brew doctor / flutter
  doctor pattern): is an engagement active, has it expired, is the scope
  file still parseable, is the proxy port free.
- **Sensible defaults, minimal required flags** — `marque proxy` with no
  flags should just work once an engagement is active.
- **Actionable errors** — "scope.yaml line 12: CIDR '10.0.0.0/33' is
  invalid — prefix must be 0–32," never a raw stack trace.
- **Scriptable escape hatch** — `--json` on every command, `NO_COLOR`
  respected.

---

## CLI surface summary (supersedes flatter examples in earlier drafts)

```
marque engagement add <name> [--scope file.yaml]   # wizard or file import
marque engagement use <name>                        # set active context
marque engagement list                              # show all, with status
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

The engagement-context layer is a thin wrapper around the same
`--scope`-driven commands underneath — it doesn't change `pkg/scope` or
`pkg/audit`'s design, only the CLI's ergonomics on top of it. `doctor`
and `engagement add/use/list` fold into Stage 3 of the build plan (second
consumer / CLI polish), not a scope increase, since they're thin
wrappers over the library, not new logic.

## Verification

Once built, walk the single-engagement flow end-to-end against a local
lab target and confirm:
1. An out-of-scope `curl` through the proxy is blocked and loudly logged.
2. Switching `marque engagement use` between two test engagements and
   running `marque validate` in each confirms the active-engagement
   banner never ambiguously shows the wrong client.
3. `marque proxy` on an expired engagement refuses to start without
   `--force`.
4. `marque proxy` returns control immediately with the backgrounded
   banner, `marque proxy status` confirms it's running, and `marque
   proxy stop` actually stops it — all from the same terminal.
