# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/)
for `pkg/scope` and `pkg/audit` starting at `v1.0.0` (see
ARCHITECTURE.md's Versioning section).

## [Unreleased]

### Added

- **`pkg/scope`**: parses and validates engagement scope files — CIDR
  and domain include/exclude rules, time-boxed engagement windows
  (including open-ended engagements with no fixed end date), and
  enforce/warn/dry-run modes.
- **`pkg/audit`**: a tamper-evident, hash-chained JSON audit log with
  exclusive single-writer file locking.
- **`marque` CLI**: `validate`, `proxy` (SOCKS5 + HTTP CONNECT,
  backgrounds itself by default with `stop`/`status` subcommands),
  `run` (exec wrapper with pre-flight scope checks on extracted
  targets), `doctor`, `engagement add/use/list/current` (auto-
  activates on the first `add`), `audit --tail`/`export`, and
  `proxychains-config`.
- Signed, checksummed release binaries for linux/darwin × amd64/arm64
  via goreleaser and cosign keyless signing.

### Security

- DNS-rebinding protection: a resolved address gets a second,
  exclude-only check (`CheckResolvedIP`) before anything connects to
  it, independent of the earlier hostname-based decision.
- Fail-closed throughout: an unparsable scope file, an expired
  engagement window, or a decision that can't be durably audit-logged
  all deny by default rather than failing open.
- The audit log refuses a second concurrent writer outright (exclusive
  non-blocking file lock) rather than risking hash-chain corruption
  from interleaved writes.

### Known limitations

See [THREAT_MODEL.md](THREAT_MODEL.md)'s "Explicitly out of scope"
section — most importantly, a tool or process that bypasses the
configured proxy entirely is invisible to RedMarque and cannot be
blocked by it.
