package main

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/AndrewChacon/marque/internal/engagement"
	"github.com/AndrewChacon/marque/pkg/scope"
	"github.com/spf13/cobra"
)

func newRunCmd() *cobra.Command {
	return newRunCmdWithStore(nil)
}

func newRunCmdWithStore(injected *engagement.Store) *cobra.Command {
	var scopeFlag string
	var auditLogFlag string

	cmd := &cobra.Command{
		Use:   "run [--scope file.yaml] -- <command> [args...]",
		Short: "Check a command's arguments against scope, then run it",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storeOrDefault(injected)
			if err != nil {
				return err
			}
			paths, err := resolvePaths(scopeFlag, auditLogFlag, store)
			if err != nil {
				return err
			}

			s, err := scope.Load(paths.scopePath)
			if err != nil {
				return err
			}
			if windowStatus(s, time.Now()) == "expired" {
				return fmt.Errorf("refusing to run: engagement window ended %s", s.End.Format(time.RFC3339))
			}
			printEngagementHeader(cmd.OutOrStdout(), s, time.Now())

			log, err := openAuditLogWithHint(paths.auditLogPath)
			if err != nil {
				return err
			}
			defer log.Close()

			if err := checkRunTargets(cmd.OutOrStdout(), s, log, args); err != nil {
				return err
			}

			return execCommand(args)
		},
	}

	addScopeFlag(cmd, &scopeFlag)
	addAuditLogFlag(cmd, &auditLogFlag)
	return cmd
}

// auditLogger is the one method checkRunTargets needs — a local
// interface rather than importing internal/proxy's Auditor, since
// run.go has no other relationship to that package. *audit.Log
// satisfies this with no wrapping; tests inject a stub.
type auditLogger interface {
	Log(scope.Decision) error
}

var (
	// ipv4RE is intentionally IPv4-only and used for substring scans
	// within an arg (e.g. "--target=10.0.0.5") — IPv6 substring
	// scanning in free text is noisy enough to skip for a best-effort
	// tool; a literal IPv6 address as a whole argv token is still
	// caught by net.ParseIP below.
	ipv4RE = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)`)

	// hostnameRE is anchored — whole-token matches only. Scanning for
	// hostname-shaped substrings inside arbitrary flag text (e.g.
	// "max.retries") would be too false-positive-prone to be useful.
	hostnameRE = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)
)

// commonFileExtensions filters out argv tokens that are far more
// likely to be a tool's input/output filename than a target hostname
// — "scan.xml", "wordlist.txt", "exploit.py" are structurally
// identical to a hostname to hostnameRE, and these are exactly the
// tokens real pentest tool invocations are full of (-oX scan.xml,
// -w wordlist.txt, a .nse script, a .jar tool). This is a heuristic,
// not a classifier: a real target under one of these as a ccTLD
// (vanishingly rare in practice) would be missed — acceptable for a
// best-effort safety net that's explicitly not a sandbox.
var commonFileExtensions = map[string]bool{
	"txt": true, "xml": true, "json": true, "csv": true, "log": true,
	"py": true, "sh": true, "rb": true, "pl": true, "go": true,
	"nse": true, "lua": true, "yaml": true, "yml": true, "conf": true,
	"cfg": true, "ini": true, "jar": true, "war": true, "class": true,
	"gnmap": true, "nmap": true, "xlsx": true, "docx": true, "pdf": true,
	"md": true, "html": true, "htm": true, "zip": true, "tar": true,
	"gz": true, "db": true, "sqlite": true, "pem": true, "key": true,
	"crt": true, "pcap": true,
}

func hasKnownFileExtension(token string) bool {
	i := strings.LastIndexByte(token, '.')
	if i < 0 {
		return false
	}
	return commonFileExtensions[strings.ToLower(token[i+1:])]
}

// extractTargets is the best-effort regex scan the brief calls for —
// explicitly not per-tool argument parsing. Three passes per arg,
// most specific first: a URL's own hostname, then "the whole token is
// an IP or hostname," then "an IPv4 address appears somewhere inside
// this token." No match anywhere in argv is not an error — nothing to
// check means exec proceeds, this is a safety net, not a sandbox.
func extractTargets(args []string) []string {
	seen := make(map[string]bool)
	var targets []string
	add := func(t string) {
		if t != "" && !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}

	for _, arg := range args {
		if strings.Contains(arg, "://") {
			if u, err := url.Parse(arg); err == nil {
				if h := u.Hostname(); h != "" {
					add(h)
					continue
				}
			}
		}

		if net.ParseIP(arg) != nil || (hostnameRE.MatchString(arg) && !hasKnownFileExtension(arg)) {
			add(arg)
			continue
		}

		for _, m := range ipv4RE.FindAllString(arg, -1) {
			add(m)
		}
	}
	return targets
}

// checkRunTargets logs every extracted target's decision — allow or
// deny — and refuses (returning an error, before anything is ever
// exec'd) if any of them is out of scope. A logging failure refuses
// too, same fail-closed rule as everywhere else in this project.
func checkRunTargets(w io.Writer, s *scope.Scope, log auditLogger, args []string) error {
	var denied []scope.Decision

	for _, target := range extractTargets(args) {
		d := s.CheckHost(target)
		if err := log.Log(d); err != nil {
			return fmt.Errorf("audit log write failed (%v); refusing to run rather than proceed unaudited", err)
		}
		if !d.Allowed {
			denied = append(denied, d)
		}
	}

	if len(denied) == 0 {
		return nil
	}
	for _, d := range denied {
		printDecision(w, d, false)
	}
	return fmt.Errorf("refusing to run: %d target(s) out of scope", len(denied))
}

// execCommand replaces the current process (not fork+wait) — the
// idiomatic shape for a wrapper tool, and fine since this project only
// targets linux.
func execCommand(args []string) error {
	path, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("%s: %w", args[0], err)
	}
	return syscall.Exec(path, args, os.Environ()) //nolint:gosec // G204: executing an operator-chosen command is this function's entire purpose, already scope-checked by the caller before this runs
}
