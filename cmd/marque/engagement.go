package main

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/AndrewChacon/red-marque/pkg/audit"
	"github.com/spf13/cobra"
)

// resolvedPaths is which scope file and audit log a command should
// use, and — if resolved via the active engagement rather than an
// explicit --scope — that engagement's name.
type resolvedPaths struct {
	scopePath    string
	auditLogPath string
	engagement   string // "" if resolved via an explicit --scope flag
}

// resolvePaths is the one place that decides where a command's scope
// file and audit log come from: an explicit --scope always wins (its
// audit log defaults to a sibling audit.jsonl next to it, matching
// Stage 2's convention, unless auditFlag overrides that too);
// otherwise it falls back to the active engagement, whose audit log
// defaults to that engagement's own directory instead. Every
// scope-aware command routes through this so --scope stays a one-off
// override everywhere, per docs/UX_FLOW.md.
func resolvePaths(scopeFlag, auditFlag string, store *engagement.Store) (resolvedPaths, error) {
	if scopeFlag != "" {
		auditPath := auditFlag
		if auditPath == "" {
			auditPath = filepath.Join(filepath.Dir(scopeFlag), "audit.jsonl")
		}
		return resolvedPaths{scopePath: scopeFlag, auditLogPath: auditPath}, nil
	}

	active, err := store.Active()
	if err != nil {
		return resolvedPaths{}, err
	}
	if active == "" {
		return resolvedPaths{}, fmt.Errorf("no --scope given and no active engagement — run `marque engagement use <name>` first, or pass --scope")
	}

	auditPath := auditFlag
	if auditPath == "" {
		auditPath = store.AuditPath(active)
	}
	return resolvedPaths{scopePath: store.ScopePath(active), auditLogPath: auditPath, engagement: active}, nil
}

// openAuditLogWithHint wraps audit.Open with one CLI-specific
// addition: when the failure is lock contention specifically, append
// a hint naming the two commands that hold an audit log open for the
// long haul — pkg/audit has no notion of "marque proxy" or "marque
// run," so it can't give this hint itself.
func openAuditLogWithHint(path string) (*audit.Log, error) {
	log, err := audit.Open(path)
	if err != nil {
		if errors.Is(err, audit.ErrLocked) {
			return nil, fmt.Errorf("%w — if `marque proxy` or another `marque run` is already running against this engagement, route traffic through the proxy, wait for the other run to finish, or `marque proxy stop` first", err)
		}
		return nil, err
	}
	return log, nil
}

// resolveScopePath is resolvePaths for commands (like validate) that
// only need a scope file, not an audit log too.
func resolveScopePath(scopeFlag string, store *engagement.Store) (string, error) {
	paths, err := resolvePaths(scopeFlag, "", store)
	if err != nil {
		return "", err
	}
	return paths.scopePath, nil
}

// addScopeFlag registers the --scope flag every scope-aware command
// accepts, with the same help text everywhere describing resolvePaths'
// fallback-to-active-engagement behavior.
func addScopeFlag(cmd *cobra.Command, scopeFlag *string) {
	cmd.Flags().StringVar(scopeFlag, "scope", "", "path to scope.yaml (default: the active engagement)")
}

// addAuditLogFlag registers the --audit-log flag every command that
// also resolves an audit log (not just a scope file) accepts.
func addAuditLogFlag(cmd *cobra.Command, auditLogFlag *string) {
	cmd.Flags().StringVar(auditLogFlag, "audit-log", "", "path to the audit log (default: derived from --scope or the active engagement)")
}

func newEngagementCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "engagement",
		Short: "Manage named engagement contexts",
	}
	cmd.AddCommand(newEngagementAddCmd())
	cmd.AddCommand(newEngagementUseCmd())
	cmd.AddCommand(newEngagementListCmd())
	cmd.AddCommand(newEngagementCurrentCmd())
	return cmd
}

// storeOrDefault lets every engagement subcommand accept an injected
// *engagement.Store (tests pass one rooted at t.TempDir()) while
// production code passes nil and gets the real ~/.marque — same
// nil-means-default pattern as internal/proxy's Resolver/Auditor.
func storeOrDefault(store *engagement.Store) (*engagement.Store, error) {
	if store != nil {
		return store, nil
	}
	return engagement.NewStore()
}
