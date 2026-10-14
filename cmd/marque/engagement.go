package main

import (
	"fmt"
	"path/filepath"

	"github.com/AndrewChacon/red-marque/internal/engagement"
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

// resolveScopePath is resolvePaths for commands (like validate) that
// only need a scope file, not an audit log too.
func resolveScopePath(scopeFlag string, store *engagement.Store) (string, error) {
	paths, err := resolvePaths(scopeFlag, "", store)
	if err != nil {
		return "", err
	}
	return paths.scopePath, nil
}

func newEngagementCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "engagement",
		Short: "Manage named engagement contexts",
	}
	cmd.AddCommand(newEngagementAddCmd())
	cmd.AddCommand(newEngagementUseCmd())
	cmd.AddCommand(newEngagementListCmd())
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
