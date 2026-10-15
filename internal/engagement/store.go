// Package engagement manages named engagement contexts: where their
// scope files and audit logs live on disk, and which one is currently
// active. It's a thin CLI-layer convenience over pkg/scope/pkg/audit —
// it doesn't change either package's design, only gives marque's
// commands a default to fall back to when --scope isn't passed.
package engagement

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Store is the on-disk layout rooted at Root:
//
//	Root/active                                — the active engagement's name
//	Root/engagements/<name>/scope.yaml          — that engagement's scope file
//	Root/engagements/<name>/audit.jsonl         — that engagement's audit log
//	Root/proxy.pid                              — the backgrounded proxy's PID/address/start time, if running
//	Root/proxy.log                              — its stdout/stderr, for crash debugging only
type Store struct {
	Root string
}

// NewStore returns a Store rooted at ~/.marque.
func NewStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("finding home directory: %w", err)
	}
	return &Store{Root: filepath.Join(home, ".marque")}, nil
}

func (s *Store) engagementDir(name string) string {
	return filepath.Join(s.Root, "engagements", name)
}

// ScopePath is where name's scope file lives.
func (s *Store) ScopePath(name string) string {
	return filepath.Join(s.engagementDir(name), "scope.yaml")
}

// AuditPath is where name's audit log lives.
func (s *Store) AuditPath(name string) string {
	return filepath.Join(s.engagementDir(name), "audit.jsonl")
}

func (s *Store) activeFile() string {
	return filepath.Join(s.Root, "active")
}

// ProxyPIDPath is where the backgrounded proxy's PID/address/start
// time live. A single global path, not per-engagement: marque proxy
// can run via an explicit --scope with no active engagement at all,
// and realistically only one backgrounded proxy makes sense at a time
// (a second concurrent instance is still possible via --foreground).
func (s *Store) ProxyPIDPath() string {
	return filepath.Join(s.Root, "proxy.pid")
}

// ProxyLogPath is where the backgrounded proxy's stdout/stderr are
// redirected — a crash/panic safety net, not a second decision log
// (that's pkg/audit's job, via ScopePath's sibling AuditPath).
func (s *Store) ProxyLogPath() string {
	return filepath.Join(s.Root, "proxy.log")
}

// Active returns the currently active engagement's name, or "" if
// none has been set yet — an unset default, not an error.
func (s *Store) Active() (string, error) {
	data, err := os.ReadFile(s.activeFile())
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading active engagement: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// SetActive makes name the active engagement. Doesn't check it
// exists — callers that want a better error should check Exists first.
func (s *Store) SetActive(name string) error {
	if err := os.MkdirAll(s.Root, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", s.Root, err)
	}
	if err := os.WriteFile(s.activeFile(), []byte(name+"\n"), 0o600); err != nil {
		return fmt.Errorf("setting active engagement: %w", err)
	}
	return nil
}

// Exists reports whether an engagement named name has a scope file.
func (s *Store) Exists(name string) bool {
	_, err := os.Stat(s.ScopePath(name))
	return err == nil
}

// Add writes scopeYAML as the scope file for engagement name,
// creating its directory if necessary. Overwrites a pre-existing one —
// callers that want to guard against that should check Exists first.
func (s *Store) Add(name string, scopeYAML []byte) error {
	dir := s.engagementDir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	if err := os.WriteFile(s.ScopePath(name), scopeYAML, 0o600); err != nil {
		return fmt.Errorf("writing scope file: %w", err)
	}
	return nil
}

// List returns every known engagement name, sorted.
func (s *Store) List() ([]string, error) {
	base := filepath.Join(s.Root, "engagements")
	entries, err := os.ReadDir(base)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("listing engagements: %w", err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}
