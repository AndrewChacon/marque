package main

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/AndrewChacon/red-marque/pkg/scope"
	"github.com/spf13/cobra"
)

func newValidateCmd() *cobra.Command {
	return newValidateCmdWithStore(nil)
}

func newValidateCmdWithStore(injected *engagement.Store) *cobra.Command {
	var scopeFlag string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Check a scope file for errors and print what's in scope",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storeOrDefault(injected)
			if err != nil {
				return err
			}
			scopePath, err := resolveScopePath(scopeFlag, store)
			if err != nil {
				return err
			}

			s, err := scope.Load(scopePath)
			if err != nil {
				return err
			}
			if jsonOut {
				return printValidationJSON(cmd.OutOrStdout(), s)
			}
			printValidationTable(cmd.OutOrStdout(), s)
			return nil
		},
	}

	addScopeFlag(cmd, &scopeFlag)
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print machine-readable JSON instead of a table")

	return cmd
}

func printValidationTable(w io.Writer, s *scope.Scope) {
	now := time.Now()

	printEngagementHeader(w, s, now)
	fmt.Fprintf(w, "mode: %s\n", s.Mode)

	fmt.Fprintln(w, "\nIN SCOPE")
	for _, r := range s.IncludeRules {
		fmt.Fprintf(w, "  %s\n", r)
	}

	if len(s.ExcludeRules) > 0 {
		fmt.Fprintln(w, "\nEXCLUDED")
		for _, r := range s.ExcludeRules {
			fmt.Fprintf(w, "  %s\n", r)
		}
	}

	if windowStatus(s, now) == "expired" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, colorize(colorRed, "⚠ engagement window has ended — scope checks will deny everything until this file is updated"))
	}
}

// engagementLabel renders "name" or "name (client)" depending on
// whether the optional client field is set.
func engagementLabel(s *scope.Scope) string {
	if s.Client == "" {
		return s.Name
	}
	return fmt.Sprintf("%s (%s)", s.Name, s.Client)
}

type validationJSON struct {
	Name    string     `json:"name"`
	Client  string     `json:"client,omitempty"`
	Start   time.Time  `json:"start"`
	End     time.Time  `json:"end"`
	Mode    scope.Mode `json:"mode"`
	Include []string   `json:"include"`
	Exclude []string   `json:"exclude"`
	Status  string     `json:"status"`
}

func printValidationJSON(w io.Writer, s *scope.Scope) error {
	now := time.Now()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(validationJSON{
		Name:    s.Name,
		Client:  s.Client,
		Start:   s.Start,
		End:     s.End,
		Mode:    s.Mode,
		Include: s.IncludeRules,
		Exclude: s.ExcludeRules,
		Status:  windowStatus(s, now),
	})
}

// windowStatus is the one active/expired/upcoming vocabulary every
// command shares — validate, proxy's banner, and marque engagement
// list's STATUS column all reuse this instead of inventing their own.
// now is passed in rather than sampled here so one render of a table
// (or one JSON encode) is judged against a single consistent instant.
func windowStatus(s *scope.Scope, now time.Time) string {
	switch {
	case now.After(s.End):
		return "expired"
	case now.Before(s.Start):
		return "upcoming"
	default:
		return "active"
	}
}

// windowDateRange renders a scope's window as "YYYY-MM-DD →
// YYYY-MM-DD" — the one place that date pair gets formatted, shared
// by every command's header and the audit export's own window line.
func windowDateRange(s *scope.Scope) string {
	return fmt.Sprintf("%s → %s", s.Start.Format("2006-01-02"), s.End.Format("2006-01-02"))
}

// printEngagementHeader renders the "RedMarque — engagement: ..." /
// "window: ..." pair every scope-aware command's output leads with,
// per docs/UX_FLOW.md's requirement that the active engagement is
// visible in every command's header, not just use/proxy. Anything
// after the window line (mode, listen address, etc.) is each caller's
// own business, since that varies by command.
func printEngagementHeader(w io.Writer, s *scope.Scope, now time.Time) {
	fmt.Fprintf(w, "RedMarque — engagement: %s\n", engagementLabel(s))
	fmt.Fprintf(w, "window: %s (%s)\n", windowDateRange(s), windowSummary(s, now))
}

func windowSummary(s *scope.Scope, now time.Time) string {
	switch windowStatus(s, now) {
	case "expired":
		return fmt.Sprintf("expired %s ago", pluralDays(max(1, int(now.Sub(s.End).Hours()/24))))
	case "upcoming":
		return fmt.Sprintf("starts in %s", pluralDays(max(1, int(s.Start.Sub(now).Hours()/24))))
	default:
		return fmt.Sprintf("%s remaining", pluralDays(int(s.End.Sub(now).Hours()/24)))
	}
}

func pluralDays(n int) string {
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}
