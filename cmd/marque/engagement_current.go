package main

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/AndrewChacon/marque/internal/engagement"
	"github.com/AndrewChacon/marque/pkg/scope"
	"github.com/spf13/cobra"
)

func newEngagementCurrentCmd() *cobra.Command {
	return newEngagementCurrentCmdWithStore(nil)
}

func newEngagementCurrentCmdWithStore(injected *engagement.Store) *cobra.Command {
	var jsonOut bool
	var short bool

	cmd := &cobra.Command{
		Use:   "current",
		Short: "Show which engagement is currently active",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storeOrDefault(injected)
			if err != nil {
				return err
			}

			active, err := store.Active()
			if err != nil {
				return err
			}
			if active == "" {
				return printNoActiveEngagement(cmd.OutOrStdout(), jsonOut, short)
			}

			s, err := scope.Load(store.ScopePath(active))
			if err != nil {
				return fmt.Errorf("engagement %q's scope file is invalid: %w", active, err)
			}

			now := time.Now()
			switch {
			case short:
				fmt.Fprintln(cmd.OutOrStdout(), active) // store key, not s.Name
			case jsonOut:
				return printCurrentJSON(cmd.OutOrStdout(), active, s, now)
			default:
				printCurrentLine(cmd.OutOrStdout(), active, s, now)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "print machine-readable JSON instead of a one-line summary")
	cmd.Flags().BoolVar(&short, "short", false, "print only the active engagement's name — nothing, on success, if none is active (for shell prompts/scripting, kubectx -c style)")
	cmd.MarkFlagsMutuallyExclusive("json", "short")

	return cmd
}

// printNoActiveEngagement handles the "nothing active" case for all
// three output modes. --short prints nothing at all (still exit 0) so
// a shell-prompt segment wired to it just disappears instead of
// showing an error string. This is deliberately different from the
// active-engagement-but-broken-scope-file case in RunE, which still
// hard-errors in every mode including --short — "nothing configured"
// and "something is actually wrong" must stay distinguishable, or a
// real corruption problem could sit silently hidden behind a prompt
// segment that just looks empty.
func printNoActiveEngagement(w io.Writer, jsonOut, short bool) error {
	switch {
	case short:
		return nil
	case jsonOut:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(currentJSON{Active: false})
	default:
		fmt.Fprintln(w, "no active engagement — "+noActiveEngagementRemedy)
		return nil
	}
}

func printCurrentLine(w io.Writer, key string, s *scope.Scope, now time.Time) {
	fmt.Fprintf(w, "%s — %s, %s\n", keyedLabel(key, s), windowStatus(s, now), windowSummary(s, now))
}

// currentJSON.Name is the store key (what store.Active() returned, and
// what `marque engagement use <name>` expects back), not s.Name — the
// scope file's own self-reported engagement.name. Those two normally
// match but can diverge for a --scope-imported engagement whose file
// declares a different name than the key it was added under. A script
// round-tripping this value into `engagement use` needs the storage
// key, not the file's internal opinion of its own name.
type currentJSON struct {
	Active bool       `json:"active"`
	Name   string     `json:"name,omitempty"`
	Client string     `json:"client,omitempty"`
	Status string     `json:"status,omitempty"`
	Start  *time.Time `json:"start,omitempty"`
	End    *time.Time `json:"end,omitempty"`
}

func printCurrentJSON(w io.Writer, active string, s *scope.Scope, now time.Time) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	start := s.Start
	return enc.Encode(currentJSON{
		Active: true,
		Name:   active,
		Client: s.Client,
		Status: windowStatus(s, now),
		Start:  &start,
		End:    s.End,
	})
}
