package main

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/AndrewChacon/red-marque/pkg/scope"
	"github.com/spf13/cobra"
)

func newEngagementListCmd() *cobra.Command {
	return newEngagementListCmdWithStore(nil)
}

func newEngagementListCmdWithStore(injected *engagement.Store) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all known engagements",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storeOrDefault(injected)
			if err != nil {
				return err
			}
			names, err := store.List()
			if err != nil {
				return err
			}
			active, err := store.Active()
			if err != nil {
				return err
			}

			printEngagementList(cmd.OutOrStdout(), store, names, active, time.Now())
			return nil
		},
	}
}

// printEngagementList's STATUS column reuses the existing
// active/expired/upcoming window-status vocabulary from validate.go —
// not a second meaning. Which engagement is the currently *selected*
// context (set via `use`) is a separate axis, marked with an arrow on
// that row instead, so the two concepts don't collide in one symbol.
func printEngagementList(w io.Writer, store *engagement.Store, names []string, active string, now time.Time) {
	if len(names) == 0 {
		fmt.Fprintln(w, "no engagements yet — run `marque engagement add <name>` to create one")
		return
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  NAME\tCLIENT\tWINDOW\tSTATUS")
	for _, name := range names {
		marker := " "
		if name == active {
			marker = "→"
		}

		s, err := scope.Load(store.ScopePath(name))
		if err != nil {
			fmt.Fprintf(tw, "%s %s\t-\t-\tparse error: %v\n", marker, name, err)
			continue
		}

		window := fmt.Sprintf("%s - %s", s.Start.Format("Jan 02 2006"), s.End.Format("Jan 02 2006"))
		fmt.Fprintf(tw, "%s %s\t%s\t%s\t%s\n", marker, name, s.Client, window, windowStatus(s, now))
	}
	tw.Flush()
}
