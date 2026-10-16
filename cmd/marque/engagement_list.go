package main

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/AndrewChacon/marque/internal/engagement"
	"github.com/AndrewChacon/marque/pkg/scope"
	"github.com/spf13/cobra"
)

func newEngagementListCmd() *cobra.Command {
	return newEngagementListCmdWithStore(nil)
}

func newEngagementListCmdWithStore(injected *engagement.Store) *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
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

			if jsonOut {
				return printEngagementListJSON(cmd.OutOrStdout(), store, names, active, time.Now())
			}
			printEngagementList(cmd.OutOrStdout(), store, names, active, time.Now())
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "print machine-readable JSON instead of a table")
	return cmd
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

		endStr := "ongoing"
		if s.End != nil {
			endStr = s.End.Format("Jan 02 2006")
		}
		window := fmt.Sprintf("%s - %s", s.Start.Format("Jan 02 2006"), endStr)
		fmt.Fprintf(tw, "%s %s\t%s\t%s\t%s\n", marker, name, s.Client, window, windowStatus(s, now))
	}
	tw.Flush()
}

type engagementListEntry struct {
	Name   string     `json:"name"`
	Active bool       `json:"active"`
	Client string     `json:"client,omitempty"`
	Start  *time.Time `json:"start,omitempty"`
	End    *time.Time `json:"end,omitempty"`
	Status string     `json:"status,omitempty"`
	Error  string     `json:"error,omitempty"`
}

func printEngagementListJSON(w io.Writer, store *engagement.Store, names []string, active string, now time.Time) error {
	var entries []engagementListEntry
	for _, name := range names {
		entry := engagementListEntry{Name: name, Active: name == active}
		s, err := scope.Load(store.ScopePath(name))
		if err != nil {
			entry.Error = err.Error()
			entries = append(entries, entry)
			continue
		}
		start := s.Start
		entry.Client = s.Client
		entry.Start = &start
		entry.End = s.End
		entry.Status = windowStatus(s, now)
		entries = append(entries, entry)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}
