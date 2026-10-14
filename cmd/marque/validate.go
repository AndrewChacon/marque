package main

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/AndrewChacon/red-marque/pkg/scope"
	"github.com/spf13/cobra"
)

func newValidateCmd() *cobra.Command {
	var scopePath string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Check a scope file for errors and print what's in scope",
		RunE: func(cmd *cobra.Command, args []string) error {
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

	cmd.Flags().StringVar(&scopePath, "scope", "", "path to scope.yaml (required)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print machine-readable JSON instead of a table")
	cmd.MarkFlagRequired("scope")

	return cmd
}

func printValidationTable(w io.Writer, s *scope.Scope) {
	now := time.Now()

	fmt.Fprintf(w, "RedMarque — engagement: %s\n", engagementLabel(s))
	fmt.Fprintf(w, "window: %s → %s (%s)\n", s.Start.Format("2006-01-02"), s.End.Format("2006-01-02"), windowSummary(s, now))
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

// windowStatus mirrors the active/expired/upcoming vocabulary
// `marque engagement list` will use once engagement contexts land
// (Stage 3), so output converges on one status vocabulary across
// commands instead of each command inventing its own. now is passed
// in rather than sampled here so one render of the table (or one
// JSON encode) is judged against a single consistent instant.
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
