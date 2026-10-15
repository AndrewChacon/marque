package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// version, commit, and date are overridden at build time via
// goreleaser's default ldflags template (-X main.version=... etc.).
// A plain `go build` leaves these placeholders in place.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// versionDetails is "v0.1.0 (commit abc123, built ..., go1.24.4)" —
// no leading "marque", since cobra's own --version template already
// prepends the command name ("marque version <versionDetails>").
func versionDetails() string {
	return fmt.Sprintf("%s (commit %s, built %s, %s)", version, commit, date, runtime.Version())
}

// versionString is what `marque version` prints on its own line,
// outside cobra's --version template, so it needs the name itself.
func versionString() string {
	return "marque " + versionDetails()
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), versionString())
			return nil
		},
	}
}
