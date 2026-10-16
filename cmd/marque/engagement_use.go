package main

import (
	"fmt"
	"io"
	"time"

	"github.com/AndrewChacon/marque/internal/engagement"
	"github.com/AndrewChacon/marque/pkg/scope"
	"github.com/spf13/cobra"
)

func newEngagementUseCmd() *cobra.Command {
	return newEngagementUseCmdWithStore(nil)
}

func newEngagementUseCmdWithStore(injected *engagement.Store) *cobra.Command {
	return &cobra.Command{
		Use:   "use <name>",
		Short: "Set the active engagement",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			store, err := storeOrDefault(injected)
			if err != nil {
				return err
			}
			if !store.Exists(name) {
				return fmt.Errorf("no engagement named %q — run `marque engagement add %s` first, or check `marque engagement list`", name, name)
			}

			s, err := scope.Load(store.ScopePath(name))
			if err != nil {
				return fmt.Errorf("engagement %q's scope file is invalid: %w", name, err)
			}
			if err := store.SetActive(name); err != nil {
				return err
			}

			printSwitchConfirmation(cmd.OutOrStdout(), name, s, time.Now())
			return nil
		},
	}
}

func printSwitchConfirmation(w io.Writer, name string, s *scope.Scope, now time.Time) {
	if windowStatus(s, now) != "active" {
		fmt.Fprintf(w, "switched to %s — %s\n", keyedLabel(name, s),
			colorize(colorRed, fmt.Sprintf("WARNING: this engagement %s", windowSummary(s, now))))
		return
	}
	fmt.Fprintf(w, "switched to %s\n", keyedLabel(name, s))
}
