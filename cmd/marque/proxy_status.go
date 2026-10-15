package main

import (
	"fmt"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/spf13/cobra"
)

func newProxyStatusCmd(injected *engagement.Store) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check whether a backgrounded marque proxy is running",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storeOrDefault(injected)
			if err != nil {
				return err
			}
			return runProxyStatus(cmd, store)
		},
	}
}

func runProxyStatus(cmd *cobra.Command, store *engagement.Store) error {
	out := cmd.OutOrStdout()

	info, alive, err := readProxyPID(store)
	if err != nil {
		return err
	}
	if !alive {
		fmt.Fprintln(out, "no backgrounded proxy is running")
		return nil
	}

	uptime := time.Since(info.StartedAt).Round(time.Second)
	fmt.Fprintf(out, "proxy running — pid %d, listening on %s, up %s\n", info.PID, info.ListenAddr, uptime)
	if info.Engagement != "" {
		fmt.Fprintf(out, "engagement: %s\n", info.Engagement)
	}
	printProxyNextSteps(out)
	return nil
}
