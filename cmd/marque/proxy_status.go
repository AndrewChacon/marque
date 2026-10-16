package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/spf13/cobra"
)

func newProxyStatusCmd(injected *engagement.Store) *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check whether a backgrounded marque proxy is running",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storeOrDefault(injected)
			if err != nil {
				return err
			}
			return runProxyStatus(cmd, store, jsonOut)
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "print machine-readable JSON instead of a text summary")
	return cmd
}

type proxyStatusJSON struct {
	Running    bool    `json:"running"`
	PID        int     `json:"pid,omitempty"`
	ListenAddr string  `json:"listen_addr,omitempty"`
	UptimeSecs float64 `json:"uptime_seconds,omitempty"`
	Engagement string  `json:"engagement,omitempty"`
}

func runProxyStatus(cmd *cobra.Command, store *engagement.Store, jsonOut bool) error {
	out := cmd.OutOrStdout()

	info, alive, err := readProxyPID(store)
	if err != nil {
		return err
	}
	if !alive {
		if jsonOut {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(proxyStatusJSON{Running: false})
		}
		fmt.Fprintln(out, "no backgrounded proxy is running")
		return nil
	}

	uptime := time.Since(info.StartedAt).Round(time.Second)
	if jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(proxyStatusJSON{
			Running:    true,
			PID:        info.PID,
			ListenAddr: info.ListenAddr,
			UptimeSecs: uptime.Seconds(),
			Engagement: info.Engagement,
		})
	}

	fmt.Fprintf(out, "proxy running — pid %d, listening on %s, up %s\n", info.PID, info.ListenAddr, uptime)
	if info.Engagement != "" {
		fmt.Fprintf(out, "engagement: %s\n", info.Engagement)
	}
	printProxyNextSteps(out)
	return nil
}
