package main

import (
	"fmt"
	"syscall"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/spf13/cobra"
)

// proxyStopGracePeriod is how long stop waits for a clean SIGTERM
// shutdown before escalating to SIGKILL — matches systemctl stop's
// own TERM-then-KILL convention. A hung instance of a safety-
// enforcement tool is worse than a forceful kill. A var, not a const,
// so tests exercising the SIGKILL-escalation path aren't stuck
// waiting out a real 5 seconds.
var proxyStopGracePeriod = 5 * time.Second

func newProxyStopCmd(injected *engagement.Store) *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop a backgrounded marque proxy",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storeOrDefault(injected)
			if err != nil {
				return err
			}
			return runProxyStop(cmd, store)
		},
	}
}

func runProxyStop(cmd *cobra.Command, store *engagement.Store) error {
	out := cmd.OutOrStdout()

	info, alive, err := readProxyPID(store)
	if err != nil {
		return err
	}
	if info == nil {
		fmt.Fprintln(out, "no backgrounded proxy is running")
		return nil
	}
	if !alive {
		// readProxyPID already cleaned up the stale file.
		fmt.Fprintf(out, "no backgrounded proxy is running (removed a stale pid file for pid %d)\n", info.PID)
		return nil
	}

	if err := syscall.Kill(info.PID, syscall.SIGTERM); err != nil {
		return fmt.Errorf("stopping proxy (pid %d): %w", info.PID, err)
	}

	deadline := time.Now().Add(proxyStopGracePeriod)
	for time.Now().Before(deadline) {
		if !processAlive(info.PID) {
			_ = removeProxyPID(store) // defensive — the child's own deferred cleanup should have already done this
			fmt.Fprintf(out, "stopped proxy (pid %d)\n", info.PID)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err := syscall.Kill(info.PID, syscall.SIGKILL); err != nil {
		return fmt.Errorf("proxy (pid %d) did not stop gracefully and SIGKILL failed: %w", info.PID, err)
	}
	_ = removeProxyPID(store) // a killed process can't run its own cleanup
	fmt.Fprintf(out, "proxy (pid %d) did not exit within %s — sent SIGKILL\n", info.PID, proxyStopGracePeriod)
	return nil
}
