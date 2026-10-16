package main

import (
	"encoding/json"
	"fmt"
	"io"
	"syscall"
	"time"

	"github.com/AndrewChacon/marque/internal/engagement"
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
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop a backgrounded marque proxy",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storeOrDefault(injected)
			if err != nil {
				return err
			}
			return runProxyStop(cmd, store, jsonOut)
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "print machine-readable JSON instead of a text summary")
	return cmd
}

type proxyStopJSON struct {
	Action string `json:"action"` // "none", "stale_cleaned", "stopped", "sigkill"
	PID    int    `json:"pid,omitempty"`
}

// reportStopResult is runProxyStop's single point of output, so its
// four outcomes (nothing running / stale cleanup / graceful stop /
// SIGKILL escalation) don't each need their own text-vs-JSON branch.
func reportStopResult(w io.Writer, jsonOut bool, action string, pid int, textMsg string) error {
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(proxyStopJSON{Action: action, PID: pid})
	}
	fmt.Fprintln(w, textMsg)
	return nil
}

func runProxyStop(cmd *cobra.Command, store *engagement.Store, jsonOut bool) error {
	out := cmd.OutOrStdout()

	info, alive, err := readProxyPID(store)
	if err != nil {
		return err
	}
	if info == nil {
		return reportStopResult(out, jsonOut, "none", 0, "no backgrounded proxy is running")
	}
	if !alive {
		// readProxyPID already cleaned up the stale file.
		return reportStopResult(out, jsonOut, "stale_cleaned", info.PID, fmt.Sprintf("no backgrounded proxy is running (removed a stale pid file for pid %d)", info.PID))
	}

	if err := syscall.Kill(info.PID, syscall.SIGTERM); err != nil {
		return fmt.Errorf("stopping proxy (pid %d): %w", info.PID, err)
	}

	deadline := time.Now().Add(proxyStopGracePeriod)
	if waitForExit(func() bool { return processAlive(info.PID) }, deadline, 100*time.Millisecond) {
		_ = removeProxyPID(store) // defensive — the child's own deferred cleanup should have already done this
		return reportStopResult(out, jsonOut, "stopped", info.PID, fmt.Sprintf("stopped proxy (pid %d)", info.PID))
	}

	if err := syscall.Kill(info.PID, syscall.SIGKILL); err != nil {
		return fmt.Errorf("proxy (pid %d) did not stop gracefully and SIGKILL failed: %w", info.PID, err)
	}
	_ = removeProxyPID(store) // a killed process can't run its own cleanup
	return reportStopResult(out, jsonOut, "sigkill", info.PID, fmt.Sprintf("proxy (pid %d) did not exit within %s — sent SIGKILL", info.PID, proxyStopGracePeriod))
}

// waitForExit polls aliveFn every pollInterval until deadline,
// reporting true the moment it sees the process dead — including one
// final check right at the deadline itself, so a process that exits
// during the very last sleep isn't missed and misreported as having
// failed to respond to SIGTERM.
func waitForExit(aliveFn func() bool, deadline time.Time, pollInterval time.Duration) bool {
	for time.Now().Before(deadline) {
		if !aliveFn() {
			return true
		}
		time.Sleep(pollInterval)
	}
	return !aliveFn()
}
