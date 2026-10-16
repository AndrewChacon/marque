package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/AndrewChacon/red-marque/pkg/audit"
	"github.com/AndrewChacon/red-marque/pkg/scope"
	"github.com/spf13/cobra"
)

// tailPollInterval is how often marque audit --tail checks the log
// file for new bytes. Polling (rather than a filesystem-watch
// dependency) is adequate for a CLI feed and keeps the dependency
// list at zero.
const tailPollInterval = 300 * time.Millisecond

func newAuditCmd() *cobra.Command {
	return newAuditCmdWithStore(nil)
}

func newAuditCmdWithStore(injected *engagement.Store) *cobra.Command {
	var scopeFlag string
	var auditLogFlag string
	var tail bool
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Inspect the audit log",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !tail {
				return fmt.Errorf("specify --tail to live-stream decisions, or use `marque audit export`")
			}

			store, err := storeOrDefault(injected)
			if err != nil {
				return err
			}
			paths, err := resolvePaths(scopeFlag, auditLogFlag, store)
			if err != nil {
				return err
			}

			s, err := scope.Load(paths.scopePath)
			if err != nil {
				return err
			}
			printEngagementHeader(cmd.OutOrStdout(), s, time.Now())

			f, err := os.Open(paths.auditLogPath)
			if err != nil {
				return fmt.Errorf("opening audit log: %w (has anything been logged yet? try `marque proxy` or `marque run` first)", err)
			}
			defer f.Close()
			if _, err := f.Seek(0, io.SeekEnd); err != nil {
				return fmt.Errorf("seeking audit log: %w", err)
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return tailAuditLog(ctx, cmd.OutOrStdout(), f, jsonOut, tailPollInterval)
		},
	}

	addScopeFlag(cmd, &scopeFlag)
	addAuditLogFlag(cmd, &auditLogFlag)
	cmd.Flags().BoolVar(&tail, "tail", false, "live-stream new audit decisions as they're logged")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print each decision as a JSON object instead of a colored line")

	cmd.AddCommand(newAuditExportCmd(injected))
	return cmd
}

// tailAuditLog polls f for newly appended bytes every pollInterval,
// printing each complete new line as it arrives, until ctx is done.
//
// It deliberately avoids bufio.Scanner: once Scan returns false at
// EOF it stays false forever, even after more data is appended to the
// same file, which makes it unusable for a growing file. Tracking a
// pending byte buffer across polls and re-reading with plain f.Read
// calls sidesteps that.
func tailAuditLog(ctx context.Context, w io.Writer, f *os.File, jsonOut bool, pollInterval time.Duration) error {
	var pending []byte
	buf := make([]byte, 64*1024)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			for {
				n, err := f.Read(buf)
				if n > 0 {
					pending = append(pending, buf[:n]...)
				}
				if err != nil {
					break
				}
			}
			pending = printCompleteLines(w, pending, jsonOut)
		}
	}
}

// printCompleteLines prints every complete (newline-terminated) line
// in data and returns the trailing, as-yet-incomplete remainder.
// Lines that don't parse as audit entries are skipped rather than
// treated as fatal — a tail is a live feed, not a validator.
func printCompleteLines(w io.Writer, data []byte, jsonOut bool) []byte {
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return data
		}
		line := data[:i]
		data = data[i+1:]

		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		printDecision(w, e.Decision, jsonOut)
	}
}
