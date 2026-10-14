package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/AndrewChacon/red-marque/pkg/audit"
	"github.com/AndrewChacon/red-marque/pkg/scope"
	"github.com/spf13/cobra"
)

func newAuditExportCmd(injected *engagement.Store) *cobra.Command {
	var scopeFlag string
	var auditLogFlag string
	var format string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the full audit log as JSON or Markdown",
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "json" && format != "markdown" {
				return fmt.Errorf("--format must be \"json\" or \"markdown\", got %q", format)
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

			entries, err := readAuditEntries(paths.auditLogPath)
			if err != nil {
				return err
			}

			// This is a reporting command, not an enforcement gate —
			// a failed verification still gets exported (the tester's
			// own historical records aren't withheld), but the failure
			// is embedded as a loud banner in the artifact itself.
			verifyErr := audit.Verify(paths.auditLogPath)

			if format == "json" {
				return exportJSON(cmd.OutOrStdout(), s, entries, verifyErr)
			}
			return exportMarkdown(cmd.OutOrStdout(), s, entries, verifyErr)
		},
	}

	addScopeFlag(cmd, &scopeFlag)
	addAuditLogFlag(cmd, &auditLogFlag)
	cmd.Flags().StringVar(&format, "format", "json", `export format: "json" or "markdown"`)

	return cmd
}

// readAuditEntries parses every complete, well-formed line in the log.
// A line that doesn't parse is skipped rather than fatal to the whole
// export — audit.Verify, run separately, is what actually judges the
// log's integrity; this just reads what it can.
func readAuditEntries(path string) ([]audit.Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading audit log: %w", err)
	}

	var entries []audit.Entry
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

type exportSummary struct {
	Total   int `json:"total"`
	Allowed int `json:"allowed"`
	Blocked int `json:"blocked"`
}

func summarizeEntries(entries []audit.Entry) exportSummary {
	sum := exportSummary{Total: len(entries)}
	for _, e := range entries {
		if e.Decision.Allowed {
			sum.Allowed++
		} else {
			sum.Blocked++
		}
	}
	return sum
}

type exportDoc struct {
	Engagement  string        `json:"engagement"`
	Client      string        `json:"client,omitempty"`
	WindowStart time.Time     `json:"window_start"`
	WindowEnd   time.Time     `json:"window_end"`
	Status      string        `json:"status"`
	Mode        scope.Mode    `json:"mode"`
	Verified    bool          `json:"verified"`
	VerifyError string        `json:"verify_error,omitempty"`
	Summary     exportSummary `json:"summary"`
	Entries     []audit.Entry `json:"entries"`
}

func exportJSON(w io.Writer, s *scope.Scope, entries []audit.Entry, verifyErr error) error {
	doc := exportDoc{
		Engagement:  s.Name,
		Client:      s.Client,
		WindowStart: s.Start,
		WindowEnd:   s.End,
		Status:      windowStatus(s, time.Now()),
		Mode:        s.Mode,
		Verified:    verifyErr == nil,
		Summary:     summarizeEntries(entries),
		Entries:     entries,
	}
	if verifyErr != nil {
		doc.VerifyError = verifyErr.Error()
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func exportMarkdown(w io.Writer, s *scope.Scope, entries []audit.Entry, verifyErr error) error {
	fmt.Fprintf(w, "# Audit export — %s\n\n", engagementLabel(s))

	if verifyErr != nil {
		fmt.Fprintf(w, "> **⚠ WARNING: audit log failed tamper verification: %s**\n>\n> The entries below are exported as-is but may not reflect what actually happened.\n\n", verifyErr)
	}

	fmt.Fprintf(w, "- Window: %s (%s)\n", windowDateRange(s), windowStatus(s, time.Now()))
	fmt.Fprintf(w, "- Mode: %s\n", s.Mode)

	sum := summarizeEntries(entries)
	fmt.Fprintf(w, "- Decisions: %d total, %d allowed, %d blocked\n\n", sum.Total, sum.Allowed, sum.Blocked)

	fmt.Fprintln(w, "| Timestamp | Decision | Target | Reason |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, e := range entries {
		decision := "ALLOW"
		if !e.Decision.Allowed {
			decision = "BLOCK"
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s |\n", e.Timestamp.Format(time.RFC3339), decision, e.Decision.Target, e.Decision.Reason)
	}
	return nil
}
