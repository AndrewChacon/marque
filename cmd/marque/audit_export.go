package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/AndrewChacon/marque/internal/engagement"
	"github.com/AndrewChacon/marque/pkg/audit"
	"github.com/AndrewChacon/marque/pkg/scope"
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
				return exportJSON(cmd.OutOrStdout(), paths.engagement, s, entries, verifyErr)
			}
			return exportMarkdown(cmd.OutOrStdout(), paths.engagement, s, entries, verifyErr)
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
	WindowEnd   *time.Time    `json:"window_end,omitempty"`
	Status      string        `json:"status"`
	Mode        scope.Mode    `json:"mode"`
	Verified    bool          `json:"verified"`
	VerifyError string        `json:"verify_error,omitempty"`
	Summary     exportSummary `json:"summary"`
	Entries     []audit.Entry `json:"entries"`
}

func exportJSON(w io.Writer, key string, s *scope.Scope, entries []audit.Entry, verifyErr error) error {
	doc := exportDoc{
		Engagement:  resolvedEngagementName(key, s),
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

func exportMarkdown(w io.Writer, key string, s *scope.Scope, entries []audit.Entry, verifyErr error) error {
	fmt.Fprintf(w, "# Audit export — %s\n\n", keyedLabel(key, s))

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
		fmt.Fprintf(w, "| %s | %s | %s | %s |\n", e.Timestamp.Format(time.RFC3339), decision,
			sanitizeForSingleLineDisplay(e.Decision.Target), sanitizeForSingleLineDisplay(e.Decision.Reason))
	}
	return nil
}

// sanitizeForSingleLineDisplay makes a string safe to render as a
// single line of output — one markdown table cell, or one terminal
// row. Decision.Target in particular is not operator-authored: it
// comes from whatever a SOCKS5 client sends as a raw domain field
// (internal/proxy/socks5.go parses it with zero character
// validation), so a literal "|" or an embedded newline is a real,
// reachable input, not a hypothetical one — a newline would let one
// decision masquerade as several fabricated lines, and an
// unescaped "|" would shift a markdown table's columns.
func sanitizeForSingleLineDisplay(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}
