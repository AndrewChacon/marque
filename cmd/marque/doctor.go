package main

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/AndrewChacon/red-marque/pkg/scope"
	"github.com/spf13/cobra"
)

type doctorCheck struct {
	name   string
	status string // "PASS", "WARN", or "FAIL"
	detail string
}

func newDoctorCmd() *cobra.Command {
	return newDoctorCmdWithStore(nil)
}

func newDoctorCmdWithStore(injected *engagement.Store) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check whether marque is ready to run",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storeOrDefault(injected)
			if err != nil {
				return err
			}

			checks := runDoctorChecks(store)
			printDoctorReport(cmd.OutOrStdout(), checks)

			for _, c := range checks {
				if c.status == "FAIL" {
					return fmt.Errorf("doctor found problems — see above")
				}
			}
			return nil
		},
	}
}

// runDoctorChecks is brew-doctor style: is an engagement active, does
// its scope file still parse, has its window expired, is the default
// proxy port free. Each later check that depends on an earlier one
// succeeding is skipped (not failed) if its prerequisite didn't hold —
// the port check is independent and always runs regardless.
func runDoctorChecks(store *engagement.Store) []doctorCheck {
	var checks []doctorCheck

	active, err := store.Active()
	switch {
	case err != nil:
		checks = append(checks, doctorCheck{"active engagement", "FAIL", fmt.Sprintf("could not read: %v", err)})
	case active == "":
		checks = append(checks, doctorCheck{"active engagement", "FAIL", "none set — run `marque engagement use <name>`"})
	default:
		checks = append(checks, doctorCheck{"active engagement", "PASS", active})

		s, err := scope.Load(store.ScopePath(active))
		if err != nil {
			checks = append(checks, doctorCheck{"scope file", "FAIL", err.Error()})
		} else {
			checks = append(checks, doctorCheck{"scope file", "PASS", "parses cleanly"})
			checks = append(checks, windowCheck(s, time.Now()))
		}
	}

	checks = append(checks, portFreeCheck(defaultProxyAddr))
	return checks
}

func windowCheck(s *scope.Scope, now time.Time) doctorCheck {
	switch windowStatus(s, now) {
	case "expired":
		return doctorCheck{"engagement window", "FAIL", windowSummary(s, now)}
	case "upcoming":
		return doctorCheck{"engagement window", "WARN", windowSummary(s, now)}
	default:
		return doctorCheck{"engagement window", "PASS", windowSummary(s, now)}
	}
}

func portFreeCheck(addr string) doctorCheck {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return doctorCheck{"proxy port " + addr, "FAIL", fmt.Sprintf("already in use: %v", err)}
	}
	ln.Close()
	return doctorCheck{"proxy port " + addr, "PASS", "free"}
}

func printDoctorReport(w io.Writer, checks []doctorCheck) {
	failed := false
	for _, c := range checks {
		label := c.status
		switch c.status {
		case "PASS":
			label = colorize(colorGreen, "PASS")
		case "WARN":
			label = colorize(colorYellow, "WARN")
		case "FAIL":
			label = colorize(colorRed, "FAIL")
			failed = true
		}
		fmt.Fprintf(w, "[%s] %-20s %s\n", label, c.name, c.detail)
	}

	fmt.Fprintln(w)
	if failed {
		fmt.Fprintln(w, "Some checks failed — fix the items above before running `marque proxy`.")
		return
	}
	fmt.Fprintln(w, "Everything looks ready.")
}
