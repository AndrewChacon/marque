package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/AndrewChacon/red-marque/internal/proxy"
	"github.com/AndrewChacon/red-marque/pkg/audit"
	"github.com/AndrewChacon/red-marque/pkg/scope"
	"github.com/spf13/cobra"
)

func newProxyCmd() *cobra.Command {
	var scopePath string
	var force bool
	var listenAddr string
	var auditLogPath string
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run the SOCKS5 + HTTP CONNECT proxy, enforcing scope on everything routed through it",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProxy(cmd, proxyOptions{
				scopePath:    scopePath,
				force:        force,
				listenAddr:   listenAddr,
				auditLogPath: auditLogPath,
				jsonOut:      jsonOut,
			})
		},
	}

	cmd.Flags().StringVar(&scopePath, "scope", "", "path to scope.yaml (required)")
	cmd.Flags().BoolVar(&force, "force", false, "start even if the engagement window has ended")
	cmd.Flags().StringVar(&listenAddr, "listen", "127.0.0.1:1080", "address to listen on")
	cmd.Flags().StringVar(&auditLogPath, "audit-log", "", "path to the audit log (default: audit.jsonl next to --scope)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print each decision as a JSON object instead of a colored line")
	cmd.MarkFlagRequired("scope")

	return cmd
}

type proxyOptions struct {
	scopePath    string
	force        bool
	listenAddr   string
	auditLogPath string
	jsonOut      bool
}

// checkProxyPreflight is the --force gate: refuse to start on an
// expired engagement window unless explicitly overridden. Kept as its
// own pure function (scope + force + now in, error out) so it's
// testable without ever touching a real listener.
func checkProxyPreflight(s *scope.Scope, force bool, now time.Time) error {
	if windowStatus(s, now) == "expired" && !force {
		return fmt.Errorf("refusing to start: engagement window ended %s — use --force to override", s.End.Format(time.RFC3339))
	}
	return nil
}

func runProxy(cmd *cobra.Command, opts proxyOptions) error {
	s, err := scope.Load(opts.scopePath)
	if err != nil {
		return err
	}
	if err := checkProxyPreflight(s, opts.force, time.Now()); err != nil {
		return err
	}

	auditLogPath := opts.auditLogPath
	if auditLogPath == "" {
		auditLogPath = filepath.Join(filepath.Dir(opts.scopePath), "audit.jsonl")
	}
	log, err := audit.Open(auditLogPath)
	if err != nil {
		return err
	}
	defer log.Close()

	ln, err := net.Listen("tcp", opts.listenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", opts.listenAddr, err)
	}

	out := cmd.OutOrStdout()
	printProxyBanner(out, s, ln.Addr().String())

	p := &proxy.Proxy{
		Scope: s,
		Audit: log,
		OnDecision: func(d scope.Decision) {
			printDecision(out, d, opts.jsonOut)
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		fmt.Fprintln(out, "\nshutting down...")
		ln.Close()
	}()

	err = p.Serve(ln)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func printProxyBanner(w io.Writer, s *scope.Scope, listenAddr string) {
	now := time.Now()
	fmt.Fprintf(w, "RedMarque — engagement: %s\n", engagementLabel(s))
	fmt.Fprintf(w, "window: %s → %s (%s)\n", s.Start.Format("2006-01-02"), s.End.Format("2006-01-02"), windowSummary(s, now))
	fmt.Fprintf(w, "mode: %s · listening on %s\n\n", s.Mode, listenAddr)
}

func printDecision(w io.Writer, d scope.Decision, jsonOut bool) {
	if jsonOut {
		json.NewEncoder(w).Encode(d)
		return
	}

	label := colorize(colorGreen, "ALLOW")
	if !d.Allowed {
		label = colorize(colorRed, "BLOCK")
	}
	fmt.Fprintf(w, "%s  %-21s  %s\n", label, d.Target, d.Reason)
}
