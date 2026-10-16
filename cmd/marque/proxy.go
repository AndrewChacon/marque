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
	"syscall"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/AndrewChacon/red-marque/internal/proxy"
	"github.com/AndrewChacon/red-marque/pkg/scope"
	"github.com/spf13/cobra"
)

// defaultProxyAddr is marque proxy's own default --listen address —
// the one canonical definition doctor's port-free check and
// proxychains-config's default snippet both reference, rather than
// each hardcoding "127.0.0.1:1080" and risking drift.
const defaultProxyAddr = "127.0.0.1:1080"

func newProxyCmd() *cobra.Command {
	return newProxyCmdWithStore(nil)
}

func newProxyCmdWithStore(injected *engagement.Store) *cobra.Command {
	var scopeFlag string
	var force bool
	var listenAddr string
	var auditLogFlag string
	var jsonOut bool
	var foreground bool

	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run the SOCKS5 + HTTP CONNECT proxy, enforcing scope on everything routed through it",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storeOrDefault(injected)
			if err != nil {
				return err
			}
			return runProxy(cmd, store, proxyOptions{
				scopeFlag:    scopeFlag,
				force:        force,
				listenAddr:   listenAddr,
				auditLogFlag: auditLogFlag,
				jsonOut:      jsonOut,
				foreground:   foreground,
			})
		},
	}

	addScopeFlag(cmd, &scopeFlag)
	cmd.Flags().BoolVar(&force, "force", false, "start even if the engagement window has ended")
	cmd.Flags().StringVar(&listenAddr, "listen", defaultProxyAddr, "address to listen on")
	addAuditLogFlag(cmd, &auditLogFlag)
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print each decision as a JSON object instead of a colored line (--foreground only)")
	cmd.Flags().BoolVar(&foreground, "foreground", false, "block in the foreground with a live decision feed instead of backgrounding (the pre-background default behavior)")

	cmd.AddCommand(newProxyStopCmd(injected))
	cmd.AddCommand(newProxyStatusCmd(injected))

	return cmd
}

type proxyOptions struct {
	scopeFlag    string
	force        bool
	listenAddr   string
	auditLogFlag string
	jsonOut      bool
	foreground   bool
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

// runProxy dispatches to one of three code paths: the re-exec'd
// daemon child (detected via daemonChildEnv, set only by
// startDaemonChild — never by a human), the --foreground opt-out
// (today's original blocking behavior, completely unchanged), or the
// new default of backgrounding itself. See proxy_daemon.go for the
// latter two's shared machinery.
func runProxy(cmd *cobra.Command, store *engagement.Store, opts proxyOptions) error {
	if os.Getenv(daemonChildEnv) == "1" {
		return runProxyChild(cmd, store, opts)
	}
	if opts.foreground {
		return runProxyForeground(cmd, store, opts)
	}
	return daemonizeProxy(cmd, store, opts)
}

// runProxyForeground is marque proxy --foreground: blocks until
// Ctrl-C, printing a live decision feed. This is the tool's entire
// behavior before backgrounding became the default — preserved
// verbatim as an explicit opt-out for scripting, containers, or
// anyone who wants the old always-visible feed.
func runProxyForeground(cmd *cobra.Command, store *engagement.Store, opts proxyOptions) error {
	paths, err := resolvePaths(opts.scopeFlag, opts.auditLogFlag, store)
	if err != nil {
		return err
	}

	s, err := scope.Load(paths.scopePath)
	if err != nil {
		return err
	}
	if err := checkProxyPreflight(s, opts.force, time.Now()); err != nil {
		return err
	}

	log, err := openAuditLogWithHint(paths.auditLogPath)
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
	printEngagementHeader(w, s, time.Now())
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
	fmt.Fprintf(w, "%s  %-21s  %s\n", label, sanitizeForSingleLineDisplay(d.Target), sanitizeForSingleLineDisplay(d.Reason))
}
